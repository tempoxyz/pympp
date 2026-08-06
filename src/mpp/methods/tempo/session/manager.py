"""Reusable lifecycle, persistence, policy, and recovery for Tempo sessions."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential
from mpp.errors import InvalidChallengeError, PaymentExpiredError

from .credentials import SessionCredentialProvider
from .models import (
    TIP20_CHANNEL_RESERVE,
    ZERO_ADDRESS,
    PendingOperation,
    PendingStatus,
    SessionAction,
    SessionPolicy,
    SessionReceipt,
    SessionRecord,
    SessionSnapshot,
    SessionStatus,
    normalize_address,
)
from .protocol import (
    ChannelState,
    SessionRpc,
    TempoSessionProtocol,
    channel_scope,
    compute_channel_id,
    decode_session_receipt,
    decode_session_snapshot,
    verify_voucher_signature,
)
from .state import (
    SessionEvent,
    resolve_opening_deposit,
    resolve_voucher_plan,
    transition,
)
from .store import SessionStore

if TYPE_CHECKING:
    from .sse import NeedVoucherEvent


class SessionRecoveryRequiredError(RuntimeError):
    """Raised when an uncertain operation cannot safely be advanced."""


@dataclass(frozen=True, slots=True)
class ChallengeContext:
    """Validated v2 fields needed to plan a session operation."""

    amount: int
    chain_id: int
    escrow: str
    fee_payer: bool
    min_voucher_delta: int
    operator: str | None
    payee: str
    suggested_deposit: int | None
    token: str
    snapshot: SessionSnapshot | None

    @property
    def scope(self) -> str:
        return channel_scope(
            payee=self.payee,
            token=self.token,
            escrow=self.escrow,
            chain_id=self.chain_id,
        )


def _decimal(value: Any, field: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError(f"session challenge {field} must be a decimal string")
    return int(value)


def resolve_challenge(challenge: Challenge) -> ChallengeContext:
    """Validate a `tempo/session` challenge and its TIP-1034 v2 details."""

    if challenge.method != "tempo" or challenge.intent != "session":
        raise ValueError("expected a tempo/session challenge")
    if challenge.expires is not None:
        try:
            expires = datetime.fromisoformat(challenge.expires)
        except (TypeError, ValueError) as error:
            raise InvalidChallengeError(challenge.id, "invalid expires") from error
        if expires.tzinfo is None:
            raise InvalidChallengeError(challenge.id, "invalid expires")
        if expires < datetime.now(UTC):
            raise PaymentExpiredError(challenge.expires)
    request = challenge.request
    details = request.get("methodDetails")
    if not isinstance(details, dict):
        raise ValueError("session challenge is missing methodDetails")
    if details.get("sessionProtocol") != "v2":
        raise ValueError("pympp supports TIP-1034 sessionProtocol v2")
    chain_id = details.get("chainId")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise ValueError("session challenge is missing a valid chainId")
    operator = details.get("operator")
    if operator is not None:
        operator = normalize_address(operator, "operator")
    suggested = request.get("suggestedDeposit")
    snapshot = details.get("sessionSnapshot")
    min_voucher_delta = details.get("minVoucherDelta", "0")
    fee_payer = details.get("feePayer", False)
    if not isinstance(fee_payer, bool):
        raise ValueError("session challenge feePayer must be a boolean")
    return ChallengeContext(
        amount=_decimal(request.get("amount"), "amount"),
        chain_id=chain_id,
        escrow=normalize_address(details.get("escrowContract"), "escrowContract"),
        fee_payer=fee_payer,
        min_voucher_delta=_decimal(min_voucher_delta, "minVoucherDelta"),
        operator=operator,
        payee=normalize_address(request.get("recipient"), "recipient"),
        suggested_deposit=(None if suggested is None else _decimal(suggested, "suggestedDeposit")),
        token=normalize_address(request.get("currency"), "currency"),
        snapshot=None if snapshot is None else SessionSnapshot.from_wire(snapshot),
    )


def is_tip1034_session_challenge(challenge: Challenge) -> bool:
    """Return whether a challenge selects the supported TIP-1034 v2 driver."""

    details = challenge.request.get("methodDetails")
    if not (
        challenge.method == "tempo"
        and challenge.intent == "session"
        and isinstance(details, dict)
        and details.get("sessionProtocol") == "v2"
    ):
        return False
    try:
        resolve_challenge(challenge)
    except (InvalidChallengeError, PaymentExpiredError, ValueError):
        return False
    return True


def _voucher_from_payload(payload: Mapping[str, Any]) -> dict[str, str] | None:
    if payload.get("action") not in {"open", "voucher", "close"}:
        return None
    return {
        "channelId": str(payload["channelId"]),
        "cumulativeAmount": str(payload["cumulativeAmount"]),
        "signature": str(payload["signature"]),
    }


class TempoSessionManager:
    """TIP-1034 client manager shared by HTTP integrations and host plugins.

    Operations are serialized by reusable-channel scope. Unrelated payees,
    tokens, escrows, or chains keep independent locks. A lock is held from
    credential preparation until the transport reports a definite or uncertain
    outcome, preventing concurrent callers from authorizing competing states.
    """

    def __init__(
        self,
        *,
        provider: SessionCredentialProvider,
        store: SessionStore,
        policy: SessionPolicy,
        rpc: SessionRpc,
        chain_id: int,
        escrow: str = TIP20_CHANNEL_RESERVE,
        protocol: TempoSessionProtocol | None = None,
    ) -> None:
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("session manager chain_id must be a positive integer")
        self.provider = provider
        self.store = store
        self.policy = policy
        self.rpc = rpc
        self.chain_id = chain_id
        self.escrow = normalize_address(escrow, "escrow")
        self.protocol = protocol or TempoSessionProtocol(provider=provider, rpc=rpc)
        self._locks_guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._held: set[str] = set()

    def can_handle_challenge(self, challenge: Challenge) -> bool:
        """Return whether a challenge is inside this manager's network policy."""

        if not is_tip1034_session_challenge(challenge):
            return False
        context = resolve_challenge(challenge)
        return context.chain_id == self.chain_id and context.escrow == self.escrow

    def _resolve_challenge(self, challenge: Challenge) -> ChallengeContext:
        context = resolve_challenge(challenge)
        if context.chain_id != self.chain_id:
            raise ValueError(
                f"session manager is restricted to chain {self.chain_id}, not {context.chain_id}"
            )
        if context.escrow != self.escrow:
            raise ValueError("session challenge escrow is outside local policy")
        return context

    def _lock_for(self, scope: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope, threading.Lock())

    async def _acquire(self, scope: str) -> None:
        lock = self._lock_for(scope)
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.005)
        with self._locks_guard:
            self._held.add(scope)

    def _release(self, scope: str) -> None:
        with self._locks_guard:
            if scope not in self._held:
                return
            self._held.remove(scope)
        self._lock_for(scope).release()

    @staticmethod
    def _pending(
        *,
        action: SessionAction,
        challenge: Challenge,
        payload: dict[str, Any],
        expected_deposit: int | None = None,
        expected_cumulative: int | None = None,
    ) -> PendingOperation:
        return PendingOperation(
            action=action,
            challenge_id=challenge.id,
            payload=payload,
            status=PendingStatus.PREPARED,
            created_at=datetime.now(UTC).isoformat(),
            expected_deposit=expected_deposit,
            expected_cumulative=expected_cumulative,
        )

    def _credential(
        self,
        challenge: Challenge,
        payload: dict[str, Any],
        chain_id: int,
    ) -> Credential:
        return Credential(
            challenge=challenge.to_echo(),
            payload=payload,
            source=(
                f"did:pkh:eip155:{chain_id}:"
                f"{normalize_address(self.provider.payer_address, 'payer')}"
            ),
        )

    def _validate_record(self, record: SessionRecord, context: ChallengeContext) -> None:
        descriptor = record.descriptor
        if record.scope != context.scope:
            raise ValueError("stored session scope does not match challenge")
        if descriptor.payee != context.payee or descriptor.token != context.token:
            raise ValueError("stored channel does not match challenge payment fields")
        if descriptor.operator != (context.operator or ZERO_ADDRESS.lower()):
            raise ValueError("stored channel operator does not match challenge")
        if descriptor.payer != normalize_address(self.provider.payer_address, "payer"):
            raise ValueError("stored channel payer does not match credential provider")
        if descriptor.effective_signer != normalize_address(self.provider.signer_address, "signer"):
            raise ValueError("stored channel signer does not match credential provider")
        expected = compute_channel_id(
            descriptor,
            escrow=context.escrow,
            chain_id=context.chain_id,
        )
        if expected != record.channel_id:
            raise ValueError("stored channel ID does not match its descriptor")
        if record.deposit > self.policy.max_deposit:
            raise ValueError("stored channel exceeds max deposit")
        if record.authorized_cumulative > self.policy.max_cumulative_spend:
            raise ValueError("stored channel exceeds max cumulative spend")

    async def _hydrate_snapshot(
        self,
        context: ChallengeContext,
        snapshot: SessionSnapshot,
        resource_url: str,
    ) -> SessionRecord:
        if (
            snapshot.chain_id != context.chain_id
            or snapshot.escrow != context.escrow
            or snapshot.descriptor.payee != context.payee
            or snapshot.descriptor.token != context.token
            or snapshot.descriptor.operator != (context.operator or ZERO_ADDRESS.lower())
        ):
            raise ValueError("session snapshot does not match challenge scope")
        if snapshot.descriptor.payer != normalize_address(
            self.provider.payer_address, "payer"
        ) or snapshot.descriptor.effective_signer != normalize_address(
            self.provider.signer_address, "signer"
        ):
            raise ValueError("session snapshot is not controlled by this credential provider")
        computed = compute_channel_id(
            snapshot.descriptor,
            escrow=snapshot.escrow,
            chain_id=snapshot.chain_id,
        )
        if computed != snapshot.channel_id:
            raise ValueError("session snapshot channel ID does not match descriptor")
        highest = snapshot.highest_voucher
        if highest is None:
            raise ValueError("session snapshot is missing its highest signed voucher")
        if (
            str(highest.get("channelId", "")).lower() != snapshot.channel_id
            or _decimal(highest.get("cumulativeAmount"), "highest voucher amount")
            != snapshot.accepted_cumulative
            or not verify_voucher_signature(
                channel_id=snapshot.channel_id,
                cumulative_amount=snapshot.accepted_cumulative,
                signature=str(highest.get("signature", "")),
                expected_signer=snapshot.descriptor.effective_signer,
                chain_id=snapshot.chain_id,
                escrow=snapshot.escrow,
            )
        ):
            raise ValueError("session snapshot highest voucher is invalid")
        state = await self.rpc.channel_state(snapshot.escrow, snapshot.channel_id)
        if not state.open:
            raise ValueError("session snapshot channel is not open on-chain")
        if state.close_requested_at != 0:
            raise SessionRecoveryRequiredError(
                "session snapshot channel has a pending on-chain close request"
            )
        if snapshot.spent > snapshot.accepted_cumulative:
            raise ValueError("session snapshot spent exceeds accepted cumulative")
        if snapshot.accepted_cumulative > state.deposit:
            raise ValueError("session snapshot accepted cumulative exceeds on-chain deposit")
        if snapshot.accepted_cumulative > self.policy.max_cumulative_spend:
            raise ValueError("session snapshot exceeds max cumulative spend")
        if state.deposit > self.policy.max_deposit:
            raise ValueError("session snapshot channel exceeds max deposit")
        record = SessionRecord(
            scope=context.scope,
            channel_id=snapshot.channel_id,
            descriptor=snapshot.descriptor,
            escrow=snapshot.escrow,
            chain_id=snapshot.chain_id,
            deposit=state.deposit,
            authorized_cumulative=snapshot.accepted_cumulative,
            accepted_cumulative=snapshot.accepted_cumulative,
            settled=state.settled,
            spent=snapshot.spent,
            status=SessionStatus.ACTIVE,
            resource_url=resource_url,
            close_requested_at=state.close_requested_at,
            highest_voucher=dict(highest),
            units=snapshot.units,
        )
        await self.store.save(record)
        return record

    async def _apply_snapshot(
        self,
        record: SessionRecord,
        snapshot: SessionSnapshot,
    ) -> bool:
        if (
            snapshot.channel_id != record.channel_id
            or snapshot.chain_id != record.chain_id
            or snapshot.escrow != record.escrow
            or snapshot.descriptor != record.descriptor
        ):
            raise ValueError("session snapshot does not match stored channel")
        if snapshot.spent > snapshot.accepted_cumulative:
            raise ValueError("session snapshot spent exceeds accepted cumulative")
        if snapshot.accepted_cumulative > record.authorized_cumulative:
            raise ValueError("session snapshot exceeds local voucher authorization")
        if snapshot.accepted_cumulative > self.policy.max_cumulative_spend:
            raise ValueError("session snapshot exceeds max cumulative spend")
        highest = snapshot.highest_voucher
        if highest is not None and (
            str(highest.get("channelId", "")).lower() != record.channel_id
            or _decimal(highest.get("cumulativeAmount"), "highest voucher amount")
            != snapshot.accepted_cumulative
            or not verify_voucher_signature(
                channel_id=record.channel_id,
                cumulative_amount=snapshot.accepted_cumulative,
                signature=str(highest.get("signature", "")),
                expected_signer=record.descriptor.effective_signer,
                chain_id=record.chain_id,
                escrow=record.escrow,
            )
        ):
            raise ValueError("session snapshot highest voucher is invalid")

        state = await self.rpc.channel_state(record.escrow, record.channel_id)
        confirmed = self._pending_confirmed(record.pending, state, snapshot)
        record.deposit = state.deposit
        record.settled = state.settled
        record.close_requested_at = state.close_requested_at
        record.accepted_cumulative = max(record.accepted_cumulative, snapshot.accepted_cumulative)
        record.spent = max(record.spent, snapshot.spent)
        record.units = max(record.units, snapshot.units)
        if highest is not None:
            record.highest_voucher = dict(highest)
        if confirmed:
            self._commit_pending(record)
        elif state.deposit == 0 and record.status != SessionStatus.OPENING:
            record.pending = None
            record.status = SessionStatus.CLOSED
        await self.store.save(record)
        return confirmed

    @staticmethod
    def _pending_confirmed(
        pending: PendingOperation | None,
        state: ChannelState,
        snapshot: SessionSnapshot | None,
    ) -> bool:
        if pending is None:
            return False
        if pending.action == SessionAction.OPEN:
            expected_deposit = pending.expected_deposit or 0
            expected_cumulative = pending.expected_cumulative or 0
            return state.deposit >= expected_deposit and (
                expected_cumulative == 0
                or state.settled >= expected_cumulative
                or (snapshot is not None and snapshot.accepted_cumulative >= expected_cumulative)
            )
        if pending.action == SessionAction.TOP_UP:
            return (
                pending.expected_deposit is not None and state.deposit >= pending.expected_deposit
            )
        if pending.action == SessionAction.VOUCHER:
            expected = pending.expected_cumulative or 0
            return state.settled >= expected or (
                snapshot is not None and snapshot.accepted_cumulative >= expected
            )
        return state.deposit == 0

    @staticmethod
    def _commit_pending(record: SessionRecord) -> None:
        pending = record.pending
        if pending is None:
            return
        if pending.expected_deposit is not None:
            record.deposit = max(record.deposit, pending.expected_deposit)
        if pending.expected_cumulative is not None:
            record.accepted_cumulative = max(
                record.accepted_cumulative, pending.expected_cumulative
            )
            voucher = _voucher_from_payload(pending.payload)
            if voucher is not None:
                record.highest_voucher = voucher
        if pending.action == SessionAction.CLOSE:
            record.status = SessionStatus.CLOSED
        else:
            record.status = SessionStatus.ACTIVE
        record.pending = None

    async def _reconcile_pending(
        self,
        record: SessionRecord,
        snapshot: SessionSnapshot | None,
    ) -> bool:
        if record.pending is None:
            return True
        state = await self.rpc.channel_state(record.escrow, record.channel_id)
        record.deposit = state.deposit
        record.settled = state.settled
        record.close_requested_at = state.close_requested_at
        if not self._pending_confirmed(record.pending, state, snapshot):
            await self.store.save(record)
            return False
        if snapshot is not None:
            record.accepted_cumulative = max(
                record.accepted_cumulative, snapshot.accepted_cumulative
            )
            record.spent = max(record.spent, snapshot.spent)
        self._commit_pending(record)
        await self.store.save(record)
        return True

    async def prepare(
        self,
        challenge: Challenge,
        *,
        resource_url: str,
        snapshot: SessionSnapshot | None = None,
        required_cumulative: int | None = None,
    ) -> Credential:
        """Persist and return the only safe next credential for a challenge."""

        context = self._resolve_challenge(challenge)
        snapshot = snapshot or context.snapshot
        await self._acquire(context.scope)
        try:
            record = await self.store.get(context.scope)
            if record is None and snapshot is not None:
                record = await self._hydrate_snapshot(context, snapshot, resource_url)
            if record is not None:
                self._validate_record(record, context)
                record.resource_url = resource_url
                if snapshot is not None:
                    await self._apply_snapshot(record, snapshot)
                elif record.pending is not None:
                    await self._reconcile_pending(record, None)

            if record is not None and record.pending is not None:
                # Rebind only the outer challenge. The signed transaction or
                # voucher remains byte-for-byte identical after uncertainty.
                record.pending.challenge_id = challenge.id
                await self.store.save(record)
                return self._credential(
                    challenge,
                    dict(record.pending.payload),
                    record.chain_id,
                )

            if (
                record is not None
                and record.close_requested_at != 0
                and record.status != SessionStatus.CLOSED
            ):
                raise SessionRecoveryRequiredError(
                    "Tempo session channel has a pending on-chain close request"
                )

            if record is None or record.status == SessionStatus.CLOSED:
                return await self._prepare_open(challenge, context, resource_url)

            plan = resolve_voucher_plan(
                authorized_cumulative=record.authorized_cumulative,
                accepted_cumulative=record.accepted_cumulative,
                spent=record.spent,
                request_amount=(
                    0 if required_cumulative is not None or snapshot is not None else context.amount
                ),
                required_cumulative=(
                    required_cumulative
                    if required_cumulative is not None
                    else (None if snapshot is None else snapshot.required_cumulative)
                ),
                deposit=record.deposit,
                suggested_deposit=context.suggested_deposit,
                policy=self.policy,
                min_voucher_delta=context.min_voucher_delta,
            )
            if plan.top_up:
                return await self._prepare_top_up(challenge, context, record, plan.top_up)
            return await self._prepare_voucher(
                challenge,
                record,
                cumulative=plan.cumulative,
                action=SessionAction.VOUCHER,
            )
        except BaseException:
            self._release(context.scope)
            raise

    async def _prepare_open(
        self,
        challenge: Challenge,
        context: ChallengeContext,
        resource_url: str,
    ) -> Credential:
        initial_cumulative = max(context.amount, context.min_voucher_delta)
        if initial_cumulative > self.policy.max_cumulative_spend:
            raise ValueError("initial voucher exceeds max cumulative spend")
        deposit = resolve_opening_deposit(
            request_amount=initial_cumulative,
            suggested_deposit=context.suggested_deposit,
            policy=self.policy,
        )
        payload = await self.protocol.open_payload(
            chain_id=context.chain_id,
            escrow=context.escrow,
            payee=context.payee,
            operator=context.operator,
            token=context.token,
            deposit=deposit,
            initial_cumulative=initial_cumulative,
            fee_payer=context.fee_payer,
        )
        descriptor = SessionSnapshot.from_wire(
            {
                "acceptedCumulative": "0",
                "chainId": context.chain_id,
                "channelId": payload["channelId"],
                "deposit": str(deposit),
                "descriptor": payload["descriptor"],
                "escrow": context.escrow,
                "requiredCumulative": str(initial_cumulative),
                "settled": "0",
                "spent": "0",
            }
        ).descriptor
        pending = self._pending(
            action=SessionAction.OPEN,
            challenge=challenge,
            payload=payload,
            expected_deposit=deposit,
            expected_cumulative=initial_cumulative,
        )
        record = SessionRecord(
            scope=context.scope,
            channel_id=payload["channelId"],
            descriptor=descriptor,
            escrow=context.escrow,
            chain_id=context.chain_id,
            deposit=0,
            authorized_cumulative=initial_cumulative,
            accepted_cumulative=0,
            settled=0,
            spent=0,
            status=transition(None, SessionEvent.OPEN_PREPARED),
            resource_url=resource_url,
            pending=pending,
        )
        # This atomic journal write happens before the payload reaches a transport.
        await self.store.save(record)
        return self._credential(challenge, payload, context.chain_id)

    async def _prepare_top_up(
        self,
        challenge: Challenge,
        context: ChallengeContext,
        record: SessionRecord,
        additional_deposit: int,
    ) -> Credential:
        payload = await self.protocol.top_up_payload(
            descriptor=record.descriptor,
            additional_deposit=additional_deposit,
            chain_id=record.chain_id,
            escrow=record.escrow,
            fee_payer=context.fee_payer,
        )
        expected = record.deposit + additional_deposit
        record.pending = self._pending(
            action=SessionAction.TOP_UP,
            challenge=challenge,
            payload=payload,
            expected_deposit=expected,
        )
        record.status = transition(record.status, SessionEvent.TOP_UP_PREPARED)
        await self.store.save(record)
        return self._credential(challenge, payload, record.chain_id)

    async def _prepare_voucher(
        self,
        challenge: Challenge,
        record: SessionRecord,
        *,
        cumulative: int,
        action: SessionAction,
    ) -> Credential:
        if cumulative > record.deposit:
            raise ValueError("voucher cumulative exceeds channel deposit")
        if cumulative > self.policy.max_cumulative_spend:
            raise ValueError("voucher cumulative exceeds max cumulative spend")
        payload = await self.protocol.voucher_payload(
            action=action.value,
            descriptor=record.descriptor,
            cumulative_amount=cumulative,
            chain_id=record.chain_id,
            escrow=record.escrow,
        )
        event = (
            SessionEvent.CLOSE_PREPARED
            if action == SessionAction.CLOSE
            else SessionEvent.VOUCHER_PREPARED
        )
        record.authorized_cumulative = max(record.authorized_cumulative, cumulative)
        record.pending = self._pending(
            action=action,
            challenge=challenge,
            payload=payload,
            expected_cumulative=cumulative,
        )
        record.status = transition(record.status, event)
        await self.store.save(record)
        return self._credential(challenge, payload, record.chain_id)

    async def prepare_close(
        self,
        challenge: Challenge,
        channel_id: str,
    ) -> Credential:
        """Persist a cooperative close voucher bound to a fresh challenge."""

        context = self._resolve_challenge(challenge)
        record = await self.store.get_by_channel(channel_id)
        if record is None:
            raise ValueError(f"unknown Tempo session channel: {channel_id}")
        if record.scope != context.scope:
            raise ValueError("close challenge does not match channel scope")
        await self._acquire(record.scope)
        try:
            current = await self.store.get(record.scope)
            if current is None:
                raise ValueError(f"unknown Tempo session channel: {channel_id}")
            if current.pending is not None:
                await self._reconcile_pending(current, context.snapshot)
            if current.pending is not None:
                current.pending.challenge_id = challenge.id
                await self.store.save(current)
                return self._credential(challenge, dict(current.pending.payload), current.chain_id)
            if current.status == SessionStatus.CLOSED:
                raise ValueError("Tempo session channel is already closed")
            cumulative = max(
                current.authorized_cumulative,
                current.accepted_cumulative,
                current.spent,
                current.settled,
            )
            return await self._prepare_voucher(
                challenge,
                current,
                cumulative=cumulative,
                action=SessionAction.CLOSE,
            )
        except BaseException:
            self._release(record.scope)
            raise

    async def handle_response(
        self,
        credential: Credential,
        *,
        status_code: int,
        headers: Mapping[str, str],
    ) -> SessionReceipt | None:
        """Commit a definite receipt or retain an exact retry after ambiguity."""

        channel_id = str(credential.payload.get("channelId", ""))
        record = await self.store.get_by_channel(channel_id)
        if record is None:
            return None
        try:
            snapshot_header = next(
                (
                    value
                    for key, value in headers.items()
                    if key.lower() == "payment-session-snapshot"
                ),
                None,
            )
            snapshot = None if snapshot_header is None else decode_session_snapshot(snapshot_header)
            if 200 <= status_code < 300:
                receipt_header = next(
                    (value for key, value in headers.items() if key.lower() == "payment-receipt"),
                    None,
                )
                if receipt_header is None:
                    content_type = next(
                        (value for key, value in headers.items() if key.lower() == "content-type"),
                        "",
                    )
                    if content_type.lower().startswith("text/event-stream"):
                        self._accept_stream_start(record, credential)
                        await self.store.save(record)
                        return None
                    raise ValueError("successful session action is missing Payment-Receipt")
                receipt = decode_session_receipt(receipt_header)
                self._accept_receipt(record, credential, receipt)
                await self.store.save(record)
                return receipt

            if snapshot is not None:
                await self._apply_snapshot(record, snapshot)
            if record.pending is not None:
                record.pending.status = PendingStatus.UNCERTAIN
                await self.store.save(record)
            return None
        except BaseException:
            if record.pending is not None:
                record.pending.status = PendingStatus.UNCERTAIN
                await self.store.save(record)
            raise
        finally:
            self._release(record.scope)

    @staticmethod
    def _accept_stream_start(record: SessionRecord, credential: Credential) -> None:
        """Commit an exact open/voucher that has begun an authenticated SSE stream."""

        pending = record.pending
        if pending is None:
            raise ValueError("session stream has no pending local operation")
        if pending.action not in {SessionAction.OPEN, SessionAction.VOUCHER}:
            raise ValueError("session management action is missing Payment-Receipt")
        if pending.challenge_id != credential.challenge.id:
            raise ValueError("session stream challenge ID does not match credential")
        if pending.payload != credential.payload:
            raise ValueError("session stream credential does not match pending operation")
        if pending.expected_cumulative is None:
            raise ValueError("session stream credential has no cumulative authorization")

        record.accepted_cumulative = max(
            record.accepted_cumulative,
            pending.expected_cumulative,
        )
        if pending.expected_deposit is not None:
            record.deposit = max(record.deposit, pending.expected_deposit)
        voucher = _voucher_from_payload(pending.payload)
        if voucher is not None:
            record.highest_voucher = voucher
        if pending.action == SessionAction.OPEN:
            record.status = transition(record.status, SessionEvent.OPEN_ACCEPTED)
        else:
            record.status = transition(record.status, SessionEvent.VOUCHER_ACCEPTED)
        record.pending = None

    def _accept_receipt(
        self,
        record: SessionRecord,
        credential: Credential,
        receipt: SessionReceipt,
    ) -> None:
        pending = record.pending
        if pending is None:
            raise ValueError("session receipt has no pending local operation")
        if receipt.challenge_id != credential.challenge.id:
            raise ValueError("session receipt challenge ID does not match credential")
        if receipt.channel_id != record.channel_id:
            raise ValueError("session receipt channel ID does not match credential")
        if receipt.reference.lower() != record.channel_id:
            raise ValueError("session receipt reference does not match channel ID")
        if receipt.accepted_cumulative > record.authorized_cumulative:
            raise ValueError("session receipt exceeds local voucher authorization")
        if receipt.spent > receipt.accepted_cumulative:
            raise ValueError("session receipt spent exceeds accepted cumulative")
        if receipt.spent > self.policy.max_cumulative_spend:
            raise ValueError("session receipt exceeds max cumulative spend")
        if (
            pending.expected_cumulative is not None
            and receipt.accepted_cumulative < pending.expected_cumulative
        ):
            raise ValueError("session receipt did not acknowledge pending voucher")
        if pending.action == SessionAction.CLOSE and (
            receipt.tx_hash is None
            or receipt.accepted_cumulative != pending.expected_cumulative
            or receipt.spent != pending.expected_cumulative
        ):
            raise ValueError("session close response included a mismatched receipt")
        record.accepted_cumulative = max(record.accepted_cumulative, receipt.accepted_cumulative)
        record.spent = max(record.spent, receipt.spent)
        if receipt.units is not None:
            record.units += receipt.units
        if pending.expected_deposit is not None:
            record.deposit = max(record.deposit, pending.expected_deposit)
        voucher = _voucher_from_payload(pending.payload)
        if voucher is not None and receipt.accepted_cumulative >= int(voucher["cumulativeAmount"]):
            record.highest_voucher = voucher
        if pending.action == SessionAction.CLOSE:
            record.status = transition(record.status, SessionEvent.CLOSE_ACCEPTED)
        elif pending.action == SessionAction.OPEN:
            record.status = transition(record.status, SessionEvent.OPEN_ACCEPTED)
        elif pending.action == SessionAction.TOP_UP:
            record.status = transition(record.status, SessionEvent.TOP_UP_ACCEPTED)
        else:
            record.status = transition(record.status, SessionEvent.VOUCHER_ACCEPTED)
        record.pending = None

    async def handle_unknown(self, credential: Credential) -> None:
        """Record an uncertain network outcome without advancing authorization."""

        channel_id = str(credential.payload.get("channelId", ""))
        record = await self.store.get_by_channel(channel_id)
        if record is None:
            return
        try:
            if record.pending is not None:
                record.pending.status = PendingStatus.UNCERTAIN
                await self.store.save(record)
        finally:
            self._release(record.scope)

    async def observe_stream_receipt(self, receipt: SessionReceipt) -> None:
        """Apply a receipt delivered in-band after the opening action completed."""

        record = await self.store.get_by_channel(receipt.channel_id)
        if record is None:
            raise ValueError("stream receipt references an unknown session channel")
        await self._acquire(record.scope)
        try:
            current = await self.store.get(record.scope)
            if current is None:
                raise ValueError("stream receipt references an unknown session channel")
            if receipt.accepted_cumulative > current.authorized_cumulative:
                raise ValueError("stream receipt exceeds local voucher authorization")
            if receipt.reference.lower() != current.channel_id:
                raise ValueError("stream receipt reference does not match channel ID")
            if receipt.spent > receipt.accepted_cumulative:
                raise ValueError("stream receipt spent exceeds accepted cumulative")
            if receipt.spent > self.policy.max_cumulative_spend:
                raise ValueError("stream receipt exceeds max cumulative spend")
            current.accepted_cumulative = max(
                current.accepted_cumulative, receipt.accepted_cumulative
            )
            current.spent = max(current.spent, receipt.spent)
            if receipt.units is not None:
                current.units += receipt.units
            await self.store.save(current)
        finally:
            self._release(record.scope)

    async def observe_need_voucher(self, event: NeedVoucherEvent) -> None:
        """Validate an SSE authorization request against local signed state."""

        record = await self.store.get_by_channel(event.channel_id)
        if record is None:
            raise ValueError("payment-need-voucher references an unknown channel")
        await self._acquire(record.scope)
        try:
            current = await self.store.get(record.scope)
            if current is None:
                raise ValueError("payment-need-voucher references an unknown channel")
            if event.accepted_cumulative > current.authorized_cumulative:
                raise ValueError("payment-need-voucher exceeds local voucher state")
            if event.required_cumulative > self.policy.max_cumulative_spend:
                raise ValueError("payment-need-voucher exceeds max cumulative spend")
            current.accepted_cumulative = max(
                current.accepted_cumulative, event.accepted_cumulative
            )
            # The event deposit is a routing hint, not authority. Advancing or
            # lowering durable deposit here could duplicate a just-accepted top-up.
            await self.store.save(current)
        finally:
            self._release(record.scope)

    async def reconcile(self, channel_id: str) -> SessionRecord:
        """Reconcile a pending channel against authoritative on-chain state."""

        record = await self.store.get_by_channel(channel_id)
        if record is None:
            raise ValueError(f"unknown Tempo session channel: {channel_id}")
        await self._acquire(record.scope)
        try:
            current = await self.store.get(record.scope)
            if current is None:
                raise ValueError(f"unknown Tempo session channel: {channel_id}")
            await self._reconcile_pending(current, None)
            state = await self.rpc.channel_state(current.escrow, current.channel_id)
            current.deposit = state.deposit
            current.settled = state.settled
            current.close_requested_at = state.close_requested_at
            if state.deposit == 0 and current.status != SessionStatus.OPENING:
                current.pending = None
                current.status = SessionStatus.CLOSED
            await self.store.save(current)
            return current
        finally:
            self._release(record.scope)

    async def list_sessions(self) -> list[SessionRecord]:
        """Return all durable session records."""

        return await self.store.list()

    async def session_hint(self, resource_url: str) -> str | None:
        """Return an active channel hint for a previously paid resource."""

        records = await self.store.list()
        for record in records:
            if (
                record.resource_url == resource_url
                and record.status != SessionStatus.CLOSED
                and record.close_requested_at == 0
            ):
                return record.channel_id
        return None
