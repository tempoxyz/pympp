"""Server-side TIP-1034 session payment method (mppx ``server/Session.ts``).

``session(...)`` returns a pympp :class:`~mpp.server.method.ServerMethod` handling the full
TIP20EscrowChannel lifecycle (open, voucher, top-up, close) over request/response flows: each
content request pays its route amount from the channel's accepted vouchers, and management
requests (top-up, close, and open/voucher on non-content requests) get ``204`` with a session
receipt. Module-level :func:`charge` and :func:`credit` adjust a channel's spend outside a route.

With ``resolve_channel_id``, challenges advertise the caller's reusable channel as a session
snapshot; with ``bootstrap=True``, a ``HEAD`` request recovers it after a zero-amount proof.

Not ported: SSE/WebSocket metering.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from mpp import Receipt
from mpp._units import parse_units
from mpp._validation import Validation
from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session._protocol import (
    SessionReceipt,
    definition,
    serialize_session_receipt,
)
from mpp.methods.tempo.session.server._bootstrap import handle_bootstrap_preflight
from mpp.methods.tempo.session.server._request_state import (
    FEE_PAYER_DISABLED,
    SnapshotPaymentFields,
    capture_request_probe,
    is_session_content_request,
    resolve_credential_verification_context,
    resolve_session_channel_id,
    resolve_session_payment_request,
    resolve_session_snapshot,
    respond_to_session_credential,
)
from mpp.methods.tempo.session.server._schedule import (
    SettlementSchedule,
    resolve_settlement_schedule,
)
from mpp.methods.tempo.session.server._settlement import (
    OnSessionSettlement,
    OnSessionSettlementFailure,
    apply_verified_http_accounting,
    charge_session_channel,
    ignore_retryable_settlement_failure,
    maybe_settle_scheduled,
    resolve_channel_store,
    should_apply_verified_http_accounting,
    should_charge_voucher_on_acceptance,
)
from mpp.methods.tempo.session.server._sponsorship_limit import SponsorshipLimit, limit_fee_payer
from mpp.methods.tempo.session.server._store import (
    ChannelState,
    CreditResult,
    StoreChannelStore,
    credit_channel,
    from_store,
    normalize_channel_id,
)
from mpp.methods.tempo.session.server._verification import (
    CredentialContext,
    broadcast_credential_payload,
    require_session_credential_payload,
    validate_credential_payload,
)
from mpp.server.method import (
    PreflightContext,
    RequestContext,
    RespondContext,
    ServerMethod,
    ValidateContext,
    VerifyContext,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods import CanOfferFn, PaymentSuccessHandler
    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.session.server._request_state import ResolveSessionChannelId
    from mpp.server.http import Response
    from mpp.store import Store

__all__ = ["SessionPaymentReceipt", "charge", "credit", "session"]

logger = logging.getLogger(__name__)

_warned_fallback_store = False


def _fallback_store() -> Store:
    """The in-memory channel store used without a configured one, warning once per process."""
    from mpp.store import MemoryStore

    global _warned_fallback_store
    if not _warned_fallback_store:
        _warned_fallback_store = True
        logger.warning(
            "tempo.session has no store configured and is using an in-memory store. Channel "
            "state (accepted vouchers and spend) is scoped to this process, so another worker "
            "or replica, or this one after a restart, cannot charge or close its channels. "
            "Pass a shared compare-and-set store (e.g. mpp.stores.RedisStore) via "
            "tempo.session(store=...) or Mpp(store=...) when running more than one instance."
        )
    return MemoryStore()


@dataclass(frozen=True, slots=True)
class SessionPaymentReceipt(Receipt):
    """A receipt whose ``Payment-Receipt`` header is exactly mppx's session receipt JSON.

    ``session`` holds the session fields; ``extensions`` mirrors them (camelCase) for code that
    reads a generic :class:`~mpp.Receipt`.
    """

    session: SessionReceipt | None = None

    def to_payment_receipt(self) -> str:
        if self.session is None:
            return Receipt.to_payment_receipt(self)
        return serialize_session_receipt(self.session)

    @classmethod
    def from_session(cls, session: SessionReceipt) -> SessionPaymentReceipt:
        """Wrap a session receipt for the engine."""
        wire = session.to_wire()
        return cls(
            status="success",
            timestamp=datetime.fromisoformat(session.timestamp.replace("Z", "+00:00")),
            reference=session.reference,
            method="tempo",
            extensions={
                key: value
                for key, value in wire.items()
                if key not in ("method", "status", "timestamp", "reference")
            },
            session=session,
        )


def _snapshot_free_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    """Binds a challenge to its whole request except its session snapshot.

    The snapshot is a hint recomputed for every request (its spend moves), so, as mppx's request
    binding does, a credential's echoed snapshot need not match the route's current one.
    """
    details: Any = request.get("methodDetails")
    if not isinstance(details, Mapping) or "sessionSnapshot" not in details:
        return dict(request)
    method_details = {
        key: value
        for key, value in cast(Mapping[str, Any], details).items()
        if key != "sessionSnapshot"
    }
    return {**request, "methodDetails": method_details}


def _reusable_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    """Binds a reusable challenge to its route and channel terms, not its quoted amount."""
    details: Any = request.get("methodDetails")
    method_details: Mapping[str, Any] = (
        cast(Mapping[str, Any], details) if isinstance(details, Mapping) else {}
    )
    return {
        "chainId": method_details.get("chainId"),
        "currency": request.get("currency"),
        "escrowContract": method_details.get("escrowContract"),
        "operator": method_details.get("operator"),
        "recipient": request.get("recipient"),
        "sessionProtocol": method_details.get("sessionProtocol"),
        "unitType": request.get("unitType"),
    }


def session(
    *,
    account: TempoAccount | None = None,
    recipient: str | None = None,
    currency: str | None = None,
    decimals: int = 6,
    chain_id: int | None = None,
    rpc_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    escrow_contract: str | None = None,
    store: Store | None = None,
    fee_payer: TempoAccount | Literal[True] | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    min_voucher_delta: str | None = None,
    settlement_schedule: SettlementSchedule | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
    on_session_settlement_failure: OnSessionSettlementFailure | None = None,
    channel_state_ttl: int = 5_000,
    reusable_challenges: bool = False,
    voucher_state_max_age: int = 0,
    charge_on_acceptance: bool = False,
    sponsorship_limit: SponsorshipLimit | None = None,
    amount: str | None = None,
    unit_type: str | None = None,
    suggested_deposit: str | None = None,
    operator: str | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
    resolve_channel_id: ResolveSessionChannelId | None = None,
    bootstrap: bool = False,
) -> ServerMethod:
    """Create the server-side Tempo session method (mppx ``tempo.session``).

    Routes take ``amount`` (decimal string, the price of one content request) and ``unit_type``,
    and optionally ``suggested_deposit``, ``min_voucher_delta``, ``recipient``, ``currency``,
    ``operator``, ``escrow_contract``, ``chain_id`` and ``fee_payer`` (False turns sponsorship off;
    an account sponsors that route in place of the method's fee payer).

    Args:
        account: Payee account: receives payments and sends server settle/close transactions.
        recipient: Payee address, when it differs from ``account`` (default: its address).
        currency: TIP-20 token (default: the chain's default currency).
        decimals: Token decimals for route amounts (default 6).
        chain_id: Tempo chain ID (default: the RPC's, or mainnet without ``rpc_url``).
        rpc_url: RPC endpoint (default: the chain's).
        http_client: HTTP client for RPC calls, owned by the caller.
        escrow_contract: Escrow advertised to clients (default: the TIP-1034 precompile).
        store: Channel store. Use a :class:`~mpp.store.CompareAndSetStore` (MemoryStore,
            RedisStore, SQLiteStore) shared by every instance, so channel updates are
            linearizable; defaults to the ``Mpp(store=...)`` store, or else a per-process
            in-memory store.
        fee_payer: Account that sponsors open/top-up and server settle/close fees; ``True``
            makes ``account`` the fee payer.
        fee_payer_policy: Overrides of the fee-payer policy (``max_gas``, ...).
        fee_token: Fee token clients use for open/top-up and the server for settle/close.
        min_voucher_delta: Minimum voucher increase (decimal string, default "0").
        settlement_schedule: Server-owned automatic settlement cadence.
        on_session_settlement: Called after a settlement or close transaction confirms.
        on_session_settlement_failure: Called when a scheduled settlement or close fails.
        channel_state_ttl: Milliseconds validation trusts a cached on-chain read (default 5000).
        reusable_challenges: Let a challenge pay later requests to the same route until it
            expires: it is bound to the route and channel terms, not the amount it quoted,
            and each request is charged its own price.
        voucher_state_max_age: Maximum age (ms) of verified on-chain channel state a voucher may
            be validated and accepted against without waiting for a fresh read (default 0: read
            on-chain state before every acceptance). The fresh read then finishes in the
            background and records a pending close, so later vouchers are rejected. A payer can
            withdraw only after the escrow's close grace period (900 s on Tempo) following a
            close request, so vouchers accepted this way stay settleable as long as the payee
            settles them within the grace period minus this age: keep it well below that bound.
            ``channel_state_ttl`` bounds how long an accepted voucher skips starting that read.
        charge_on_acceptance: Charge request-priced content (``unit_type="request"``) in the same
            store update that accepts its voucher, before the response, instead of in a second
            update after it. The server must then refund requests it cannot serve (:func:`credit`).
        sponsorship_limit: Limits fee-payer-sponsored channel opens and top-ups to
            ``per_day`` of each per payer per UTC day (default 5), counted in its store. The payer
            is the verified signer of the transaction, never the credential's ``source``. A
            transaction over the limit, or whose signatures prove no payer, is broadcast
            unsponsored, so it lands only if the payer pays its own fees.
        amount: Default route amount.
        unit_type: Default unit type (such as ``"request"``).
        suggested_deposit: Default suggested deposit (decimal string).
        operator: Default channel operator clients encode in new channels.
        can_offer: Decides whether to advertise an offer for a wire request.
        on_payment_success: Called with each successful session payment event.
        resolve_channel_id: Maps authenticated application identity and payment scope to an
            existing channel ID; called with a
            :class:`~mpp.methods.tempo.session.server.ResolveSessionChannelIdParameters` when the
            route doesn't set ``channel_id``. The channel is loaded from ``store`` and validated
            before its snapshot is included in a challenge or bootstrap response; the store is
            never searched.
        bootstrap: Enable same-route ``HEAD`` recovery before a paid request: the server issues a
            zero-amount identity challenge, verifies the returned proof, passes its ``source``
            to ``resolve_channel_id``, validates the channel's payment scope and returns its
            snapshot (with the signed highest voucher) in ``Payment-Session-Snapshot``.
    """
    from mpp.methods.tempo._defaults import (
        CHAIN_ID,
        default_currency_for_chain,
        rpc_url_for_chain,
    )

    if chain_id is None and rpc_url is None:
        chain_id = CHAIN_ID
    resolved_rpc_url = rpc_url or rpc_url_for_chain(chain_id or CHAIN_ID)
    resolved_currency = currency or default_currency_for_chain(chain_id)
    resolved_recipient = recipient or (account.address if account is not None else None)
    resolved_fee_payer: TempoAccount | None = (
        account if fee_payer is True else fee_payer if fee_payer is not None else None
    )
    if fee_payer is True and account is None:
        raise ValueError("fee_payer=True requires an account")
    schedule = resolve_settlement_schedule(settlement_schedule, decimals)
    channel_stores: list[StoreChannelStore] = [from_store(store)] if store is not None else []

    def channel_store() -> StoreChannelStore:
        # Without its own store, the method adopts `Mpp(store=...)` (`use_store`) or, failing
        # that, the per-process fallback on first use.
        if not channel_stores:
            channel_stores.append(from_store(_fallback_store()))
        return channel_stores[0]

    def use_store(engine_store: Store) -> None:
        if not channel_stores:
            channel_stores.append(from_store(engine_store))

    last_on_chain_verified: dict[str, int] = {}
    chain_ids: list[int] = [chain_id] if chain_id is not None else []

    async def resolve_chain_id() -> int:
        if not chain_ids:
            from mpp.methods.tempo.session import _chain as chain

            result = await chain._rpc(  # pyright: ignore[reportPrivateUsage]
                resolved_rpc_url, "eth_chainId", [], http_client
            )
            chain_ids.append(int(str(result), 16))
        return chain_ids[0]

    defaults = {
        key: value
        for key, value in {
            "amount": amount,
            "currency": resolved_currency,
            "decimals": decimals,
            "operator": operator,
            "recipient": resolved_recipient,
            "suggested_deposit": suggested_deposit,
            "unit_type": unit_type,
        }.items()
        if value is not None
    }

    async def resolve_request(context: RequestContext) -> dict[str, Any]:
        request = context.request
        if request.get("recipient") is None:
            raise ValueError("tempo.session() needs a recipient: pass account or recipient")
        resolved = resolve_session_payment_request(
            request=request,
            chain_id=await resolve_chain_id(),
            default_fee_payer=resolved_fee_payer,
            parameter_escrow_contract=escrow_contract,
            fee_token=fee_token,
        )
        resolved.setdefault("decimals", decimals)
        snapshot = await resolve_request_snapshot(context, resolved)
        if snapshot is not None:
            resolved["session_snapshot"] = snapshot
        return resolved

    async def resolve_request_snapshot(
        context: RequestContext, resolved: dict[str, Any]
    ) -> dict[str, Any] | None:
        """The challenge's session snapshot hint (mppx ``resolveSessionPaymentRequest``)."""
        channel_id = await resolve_session_channel_id(
            request=context.input,
            credential=context.credential,
            payment_request=context.request,
            resolve_channel_id=resolve_channel_id,
            store=channel_store(),
        )
        if channel_id is None:
            return None
        probe = capture_request_probe(context.input) if context.input is not None else None
        content = probe is not None and is_session_content_request(probe)
        route_decimals = int(resolved.get("decimals", decimals))
        amount_value = resolved.get("amount")
        request_amount = (
            parse_units(amount_value, route_decimals) if isinstance(amount_value, str) else 0
        )
        snapshot = await resolve_session_snapshot(
            amount=0 if probe is not None and not content else request_amount,
            channel_id=channel_id,
            store=channel_store(),
            expected=SnapshotPaymentFields(
                chain_id=int(resolved["chain_id"]),
                currency=str(resolved.get("currency")),
                escrow_contract=str(resolved["escrow_contract"]),
                recipient=str(resolved.get("recipient")),
            ),
            minimum_voucher_advance=parse_units(min_voucher_delta or "0", decimals),
            require_voucher_advance=content,
        )
        return snapshot.to_wire() if snapshot is not None else None

    async def preflight(context: PreflightContext) -> Response | None:
        if context.input.method != "HEAD":
            return None
        return await handle_bootstrap_preflight(
            context,
            chain_id=await resolve_chain_id(),
            escrow_contract=escrow_contract,
            resolve_channel_id=resolve_channel_id,
            store=channel_store(),
            proof_store=channel_store().store,
        )

    def credential_context(
        context: VerifyContext, payload: Any, **overrides: Any
    ) -> CredentialContext:
        verification = resolve_credential_verification_context(
            challenge=context.challenge,
            decimals=decimals,
            fee_payer=resolved_fee_payer,
            min_voucher_delta=min_voucher_delta,
            request_fee_payer=(
                False
                if context.request.get(FEE_PAYER_DISABLED)
                else context.request.get("fee_payer")
            ),
        )
        return CredentialContext(
            challenge=context.challenge,
            payload=payload,
            chain_id=verification.chain_id,
            escrow=verification.escrow,
            rpc_url=resolved_rpc_url,
            store=channel_store(),
            account=account,
            http_client=http_client,
            channel_state_ttl=channel_state_ttl,
            credential_source=context.credential.source,
            expected_operator=verification.method_details.operator,
            fee_payer=verification.fee_payer,
            fee_payer_policy=fee_payer_policy,
            fee_token=verification.method_details.fee_token,
            last_on_chain_verified=last_on_chain_verified,
            min_voucher_delta=verification.min_voucher_delta,
            on_session_settlement=on_session_settlement,
            on_session_settlement_failure=on_session_settlement_failure,
            voucher_state_max_age=voucher_state_max_age,
            **overrides,
        )

    async def validate(context: ValidateContext) -> Validation:
        payload = require_session_credential_payload(context.credential.payload)
        credential = replace(context.credential, payload=payload.to_wire())
        if context.operation == "broadcast" and payload.action == "voucher":
            # A broadcast voucher is checked against the stored channel by its acceptance.
            details: dict[str, Any] = {
                "action": payload.action,
                "channelId": normalize_channel_id(payload.channel_id),
            }
        else:
            validation = await validate_credential_payload(
                credential_context(
                    context, payload, allow_pending_close=context.operation == "broadcast"
                )
            )
            details = {"action": validation.action, "channelId": validation.channel_id}
        return Validation(
            credential=credential,
            details=details,
            intent="session",
            request=dict(context.challenge.request),
        )

    def route_amount(context: VerifyContext) -> int:
        """The price of this request: the route's amount, not the challenge's quote."""
        request = context.request
        value = request.get("amount")
        if isinstance(value, str):
            return parse_units(value, int(request.get("decimals", decimals)))
        quoted = context.challenge.request.get("amount")
        if isinstance(quoted, str) and quoted.isdigit():
            return int(quoted)
        raise VerificationFailedError("missing request amount")

    async def settle_charged(channel: ChannelState, fee_payer: TempoAccount | None) -> str | None:
        try:
            return await maybe_settle_scheduled(
                channel=channel,
                schedule=schedule,
                store=channel_store(),
                account=account,
                rpc_url=resolved_rpc_url,
                http_client=http_client,
                fee_payer=fee_payer,
                fee_payer_policy=fee_payer_policy,
                fee_token=fee_token,
                on_session_settlement=on_session_settlement,
                on_session_settlement_failure=on_session_settlement_failure,
            )
        except Exception as error:
            # A failed scheduled settlement is reported and retried by the next one; the
            # charged request stays served because the payer's voucher covers the charge.
            return ignore_retryable_settlement_failure(error)

    async def broadcast(context: VerifyContext) -> Receipt:
        payload = require_session_credential_payload(context.credential.payload)
        probe = capture_request_probe(context.input) if context.input is not None else None
        verify_context = credential_context(
            context,
            payload,
            require_voucher_advance=should_apply_verified_http_accounting(
                request=probe, payload_action=payload.action
            ),
        )
        unit_type = context.request.get("unit_type", context.challenge.request.get("unitType"))
        charge_amount = (
            route_amount(context)
            if charge_on_acceptance
            and should_charge_voucher_on_acceptance(
                request=probe, payload_action=payload.action, unit_type=unit_type
            )
            else None
        )
        accepted_charges: list[ChannelState] = []
        # Settlement keeps the fee payer the challenge allowed; only the open or top-up itself
        # goes unsponsored over the limit.
        fee_payer = verify_context.fee_payer
        verify_context = replace(
            verify_context,
            charge_amount=charge_amount,
            on_charged=accepted_charges.append,
            fee_payer=await limit_fee_payer(
                chain_id=verify_context.chain_id,
                fee_payer=fee_payer,
                limit=sponsorship_limit,
                payload=payload,
            ),
        )
        receipt = await broadcast_credential_payload(verify_context)
        if accepted_charges:
            tx_hash = await settle_charged(accepted_charges[-1], fee_payer)
            return SessionPaymentReceipt.from_session(
                replace(receipt, tx_hash=tx_hash) if tx_hash else receipt
            )

        async def charge_channel(channel_id: str, request_amount: int) -> ChannelState:
            return await charge_session_channel(channel_store(), channel_id, request_amount)

        async def settle_accepted_charge(channel: ChannelState) -> str | None:
            # Like mppx, with the fee payer the credential's challenge allowed.
            return await settle_charged(channel, fee_payer)

        charged = await apply_verified_http_accounting(
            receipt=receipt,
            request=probe,
            payload_action=payload.action,
            request_amount=lambda: route_amount(context),
            charge=charge_channel,
            settle_charged=settle_accepted_charge,
        )
        return SessionPaymentReceipt.from_session(charged)

    def respond(context: RespondContext) -> Response | None:
        payload = require_session_credential_payload(context.credential.payload)
        return respond_to_session_credential(payload_action=payload.action, request=context.input)

    return ServerMethod(
        method=definition,
        validate=validate,
        broadcast=broadcast,
        resolve_request=resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        defaults=defaults,
        respond=respond,
        use_store=use_store,
        stable_binding=_reusable_binding if reusable_challenges else _snapshot_free_binding,
        preflight=preflight if bootstrap else None,
        # Accounting and respond classify a POST as content by its body (mppx: request.body
        # !== null), so framework adapters must read it.
        needs_request_body=True,
    )


async def charge(
    store: Any,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str | None = None,
    retention: int | None = None,
) -> ChannelState:
    """Charge ``amount`` (raw units) against a channel's accepted vouchers, outside a route.

    With ``idempotency_key`` the channel is charged at most once per key: a retry with the same
    key and amount returns the channel without charging again; the same key with another
    amount raises :class:`~mpp.methods.tempo.session.server._store.IdempotencyKeyConflictError`.
    ``retention`` (ms, default a day) must cover every retry.

    Raises:
        InsufficientBalanceError: The accepted vouchers do not cover the charge.
        ChannelClosedError: The channel is missing, closing or finalized.
    """
    return await charge_session_channel(
        resolve_channel_store(store),
        channel_id,
        amount,
        idempotency_key=idempotency_key,
        retention=retention,
    )


async def credit(
    store: Any,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str,
    retention: int | None = None,
    units: int = 0,
) -> CreditResult:
    """Return an unused ``amount`` to a channel's spend at most once per idempotency key.

    The first outcome for a key is final. A credit is ``declined`` when the channel is closing
    or finalized, or when it would take ``spent`` below zero or below what settled, or may still
    settle, on-chain; the caller then refunds another way. ``unknown`` reports a store write
    that failed and may have committed: retry with the same key.
    """
    return await credit_channel(
        resolve_channel_store(store),
        channel_id,
        amount,
        idempotency_key=idempotency_key,
        retention=retention,
        units=units,
    )
