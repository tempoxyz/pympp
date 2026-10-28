"""Session charging and on-chain settlement (mppx ``server/Settlement.ts``, non-store parts).

The schedule and lease state live in :mod:`mpp.methods.tempo.session.server.schedule`.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal, TypeAlias

import httpx

from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods.tempo.session import chain
from mpp.methods.tempo.session.protocol import ZERO_ADDRESS, SessionReceipt, uint96
from mpp.methods.tempo.session.server.request_state import (
    RequestProbe,
    is_session_content_request,
)
from mpp.methods.tempo.session.server.schedule import (
    SCHEDULED_SETTLEMENT_LEASE_MS,
    ResolvedSettlementSchedule,
    claim_scheduled_settlement,
    is_settlement_due,
    mark_settlement_complete,
    release_scheduled_settlement,
    renew_scheduled_settlement,
)
from mpp.methods.tempo.session.server.store import (
    PENDING_CLOSE_CLOCK_SKEW_SECONDS,
    PENDING_CLOSE_VALIDITY_SECONDS,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    ChannelStore,
    IdempotencyKeyConflictError,
    InsufficientBalanceError,
    PendingSettlement,
    StoreChannelStore,
    assert_idempotency_options,
    deduct_from_channel,
    from_store,
    is_precompile_state,
    keep_greater,
    normalize_channel_id,
    resolve_settleable_voucher,
)

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount
    from mpp.store import Store

__all__ = [
    "OnSessionSettlement",
    "OnSessionSettlementFailure",
    "SessionSettlementContext",
    "SessionSettlementFailureContext",
    "SessionStoreInput",
    "SettlementCheckpointError",
    "SettlementLeaseError",
    "apply_verified_http_accounting",
    "assert_settlement_sender",
    "charge_session_channel",
    "ignore_retryable_settlement_failure",
    "maybe_settle_scheduled",
    "report_session_settlement_failure",
    "resolve_channel_store",
    "settle",
    "settle_batch",
    "should_apply_verified_http_accounting",
]


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSettlementContext:
    """Emitted when an on-chain settlement or close transaction is confirmed."""

    tx_hash: str
    channel_id: str
    trigger: Literal["settle", "close", "scheduled"]
    amount: int
    """Cumulative amount settled on-chain to the payee (raw units)."""
    delta: int
    """Amount this transaction settled (raw units)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSettlementFailureContext:
    """Emitted when a scheduled settlement or close transaction fails."""

    chain_id: int
    channel_id: str
    error: BaseException
    trigger: Literal["close", "scheduled"]


OnSessionSettlement: TypeAlias = Callable[[SessionSettlementContext], Awaitable[None] | None]
"""Callback invoked after an on-chain settlement or close transaction is confirmed."""
OnSessionSettlementFailure: TypeAlias = Callable[
    [SessionSettlementFailureContext], Awaitable[None] | None
]
"""Callback invoked when a scheduled settlement or close transaction fails."""

SessionStoreInput: TypeAlias = "Store | ChannelStore"
"""A pympp store or an already-wrapped channel store."""


class SettlementCheckpointError(Exception):
    """A settlement transaction confirmed but the channel store could not record it."""

    def __init__(self, *, tx_hash: str, cause: BaseException) -> None:
        super().__init__(f"Settlement {tx_hash} confirmed but was not recorded.")
        self.tx_hash = tx_hash
        self.__cause__ = cause


class SettlementLeaseError(Exception):
    """A scheduled settlement could not claim its lease; no transaction was submitted."""

    def __init__(self, *, cause: BaseException) -> None:
        super().__init__("Scheduled settlement lease could not be claimed.")
        self.__cause__ = cause


async def _call(callback: Callable[[Any], Any], context: Any) -> None:
    result = callback(context)
    if inspect.isawaitable(result):
        await result


async def report_session_settlement_failure(
    on_failure: OnSessionSettlementFailure | None, context: SessionSettlementFailureContext
) -> None:
    """Report a settlement failure; observer errors never replace it."""
    if on_failure is None:
        return
    with contextlib.suppress(Exception):
        await _call(on_failure, context)


async def emit_session_settlement(
    on_settlement: OnSessionSettlement | None, context: SessionSettlementContext
) -> None:
    """Emit a confirmed settlement; observer errors cannot break the settlement flow."""
    if on_settlement is None:
        return
    with contextlib.suppress(Exception):
        await _call(on_settlement, context)


def resolve_channel_store(store: Any) -> ChannelStore:
    """A channel store from a pympp store or an already-wrapped channel store."""
    if isinstance(store, StoreChannelStore) or (
        hasattr(store, "get_channel") and hasattr(store, "update_channel")
    ):
        return store
    return from_store(store)


# --------------------------------------------------------------------------------------------
# Charging
# --------------------------------------------------------------------------------------------


async def charge_session_channel(
    store: ChannelStore,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str | None = None,
    retention: int | None = None,
) -> ChannelState:
    """Atomically deduct spend from a channel, mapping failures to typed session errors.

    Raises:
        ChannelClosedError: The channel is missing, finalized or closing.
        InsufficientBalanceError: The accepted vouchers do not cover ``amount``.
        IdempotencyKeyConflictError: ``idempotency_key`` was recorded with another amount.
    """
    assert_idempotency_options(idempotency_key=idempotency_key, retention=retention)
    try:
        result = await deduct_from_channel(
            store, channel_id, amount, idempotency_key=idempotency_key, retention=retention
        )
    except IdempotencyKeyConflictError:
        raise
    except Exception as error:
        raise ChannelClosedError("channel not found") from error
    if not result.ok:
        channel = result.channel
        if channel.finalized:
            raise ChannelClosedError("channel is finalized")
        if channel.close_requested_at != 0:
            raise ChannelClosedError("channel has a pending close request")
        available = channel.highest_voucher_amount - channel.spent
        raise InsufficientBalanceError(f"requested {amount}, available {available}")
    return result.channel


def should_apply_verified_http_accounting(
    *, request: RequestProbe | None, payload_action: str
) -> bool:
    """Whether an accepted credential authorizes, and is charged for, an HTTP content response."""
    if request is None:
        return False
    if payload_action not in ("open", "voucher"):
        return False
    return is_session_content_request(request)


SettleChargedSessionChannel: TypeAlias = Callable[[ChannelState], Awaitable[str | None]]
"""Runs the server's settlement policy after a committed charge; returns a settlement tx hash."""


async def apply_verified_http_accounting(
    *,
    receipt: SessionReceipt,
    request: RequestProbe | None,
    payload_action: str,
    request_amount: Callable[[], int],
    charge: Callable[[str, int], Awaitable[ChannelState]],
    settle_charged: SettleChargedSessionChannel,
) -> SessionReceipt:
    """Charge one content response after a session credential has been accepted."""
    if not should_apply_verified_http_accounting(request=request, payload_action=payload_action):
        return receipt
    charged = await charge(receipt.channel_id, request_amount())
    tx_hash = await settle_charged(charged)
    return replace(
        receipt,
        spent=str(charged.spent),
        units=charged.units,
        tx_hash=tx_hash if tx_hash else receipt.tx_hash,
    )


# --------------------------------------------------------------------------------------------
# Settlement
# --------------------------------------------------------------------------------------------


def _same_address(a: str, b: str) -> bool:
    return a.lower() == b.lower()


def assert_settlement_sender(
    *,
    operation: Literal["close", "settle"],
    channel_id: str,
    operator: str,
    payee: str,
    sender: str | None,
) -> None:
    """Check the settlement transaction sender is the channel payee or its nonzero operator."""
    if not sender:
        raise ValueError(
            f"Cannot {operation} precompile channel {channel_id}: no account available. "
            "Pass the payee or operator account."
        )
    if _same_address(sender, payee):
        return
    if not _same_address(operator, ZERO_ADDRESS) and _same_address(sender, operator):
        return
    operator_text = "." if _same_address(operator, ZERO_ADDRESS) else f" or operator {operator}."
    raise BadRequestError(
        f"Cannot {operation} precompile channel {channel_id}: tx sender {sender} is not the "
        f"channel payee {payee}{operator_text}"
    )


def _rpc_error_code(error: BaseException) -> int | None:
    import re

    match = re.search(r"'code':\s*(-?\d+)", str(error))
    return int(match.group(1)) if match else None


def is_execution_revert(error: BaseException) -> bool:
    """Whether a node rejected a transaction because its execution reverted."""
    return isinstance(error, RuntimeError) and "revert" in str(error).lower()


def is_retryable_settlement_failure(error: BaseException) -> bool:
    """Whether a settlement failed on a transport or RPC outage that a later one can retry."""
    if isinstance(error, SettlementLeaseError):
        return True
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        return status == 429 or status >= 500
    if isinstance(error, (httpx.TransportError, TimeoutError, asyncio.TimeoutError)):
        return True
    if isinstance(error, RuntimeError) and str(error).startswith("RPC error"):
        # Rate limits, internal errors, limit exceeded and resource unavailable.
        return _rpc_error_code(error) in (429, -32603, -32005, -32002)
    return False


def ignore_retryable_settlement_failure(error: BaseException) -> None:
    """Keep a charged request served when its scheduled settlement hit a retryable failure.

    Re-raises other errors.
    """
    if is_retryable_settlement_failure(error):
        return None
    raise error


async def settle(
    store: Any,
    channel_id: str,
    *,
    account: TempoAccount,
    rpc_url: str,
    http_client: httpx.AsyncClient | None = None,
    escrow_contract: str | None = None,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
) -> str:
    """Settle the largest accepted voucher within the channel's ``spent`` (mppx ``settle``).

    The escrow captures the voucher's whole cumulative amount, so a voucher above ``spent``
    (such as the highest one after a credit) is never settled. Until the transaction can no
    longer land, credits keep ``spent`` at or above it. Returns the transaction hash.

    Raises:
        SettlementCheckpointError: The transaction confirmed but the store write failed.
    """
    channel_store = resolve_channel_store(store)
    channel_id = normalize_channel_id(channel_id)
    channel = await channel_store.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    if not is_precompile_state(channel) or channel.descriptor is None:
        raise VerificationFailedError("channel is not precompile-backed")
    if channel.highest_voucher is None:
        raise VerificationFailedError("no voucher to settle")
    descriptor = channel.descriptor
    escrow = escrow_contract or channel.escrow_contract
    assert_settlement_sender(
        operation="settle",
        channel_id=channel_id,
        operator=channel.operator or ZERO_ADDRESS,
        payee=channel.payee,
        sender=account.address,
    )
    # Pin the transaction's expiry so the credit floor below can expire once it cannot land.
    valid_before = int(time.time()) + PENDING_CLOSE_VALIDITY_SECONDS
    pending_expires_at = (valid_before + PENDING_CLOSE_CLOCK_SKEW_SECONDS) * 1000
    claim: dict[str, Any] = {}

    def choose(current: ChannelState | None) -> ChannelState | None:
        claim["channel"] = current
        voucher = resolve_settleable_voucher(current) if current is not None else None
        claim["voucher"] = voucher
        if current is None or voucher is None:
            return current
        now = int(time.time() * 1000)
        live = current.pending_settlement
        if live is not None and live.expires_at <= now:
            live = None
        return replace(
            current,
            pending_settlement=PendingSettlement(
                amount=keep_greater(live.amount if live else 0, voucher.cumulative_amount),
                expires_at=max(live.expires_at if live else 0, pending_expires_at),
            ),
        )

    # Choosing the voucher and raising the credit floor in one update keeps a concurrent
    # credit from lowering spent below what this transaction captures.
    await channel_store.update_channel(channel_id, choose)
    voucher = claim.get("voucher")
    claimed: ChannelState | None = claim.get("channel")
    if voucher is None or claimed is None:
        raise VerificationFailedError(
            "nothing to settle: no accepted voucher above the settled amount is within spent"
        )
    amount = uint96(voucher.cumulative_amount)
    pending_amount = amount

    async def release() -> None:
        def update(current: ChannelState | None) -> ChannelState | None:
            pending = current.pending_settlement if current is not None else None
            if (
                current is None
                or pending is None
                or pending.amount != pending_amount
                or pending.expires_at != pending_expires_at
            ):
                return current
            return replace(current, pending_settlement=None)

        with contextlib.suppress(Exception):
            await channel_store.update_channel(channel_id, update)

    try:
        # A replica behind the open or top-up that admitted this voucher rejects the settle
        # while preparing it; nothing was broadcast, so retry until it catches up.
        tx_hash = await chain.readback_with_retry(
            lambda: chain.settle_on_chain(
                rpc_url,
                account,
                descriptor,
                amount,
                voucher.signature,
                escrow=escrow,
                fee_payer=fee_payer,
                fee_payer_policy=fee_payer_policy,
                fee_token=fee_token,
                candidate_fee_tokens=candidate_fee_tokens or [channel.token],
                valid_before=valid_before,
                client=http_client,
            ),
            should_retry=is_execution_revert,
        )
        receipt = await chain.wait_for_successful_receipt(rpc_url, tx_hash, client=http_client)
    except Exception as error:
        if is_execution_revert(error) or isinstance(error, VerificationFailedError):
            await release()
        raise
    settled_event = chain.get_channel_event(receipt, "Settled", channel_id)
    delta_paid = int(settled_event["deltaPaid"])
    new_settled = int(settled_event["newSettled"])
    if new_settled < amount:
        raise VerificationFailedError("Settled event is below voucher amount")
    block = receipt.get("blockNumber")
    block_number = int(block, 16) if isinstance(block, str) else block
    # A replica behind the receipt's block would report the pre-settlement state.
    state = await chain.readback_with_retry(
        lambda: chain.get_channel_state(
            rpc_url, channel_id, escrow=escrow, block=block_number, client=http_client
        )
    )
    if state.settled != new_settled:
        raise VerificationFailedError("on-chain channel state does not match settle receipt")

    settled_at = _now_iso()

    def record(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            return current
        settled_on_chain = keep_greater(current.settled_on_chain, new_settled)
        pending = current.pending_settlement
        return replace(
            current,
            # The recorded settlement now keeps spent at or above what this tx captured.
            pending_settlement=pending
            if pending is not None and pending.amount > settled_on_chain
            else None,
            retained_vouchers=tuple(
                v for v in current.retained_vouchers if v.cumulative_amount > settled_on_chain
            )
            if current.retained_vouchers is not None
            else None,
            settled_on_chain=settled_on_chain,
            last_settlement_at=settled_at,
            # Charges accepted after the voucher was chosen are not covered by this tx.
            last_settlement_spent=keep_greater(current.last_settlement_spent or 0, amount),
            last_settlement_units=max(current.last_settlement_units or 0, claimed.units),
        )

    checkpoint_error: BaseException | None = None
    try:
        await channel_store.update_channel(channel_id, record)
    except Exception as error:
        checkpoint_error = error
    await emit_session_settlement(
        on_session_settlement,
        SessionSettlementContext(
            tx_hash=tx_hash,
            channel_id=channel_id,
            trigger="settle",
            amount=new_settled,
            # The stored checkpoint can be stale after a failed write; the receipt is not.
            delta=delta_paid,
        ),
    )
    if checkpoint_error is not None:
        raise SettlementCheckpointError(tx_hash=tx_hash, cause=checkpoint_error)
    return tx_hash


def _now_iso() -> str:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


async def settle_batch(
    store: Any,
    channel_ids: Iterable[str],
    *,
    account: TempoAccount,
    rpc_url: str,
    http_client: httpx.AsyncClient | None = None,
    escrow_contract: str | None = None,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
) -> list[str]:
    """Settle several channels one after another, with the same checks as :func:`settle`."""
    return [
        await settle(
            store,
            channel_id,
            account=account,
            rpc_url=rpc_url,
            http_client=http_client,
            escrow_contract=escrow_contract,
            fee_payer=fee_payer,
            fee_payer_policy=fee_payer_policy,
            fee_token=fee_token,
            candidate_fee_tokens=candidate_fee_tokens,
            on_session_settlement=on_session_settlement,
        )
        for channel_id in channel_ids
    ]


async def maybe_settle_scheduled(
    *,
    channel: ChannelState,
    schedule: ResolvedSettlementSchedule | None,
    store: ChannelStore,
    account: TempoAccount | None,
    rpc_url: str,
    http_client: httpx.AsyncClient | None = None,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
    on_session_settlement_failure: OnSessionSettlementFailure | None = None,
    lease_ms: int = SCHEDULED_SETTLEMENT_LEASE_MS,
) -> str | None:
    """Settle a channel when the server-owned schedule is due; returns the settlement tx hash.

    One worker settles a due channel under a store lease; others skip it.
    """
    if schedule is None or not is_settlement_due(channel, schedule):
        return None

    async def report(error: BaseException) -> None:
        await report_session_settlement_failure(
            on_session_settlement_failure,
            SessionSettlementFailureContext(
                chain_id=channel.chain_id,
                channel_id=channel.channel_id,
                error=error,
                trigger="scheduled",
            ),
        )

    try:
        lease_owner = await claim_scheduled_settlement(
            channel_id=channel.channel_id, schedule=schedule, store=store, lease_ms=lease_ms
        )
    except Exception as error:
        await report(error)
        # Nothing was submitted, so the next settlement can still collect this charge.
        raise SettlementLeaseError(cause=error) from error
    if lease_owner is None:
        return None
    owner = lease_owner

    async def release() -> None:
        with contextlib.suppress(Exception):
            await release_scheduled_settlement(
                channel_id=channel.channel_id, lease_owner=owner, store=store
            )

    async def renew() -> None:
        while True:
            await asyncio.sleep(lease_ms / 2 / 1000)
            with contextlib.suppress(Exception):
                await renew_scheduled_settlement(
                    channel_id=channel.channel_id, lease_owner=owner, store=store, lease_ms=lease_ms
                )

    async def scheduled(context: SessionSettlementContext) -> None:
        if on_session_settlement is not None:
            await _call(on_session_settlement, replace(context, trigger="scheduled"))

    renewal = asyncio.create_task(renew())
    try:
        if account is None:
            raise ValueError(
                f"Cannot settle precompile channel {channel.channel_id}: no account available."
            )
        tx_hash = await settle(
            store,
            channel.channel_id,
            account=account,
            rpc_url=rpc_url,
            http_client=http_client,
            fee_payer=fee_payer,
            fee_payer_policy=fee_payer_policy,
            fee_token=fee_token,
            on_session_settlement=scheduled if on_session_settlement is not None else None,
        )
    except Exception as error:
        await release()
        await report(error)
        # The transaction confirmed and collected the charge; only the local record failed.
        if isinstance(error, SettlementCheckpointError):
            return error.tx_hash
        raise
    finally:
        renewal.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await renewal
    # Bookkeeping after a confirmed settlement must not fail the charged request.
    try:
        await mark_settlement_complete(
            channel_id=channel.channel_id, lease_owner=owner, store=store
        )
    except Exception:
        await release()
    return tx_hash
