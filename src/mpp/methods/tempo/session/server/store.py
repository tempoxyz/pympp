"""Server channel state and its atomic store (mppx ``tempo/session/server/ChannelStore.ts``).

A channel is created when a payer opens a TIP-1034 channel on-chain and persists until it is
finalized. One channel is one session: the client owns the key and cannot race with itself.

Monotonicity invariants (kept by the update helpers):

- ``highest_voucher_amount`` only increases
- ``settled_on_chain`` only increases
- ``deposit`` reflects the latest on-chain value

:class:`StoreChannelStore` wraps a pympp :class:`~mpp.store.Store`. With a
:class:`~mpp.store.CompareAndSetStore` (``MemoryStore``, ``RedisStore``, ``SQLiteStore``)
:meth:`~StoreChannelStore.update_channel` is a compare-and-set retry loop, linearizable
across processes; with a plain store it serializes updates within this process only.
Channel records are stored as canonical JSON text under the normalized channel ID, with
``bigint`` fields as decimal strings, so every backend round-trips and compares them exactly.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import secrets
import time
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Generic, Literal, Protocol, TypeVar, cast

from mpp.errors import PaymentError, VerificationFailedError
from mpp.methods.tempo.session.protocol import ChannelDescriptor, SignedVoucher, uint96
from mpp.store import CompareAndSetStore, Store

_R = TypeVar("_R")

# --------------------------------------------------------------------------------------------
# Errors (mppx Errors.ts session problem types)
# --------------------------------------------------------------------------------------------

_SESSION_PROBLEMS = "https://paymentauth.org/problems/session"


class InsufficientBalanceError(PaymentError):
    """The channel's available voucher balance cannot cover the requested amount."""

    status = 402
    type = f"{_SESSION_PROBLEMS}/insufficient-balance"
    title = "Insufficient Balance"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(f"Insufficient balance: {reason}." if reason else "Insufficient balance.")


class InvalidSignatureError(PaymentError):
    """A voucher or close request signature is invalid."""

    status = 402
    type = f"{_SESSION_PROBLEMS}/invalid-signature"
    title = "Invalid Signature"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(f"Invalid signature: {reason}." if reason else "Invalid signature.")


class AmountExceedsDepositError(PaymentError):
    """A voucher or close amount exceeds the channel's on-chain deposit."""

    status = 402
    type = f"{_SESSION_PROBLEMS}/amount-exceeds-deposit"
    title = "Amount Exceeds Deposit"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(
            f"Amount exceeds deposit: {reason}."
            if reason
            else "Voucher amount exceeds channel deposit."
        )


class DeltaTooSmallError(PaymentError):
    """A voucher's increase is below the minimum voucher delta."""

    status = 402
    type = f"{_SESSION_PROBLEMS}/delta-too-small"
    title = "Delta Too Small"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(
            f"Delta too small: {reason}."
            if reason
            else "Amount increase below minimum voucher delta."
        )


class ChannelNotFoundError(PaymentError):
    """No channel with this ID exists."""

    status = 410
    type = f"{_SESSION_PROBLEMS}/channel-not-found"
    title = "Channel Not Found"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(
            f"Channel not found: {reason}." if reason else "No channel with this ID exists."
        )


class ChannelClosedError(PaymentError):
    """The channel is closed, finalized or has a pending close request."""

    status = 410
    type = f"{_SESSION_PROBLEMS}/channel-finalized"
    title = "Channel Closed"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(f"Channel closed: {reason}." if reason else "Channel is closed.")


class IdempotencyKeyConflictError(Exception):
    """An idempotency key was reused with terms other than those it recorded."""

    def __init__(self, *, idempotency_key: str, operation: Literal["charge", "credit"]) -> None:
        super().__init__(
            f'Session {operation} "{idempotency_key}" was recorded with different terms.'
        )
        self.idempotency_key = idempotency_key


# --------------------------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------------------------

Backend = Literal["precompile", "contract", "external"]
CreditDeclineReason = Literal["belowSettled", "closing", "exceedsSpent", "finalized"]
"""Why a credit was not applied (mppx ``CreditDeclineReason``).

``belowSettled``: crediting would take ``spent`` below what settled, or may still settle,
on-chain. ``closing``: a close is pending, so its capture is fixed. ``exceedsSpent``: the
amount is larger than ``spent``. ``finalized``: the channel is closed.
"""
MarkerOutcome = Literal[
    "charged", "credited", "belowSettled", "closing", "exceedsSpent", "finalized"
]


class OnChainChannelState(Protocol):
    """On-chain fields read from the TIP-1034 precompile (``chain.ChannelState`` fits)."""

    @property
    def deposit(self) -> int: ...
    @property
    def settled(self) -> int: ...
    @property
    def close_requested_at(self) -> int: ...


@dataclass(frozen=True, slots=True)
class ScheduledSettlementLease:
    """Expiring ownership claim for one server-scheduled settlement attempt."""

    expires_at: int
    """Unix milliseconds."""
    owner: str


@dataclass(frozen=True, slots=True)
class RetainedVoucher:
    """An accepted voucher kept below the highest one."""

    cumulative_amount: int
    signature: str


@dataclass(frozen=True, slots=True)
class PendingSettlement:
    """A settlement transaction that may land until ``expires_at`` (Unix milliseconds)."""

    amount: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class StreamReservation:
    """An uncommitted stream charge shared across workers."""

    amount: int
    units: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class IdempotencyMarker:
    """Recorded outcome of one keyed charge or credit."""

    amount: int
    expires_at: int
    """Unix milliseconds until which a retry with the same key replays this outcome."""
    outcome: MarkerOutcome
    units: int | None = None
    """Charge operations a credit returned, when any."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelState:
    """Persisted state of one payment channel (mppx ``ChannelStore.State``).

    Precompile-backed channels set ``backend="precompile"`` and the descriptor fields.
    """

    channel_id: str
    authorized_signer: str
    chain_id: int
    escrow_contract: str
    payer: str
    payee: str
    token: str
    deposit: int
    settled_on_chain: int
    highest_voucher_amount: int
    highest_voucher: SignedVoucher | None
    spent: int
    units: int
    close_requested_at: int
    """On-chain timestamp of a close request (or the local pending-close marker); 0 if none."""
    finalized: bool
    created_at: str
    """ISO 8601 timestamp when the channel was created."""
    backend: Backend | None = None
    descriptor: ChannelDescriptor | None = None
    expiring_nonce_hash: str | None = None
    operator: str | None = None
    salt: str | None = None
    on_chain_verified_at: int | None = None
    """Unix milliseconds when deposit, settlement and close state were last read on-chain."""
    stream_reservations: Mapping[str, StreamReservation] | None = None
    scheduled_settlement_lease: ScheduledSettlementLease | None = None
    last_settlement_at: str | None = None
    last_settlement_spent: int | None = None
    last_settlement_units: int | None = None
    retained_vouchers: tuple[RetainedVoucher, ...] | None = None
    """Accepted vouchers below ``highest_voucher``, ascending (see resolve_settleable_voucher)."""
    pending_settlement: PendingSettlement | None = None
    idempotency_markers: Mapping[str, IdempotencyMarker] | None = None
    """Keyed charge and credit outcomes, by ``charge:<key>`` and ``credit:<key>``."""
    close_supervised_from_block: int | None = None


@dataclass(frozen=True, slots=True)
class DeductResult:
    """Result of an atomic deduction; ``replayed`` marks a keyed charge recorded earlier."""

    ok: bool
    channel: ChannelState
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class CreditResult:
    """Outcome of a credit (mppx ``CreditResult``).

    ``declined`` leaves ``spent`` unchanged, so the caller refunds the amount another way.
    ``unknown`` means the store write failed and may have committed: retry with the same key.
    """

    status: Literal["credited", "declined", "unknown"]
    channel: ChannelState | None = None
    replayed: bool = False
    reason: CreditDeclineReason | None = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class HighestVoucher:
    highest_voucher_amount: int
    highest_voucher: SignedVoucher | None


@dataclass(frozen=True, slots=True)
class ActiveOnChainState:
    close_requested_at: int
    deposit: int
    settled_on_chain: int


@dataclass(frozen=True, slots=True)
class PendingCloseUpdate:
    """Amount a close captures on-chain and the next local state (None without a channel)."""

    capture_amount: int
    state: ChannelState | None


@dataclass(frozen=True, slots=True)
class VoucherValidation:
    already_accepted: bool


@dataclass(frozen=True, slots=True)
class VoucherAcceptance:
    channel: ChannelState
    charged: bool


@dataclass(frozen=True, slots=True)
class StoreChange(Generic[_R]):
    """An atomic store change: ``set`` value, ``delete`` or ``noop``, plus a result to return."""

    op: Literal["set", "delete", "noop"]
    result: _R
    value: ChannelState | None = None


def is_precompile_state(state: ChannelState) -> bool:
    """Whether a channel is backed by the TIP20EscrowChannel precompile."""
    return state.backend == "precompile"


# --------------------------------------------------------------------------------------------
# Pure state helpers
# --------------------------------------------------------------------------------------------


def keep_greater(current: int, next_value: int) -> int:
    """The greater value, so persisted monotonic state never decreases."""
    return current if current > next_value else next_value


def keep_greater_timestamp(current: int, next_value: int) -> int:
    return keep_greater(current, int(next_value))


def merge_active_on_chain_state(
    current: ChannelState | ActiveOnChainState | None, state: OnChainChannelState
) -> ActiveOnChainState:
    """Keeps local active-channel state in sync with authoritative on-chain reads."""
    return ActiveOnChainState(
        close_requested_at=keep_greater_timestamp(
            current.close_requested_at if current else 0, state.close_requested_at
        ),
        deposit=keep_greater(current.deposit if current else 0, state.deposit),
        settled_on_chain=keep_greater(current.settled_on_chain if current else 0, state.settled),
    )


def resolve_highest_voucher(
    *,
    channel_id: str,
    current: ChannelState | HighestVoucher | None,
    cumulative_amount: int,
    signature: str,
) -> HighestVoucher:
    """Keeps an existing higher voucher, otherwise the candidate voucher."""
    if current is not None and current.highest_voucher_amount > cumulative_amount:
        return HighestVoucher(current.highest_voucher_amount, current.highest_voucher)
    return HighestVoucher(
        cumulative_amount,
        SignedVoucher(
            channel_id=channel_id, cumulative_amount=cumulative_amount, signature=signature
        ),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class PrecompileChannelIdentity:
    authorized_signer: str
    backend: Literal["precompile"]
    chain_id: int
    channel_id: str
    descriptor: ChannelDescriptor
    escrow_contract: str
    expiring_nonce_hash: str
    operator: str
    payee: str
    payer: str
    salt: str
    token: str


def resolve_precompile_channel_identity(
    *,
    authorized_signer: str,
    chain_id: int,
    channel_id: str,
    descriptor: ChannelDescriptor,
    escrow: str,
    expiring_nonce_hash: str,
) -> PrecompileChannelIdentity:
    """Persisted identity fields derived from a verified precompile channel descriptor."""
    return PrecompileChannelIdentity(
        authorized_signer=authorized_signer,
        backend="precompile",
        chain_id=chain_id,
        channel_id=channel_id,
        descriptor=descriptor,
        escrow_contract=escrow,
        expiring_nonce_hash=expiring_nonce_hash,
        operator=descriptor.operator,
        payee=descriptor.payee,
        payer=descriptor.payer,
        salt=descriptor.salt,
        token=descriptor.token,
    )


def _now_iso() -> str:
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _now_ms() -> int:
    return int(time.time() * 1000)


def open_channel_state(
    *,
    authorized_signer: str,
    chain_id: int,
    channel_id: str,
    current: ChannelState | None,
    descriptor: ChannelDescriptor,
    escrow: str,
    expiring_nonce_hash: str,
    cumulative_amount: int,
    signature: str,
    state: OnChainChannelState,
) -> ChannelState:
    """The persisted state for a verified precompile channel open."""
    highest = resolve_highest_voucher(
        channel_id=channel_id,
        current=current,
        cumulative_amount=cumulative_amount,
        signature=signature,
    )
    on_chain = merge_active_on_chain_state(current, state)
    identity = resolve_precompile_channel_identity(
        authorized_signer=authorized_signer,
        chain_id=chain_id,
        channel_id=channel_id,
        descriptor=descriptor,
        escrow=escrow,
        expiring_nonce_hash=expiring_nonce_hash,
    )
    fields: dict[str, Any] = {
        "authorized_signer": identity.authorized_signer,
        "backend": identity.backend,
        "chain_id": identity.chain_id,
        "channel_id": identity.channel_id,
        "descriptor": identity.descriptor,
        "escrow_contract": identity.escrow_contract,
        "expiring_nonce_hash": identity.expiring_nonce_hash,
        "operator": identity.operator,
        "payee": identity.payee,
        "payer": identity.payer,
        "salt": identity.salt,
        "token": identity.token,
        "close_requested_at": on_chain.close_requested_at,
        "deposit": on_chain.deposit,
        "settled_on_chain": on_chain.settled_on_chain,
        "highest_voucher_amount": highest.highest_voucher_amount,
        "highest_voucher": highest.highest_voucher,
        "spent": keep_greater(current.spent if current else 0, state.settled),
        "units": current.units if current else 0,
        "finalized": current.finalized if current else False,
        "created_at": current.created_at if current else _now_iso(),
    }
    if current is not None and highest.highest_voucher_amount > current.highest_voucher_amount:
        fields["retained_vouchers"] = retain_vouchers(
            current, highest.highest_voucher_amount, on_chain.settled_on_chain
        )
    if current is None:
        return ChannelState(**fields)
    return replace(current, **fields)


def top_up_channel_state(
    *, current: ChannelState | None, state: OnChainChannelState
) -> ChannelState | None:
    """Merges top-up on-chain state without decreasing monotonic fields."""
    if current is None:
        return None
    return _with_on_chain(current, merge_active_on_chain_state(current, state))


def _with_on_chain(current: ChannelState, on_chain: ActiveOnChainState) -> ChannelState:
    return replace(
        current,
        close_requested_at=on_chain.close_requested_at,
        deposit=on_chain.deposit,
        settled_on_chain=on_chain.settled_on_chain,
    )


MAX_RETAINED_VOUCHERS = 16
"""Accepted vouchers kept below the highest one (mppx ``maxRetainedVouchers``).

Once a credit lowers ``spent`` the highest voucher stays above it for good, so only earlier
vouchers can be settled; those fall at or below ``spent`` as later charges accumulate.
"""


def retain_vouchers(
    current: ChannelState,
    highest_voucher_amount: int,
    settled_on_chain: int | None = None,
) -> tuple[RetainedVoucher, ...]:
    """The vouchers to keep once ``highest_voucher_amount`` replaces the highest voucher.

    Keeps the retained ones and the superseded highest voucher above ``settled_on_chain``;
    beyond :data:`MAX_RETAINED_VOUCHERS` it repeatedly drops the voucher whose neighbours are
    closest, so the kept ones stay spread over the unsettled range.
    """
    settled = current.settled_on_chain if settled_on_chain is None else settled_on_chain
    candidates = list(current.retained_vouchers or ())
    if current.highest_voucher is not None:
        candidates.append(
            RetainedVoucher(
                current.highest_voucher.cumulative_amount, current.highest_voucher.signature
            )
        )
    kept = sorted(
        (v for v in candidates if settled < v.cumulative_amount < highest_voucher_amount),
        key=lambda v: v.cumulative_amount,
    )
    while len(kept) > MAX_RETAINED_VOUCHERS:
        drop = 0
        narrowest: int | None = None
        for index in range(len(kept)):
            below = settled if index == 0 else kept[index - 1].cumulative_amount
            above = (
                highest_voucher_amount
                if index == len(kept) - 1
                else kept[index + 1].cumulative_amount
            )
            if narrowest is None or above - below < narrowest:
                narrowest = above - below
                drop = index
        del kept[drop]
    return tuple(kept)


def resolve_settleable_voucher(state: ChannelState) -> SignedVoucher | None:
    """The largest accepted voucher a settlement may capture.

    ``settle`` captures a voucher's whole cumulative amount and a credit may leave the
    highest voucher above ``spent``, so it must be at most ``spent``; one at or below
    ``settled_on_chain`` captures nothing.
    """
    settleable: RetainedVoucher | None = None
    vouchers = list(state.retained_vouchers or ())
    if state.highest_voucher is not None:
        vouchers.append(
            RetainedVoucher(
                state.highest_voucher.cumulative_amount, state.highest_voucher.signature
            )
        )
    for voucher in vouchers:
        if (
            voucher.cumulative_amount > state.spent
            or voucher.cumulative_amount <= state.settled_on_chain
        ):
            continue
        if settleable is None or voucher.cumulative_amount > settleable.cumulative_amount:
            settleable = voucher
    if settleable is None:
        return None
    return SignedVoucher(
        channel_id=state.channel_id,
        cumulative_amount=settleable.cumulative_amount,
        signature=settleable.signature,
    )


def accept_voucher_state_update(
    *,
    channel_state: OnChainChannelState,
    current: ChannelState | None,
    voucher: SignedVoucher,
    verified_at: int | None = None,
) -> ChannelState:
    """Merges an accepted voucher after its signature and on-chain checks pass.

    ``verified_at`` is when ``channel_state`` was read from chain (Unix ms); omit it when it
    came from the store.
    """
    if current is None:
        raise ChannelNotFoundError("channel not found")
    if current.finalized:
        raise ChannelClosedError("channel is finalized")
    if current.close_requested_at != 0:
        raise ChannelClosedError("channel has a pending close request")

    on_chain = merge_active_on_chain_state(current, channel_state)
    merged = _with_on_chain(current, on_chain)
    if verified_at is not None:
        merged = replace(
            merged, on_chain_verified_at=max(verified_at, current.on_chain_verified_at or 0)
        )
    if voucher.cumulative_amount <= current.highest_voucher_amount:
        return merged
    return replace(
        merged,
        highest_voucher_amount=voucher.cumulative_amount,
        highest_voucher=voucher,
        retained_vouchers=retain_vouchers(
            current, voucher.cumulative_amount, on_chain.settled_on_chain
        ),
    )


def resolve_close_capture_amount(
    *, cumulative_amount: int, on_chain_deposit: int, on_chain_settled: int, spent: int
) -> int:
    """The amount a close captures, ``max(spent, settled)``, checked against voucher and deposit."""
    if cumulative_amount < spent:
        raise VerificationFailedError(f"close voucher amount must be >= {spent} (spent)")
    capture_amount = uint96(spent if spent > on_chain_settled else on_chain_settled)
    if capture_amount > cumulative_amount:
        raise VerificationFailedError(
            f"close voucher amount must be >= {capture_amount} (capture amount)"
        )
    if capture_amount > on_chain_deposit:
        raise AmountExceedsDepositError("close capture amount exceeds on-chain deposit")
    return capture_amount


PENDING_CLOSE_VALIDITY_SECONDS = 25
"""Seconds a server close transaction stays valid after its pending-close marker is written."""

PENDING_CLOSE_CLOCK_SKEW_SECONDS = 30
"""Extra seconds allowed for clock differences between the server and the chain."""


def reconcile_expired_pending_close(
    *, current: ChannelState | None, now: int, state: OnChainChannelState
) -> ChannelState | None:
    """Clears a pending-close marker whose close transaction expired without closing.

    ``now`` is Unix seconds.
    """
    if current is None or current.finalized or current.close_requested_at == 0:
        return current
    # An open channel with no on-chain close request proves the expired close never executed.
    if int(state.close_requested_at) != 0 or state.deposit == 0:
        return current
    expires_at = current.close_requested_at + PENDING_CLOSE_VALIDITY_SECONDS
    if now <= expires_at + PENDING_CLOSE_CLOCK_SKEW_SECONDS:
        return current
    return replace(current, close_requested_at=0)


def mark_pending_close(
    *,
    close_requested_at: int,
    cumulative_amount: int,
    current: ChannelState | None,
    on_chain_deposit: int,
    on_chain_settled: int,
) -> PendingCloseUpdate:
    """Marks local state as pending close and returns the bounded capture amount."""
    if current is None:
        return PendingCloseUpdate(0, None)
    if current.finalized:
        raise ChannelClosedError("channel is already finalized")
    if current.close_requested_at != 0:
        raise ChannelClosedError("channel has a pending close request")
    capture_amount = resolve_close_capture_amount(
        cumulative_amount=cumulative_amount,
        on_chain_deposit=on_chain_deposit,
        on_chain_settled=on_chain_settled,
        spent=current.spent,
    )
    return PendingCloseUpdate(
        capture_amount, replace(current, close_requested_at=close_requested_at)
    )


def finalize_closed_channel_state(
    *,
    capture_amount: int,
    channel_id: str,
    cumulative_amount: int,
    current: ChannelState | None,
    signature: str,
) -> ChannelState | None:
    """Finalizes local state after a successful close transaction."""
    if current is None:
        return None
    highest = resolve_highest_voucher(
        channel_id=channel_id,
        current=current,
        cumulative_amount=cumulative_amount,
        signature=signature,
    )
    return replace(
        current,
        finalized=True,
        close_requested_at=0,
        deposit=0,
        settled_on_chain=keep_greater(current.settled_on_chain, capture_amount),
        highest_voucher_amount=highest.highest_voucher_amount,
        highest_voucher=highest.highest_voucher,
    )


def _validate_channel_state(state: OnChainChannelState) -> None:
    # mppx CredentialVerification.validateChannelState, without the amount check.
    if state.deposit == 0:
        raise ChannelNotFoundError("channel not funded on-chain")
    if state.close_requested_at != 0:
        raise ChannelClosedError("channel has a pending close request")


def assert_voucher_amounts(
    *,
    channel: ChannelState,
    channel_state: OnChainChannelState,
    min_voucher_delta: int,
    cumulative_amount: int,
) -> VoucherValidation:
    """Checks a voucher's amounts against channel state, without its signature.

    Runs inside the store update that accepts the voucher.
    """
    _validate_channel_state(channel_state)
    if cumulative_amount > channel_state.deposit:
        raise AmountExceedsDepositError("voucher amount exceeds on-chain deposit")
    if cumulative_amount < channel.highest_voucher_amount:
        raise VerificationFailedError(
            "voucher cumulativeAmount must be strictly greater than highest accepted voucher"
        )
    if cumulative_amount <= channel_state.settled:
        raise VerificationFailedError("voucher cumulativeAmount is below on-chain settled amount")
    if cumulative_amount == channel.highest_voucher_amount:
        return VoucherValidation(already_accepted=True)
    delta = cumulative_amount - channel.highest_voucher_amount
    if delta < min_voucher_delta:
        raise DeltaTooSmallError(f"voucher delta {delta} below minimum {min_voucher_delta}")
    return VoucherValidation(already_accepted=False)


def plan_voucher_acceptance(
    *, accepted: ChannelState, charge_amount: int | None = None
) -> VoucherAcceptance:
    """Charges ``charge_amount`` to a state that just accepted a voucher, in the same update.

    A charge the available balance cannot cover leaves the accepted state uncharged.
    """
    if charge_amount is None:
        return VoucherAcceptance(accepted, False)
    deduction = _plan_deduction(accepted, charge_amount)
    if deduction.op != "set" or deduction.value is None:
        return VoucherAcceptance(accepted, False)
    return VoucherAcceptance(deduction.value, True)


def insufficient_balance_for_charge(
    channel: ChannelState, charge_amount: int
) -> InsufficientBalanceError:
    """The error for a request charge the channel's available balance could not cover."""
    available = channel.highest_voucher_amount - channel.spent - reserved_stream_amount(channel)
    return InsufficientBalanceError(f"requested {charge_amount}, available {available}")


def reserved_stream_amount(state: ChannelState) -> int:
    """Unexpired stream reservations that ordinary deductions must respect."""
    now = _now_ms()
    return sum(r.amount for r in (state.stream_reservations or {}).values() if r.expires_at > now)


# --------------------------------------------------------------------------------------------
# JSON codec
# --------------------------------------------------------------------------------------------


def _voucher_to_json(voucher: SignedVoucher) -> dict[str, Any]:
    return {
        "channelId": voucher.channel_id,
        "cumulativeAmount": str(voucher.cumulative_amount),
        "signature": voucher.signature,
    }


def channel_state_to_json(state: ChannelState) -> dict[str, Any]:
    """The JSON-compatible camelCase record (``bigint`` fields as decimal strings)."""
    data: dict[str, Any] = {
        "authorizedSigner": state.authorized_signer,
        "chainId": state.chain_id,
        "channelId": state.channel_id,
        "closeRequestedAt": str(state.close_requested_at),
        "createdAt": state.created_at,
        "deposit": str(state.deposit),
        "escrowContract": state.escrow_contract,
        "finalized": state.finalized,
        "highestVoucher": (
            _voucher_to_json(state.highest_voucher) if state.highest_voucher else None
        ),
        "highestVoucherAmount": str(state.highest_voucher_amount),
        "payee": state.payee,
        "payer": state.payer,
        "settledOnChain": str(state.settled_on_chain),
        "spent": str(state.spent),
        "token": state.token,
        "units": state.units,
    }
    if state.backend is not None:
        data["backend"] = state.backend
    if state.descriptor is not None:
        data["descriptor"] = state.descriptor.to_wire()
    if state.expiring_nonce_hash is not None:
        data["expiringNonceHash"] = state.expiring_nonce_hash
    if state.operator is not None:
        data["operator"] = state.operator
    if state.salt is not None:
        data["salt"] = state.salt
    if state.on_chain_verified_at is not None:
        data["onChainVerifiedAt"] = state.on_chain_verified_at
    if state.stream_reservations is not None:
        data["streamReservations"] = {
            key: {"amount": str(r.amount), "units": r.units, "expiresAt": r.expires_at}
            for key, r in state.stream_reservations.items()
        }
    if state.scheduled_settlement_lease is not None:
        lease = state.scheduled_settlement_lease
        data["scheduledSettlementLease"] = {"expiresAt": lease.expires_at, "owner": lease.owner}
    if state.last_settlement_at is not None:
        data["lastSettlementAt"] = state.last_settlement_at
    if state.last_settlement_spent is not None:
        data["lastSettlementSpent"] = str(state.last_settlement_spent)
    if state.last_settlement_units is not None:
        data["lastSettlementUnits"] = state.last_settlement_units
    if state.retained_vouchers is not None:
        data["retainedVouchers"] = [
            {"cumulativeAmount": str(v.cumulative_amount), "signature": v.signature}
            for v in state.retained_vouchers
        ]
    if state.pending_settlement is not None:
        data["pendingSettlement"] = {
            "amount": str(state.pending_settlement.amount),
            "expiresAt": state.pending_settlement.expires_at,
        }
    if state.idempotency_markers is not None:
        markers: dict[str, Any] = {}
        for key, m in state.idempotency_markers.items():
            marker: dict[str, Any] = {
                "amount": str(m.amount),
                "expiresAt": m.expires_at,
                "outcome": m.outcome,
            }
            if m.units is not None:
                marker["units"] = m.units
            markers[key] = marker
        data["idempotencyMarkers"] = markers
    if state.close_supervised_from_block is not None:
        data["closeSupervisedFromBlock"] = str(state.close_supervised_from_block)
    return data


def _int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("expected an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise ValueError("expected an integer")


def _opt_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    return None if value is None else _int(value)


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return None if value is None else str(value)


def _obj(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return cast(dict[str, Any], value)


def _voucher_from_json(value: Any) -> SignedVoucher:
    data = _obj(value)
    return SignedVoucher(
        channel_id=str(data["channelId"]),
        cumulative_amount=_int(data["cumulativeAmount"]),
        signature=str(data["signature"]),
    )


def _reservation_from_json(value: Any) -> StreamReservation:
    data = _obj(value)
    return StreamReservation(
        amount=_int(data["amount"]), units=_int(data["units"]), expires_at=_int(data["expiresAt"])
    )


def _marker_from_json(value: Any) -> IdempotencyMarker:
    data = _obj(value)
    outcome = data["outcome"]
    if outcome not in (
        "charged",
        "credited",
        "belowSettled",
        "closing",
        "exceedsSpent",
        "finalized",
    ):
        raise ValueError(f"unknown idempotency marker outcome {outcome!r}")
    return IdempotencyMarker(
        amount=_int(data["amount"]),
        expires_at=_int(data["expiresAt"]),
        outcome=outcome,
        units=_opt_int(data, "units"),
    )


def channel_state_from_json(value: Mapping[str, Any]) -> ChannelState:
    """Parses the record :func:`channel_state_to_json` produces."""
    data = dict(value)
    highest = data.get("highestVoucher")
    descriptor = data.get("descriptor")
    reservations = data.get("streamReservations")
    lease = data.get("scheduledSettlementLease")
    retained = data.get("retainedVouchers")
    pending = data.get("pendingSettlement")
    markers = data.get("idempotencyMarkers")
    backend = data.get("backend")
    if backend is not None and backend not in ("precompile", "contract", "external"):
        raise ValueError(f"unknown channel backend {backend!r}")
    lease_data = None if lease is None else _obj(lease)
    pending_data = None if pending is None else _obj(pending)
    return ChannelState(
        channel_id=str(data["channelId"]),
        authorized_signer=str(data["authorizedSigner"]),
        chain_id=_int(data["chainId"]),
        escrow_contract=str(data["escrowContract"]),
        payer=str(data["payer"]),
        payee=str(data["payee"]),
        token=str(data["token"]),
        deposit=_int(data["deposit"]),
        settled_on_chain=_int(data["settledOnChain"]),
        highest_voucher_amount=_int(data["highestVoucherAmount"]),
        highest_voucher=None if highest is None else _voucher_from_json(highest),
        spent=_int(data["spent"]),
        units=_int(data["units"]),
        close_requested_at=_int(data["closeRequestedAt"]),
        finalized=bool(data["finalized"]),
        created_at=str(data["createdAt"]),
        backend=backend,
        descriptor=None if descriptor is None else ChannelDescriptor.from_wire(descriptor),
        expiring_nonce_hash=_opt_str(data, "expiringNonceHash"),
        operator=_opt_str(data, "operator"),
        salt=_opt_str(data, "salt"),
        on_chain_verified_at=_opt_int(data, "onChainVerifiedAt"),
        stream_reservations=(
            None
            if reservations is None
            else {str(k): _reservation_from_json(r) for k, r in _obj(reservations).items()}
        ),
        scheduled_settlement_lease=(
            None
            if lease_data is None
            else ScheduledSettlementLease(
                expires_at=_int(lease_data["expiresAt"]), owner=str(lease_data["owner"])
            )
        ),
        last_settlement_at=_opt_str(data, "lastSettlementAt"),
        last_settlement_spent=_opt_int(data, "lastSettlementSpent"),
        last_settlement_units=_opt_int(data, "lastSettlementUnits"),
        retained_vouchers=(
            None
            if retained is None
            else tuple(
                RetainedVoucher(
                    cumulative_amount=_int(_obj(v)["cumulativeAmount"]),
                    signature=str(_obj(v)["signature"]),
                )
                for v in cast(list[Any], retained)
            )
        ),
        pending_settlement=(
            None
            if pending_data is None
            else PendingSettlement(
                amount=_int(pending_data["amount"]), expires_at=_int(pending_data["expiresAt"])
            )
        ),
        idempotency_markers=(
            None
            if markers is None
            else {str(k): _marker_from_json(m) for k, m in _obj(markers).items()}
        ),
        close_supervised_from_block=_opt_int(data, "closeSupervisedFromBlock"),
    )


def encode_channel_state(state: ChannelState) -> str:
    """Canonical JSON text stored for a channel (sorted keys, compact)."""
    return json.dumps(channel_state_to_json(state), sort_keys=True, separators=(",", ":"))


def decode_channel_state(raw: str | bytes | Mapping[str, Any]) -> ChannelState:
    """Parses a stored channel value: JSON text, its UTF-8 bytes, or an already-parsed dict."""
    if isinstance(raw, bytes):
        raw = raw.decode()
    if isinstance(raw, str):
        return channel_state_from_json(_obj(json.loads(raw)))
    return channel_state_from_json(raw)


# --------------------------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------------------------

_HEX = frozenset("0123456789abcdefABCDEF")


def normalize_channel_id(channel_id: str) -> str:
    """Validates a 32-byte channel ID and lowercases it for store lookup and persistence."""
    if (
        not isinstance(channel_id, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or len(channel_id) != 66
        or not channel_id.startswith("0x")
        or not _HEX.issuperset(channel_id[2:])
    ):
        raise ValueError("Invalid session channel ID.")
    return channel_id.lower()


class ChannelStore(Protocol):
    """Channel state persistence with an atomic read-modify-write (mppx ``ChannelStore``).

    ``update_channel`` must guarantee no concurrent mutation between reading ``current``
    and writing the callback's return value. Callbacks must be synchronous and
    deterministic: compare-and-set backends may run them more than once.
    """

    async def get_channel(self, channel_id: str) -> ChannelState | None: ...

    async def update_channel(
        self, channel_id: str, fn: Callable[[ChannelState | None], ChannelState | None]
    ) -> ChannelState | None:
        """Atomic read-modify-write; returning None from ``fn`` deletes the channel."""
        ...


def _normalize_state(channel_id: str, state: ChannelState | None) -> ChannelState | None:
    if state is None or state.channel_id == channel_id:
        return state
    return replace(state, channel_id=channel_id)


def _decode_stored(channel_id: str, raw: Any) -> ChannelState | None:
    if raw is None:
        return None
    return _normalize_state(channel_id, decode_channel_state(raw))


_CAS_PROBE_KEY = "mpp:session:cas-probe"
"""Key the store atomicity probe writes before a broadcast, then removes."""

_CAS_REFUSED = (
    "the session channel store refused compare_and_set; use a store that supports it, "
    "such as a Redis server that allows EVAL"
)


class StoreChannelStore:
    """:class:`ChannelStore` over a pympp key-value store (mppx ``fromStore``).

    Use :func:`from_store`, which returns one adapter per store so in-process waiters see
    every update made through it.
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self._cas = isinstance(store, CompareAndSetStore)
        self._cas_checked = False
        self._cas_probe_lock = asyncio.Lock()
        self._cas_probe_key = f"{_CAS_PROBE_KEY}:{secrets.token_hex(8)}"
        self._locks: dict[str, asyncio.Lock] = {}
        self._waiters: dict[str, set[asyncio.Future[None]]] = {}

    @property
    def store(self) -> Store:
        return self._store

    @property
    def atomic(self) -> bool:
        """False when the backing store only serializes updates within this process."""
        return self._cas

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        key = normalize_channel_id(channel_id)
        return _decode_stored(key, await self._store.get(key))

    async def update_channel(
        self, channel_id: str, fn: Callable[[ChannelState | None], ChannelState | None]
    ) -> ChannelState | None:
        def change(current: ChannelState | None) -> StoreChange[ChannelState | None]:
            next_state = fn(current)
            if next_state is not None:
                return StoreChange("set", next_state, next_state)
            return StoreChange("delete", None)

        return await self.update_channel_result(channel_id, change)

    async def update_channel_result(
        self, channel_id: str, fn: Callable[[ChannelState | None], StoreChange[_R]]
    ) -> _R:
        """Atomic read-modify-write returning the callback's ``result``."""
        key = normalize_channel_id(channel_id)
        if self._cas:
            return await self._update_cas(key, fn)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            change = fn(_decode_stored(key, await self._store.get(key)))
            if change.op == "set":
                value = _normalize_state(key, change.value)
                if value is None:
                    raise ValueError("a set change needs a value")
                await self._store.put(key, encode_channel_state(value))
            elif change.op == "delete":
                await self._store.delete(key)
            if change.op != "noop":
                self._notify(key)
            return change.result

    async def check_atomic_update(self, channel_id: str) -> None:
        """Raise when a compare-and-set store refuses ``compare_and_set``.

        Credential handlers call it before broadcasting a transaction whose outcome they
        must then record, so a store that cannot record it fails before any funds move.
        The probe writes and then deletes a throwaway key next to the channel's, so it
        exercises the same write a channel update makes (Redis's ``SET ... KEEPTTL``).

        Raises:
            NotImplementedError: The backing store refused ``compare_and_set``.
        """
        if not self._cas or self._cas_checked:
            return
        async with self._cas_probe_lock:
            if self._cas_checked:
                return
            store = cast(CompareAndSetStore, self._store)
            try:
                # The adapter's own key: no other prober races it, so a False write is a
                # refusal, and a probe that cannot be cleaned up leaves one key per adapter.
                written = await store.compare_and_set(self._cas_probe_key, None, "1")
            except NotImplementedError as error:
                raise NotImplementedError(_CAS_REFUSED) from error
            if not written:
                raise NotImplementedError(_CAS_REFUSED)
            # The write path is what channel updates need; removing the probe is best effort.
            with contextlib.suppress(Exception):
                raw = await store.get(self._cas_probe_key)
                if raw is not None:
                    await self._compare_and_set_raw(self._cas_probe_key, raw, None)
            self._cas_checked = True

    async def _compare_and_set_raw(self, key: str, raw: Any | None, value: str | None) -> bool:
        """compare_and_set against a value read back, as bytes or as the text it holds."""
        store = cast(CompareAndSetStore, self._store)
        return await store.compare_and_set(key, raw, value) or (
            # Stores returning bytes may compare either the bytes or the text they were given.
            isinstance(raw, bytes) and await store.compare_and_set(key, raw.decode(), value)
        )

    async def _update_cas(
        self, key: str, fn: Callable[[ChannelState | None], StoreChange[_R]]
    ) -> _R:
        store = cast(CompareAndSetStore, self._store)
        while True:
            raw = await store.get(key)
            change = fn(_decode_stored(key, raw))
            if change.op == "noop":
                return change.result
            value: str | None = None
            if change.op == "set":
                normalized = _normalize_state(key, change.value)
                if normalized is None:
                    raise ValueError("a set change needs a value")
                value = encode_channel_state(normalized)
            if raw is None and value is None:
                self._notify(key)
                return change.result
            try:
                written = await self._compare_and_set_raw(key, raw, value)
            except NotImplementedError as error:
                raise NotImplementedError(_CAS_REFUSED) from error
            if written:
                self._notify(key)
                return change.result

    def wait_for_update(self, channel_id: str) -> asyncio.Future[None]:
        """A future resolved by the next update to ``channel_id`` through this adapter.

        It is registered when called, so an update before it is awaited still resolves it.
        Cancelling it releases the subscription.
        """
        key = normalize_channel_id(channel_id)
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.setdefault(key, set()).add(future)

        def release(done: asyncio.Future[None]) -> None:
            current = self._waiters.get(key)
            if current is None:
                return
            current.discard(done)
            if not current:
                del self._waiters[key]

        future.add_done_callback(release)
        return future

    def _notify(self, key: str) -> None:
        for future in self._waiters.pop(key, None) or ():
            if not future.done():
                future.set_result(None)


_store_cache: weakref.WeakKeyDictionary[Any, StoreChannelStore] = weakref.WeakKeyDictionary()
# Stores that cannot be weak dictionary keys (unhashable or not weak-referenceable), by
# identity. Each entry keeps its store alive so the identity stays its own.
_store_cache_by_id: dict[int, tuple[Store, StoreChannelStore]] = {}


def from_store(store: Store) -> StoreChannelStore:
    """Wraps a pympp store in the session channel-store interface, once per store."""
    try:
        cached = _store_cache.get(store)
    except TypeError:
        entry = _store_cache_by_id.get(id(store))
        if entry is not None and entry[0] is store:
            return entry[1]
        channel_store = StoreChannelStore(store)
        _store_cache_by_id[id(store)] = (store, channel_store)
        return channel_store
    if cached is not None:
        return cached
    channel_store = StoreChannelStore(store)
    _store_cache[store] = channel_store
    return channel_store


async def check_atomic_update(store: ChannelStore, channel_id: str) -> None:
    """Raise before a broadcast when ``store`` cannot record its outcome atomically.

    Raises:
        NotImplementedError: A compare-and-set backing store refused ``compare_and_set``.
    """
    if isinstance(store, StoreChannelStore):
        await store.check_atomic_update(channel_id)


# --------------------------------------------------------------------------------------------
# Charges and credits
# --------------------------------------------------------------------------------------------

DEFAULT_IDEMPOTENCY_RETENTION = 24 * 60 * 60 * 1000
"""Milliseconds a keyed charge or credit outcome is kept by default: a day."""


async def _apply_change(
    store: ChannelStore,
    channel_id: str,
    fn: Callable[[ChannelState | None], StoreChange[_R]],
) -> _R:
    if isinstance(store, StoreChannelStore):
        return await store.update_channel_result(channel_id, fn)
    # The callback can rerun on a contended write; its last run's result is the stored one.
    results: list[_R] = []

    def update(current: ChannelState | None) -> ChannelState | None:
        change = fn(current)
        results.append(change.result)
        if change.op == "set":
            return change.value
        if change.op == "delete":
            return None
        return current

    await store.update_channel(channel_id, update)
    return results[-1]


def assert_idempotency_options(
    *, idempotency_key: str | None = None, retention: float | None = None
) -> None:
    """Validates the idempotency options of a keyed charge or credit."""
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or not idempotency_key
    ):
        raise ValueError("`idempotency_key` must be a non-empty string.")
    if retention is not None and (
        isinstance(retention, bool) or not math.isfinite(retention) or retention <= 0
    ):
        raise ValueError("`retention` must be a positive number.")


def _live_markers(state: ChannelState, now: int) -> dict[str, IdempotencyMarker]:
    return {
        key: marker
        for key, marker in (state.idempotency_markers or {}).items()
        if marker.expires_at > now
    }


def _plan_deduction(current: ChannelState | None, amount: int) -> StoreChange[DeductResult | None]:
    if current is None:
        return StoreChange("noop", None)
    if current.finalized or current.close_requested_at != 0:
        return StoreChange("noop", DeductResult(False, current))
    if current.highest_voucher_amount - current.spent - reserved_stream_amount(current) < amount:
        return StoreChange("noop", DeductResult(False, current))
    next_state = replace(current, spent=current.spent + amount, units=current.units + 1)
    return StoreChange("set", DeductResult(True, next_state), next_state)


_Conflict = Literal["conflict"]


def _plan_keyed_deduction(
    current: ChannelState | None, amount: int, idempotency_key: str, expires_at: int, now: int
) -> StoreChange[DeductResult | _Conflict | None]:
    if current is None:
        return StoreChange("noop", None)
    markers = _live_markers(current, now)
    marker_key = f"charge:{idempotency_key}"
    recorded = markers.get(marker_key)
    if recorded is not None:
        if recorded.outcome != "charged" or recorded.amount != amount:
            return StoreChange("noop", "conflict")
        return StoreChange("noop", DeductResult(True, current, replayed=True))
    deduction = _plan_deduction(current, amount)
    if deduction.op != "set" or deduction.value is None:
        return StoreChange("noop", deduction.result)
    channel = replace(
        deduction.value,
        idempotency_markers={
            **markers,
            marker_key: IdempotencyMarker(amount=amount, expires_at=expires_at, outcome="charged"),
        },
    )
    return StoreChange("set", DeductResult(True, channel), channel)


async def deduct_from_channel(
    store: ChannelStore,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str | None = None,
    retention: int | None = None,
) -> DeductResult:
    """Atomically deducts ``amount`` from a channel's available voucher balance.

    Returns ``ok=True`` with updated ``spent``/``units`` on success and ``ok=False`` without
    changing state when the channel cannot be charged now. With ``idempotency_key``, a charge
    recorded under the key returns ``replayed=True`` without charging again; the same key
    with another amount raises :class:`IdempotencyKeyConflictError`. A refused charge records
    nothing. ``retention`` (ms, default a day) must cover every retry.

    Raises:
        ChannelNotFoundError: When the channel does not exist.
    """
    if idempotency_key is not None:
        assert_idempotency_options(idempotency_key=idempotency_key, retention=retention)
        now = _now_ms()
        expires_at = now + (retention if retention is not None else DEFAULT_IDEMPOTENCY_RETENTION)
        key = idempotency_key
        keyed = await _apply_change(
            store,
            channel_id,
            lambda current: _plan_keyed_deduction(current, amount, key, expires_at, now),
        )
        if keyed is None:
            raise ChannelNotFoundError("channel not found")
        if keyed == "conflict":
            raise IdempotencyKeyConflictError(idempotency_key=key, operation="charge")
        return keyed

    result = await _apply_change(store, channel_id, lambda c: _plan_deduction(c, amount))
    if result is None:
        raise ChannelNotFoundError("channel not found")
    return result


def _credit_decline_reason(
    current: ChannelState, amount: int, now: int
) -> CreditDeclineReason | None:
    if current.finalized:
        return "finalized"
    if current.close_requested_at != 0:
        return "closing"
    if amount > current.spent:
        return "exceedsSpent"
    pending = current.pending_settlement
    settling = pending.amount if pending is not None and pending.expires_at > now else 0
    if current.spent - amount < keep_greater(current.settled_on_chain, settling):
        return "belowSettled"
    return None


def _plan_credit(
    current: ChannelState | None,
    *,
    amount: int,
    expires_at: int,
    idempotency_key: str,
    now: int,
    units: int,
) -> StoreChange[CreditResult | _Conflict | None]:
    if current is None:
        return StoreChange("noop", None)
    markers = _live_markers(current, now)
    marker_key = f"credit:{idempotency_key}"
    recorded = markers.get(marker_key)
    if recorded is not None:
        if (
            recorded.outcome == "charged"
            or recorded.amount != amount
            or (recorded.units or 0) != units
        ):
            return StoreChange("noop", "conflict")
        if recorded.outcome == "credited":
            return StoreChange("noop", CreditResult("credited", current, replayed=True))
        return StoreChange(
            "noop", CreditResult("declined", current, replayed=True, reason=recorded.outcome)
        )
    reason = _credit_decline_reason(current, amount, now)
    marker = IdempotencyMarker(
        amount=amount,
        expires_at=expires_at,
        outcome=reason or "credited",
        units=units if units > 0 else None,
    )
    channel = current
    if reason is None:
        channel = replace(
            channel, spent=current.spent - amount, units=max(0, current.units - units)
        )
    channel = replace(channel, idempotency_markers={**markers, marker_key: marker})
    result = (
        CreditResult("declined", channel, reason=reason)
        if reason
        else CreditResult("credited", channel)
    )
    return StoreChange("set", result, channel)


async def credit_channel(
    store: ChannelStore,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str,
    retention: int | None = None,
    units: int = 0,
) -> CreditResult:
    """Returns ``amount`` to a channel's ``spent`` at most once per idempotency key.

    Declined when the channel is closing or finalized, or when it would take ``spent`` below
    zero or below what settled, or may still settle, on-chain (a close captures
    ``max(spent, settled)``). The first outcome for a key is final. ``units`` charge
    operations are taken back from the channel's ``units``.

    Raises:
        ChannelNotFoundError: When the channel does not exist.
        IdempotencyKeyConflictError: When the key was recorded with other terms.
    """
    assert_idempotency_options(idempotency_key=idempotency_key, retention=retention)
    if not isinstance(idempotency_key, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("`idempotency_key` is required.")
    if amount <= 0:
        raise ValueError("Credit amount must be positive.")
    if isinstance(units, bool) or units < 0:
        raise ValueError("`units` must be a non-negative integer.")
    now = _now_ms()
    expires_at = now + (retention if retention is not None else DEFAULT_IDEMPOTENCY_RETENTION)
    try:
        result = await _apply_change(
            store,
            channel_id,
            lambda current: _plan_credit(
                current,
                amount=amount,
                expires_at=expires_at,
                idempotency_key=idempotency_key,
                now=now,
                units=units,
            ),
        )
    except Exception as error:
        return CreditResult("unknown", error=error)
    if result is None:
        raise ChannelNotFoundError("channel not found")
    if result == "conflict":
        raise IdempotencyKeyConflictError(idempotency_key=idempotency_key, operation="credit")
    return result
