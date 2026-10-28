"""Server-scheduled settlement state (the store-only parts of mppx ``server/Settlement.ts``).

Resolves a settlement schedule, measures a channel's progress against it, and claims, renews
and releases the cross-worker lease that lets one worker run a due settlement.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from mpp._units import parse_units
from mpp.methods.tempo.session.server.store import (
    ChannelState,
    ChannelStore,
    ScheduledSettlementLease,
    is_precompile_state,
    resolve_settleable_voucher,
)

SCHEDULED_SETTLEMENT_LEASE_MS = 5 * 60_000
"""Default lease a worker holds while its scheduled settlement transaction is in flight."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SettlementSchedule:
    """Declarative server-side settlement cadence (mppx ``SettlementSchedule``).

    A channel is due once any threshold is crossed since the previous scheduled settlement.
    """

    units: int | None = None
    """Settle after this many additional paid units."""
    amount: str | int | None = None
    """Settle after this much additional spend: a decimal string in token units, or raw units."""
    interval_ms: int | None = None
    """Settle after this many milliseconds."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedSettlementSchedule:
    """A settlement schedule with ``amount`` in raw token units."""

    amount: int | None = None
    interval_ms: int | None = None
    units: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SettlementProgress:
    """Progress since the previous scheduled settlement boundary."""

    amount: int
    """Additional raw spend."""
    units: int
    """Additional paid units."""
    elapsed_ms: int | None = None
    """Milliseconds elapsed, when the boundary timestamp parses."""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _now_iso() -> str:
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _parse_iso_ms(value: str) -> int | None:
    try:
        return int(datetime.fromisoformat(value).timestamp() * 1000)
    except ValueError:
        return None


def resolve_settlement_schedule(
    schedule: SettlementSchedule | None, decimals: int
) -> ResolvedSettlementSchedule | None:
    """Converts a public settlement schedule into raw-unit thresholds."""
    if schedule is None:
        return None
    amount = schedule.amount
    return ResolvedSettlementSchedule(
        amount=(
            None
            if amount is None
            else amount
            if isinstance(amount, int)
            else parse_units(amount, decimals)
        ),
        interval_ms=schedule.interval_ms,
        units=schedule.units,
    )


def resolve_settlement_progress(channel: ChannelState) -> SettlementProgress | None:
    """The schedule progress of an unsettled precompile-backed channel.

    None for channels that cannot be scheduled: non-precompile records, or channels without
    an accepted voucher above the settled amount and within ``spent``.
    """
    if not is_precompile_state(channel):
        return None
    # A settlement captures a voucher whole, so only a voucher within spend can be scheduled.
    if resolve_settleable_voucher(channel) is None:
        return None
    amount_boundary = (
        channel.last_settlement_spent
        if channel.last_settlement_spent is not None
        else channel.settled_on_chain
    )
    timestamp_boundary = _parse_iso_ms(channel.last_settlement_at or channel.created_at)
    return SettlementProgress(
        amount=channel.spent - amount_boundary,
        units=channel.units - (channel.last_settlement_units or 0),
        elapsed_ms=None if timestamp_boundary is None else _now_ms() - timestamp_boundary,
    )


def is_settlement_due(channel: ChannelState, schedule: ResolvedSettlementSchedule | None) -> bool:
    """Whether a precompile channel has crossed any configured settlement threshold."""
    if schedule is None:
        return False
    progress = resolve_settlement_progress(channel)
    if progress is None:
        return False
    # A detected force-close makes outstanding vouchers immediately due.
    if not channel.finalized and channel.close_requested_at > 0:
        return True
    if schedule.units is not None and progress.units >= schedule.units:
        return True
    if schedule.amount is not None and progress.amount >= schedule.amount:
        return True
    return schedule.interval_ms is not None and (progress.elapsed_ms or 0) >= schedule.interval_ms


async def mark_settlement_complete(
    *,
    channel_id: str,
    lease_owner: str,
    store: ChannelStore,
    settled_at: str | None = None,
) -> None:
    """Releases a completed scheduled settlement lease and records when it settled.

    The settlement itself records the settled counters.
    """
    at = settled_at if settled_at is not None else _now_iso()

    def update(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            return current
        lease = current.scheduled_settlement_lease
        if lease is None or lease.owner != lease_owner:
            return current
        return replace(current, scheduled_settlement_lease=None, last_settlement_at=at)

    await store.update_channel(channel_id, update)


async def claim_scheduled_settlement(
    *,
    channel_id: str,
    schedule: ResolvedSettlementSchedule,
    store: ChannelStore,
    lease_ms: int = SCHEDULED_SETTLEMENT_LEASE_MS,
) -> str | None:
    """Atomically claims one due scheduled settlement across workers.

    Returns the lease owner token, or None when the channel is not due or another worker
    holds an unexpired lease.
    """
    now = _now_ms()
    owner = str(uuid.uuid4())
    claimed = False

    def update(current: ChannelState | None) -> ChannelState | None:
        nonlocal claimed
        claimed = False
        if current is None or not is_settlement_due(current, schedule):
            return current
        lease = current.scheduled_settlement_lease
        if lease is not None and lease.expires_at > now:
            return current
        claimed = True
        return replace(
            current,
            scheduled_settlement_lease=ScheduledSettlementLease(
                expires_at=now + lease_ms, owner=owner
            ),
        )

    await store.update_channel(channel_id, update)
    return owner if claimed else None


async def renew_scheduled_settlement(
    *,
    channel_id: str,
    lease_owner: str,
    store: ChannelStore,
    lease_ms: int = SCHEDULED_SETTLEMENT_LEASE_MS,
) -> None:
    """Extends an owned scheduled settlement lease while its transaction is in flight."""

    def update(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            return current
        lease = current.scheduled_settlement_lease
        if lease is None or lease.owner != lease_owner:
            return current
        return replace(
            current,
            scheduled_settlement_lease=ScheduledSettlementLease(
                expires_at=_now_ms() + lease_ms, owner=lease_owner
            ),
        )

    await store.update_channel(channel_id, update)


async def release_scheduled_settlement(
    *, channel_id: str, lease_owner: str, store: ChannelStore
) -> None:
    """Releases a scheduled settlement claim after a failed attempt."""

    def update(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            return current
        lease = current.scheduled_settlement_lease
        if lease is None or lease.owner != lease_owner:
            return current
        return replace(current, scheduled_settlement_lease=None)

    await store.update_channel(channel_id, update)
