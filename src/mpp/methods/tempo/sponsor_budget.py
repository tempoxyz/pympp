"""Aggregate in-flight fee exposure for locally sponsored Tempo charges.

A sponsor's reservations live in one JSON document per ``(chain, sponsor)`` in a
:class:`~mpp.store.CompareAndSetStore` shared by every process using the sponsor::

    {"reservations": {<id>: {"expiresAt", "fee", "leaseUntil", "owner", "phase",
                             "transactionHash"}}, "version": 1}

Times are Unix milliseconds and ``fee`` is a decimal string.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeVar

from mpp.errors import VerificationError
from mpp.methods.tempo.fee_payer_policy import DEFAULT_POLICY
from mpp.store import CompareAndSetStore, MemoryStore

_INITIAL_POLL_INTERVAL_MS: Final = 10
_MAX_POLL_INTERVAL_MS: Final = 250
_PREPARED_LEASE_MS: Final = 30_000
# Waiters share receipt lookups: each pending transaction is checked at most
# once per interval per process, with a bounded number of lookups at a time.
_RECEIPT_CHECK_INTERVAL_MS: Final = 1_000
_MAX_CONCURRENT_RECEIPT_CHECKS: Final = 8

_receipt_checked_at: dict[tuple[str, str], int] = {}
_process_store: MemoryStore | None = None


def process_store() -> MemoryStore:
    """Return the in-process store shared by every charge without a shared one."""
    global _process_store
    if _process_store is None:
        _process_store = MemoryStore()
    return _process_store


@dataclass(frozen=True, slots=True, kw_only=True)
class SponsorBudget:
    """Caps the fees a local fee payer has in flight across every charge using it.

    A sponsored charge reserves its declared fee (gas limit times max fee per
    gas) before broadcast and waits, until its challenge or transaction
    expires, while the sponsor is at capacity. A broadcast whose outcome is
    unknown stays reserved until a receipt is observed or it expires.
    """

    max_in_flight_reservations: int = 100
    """Maximum number of sponsored transactions awaiting a terminal receipt."""
    max_in_flight_total_fee: int = DEFAULT_POLICY.max_total_fee * 10
    """Maximum aggregate declared fee, in attodollars, of those transactions."""
    store: CompareAndSetStore | None = None
    """Store shared by every process using the sponsor (default: the charge store)."""

    def __post_init__(self) -> None:
        reservations = self.max_in_flight_reservations
        if isinstance(reservations, bool) or not isinstance(reservations, int) or reservations < 1:
            raise ValueError("max_in_flight_reservations must be a positive integer")
        if self.max_in_flight_total_fee <= 0:
            raise ValueError("max_in_flight_total_fee must be greater than zero")


@dataclass(frozen=True, slots=True)
class Reservation:
    """A reservation's location; ``owner`` fences stale workers."""

    key: str
    id: str
    owner: str


IsSettled = Callable[[str], Awaitable[bool]]
_R = TypeVar("_R")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _key(chain_id: int, sponsor: str) -> str:
    # Exposure belongs to the sponsor, so the key is never tenant-specific.
    return f"mpp:charge:sponsor-budget:{chain_id}:{sponsor.lower()}"


def _decode(raw: Any) -> dict[str, Any] | None:
    """Return the stored reservations, empty when absent, or ``None`` when incompatible."""
    if raw is None:
        return {}
    try:
        state = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(state, dict) or state.get("version") != 1:
        return None
    reservations = state.get("reservations")
    return reservations if isinstance(reservations, dict) else None


async def _update(
    store: CompareAndSetStore,
    key: str,
    change: Callable[[dict[str, Any] | None], tuple[_R, dict[str, Any] | None]],
) -> _R:
    """Apply ``change`` atomically; it returns a result and the new reservations, if any."""
    while True:
        raw = await store.get(key)
        result, reservations = change(_decode(raw.decode() if isinstance(raw, bytes) else raw))
        if reservations is None:
            return result
        value = (
            json.dumps({"reservations": reservations, "version": 1}, sort_keys=True)
            if reservations
            else None
        )
        if await store.compare_and_set(key, raw, value):
            return result
        # Stores that return bytes may compare either the bytes or the text they
        # were given; both stand for the same document.
        if isinstance(raw, bytes) and await store.compare_and_set(key, raw.decode(), value):
            return result


async def _mutate_owned(
    store: CompareAndSetStore,
    reservation: Reservation,
    mutate: Callable[[dict[str, Any]], dict[str, Any] | None],
    unless: Callable[[dict[str, Any]], bool] | None = None,
) -> bool:
    def change(current: dict[str, Any] | None) -> tuple[bool, dict[str, Any] | None]:
        entry = (current or {}).get(reservation.id)
        if not isinstance(entry, dict) or entry.get("owner") != reservation.owner:
            return False, None
        if unless is not None and unless(entry):
            return False, None
        assert current is not None
        reservations = dict(current)
        updated = mutate(entry)
        if updated is None:
            del reservations[reservation.id]
        else:
            reservations[reservation.id] = updated
        return True, reservations

    return await _update(store, reservation.key, change)


async def transition(
    store: CompareAndSetStore,
    reservation: Reservation,
    phase: Literal["broadcasting", "pending"],
) -> bool:
    """Advance a reservation; return ``False`` when the caller no longer owns it."""
    return await _mutate_owned(store, reservation, lambda entry: {**entry, "phase": phase})


async def release(store: CompareAndSetStore, reservation: Reservation) -> bool:
    """Release a reservation only while the caller still owns it."""
    return await _mutate_owned(store, reservation, lambda _: None)


def _is_stale(entry: dict[str, Any], now: int) -> bool:
    return entry["expiresAt"] <= now or (
        entry["phase"] == "prepared" and entry["leaseUntil"] <= now
    )


async def _reconcile(store: CompareAndSetStore, key: str, is_settled: IsSettled) -> None:
    """Release expired reservations, stale prepared leases and settled broadcasts."""
    raw = await store.get(key)
    current = _decode(raw.decode() if isinstance(raw, bytes) else raw)
    if not current:
        return
    now = _now_ms()
    for checked, at in list(_receipt_checked_at.items()):
        if at + _RECEIPT_CHECK_INTERVAL_MS <= now:
            del _receipt_checked_at[checked]
    lookups = asyncio.Semaphore(_MAX_CONCURRENT_RECEIPT_CHECKS)

    async def reconcile_one(id: str, entry: dict[str, Any]) -> None:
        reservation = Reservation(key, id, entry["owner"])
        if _is_stale(entry, now):
            # The snapshot may be old: release only while the entry is still
            # stale, never one its owner has since moved on to broadcasting.
            await _mutate_owned(
                store, reservation, lambda _: None, unless=lambda e: not _is_stale(e, now)
            )
            return
        # A broadcasting owner has not published its outcome yet; releasing it
        # here would race its own transition to pending.
        if entry["phase"] != "pending":
            return
        checked = (key, id)
        if checked in _receipt_checked_at:
            return
        _receipt_checked_at[checked] = now
        try:
            async with lookups:
                settled = await is_settled(entry["transactionHash"])
        except Exception:
            return
        if settled:
            await _mutate_owned(
                store, reservation, lambda _: None, unless=lambda e: e["phase"] != "pending"
            )

    await asyncio.gather(*(reconcile_one(id, entry) for id, entry in current.items()))


async def reserve(
    store: CompareAndSetStore,
    budget: SponsorBudget,
    *,
    chain_id: int,
    sponsor: str,
    transaction_hash: str,
    fee: int,
    expires_at: int,
    wait_until: int,
    is_settled: IsSettled,
) -> Reservation:
    """Reserve ``fee`` against the sponsor's budget, waiting (without writing) for room.

    Raises:
        VerificationError: When the fee can never fit, no room frees up before
            ``wait_until``, the store holds incompatible state, or the
            transaction already has a reservation.
    """
    if fee > budget.max_in_flight_total_fee:
        raise VerificationError("Sponsored transaction fee exceeds the aggregate sponsor budget")
    key = _key(chain_id, sponsor)
    reservation = Reservation(key, transaction_hash.lower(), str(uuid.uuid4()))
    poll_interval = _INITIAL_POLL_INTERVAL_MS
    while True:
        now = _now_ms()
        if now >= wait_until:
            raise VerificationError(
                "Sponsored transaction expired while waiting for sponsor budget"
            )
        await _reconcile(store, key, is_settled)

        def change(
            current: dict[str, Any] | None, now: int = now
        ) -> tuple[str, dict[str, Any] | None]:
            if current is None:
                return "invalid", None
            if reservation.id in current:
                return "duplicate", None
            total = sum(int(entry["fee"]) for entry in current.values())
            if (
                len(current) >= budget.max_in_flight_reservations
                or total + fee > budget.max_in_flight_total_fee
            ):
                return "wait", None
            return "reserved", {
                **current,
                reservation.id: {
                    "expiresAt": expires_at,
                    "fee": str(fee),
                    "leaseUntil": min(expires_at, now + _PREPARED_LEASE_MS),
                    "owner": reservation.owner,
                    "phase": "prepared",
                    "transactionHash": transaction_hash,
                },
            }

        match await _update(store, key, change):
            case "reserved":
                return reservation
            case "invalid":
                raise VerificationError("Sponsor budget store contains incompatible state")
            case "duplicate":
                raise VerificationError("Sponsored transaction already has a budget reservation")
        await asyncio.sleep(min(poll_interval, wait_until - now) / 1000)
        poll_interval = min(poll_interval * 2, _MAX_POLL_INTERVAL_MS)
