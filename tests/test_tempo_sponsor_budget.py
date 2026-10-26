"""Tests for the aggregate in-flight sponsor budget of Tempo charges."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from mpp.errors import VerificationError
from mpp.methods.tempo import SponsorBudget
from mpp.methods.tempo import sponsor_budget as budget_module
from mpp.store import CompareAndSetStore, MemoryStore

SPONSOR = "0x00000000000000000000000000000000000000Aa"
CHAIN_ID = 42431
KEY = f"mpp:charge:sponsor-budget:{CHAIN_ID}:{SPONSOR.lower()}"


async def never_settled(_tx_hash: str) -> bool:
    return False


async def reserve(
    store: CompareAndSetStore,
    budget: SponsorBudget,
    tx_hash: str,
    *,
    fee: int = 1,
    expires_in_ms: int = 60_000,
    wait_ms: int = 60_000,
    is_settled: budget_module.IsSettled = never_settled,
) -> budget_module.Reservation:
    now = int(time.time() * 1000)
    return await budget_module.reserve(
        store,
        budget,
        chain_id=CHAIN_ID,
        sponsor=SPONSOR,
        transaction_hash=tx_hash,
        fee=fee,
        expires_at=now + expires_in_ms,
        wait_until=now + wait_ms,
        is_settled=is_settled,
    )


async def reservations(store: MemoryStore) -> dict:
    raw = await store.get(KEY)
    return {} if raw is None else json.loads(raw)["reservations"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_in_flight_reservations": 0},
        {"max_in_flight_reservations": True},
        {"max_in_flight_total_fee": 0},
    ],
)
def test_rejects_invalid_config(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        SponsorBudget(**kwargs)


def test_defaults_to_ten_times_the_policy_fee_cap() -> None:
    budget = SponsorBudget()
    assert budget.max_in_flight_reservations == 100
    assert budget.max_in_flight_total_fee == 500_000_000_000_000_000


@pytest.mark.asyncio
async def test_memory_store_compare_and_set() -> None:
    store = MemoryStore()
    assert isinstance(store, CompareAndSetStore)
    assert await store.compare_and_set("k", None, "a")
    assert not await store.compare_and_set("k", None, "b")
    assert not await store.compare_and_set("k", "b", "c")
    assert await store.compare_and_set("k", "a", "c")
    assert await store.compare_and_set("k", "c", None)
    assert await store.get("k") is None


@pytest.mark.asyncio
async def test_sqlite_store_compare_and_set() -> None:
    pytest.importorskip("aiosqlite")
    from mpp.stores.sqlite import SQLiteStore

    async with await SQLiteStore.create(":memory:") as store:
        assert isinstance(store, CompareAndSetStore)
        assert await store.compare_and_set("k", None, "a")
        assert not await store.compare_and_set("k", None, "b")
        assert not await store.compare_and_set("k", "b", "c")
        assert await store.compare_and_set("k", "a", "c")
        assert await store.compare_and_set("k", "c", None)
        assert await store.get("k") is None


@pytest.mark.asyncio
async def test_fee_above_the_budget_is_refused() -> None:
    with pytest.raises(VerificationError, match="exceeds the aggregate sponsor budget"):
        await reserve(MemoryStore(), SponsorBudget(max_in_flight_total_fee=10), "0x01", fee=11)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "budget",
    [SponsorBudget(max_in_flight_reservations=1), SponsorBudget(max_in_flight_total_fee=15)],
)
async def test_waits_for_capacity_until_deadline(budget: SponsorBudget) -> None:
    store = MemoryStore()
    await reserve(store, budget, "0x01", fee=10)
    with pytest.raises(VerificationError, match="expired while waiting for sponsor budget"):
        await reserve(store, budget, "0x02", fee=10, wait_ms=50)
    assert list(await reservations(store)) == ["0x01"]


@pytest.mark.asyncio
async def test_released_capacity_admits_a_waiter() -> None:
    store = MemoryStore()
    budget = SponsorBudget(max_in_flight_reservations=1)
    first = await reserve(store, budget, "0x01")
    waiter = asyncio.create_task(reserve(store, budget, "0x02"))
    await asyncio.sleep(0.05)
    assert not waiter.done()
    assert await budget_module.release(store, first)
    second = await asyncio.wait_for(waiter, 1)
    assert list(await reservations(store)) == [second.id]


@pytest.mark.asyncio
async def test_pending_broadcast_is_released_once_settled() -> None:
    store = MemoryStore()
    budget = SponsorBudget(max_in_flight_reservations=1)
    first = await reserve(store, budget, "0x01")
    assert await budget_module.transition(store, first, "broadcasting")
    settled = {"0x01"}

    async def is_settled(tx_hash: str) -> bool:
        return tx_hash in settled

    # A broadcasting owner has not published its outcome, so it is not reconciled.
    with pytest.raises(VerificationError, match="expired while waiting"):
        await reserve(store, budget, "0x02", wait_ms=50, is_settled=is_settled)
    assert await budget_module.transition(store, first, "pending")
    await reserve(store, budget, "0x02", is_settled=is_settled)
    assert list(await reservations(store)) == ["0x02"]


@pytest.mark.asyncio
async def test_expired_and_stale_prepared_reservations_are_released() -> None:
    store = MemoryStore()
    budget = SponsorBudget(max_in_flight_reservations=1)
    await reserve(store, budget, "0x01", expires_in_ms=0)
    await reserve(store, budget, "0x02")
    raw = await store.get(KEY)
    assert raw is not None
    state = json.loads(raw)
    state["reservations"]["0x02"]["leaseUntil"] = 0
    await store.put(KEY, json.dumps(state))
    await reserve(store, budget, "0x03")
    assert list(await reservations(store)) == ["0x03"]


@pytest.mark.asyncio
async def test_duplicate_and_foreign_owner_are_refused() -> None:
    store = MemoryStore()
    budget = SponsorBudget()
    reservation = await reserve(store, budget, "0x01")
    with pytest.raises(VerificationError, match="already has a budget reservation"):
        await reserve(store, budget, "0x01")
    stale = budget_module.Reservation(reservation.key, reservation.id, "someone-else")
    assert not await budget_module.transition(store, stale, "pending")
    assert not await budget_module.release(store, stale)
    assert await budget_module.release(store, reservation)
    assert await store.get(KEY) is None


@pytest.mark.asyncio
async def test_incompatible_state_is_refused() -> None:
    store = MemoryStore()
    await store.put(KEY, json.dumps({"version": 2}))
    with pytest.raises(VerificationError, match="incompatible state"):
        await reserve(store, SponsorBudget(), "0x01")
