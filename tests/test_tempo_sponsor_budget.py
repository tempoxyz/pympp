"""Tests for the aggregate in-flight sponsor budget of Tempo charges."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from mpp.errors import InternalPaymentError, VerificationError
from mpp.methods.tempo import SponsorBudget
from mpp.methods.tempo import sponsor_budget as budget_module
from mpp.store import CompareAndSetStore, MemoryStore

SPONSOR = "0x00000000000000000000000000000000000000Aa"
CHAIN_ID = 42431
KEY = f"mpp:charge:sponsor-budget:{CHAIN_ID}:{SPONSOR.lower()}"


@pytest.fixture(autouse=True)
def _clear_receipt_checks() -> None:
    clear_receipt_checks()


def clear_receipt_checks() -> None:
    getattr(budget_module, "_receipt_checked_at", {}).clear()


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
    # An earlier attempt may have broadcast it: never a retryable 402.
    with pytest.raises(InternalPaymentError) as raised:
        await reserve(store, budget, "0x01")
    assert "already has a budget reservation" in str(raised.value.__cause__)
    stale = budget_module.Reservation(reservation.key, reservation.id, "someone-else")
    assert not await budget_module.transition(store, stale, "pending")
    assert not await budget_module.release(store, stale)
    assert await budget_module.release(store, reservation)
    assert await store.get(KEY) is None


@pytest.mark.asyncio
async def test_stale_entry_of_the_same_transaction_does_not_block_a_retry() -> None:
    store = MemoryStore()
    budget = SponsorBudget()
    # An earlier attempt whose release failed left its prepared entry behind.
    earlier = await reserve(store, budget, "0x01")
    raw = await store.get(KEY)
    assert raw is not None
    state = json.loads(raw)
    state["reservations"]["0x01"]["leaseUntil"] = 0
    await store.put(KEY, json.dumps(state))
    # The budget has room, so no reconciliation runs: the retry replaces it.
    retry = await reserve(store, budget, "0x01")
    assert retry.owner != earlier.owner
    assert (await reservations(store))["0x01"]["owner"] == retry.owner
    assert not await budget_module.release(store, earlier)
    assert await budget_module.release(store, retry)


@pytest.mark.asyncio
async def test_incompatible_state_is_refused() -> None:
    store = MemoryStore()
    await store.put(KEY, json.dumps({"version": 2}))
    with pytest.raises(InternalPaymentError) as raised:
        await reserve(store, SponsorBudget(), "0x01")
    assert "incompatible state" in str(raised.value.__cause__)


class BytesStore:
    """A conforming store that returns bytes and compares the expected value literally."""

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        await asyncio.sleep(0)
        return self.data.get(key)

    async def put(self, key: str, value: str | bytes) -> None:
        self.data[key] = value.encode() if isinstance(value, str) else value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)

    async def put_if_absent(self, key: str, value: str | bytes) -> bool:
        if key in self.data:
            return False
        await self.put(key, value)
        return True

    async def compare_and_set(self, key: str, expected: object, value: str | None) -> bool:
        if self.data.get(key) != expected:
            return False
        if value is None:
            self.data.pop(key, None)
        else:
            self.data[key] = value.encode()
        return True


@pytest.mark.asyncio
async def test_byte_returning_store_updates_existing_state() -> None:
    store = BytesStore()
    budget = SponsorBudget()
    first = await asyncio.wait_for(reserve(store, budget, "0x01"), 1)
    second = await asyncio.wait_for(reserve(store, budget, "0x02"), 1)
    assert await asyncio.wait_for(budget_module.release(store, first), 1)
    assert await asyncio.wait_for(budget_module.release(store, second), 1)
    assert store.data == {}


@pytest.mark.asyncio
async def test_sqlite_noop_compare_and_set_commits_pruning() -> None:
    pytest.importorskip("aiosqlite")
    from mpp.stores.sqlite import SQLiteStore

    async with await SQLiteStore.create(":memory:") as store:
        await store._db.execute(
            "INSERT INTO kv (key, value, expires_at) VALUES ('old', 'x', ?)", (time.time() - 1,)
        )
        await store._db.commit()
        assert await store.compare_and_set("k", None, None)
        assert not store._db.in_transaction


@pytest.mark.asyncio
async def test_reconcile_keeps_a_reservation_that_moved_on_since_its_snapshot() -> None:
    store = MemoryStore()
    budget = SponsorBudget()
    reservation = await reserve(store, budget, "0x01")
    raw = await store.get(KEY)
    assert raw is not None
    stale = json.loads(raw)
    stale["reservations"]["0x01"]["leaseUntil"] = 0
    # The owner moves to broadcasting after the reconciler read its snapshot.
    assert await budget_module.transition(store, reservation, "broadcasting")
    real_get = store.get

    async def snapshot_get(key: str) -> object:
        store.get = real_get  # type: ignore[method-assign]
        return json.dumps(stale)

    store.get = snapshot_get  # type: ignore[method-assign]
    await budget_module._reconcile(store, KEY, never_settled)
    assert (await reservations(store))["0x01"]["phase"] == "broadcasting"


@pytest.mark.asyncio
async def test_waiters_share_bounded_receipt_lookups() -> None:
    store = MemoryStore()
    pending = 20
    budget = SponsorBudget(max_in_flight_reservations=pending)
    for i in range(pending):
        reservation = await reserve(store, budget, f"0x{i:02x}")
        assert await budget_module.transition(store, reservation, "pending")
    clear_receipt_checks()
    calls = 0
    active = 0
    peak = 0

    async def slow_unsettled(_tx_hash: str) -> bool:
        nonlocal active, calls, peak
        calls += 1
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return False

    waiters = [
        reserve(store, budget, f"0xff{i}", wait_ms=300, is_settled=slow_unsettled) for i in range(5)
    ]
    results = await asyncio.gather(*waiters, return_exceptions=True)
    assert all(isinstance(result, VerificationError) for result in results)
    # Each pending transaction is looked up once per interval, whatever the waiters.
    assert calls == pending
    assert peak <= 8


async def never_answers(_tx_hash: str) -> bool:
    await asyncio.Event().wait()
    return False


@pytest.mark.asyncio
async def test_reservation_with_room_skips_receipt_lookups() -> None:
    store = MemoryStore()
    budget = SponsorBudget()
    for i in range(20):
        reservation = await reserve(store, budget, f"0x{i:02x}")
        assert await budget_module.transition(store, reservation, "pending")
    clear_receipt_checks()
    await asyncio.wait_for(reserve(store, budget, "0xff", is_settled=never_answers), 1)
    assert "0xff" in await reservations(store)


@pytest.mark.asyncio
async def test_receipt_lookups_never_outlast_the_wait_deadline() -> None:
    store = MemoryStore()
    budget = SponsorBudget(max_in_flight_reservations=1)
    reservation = await reserve(store, budget, "0x01")
    assert await budget_module.transition(store, reservation, "pending")
    with pytest.raises(VerificationError, match="expired while waiting"):
        await asyncio.wait_for(
            reserve(store, budget, "0x02", wait_ms=100, is_settled=never_answers), 2
        )


@pytest.mark.asyncio
async def test_redis_transient_errors_are_not_reported_as_unsupported() -> None:
    pytest.importorskip("redis")
    from unittest.mock import AsyncMock

    from redis.exceptions import OutOfMemoryError, ReadOnlyError, ResponseError

    from mpp.stores.redis import RedisStore

    client = AsyncMock()
    for error in (
        ReadOnlyError("You can't write against a read only replica."),
        OutOfMemoryError("command not allowed when used memory > 'maxmemory'."),
        ResponseError("LOADING Redis is loading the dataset in memory"),
    ):
        client.eval.side_effect = error
        with pytest.raises(type(error)):
            await RedisStore(client).compare_and_set("k", None, "v")
    client.eval.side_effect = ResponseError("unknown command 'eval', with args beginning with: ")
    with pytest.raises(NotImplementedError):
        await RedisStore(client).compare_and_set("k", None, "v")


@pytest.mark.asyncio
async def test_redis_without_eval_reports_compare_and_set_unsupported() -> None:
    pytest.importorskip("redis")
    from unittest.mock import AsyncMock

    from redis.exceptions import NoPermissionError

    from mpp.stores.redis import RedisStore

    client = AsyncMock()
    client.eval.side_effect = NoPermissionError("no permissions to run the 'eval' command")
    with pytest.raises(NotImplementedError):
        await RedisStore(client).compare_and_set("k", None, "v")


@pytest.mark.asyncio
async def test_prepared_lease_starts_after_slow_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    budget = SponsorBudget(max_in_flight_reservations=1)
    pending = await reserve(store, budget, "0x01")
    assert await budget_module.transition(store, pending, "pending")
    clock = [int(time.time() * 1000)]
    monkeypatch.setattr(budget_module, "_now_ms", lambda: clock[0])

    async def slow_lookup(_tx_hash: str) -> bool:
        clock[0] += 31_000
        return True

    await reserve(store, budget, "0x02", expires_in_ms=600_000, is_settled=slow_lookup)
    # The lease runs from when the reservation was written, so it is still live.
    assert (await reservations(store))["0x02"]["leaseUntil"] > clock[0]
