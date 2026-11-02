"""Sponsored top-ups cannot reset their allowance by succeeding sequentially."""

import asyncio
from dataclasses import replace

import pytest

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session.server.sponsorship_limit import (
    SessionSponsorshipLimit,
    reserve_top_up,
)
from mpp.store import MemoryStore


async def reserve(store, limit, payer="payer", fee=10):
    await reserve_top_up(
        limit=limit, store=store, chain_id=4217, sponsor="SPONSOR", payer=payer, maximum_fee=fee
    )


async def test_payer_allowance_survives_success_and_policy_reconstruction():
    store = MemoryStore()
    for _ in range(5):
        await reserve(store, SessionSponsorshipLimit())
    with pytest.raises(VerificationFailedError, match="allowance"):
        await reserve(store, SessionSponsorshipLimit(), payer="PAYER")
    await reserve(store, SessionSponsorshipLimit(), payer="another")


@pytest.mark.parametrize("bound", ["fees", "count"])
async def test_aggregate_allowance_covers_distinct_payers(bound):
    store = MemoryStore()
    limit = SessionSponsorshipLimit(
        max_total_fee=20 if bound == "fees" else 1000,
        max_transactions=2 if bound == "count" else 100,
    )
    for payer in ["first", "second"]:
        await reserve(store, limit, payer=payer)
    with pytest.raises(VerificationFailedError, match="allowance"):
        await reserve(store, limit, payer="third")


async def test_atomic_reservations_across_instances():
    class ContendedStore(MemoryStore):
        async def get(self, key):
            value = await super().get(key)
            await asyncio.sleep(0)
            return value

    store = ContendedStore()
    results = await asyncio.gather(
        *(reserve(store, SessionSponsorshipLimit(per_payer=3)) for _ in range(12)),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 3
    assert all(result is None or isinstance(result, VerificationFailedError) for result in results)


async def test_rolling_window_does_not_reset_at_calendar_boundary(monkeypatch):
    now = 86_399.0
    monkeypatch.setattr("mpp.methods.tempo.session.server.sponsorship_limit.time.time", lambda: now)
    store = MemoryStore()
    limit = SessionSponsorshipLimit(per_payer=1, window_seconds=60)
    await reserve(store, limit)
    now += 2
    with pytest.raises(VerificationFailedError, match="allowance"):
        await reserve(store, limit)
    now += 59
    await reserve(store, limit)


@pytest.mark.parametrize(
    "name", ["per_payer", "max_total_fee", "max_transactions", "window_seconds"]
)
@pytest.mark.parametrize("value", [True, 0, -1, 1.5])
def test_invalid_limits(name, value):
    with pytest.raises(ValueError):
        replace(SessionSponsorshipLimit(), **{name: value})


async def test_malformed_usage_fails_closed():
    store = MemoryStore()
    await store.put("mpp:session:sponsorship:4217:sponsor", '{"entries": [{"payer": "payer"}]}')
    with pytest.raises(VerificationFailedError, match="stored sponsorship"):
        await reserve(store, SessionSponsorshipLimit())
