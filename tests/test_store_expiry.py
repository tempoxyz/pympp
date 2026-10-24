"""Absolute recovery deadlines must not shorten or refresh on duplicate writes."""

from unittest.mock import AsyncMock, patch

import pytest

from mpp.store import ExpiringStore, MemoryStore
from mpp.stores.redis import RedisStore
from mpp.stores.sqlite import SQLiteStore


@pytest.fixture(params=["memory", "sqlite", "sqlite_ttl"])
async def expiring_store(request):
    if request.param == "memory":
        yield MemoryStore(max_entries=2)
    else:
        store = await SQLiteStore.create(
            ":memory:", ttl_seconds=1 if request.param == "sqlite_ttl" else None
        )
        try:
            yield store
        finally:
            await store.close()


async def test_absolute_expiry_without_retry_or_refresh(expiring_store):
    store = expiring_store
    assert isinstance(store, ExpiringStore)
    with patch("time.time", return_value=1000):
        assert await store.put_if_absent_until("abandoned", "original", 1100)
    with patch("time.time", return_value=1099):
        assert await store.get("abandoned") == "original"
        assert not await store.put_if_absent_until("abandoned", "replacement", 1200)
    with patch("time.time", return_value=1100):
        # A new write reclaims abandoned records without retrying their keys.
        assert await store.put_if_absent("new", "value")
        assert await store.get("abandoned") is None
        assert await store.get("new") == "value"
    if isinstance(store, SQLiteStore):
        cursor = await store._db.execute("SELECT count(*) FROM kv")
        assert (await cursor.fetchone())[0] == 1


@pytest.mark.parametrize("deadline", [1000, 999, float("nan"), float("inf")])
async def test_invalid_expiry_leaves_no_record(expiring_store, deadline):
    with patch("time.time", return_value=1000):
        with pytest.raises(ValueError, match="finite future"):
            await expiring_store.put_if_absent_until("invalid", "value", deadline)
        assert await expiring_store.get("invalid") is None


async def test_expiry_reclaims_capacity_without_evicting_replay_keys():
    store = MemoryStore(max_entries=2)
    with patch("time.time", return_value=1000):
        await store.put("paid", "receipt")
        await store.put_if_absent_until("abandoned", "raw", 1100)
        with pytest.raises(RuntimeError, match="capacity"):
            await store.put("new", "value")
    with patch("time.time", return_value=1100):
        await store.put("new", "value")
        assert await store.get("paid") == "receipt"
        assert not await store.put_if_absent("paid", "replay")


@pytest.mark.parametrize("result, inserted", [(True, True), (None, False)])
async def test_redis_uses_atomic_absolute_deadline_over_default_ttl(result, inserted):
    client = AsyncMock()
    client.set.return_value = result
    store = RedisStore(client, ttl_seconds=1)
    assert isinstance(store, ExpiringStore)
    with patch("time.time", return_value=1000):
        assert await store.put_if_absent_until("recovery", "raw", 1100.0001) is inserted
    client.set.assert_awaited_once_with("mpp:recovery", "raw", nx=True, pxat=1100001)
