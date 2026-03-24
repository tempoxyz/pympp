"""Integration tests for RedisStore against a real Redis instance.

Run with:
    docker compose up -d redis
    REDIS_URL=redis://localhost:6379 uv run pytest -m redis -v
"""

from __future__ import annotations

import os
import uuid

import pytest

REDIS_URL = os.environ.get("REDIS_URL")

pytestmark = [
    pytest.mark.redis,
    pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
]


@pytest.fixture
async def redis_client():
    from redis.asyncio import from_url

    assert REDIS_URL is not None
    client = from_url(REDIS_URL)
    yield client
    await client.aclose()


@pytest.fixture
def store_prefix():
    """Unique prefix per test to avoid key collisions across parallel runs."""
    return f"test:{uuid.uuid4().hex[:8]}:"


@pytest.fixture
async def store(redis_client, store_prefix):
    from mpp.stores.redis import RedisStore

    return RedisStore(redis_client, key_prefix=store_prefix, ttl_seconds=10)


class TestRedisStoreIntegration:
    @pytest.mark.asyncio
    async def test_put_and_get(self, store) -> None:
        await store.put("key1", "value1")
        result = await store.get("key1")
        assert result == b"value1"

    @pytest.mark.asyncio
    async def test_get_returns_none_when_missing(self, store) -> None:
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, store) -> None:
        await store.put("key1", "value1")
        await store.delete("key1")
        result = await store.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_put_overwrites(self, store) -> None:
        await store.put("key1", "old")
        await store.put("key1", "new")
        result = await store.get("key1")
        assert result == b"new"

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_true_when_absent(self, store) -> None:
        result = await store.put_if_absent("new-key", "val")
        assert result is True
        assert await store.get("new-key") == b"val"

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_false_when_exists(self, store) -> None:
        await store.put("existing", "original")
        result = await store.put_if_absent("existing", "new")
        assert result is False
        assert await store.get("existing") == b"original"

    @pytest.mark.asyncio
    async def test_ttl_is_set(self, redis_client, store_prefix) -> None:
        """Verify that keys have a TTL set in Redis."""
        from mpp.stores.redis import RedisStore

        store = RedisStore(redis_client, key_prefix=store_prefix, ttl_seconds=60)
        await store.put("ttl-key", "val")

        ttl = await redis_client.ttl(f"{store_prefix}ttl-key")
        assert 0 < ttl <= 60

    @pytest.mark.asyncio
    async def test_put_if_absent_is_atomic(self, store) -> None:
        """Two concurrent put_if_absent calls — exactly one wins."""
        import asyncio

        key = "race-key"
        results = await asyncio.gather(
            store.put_if_absent(key, "a"),
            store.put_if_absent(key, "b"),
        )
        assert sorted(results) == [False, True]

    @pytest.mark.asyncio
    async def test_multiple_keys(self, store) -> None:
        await store.put("a", "1")
        await store.put("b", "2")
        await store.put("c", "3")
        assert await store.get("a") == b"1"
        assert await store.get("b") == b"2"
        assert await store.get("c") == b"3"

    @pytest.mark.asyncio
    async def test_key_isolation(self, redis_client) -> None:
        """Two stores with different prefixes don't see each other's keys."""
        from mpp.stores.redis import RedisStore

        store_a = RedisStore(redis_client, key_prefix="ns-a:", ttl_seconds=10)
        store_b = RedisStore(redis_client, key_prefix="ns-b:", ttl_seconds=10)

        await store_a.put("shared-name", "from-a")
        await store_b.put("shared-name", "from-b")

        assert await store_a.get("shared-name") == b"from-a"
        assert await store_b.get("shared-name") == b"from-b"

        await store_a.delete("shared-name")
        await store_b.delete("shared-name")
