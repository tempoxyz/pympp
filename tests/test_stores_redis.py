"""Tests for RedisStore."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mpp.stores.redis import RedisStore


@pytest.fixture
def mock_redis():
    return AsyncMock()


@pytest.fixture
def store(mock_redis):
    return RedisStore(mock_redis)


class TestRedisStore:
    @pytest.mark.asyncio
    async def test_get_returns_value(self, store, mock_redis) -> None:
        mock_redis.get.return_value = b"some-value"
        result = await store.get("foo")
        assert result == b"some-value"
        mock_redis.get.assert_awaited_once_with("mpp:foo")

    @pytest.mark.asyncio
    async def test_get_returns_none_when_missing(self, store, mock_redis) -> None:
        mock_redis.get.return_value = None
        result = await store.get("missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_put(self, store, mock_redis) -> None:
        await store.put("key1", "val1")
        mock_redis.set.assert_awaited_once_with("mpp:key1", "val1")

    @pytest.mark.asyncio
    async def test_delete(self, store, mock_redis) -> None:
        await store.delete("key1")
        mock_redis.delete.assert_awaited_once_with("mpp:key1")

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_true_when_key_absent(self, store, mock_redis) -> None:
        mock_redis.set.return_value = True  # Redis SET NX returns True on success
        result = await store.put_if_absent("new-key", "val")
        assert result is True
        mock_redis.set.assert_awaited_once_with("mpp:new-key", "val", nx=True)

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_false_when_key_exists(self, store, mock_redis) -> None:
        mock_redis.set.return_value = None  # Redis SET NX returns None on conflict
        result = await store.put_if_absent("existing", "val")
        assert result is False

    @pytest.mark.asyncio
    async def test_key_prefix(self, mock_redis) -> None:
        store = RedisStore(mock_redis, key_prefix="custom:")
        mock_redis.get.return_value = b"x"
        await store.get("abc")
        mock_redis.get.assert_awaited_once_with("custom:abc")

    @pytest.mark.asyncio
    async def test_custom_ttl(self, mock_redis) -> None:
        store = RedisStore(mock_redis, ttl_seconds=60)
        await store.put("k", "v")
        mock_redis.set.assert_awaited_once_with("mpp:k", "v", ex=60)

    @pytest.mark.asyncio
    async def test_custom_ttl_applies_to_put_if_absent(self, mock_redis) -> None:
        store = RedisStore(mock_redis, ttl_seconds=60)
        mock_redis.set.return_value = True
        await store.put_if_absent("k", "v")
        mock_redis.set.assert_awaited_once_with("mpp:k", "v", nx=True, ex=60)
