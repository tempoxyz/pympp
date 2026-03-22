"""Tests for RedisStore."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mpp.stores.redis import RedisStore


@pytest.fixture
def redis_client() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=1)
    return client


@pytest.fixture
def store(redis_client: MagicMock) -> RedisStore:
    return RedisStore(redis_client, ttl_seconds=60, key_prefix="test:")


async def test_put(store: RedisStore, redis_client: MagicMock) -> None:
    await store.put("challenge-1", "value-1")
    redis_client.set.assert_awaited_once_with("test:challenge-1", "value-1", ex=60)


async def test_get_returns_value(store: RedisStore, redis_client: MagicMock) -> None:
    redis_client.get.return_value = b"stored-value"
    result = await store.get("challenge-1")
    redis_client.get.assert_awaited_once_with("test:challenge-1")
    assert result == b"stored-value"


async def test_get_returns_none_when_missing(store: RedisStore, redis_client: MagicMock) -> None:
    redis_client.get.return_value = None
    result = await store.get("missing")
    assert result is None


async def test_delete(store: RedisStore, redis_client: MagicMock) -> None:
    await store.delete("challenge-1")
    redis_client.delete.assert_awaited_once_with("test:challenge-1")


async def test_put_if_absent_returns_true_when_key_absent(
    store: RedisStore, redis_client: MagicMock
) -> None:
    redis_client.set.return_value = True  # Redis returns OK when SET NX succeeds
    result = await store.put_if_absent("challenge-1", "value-1")
    redis_client.set.assert_awaited_once_with("test:challenge-1", "value-1", nx=True, ex=60)
    assert result is True


async def test_put_if_absent_returns_false_when_key_exists(
    store: RedisStore, redis_client: MagicMock
) -> None:
    redis_client.set.return_value = None  # Redis returns None when SET NX fails
    result = await store.put_if_absent("challenge-1", "value-1")
    assert result is False


async def test_key_prefix(redis_client: MagicMock) -> None:
    store = RedisStore(redis_client, key_prefix="mpp:")
    await store.get("foo")
    redis_client.get.assert_awaited_once_with("mpp:foo")
