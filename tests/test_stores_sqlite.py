"""Tests for SQLiteStore."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from mpp.stores.sqlite import SQLiteStore


@pytest.fixture
async def store():
    s = await SQLiteStore.create(":memory:", ttl_seconds=300)
    yield s
    await s.close()


class TestSQLiteStore:
    @pytest.mark.asyncio
    async def test_put_and_get(self, store) -> None:
        await store.put("key1", "value1")
        result = await store.get("key1")
        assert result == "value1"

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
        assert result == "new"

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_true_when_key_absent(self, store) -> None:
        result = await store.put_if_absent("new-key", "val")
        assert result is True
        assert await store.get("new-key") == "val"

    @pytest.mark.asyncio
    async def test_put_if_absent_returns_false_when_key_exists(self, store) -> None:
        await store.put("existing", "original")
        result = await store.put_if_absent("existing", "new-val")
        assert result is False
        assert await store.get("existing") == "original"

    @pytest.mark.asyncio
    async def test_expired_key_returns_none(self, store) -> None:
        """Keys past their TTL should not be returned by get()."""
        far_past = time.time() - 1000
        await store._db.execute(
            "INSERT INTO kv (key, value, expires_at) VALUES (?, ?, ?)",
            ("expired", "old", far_past),
        )
        await store._db.commit()
        assert await store.get("expired") is None

    @pytest.mark.asyncio
    async def test_put_if_absent_reclaims_expired_key(self, store) -> None:
        """An expired key should be cleaned up, allowing a new insert."""
        far_past = time.time() - 1000
        await store._db.execute(
            "INSERT INTO kv (key, value, expires_at) VALUES (?, ?, ?)",
            ("reclaim", "old", far_past),
        )
        await store._db.commit()

        result = await store.put_if_absent("reclaim", "new")
        assert result is True
        assert await store.get("reclaim") == "new"

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        async with await SQLiteStore.create(":memory:") as store:
            await store.put("ctx", "val")
            assert await store.get("ctx") == "val"

    @pytest.mark.asyncio
    async def test_custom_ttl(self) -> None:
        store = await SQLiteStore.create(":memory:", ttl_seconds=1)
        await store.put("short", "val")
        assert await store.get("short") == "val"

        with patch("mpp.stores.sqlite.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert await store.get("short") is None

        await store.close()

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key_is_noop(self, store) -> None:
        await store.delete("nope")  # should not raise

    @pytest.mark.asyncio
    async def test_multiple_keys(self, store) -> None:
        await store.put("a", "1")
        await store.put("b", "2")
        await store.put("c", "3")
        assert await store.get("a") == "1"
        assert await store.get("b") == "2"
        assert await store.get("c") == "3"
