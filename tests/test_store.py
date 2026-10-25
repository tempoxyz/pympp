"""Tests for the in-memory replay protection store."""

from __future__ import annotations

import pytest

from mpp.store import MemoryStore


class TestMemoryStore:
    @pytest.mark.asyncio
    async def test_put_get_delete_roundtrip(self) -> None:
        store = MemoryStore()

        await store.put("receipt:1", {"status": "ok"})
        assert await store.get("receipt:1") == {"status": "ok"}

        await store.delete("receipt:1")
        assert await store.get("receipt:1") is None

    @pytest.mark.asyncio
    async def test_put_if_absent_rejects_duplicates(self) -> None:
        store = MemoryStore()

        assert await store.put_if_absent("receipt:1", "first") is True
        assert await store.put_if_absent("receipt:1", "second") is False
        assert await store.get("receipt:1") == "first"

    @pytest.mark.parametrize("operation", ["put", "put_if_absent"])
    async def test_capacity_rejects_new_keys_without_eviction(self, operation: str) -> None:
        store = MemoryStore(max_entries=1)
        assert await store.put_if_absent("paid", "receipt")
        with pytest.raises(RuntimeError, match="configure a persistent store"):
            await getattr(store, operation)("new", "value")
        assert await store.get("paid") == "receipt"
        assert await store.get("new") is None
        assert not await store.put_if_absent("paid", "replay")
        await store.put("paid", "updated")
        assert await store.get("paid") == "updated"
        await store.delete("paid")
        assert await store.put_if_absent("new", "value")

    @pytest.mark.parametrize("max_entries", [0, -1])
    def test_invalid_capacity(self, max_entries: int) -> None:
        with pytest.raises(ValueError, match="max_entries must be positive"):
            MemoryStore(max_entries=max_entries)

    async def test_concurrent_reservations_respect_capacity(self) -> None:
        import asyncio

        store = MemoryStore(max_entries=1)
        results = await asyncio.gather(
            *(store.put_if_absent(str(i), i) for i in range(8)), return_exceptions=True
        )
        assert results.count(True) == 1
        assert sum(isinstance(result, RuntimeError) for result in results) == 7
