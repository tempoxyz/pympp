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
