"""Tests for Mpp store wiring."""

from __future__ import annotations

import pytest

from mpp import Challenge
from mpp.methods.tempo import tempo
from mpp.methods.tempo.intents import ChargeIntent
from mpp.server import Mpp
from mpp.store import MemoryStore


class TestMppStoreWiring:
    def test_store_wired_into_charge_intent(self) -> None:
        """Mpp.create(store=...) should inject the store into ChargeIntent."""
        store = MemoryStore()
        intent = ChargeIntent()
        assert intent._store is None

        Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": intent},
            ),
            realm="test.com",
            secret_key="test-secret",
            store=store,
        )

        assert intent._store is store

    def test_store_not_wired_when_none(self) -> None:
        """Mpp.create() without store should leave intent._store as None."""
        intent = ChargeIntent()
        Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": intent},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        assert intent._store is None

    def test_store_does_not_overwrite_existing_intent_store(self) -> None:
        """If an intent already has a store, Mpp should not overwrite it."""
        existing_store = MemoryStore()
        new_store = MemoryStore()
        intent = ChargeIntent(store=existing_store)

        Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": intent},
            ),
            realm="test.com",
            secret_key="test-secret",
            store=new_store,
        )

        assert intent._store is existing_store

    def test_constructor_also_wires_store(self) -> None:
        """Direct Mpp() constructor should also wire the store."""
        store = MemoryStore()
        intent = ChargeIntent()
        Mpp(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": intent},
            ),
            realm="test.com",
            secret_key="test-secret",
            store=store,
        )
        assert intent._store is store

    @pytest.mark.asyncio
    async def test_charge_with_store_returns_challenge(self) -> None:
        """End-to-end: Mpp with store still returns challenges correctly."""
        store = MemoryStore()
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
            store=store,
        )
        result = await srv.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)


class TestStoreProtocolConformance:
    """Verify MemoryStore conforms to the Store protocol."""

    @pytest.mark.asyncio
    async def test_memory_store_get_put_delete(self) -> None:
        store = MemoryStore()
        assert await store.get("k") is None
        await store.put("k", "v")
        assert await store.get("k") == "v"
        await store.delete("k")
        assert await store.get("k") is None

    @pytest.mark.asyncio
    async def test_memory_store_put_if_absent(self) -> None:
        store = MemoryStore()
        assert await store.put_if_absent("k", "v1") is True
        assert await store.put_if_absent("k", "v2") is False
        assert await store.get("k") == "v1"
