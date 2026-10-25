"""Tests for Tempo charge store wiring."""

from __future__ import annotations

import pytest

from mpp import Challenge, Credential
from mpp.errors import CredentialReplayedError
from mpp.methods.tempo import server as tempo_server
from mpp.server import Mpp
from mpp.store import MemoryStore
from tests import challenge, http_request


class TestMppStoreWiring:
    @pytest.mark.asyncio
    async def test_store_wired_into_charge_intent(self) -> None:
        """tempo_server.charge(store=...) should use the store for replay protection."""
        store = MemoryStore()
        tx_hash = "0x" + "ab" * 32
        await store.put(f"mpp:charge:{tx_hash}", tx_hash)

        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                store=store,
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        issued = challenge(await srv.charge(amount="0.50")(http_request()))
        credential = Credential(
            challenge=issued.to_echo(), payload={"type": "hash", "hash": tx_hash}
        )

        with pytest.raises(CredentialReplayedError):
            await srv.validate_credential(credential)

    @pytest.mark.asyncio
    async def test_charge_with_store_returns_challenge(self) -> None:
        """End-to-end: Mpp with store still returns challenges correctly."""
        store = MemoryStore()
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                store=store,
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(amount="0.50")(http_request())
        assert isinstance(challenge(result), Challenge)


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
