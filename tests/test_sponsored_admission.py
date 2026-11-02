"""Atomic admission serializes payer spending before transaction simulation."""

import asyncio
import time

import pytest

from mpp.errors import CredentialReplayedError, InternalPaymentError
from mpp.methods.tempo import _sponsored_admission as admission
from mpp.store import MemoryStore


async def challenge(store, tx="0x01"):
    return await admission.claim_challenge(
        store,
        realm="merchant.example",
        chain_id=1,
        challenge_id="challenge",
        transaction_hash=tx,
        payer="0xAA",
        currency="0xBB",
        amount="1",
        expires_at=time.time() + 60,
    )


async def payer(store, tx="0x01", *, reconciling=False):
    return await admission.claim_payer(
        store,
        chain_id=1,
        payer="0xAA",
        currency="0xBB",
        transaction_hash=tx,
        expires_at=time.time() + 60,
        reconciling=reconciling,
    )


@pytest.mark.asyncio
async def test_distinct_envelopes_have_one_challenge_winner():
    store = MemoryStore()
    results = await asyncio.gather(
        *(challenge(store, f"0x{i:02x}") for i in range(20)), return_exceptions=True
    )
    assert sum(isinstance(result, admission.Claim) for result in results) == 1
    assert sum(isinstance(result, CredentialReplayedError) for result in results) == 19
    original = next(result for result in results if isinstance(result, admission.Claim))
    await admission.release(store, original)
    assert (await challenge(store, "0xff")).created


@pytest.mark.asyncio
async def test_payer_is_serialized_and_retry_keeps_expiry():
    store = MemoryStore()
    first = await payer(store)
    with pytest.raises(InternalPaymentError):
        await payer(store)
    retry = await payer(store, reconciling=True)
    assert not retry.created
    assert retry.value == first.value
    with pytest.raises(InternalPaymentError):
        await payer(store, "0x02")
    await admission.release(store, first)
    assert (await payer(store, "0x02")).created


@pytest.mark.asyncio
async def test_stale_release_cannot_delete_replacement(monkeypatch):
    store = MemoryStore()
    first = await payer(store)
    monkeypatch.setattr(admission.time, "time", lambda: 99999999999)
    second = await payer(store, "0x02")
    await admission.release(store, first)
    assert await store.get(second.key) == second.value


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["not-json", "{}", '{"hash":"other","expiresAt":"bad"}'])
async def test_malformed_payer_claim_fails_closed(invalid):
    store = MemoryStore()
    first = await payer(store)
    await store.put(first.key, invalid)
    with pytest.raises(InternalPaymentError):
        await payer(store, "0x02")
    assert await store.get(first.key) == invalid


@pytest.mark.asyncio
async def test_redis_bytes_preserve_challenge_retry():
    class BytesStore(MemoryStore):
        async def get(self, key):
            value = await super().get(key)
            return value.encode() if isinstance(value, str) else value

    store = BytesStore()
    first = await challenge(store)
    retry = await challenge(store)
    assert retry.value == first.value
    assert not retry.created
    await admission.release(store, retry)
    assert await store.get(first.key) is None
