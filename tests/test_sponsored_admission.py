"""Atomic admission serializes payer spending before transaction simulation."""

import asyncio
import time

import pytest

from mpp.errors import CredentialReplayedError, InternalPaymentError
from mpp.methods.tempo import _sponsored_admission as admission
from mpp.store import MemoryStore


async def challenge(store, tx="0x01", payer="0xAA"):
    return await admission.claim_challenge(
        store,
        realm="merchant.example",
        chain_id=1,
        challenge_id="challenge",
        transaction_hash=tx,
        payer=payer,
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


@pytest.mark.asyncio
async def test_literal_bytes_store_releases_both_claims():
    class LiteralBytesStore(MemoryStore):
        async def put_if_absent(self, key, value):
            return await super().put_if_absent(key, value.encode())

    store = LiteralBytesStore()
    for claim in [await challenge(store), await payer(store)]:
        assert isinstance(await store.get(claim.key), bytes)
        await admission.release(store, claim)
        assert await store.get(claim.key) is None


@pytest.mark.asyncio
async def test_payer_claim_has_backend_expiry():
    store = MemoryStore()
    claim = await payer(store)
    assert time.time() < store._expiry_deadlines[claim.key] <= time.time() + 60


@pytest.mark.asyncio
async def test_shared_challenge_allows_distinct_payers():
    store = MemoryStore()
    first = await challenge(store)
    second = await challenge(store, "0x02", payer="0xCC")
    assert first.key != second.key


@pytest.mark.asyncio
async def test_released_competing_challenge_is_retried():
    class RacingStore(MemoryStore):
        raced = False

        async def put_if_absent(self, key, value):
            if not self.raced:
                self.raced = True
                return False
            return await super().put_if_absent(key, value)

    assert (await challenge(RacingStore())).created


@pytest.mark.asyncio
async def test_busy_payer_waits_for_release():
    store = MemoryStore()
    first = await payer(store)

    async def finish():
        await asyncio.sleep(0.01)
        await admission.release(store, first)

    waiter = asyncio.create_task(finish())
    second = await admission.claim_payer(
        store,
        chain_id=1,
        payer="0xAA",
        currency="0xBB",
        transaction_hash="0x02",
        expires_at=time.time() + 60,
        wait_until=time.time() + 1,
    )
    await waiter
    assert second.created
