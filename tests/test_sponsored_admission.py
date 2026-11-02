"""Atomic admission serializes payer spending before transaction simulation."""

import asyncio
import time

import pytest

from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationError
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


async def payer(store, tx="0x01", *, reconciling=False, is_settled=None):
    return await admission.claim_payer(
        store,
        chain_id=1,
        payer="0xAA",
        currency="0xBB",
        transaction_hash=tx,
        expires_at=time.time() + 60,
        reconciling=reconciling,
        is_settled=is_settled,
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
    with pytest.raises(VerificationError, match="not submitted"):
        await payer(store, "0x02")
    await admission.release(store, first)
    assert (await payer(store, "0x02")).created


@pytest.mark.asyncio
async def test_stale_release_cannot_delete_replacement(monkeypatch):
    store = MemoryStore()
    first = await payer(store)
    monkeypatch.setattr(admission.time, "time", lambda: 99999999999)

    async def settled(*args):
        return True

    second = await payer(store, "0x02", is_settled=settled)
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
    assert not retry.created
    assert (await challenge(store)).value == retry.value
    await admission.release(store, retry)
    assert await store.get(first.key) is None


@pytest.mark.asyncio
async def test_adopted_challenge_survives_its_creators_cleanup():
    store = MemoryStore()
    creator = await challenge(store)
    adopter = await challenge(store)
    assert creator.created and not adopter.created
    await admission.release(store, creator)
    assert await store.get(creator.key) == adopter.value
    with pytest.raises(CredentialReplayedError):
        await challenge(store, "0x02")


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
async def test_payer_claim_survives_wall_clock_expiry_until_chain_confirmation():
    store = MemoryStore()
    claim = await payer(store)
    assert claim.key not in store._expiry_deadlines


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


@pytest.mark.asyncio
async def test_payer_lock_covers_swap_source_tokens():
    store = MemoryStore()
    await payer(store)
    with pytest.raises(VerificationError, match="not submitted"):
        await admission.claim_payer(
            store,
            chain_id=1,
            payer="0xAA",
            currency="0xCC",
            transaction_hash="0x02",
            expires_at=time.time() + 60,
        )


@pytest.mark.asyncio
async def test_wall_clock_expiry_does_not_admit_another_transaction_on_a_lagging_chain(monkeypatch):
    store = MemoryStore()
    first = await payer(store)
    monkeypatch.setattr(admission.time, "time", lambda: 99999999999)
    checked = []

    async def unresolved(tx_hash, expiry):
        checked.append(tx_hash)
        return False

    with pytest.raises(VerificationError, match="not submitted"):
        await payer(store, "0x02", is_settled=unresolved)
    assert checked == ["0x01"]
    assert await store.get(first.key) == first.value


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", [False, True])
async def test_atomic_store_probe_cleans_up_and_rejects_broken_cas(broken):
    from unittest.mock import AsyncMock

    store = MemoryStore()
    if broken:
        store.compare_and_set = AsyncMock(return_value=False)
        with pytest.raises(RuntimeError, match="working compare_and_set"):
            await admission.ensure_atomic_store(store)
    else:
        await admission.ensure_atomic_store(store)
    assert not store._data


@pytest.mark.asyncio
async def test_settled_payer_is_released_before_waiting():
    from unittest.mock import AsyncMock, patch

    store = MemoryStore()
    await payer(store)
    settled = AsyncMock(return_value=True)
    with patch.object(admission.asyncio, "sleep", AsyncMock()) as sleep:
        claim = await admission.claim_payer(
            store,
            chain_id=1,
            payer="0xAA",
            currency="0xBB",
            transaction_hash="0x02",
            expires_at=time.time() + 60,
            wait_until=time.time() + 5,
            is_settled=settled,
        )
    assert claim.created
    sleep.assert_not_awaited()
    settled.assert_awaited_once()
