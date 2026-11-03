"""Atomic admission serializes payer spending before transaction simulation."""

import asyncio
import time

import pytest

from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationError
from mpp.methods.tempo import _sponsored_admission as admission
from mpp.store import MemoryStore


async def challenge(store, tx="0x01", payer="0xAA", *, expiring=True):
    return await admission.claim_challenge(
        store,
        realm="merchant.example",
        chain_id=1,
        challenge_id="challenge",
        transaction_hash=tx,
        payer=payer,
        currency="0xBB",
        amount="1",
        expires_at=time.time() + 60 if expiring else None,
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
    claims = [await challenge(store) for _ in range(3)]
    assert claims[0].created and not claims[1].created
    for index, claim in enumerate(claims):
        await admission.release(store, claim)
        assert (await store.get(claim.key) is not None) is (index < 2)


@pytest.mark.asyncio
async def test_adopted_challenge_survives_its_creators_cleanup():
    store = MemoryStore()
    creator = await challenge(store)
    adopter = await challenge(store)
    assert creator.created and not adopter.created
    await admission.release(store, creator)
    import json

    current = await store.get(creator.key)
    assert current is not None
    assert json.loads(current)["attempts"] == [adopter.attempt]
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


@pytest.mark.asyncio
@pytest.mark.parametrize("retaining", [0, 1])
@pytest.mark.parametrize("order", [(0, 1), (1, 0)])
async def test_submitted_attempt_retains_binding_after_every_attempt_finishes(retaining, order):
    store = MemoryStore()
    claims = [await challenge(store), await challenge(store)]
    for index in order:
        await admission.release(store, claims[index], retain=index == retaining)
    with pytest.raises(CredentialReplayedError):
        await challenge(store, "0x02")
    reconciliation = await challenge(store)
    await admission.release(store, reconciliation, reset_retained=True)
    assert (await challenge(store, "0x02")).created


@pytest.mark.asyncio
async def test_repeated_cleanup_cannot_release_a_replacement_attempt():
    store = MemoryStore()
    old = await challenge(store)
    await admission.release(store, old)
    replacement = await challenge(store)
    await admission.release(store, old)
    assert await store.get(old.key) == replacement.value


@pytest.mark.asyncio
async def test_concurrent_attempt_cleanup_preserves_expiry():
    class ContendedStore(MemoryStore):
        async def compare_and_set(self, key, expected, value):
            await asyncio.sleep(0)
            return await super().compare_and_set(key, expected, value)

    store = ContendedStore()
    first = await challenge(store)
    expiry = store._expiry_deadlines[first.key]
    claims = [first, *await asyncio.gather(*(challenge(store) for _ in range(10)))]
    assert store._expiry_deadlines[first.key] == expiry
    await asyncio.gather(*(admission.release(store, claim) for claim in claims))
    assert await store.get(first.key) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("adopted", [False, True])
async def test_legacy_binding_retained_when_old_attempt_outcomes_are_unknown(adopted):
    import json

    store = MemoryStore()
    initial = await challenge(store)
    legacy = json.loads(initial.value)
    legacy.pop("attempts")
    legacy.pop("retained")
    if adopted:
        legacy["adopted"] = True
    await store.put(initial.key, json.dumps(legacy))
    retry = await challenge(store)
    await admission.release(store, retry)
    with pytest.raises(CredentialReplayedError):
        await challenge(store, "0x02")


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [{"attempts": 1}, {"attempts": [1]}, {"retained": "yes"}])
async def test_malformed_ownership_fails_closed(invalid):
    import json

    store = MemoryStore()
    initial = await challenge(store)
    await store.put(initial.key, json.dumps({**json.loads(initial.value), **invalid}))
    with pytest.raises(InternalPaymentError):
        await challenge(store)


@pytest.mark.asyncio
@pytest.mark.parametrize("order", [(0, 1), (1, 0)])
async def test_nonexpiring_binding_is_released_after_both_attempts_fail(order):
    store = MemoryStore()
    claims = [await challenge(store, expiring=False), await challenge(store, expiring=False)]
    await admission.release(store, claims[order[0]])
    assert await store.get(claims[0].key) is not None
    await admission.release(store, claims[order[1]])
    assert await store.get(claims[0].key) is None
    assert (await challenge(store, "0x02", expiring=False)).created


@pytest.mark.asyncio
async def test_confirmed_exclusion_releases_crashed_attempt_without_deleting_replacement():
    store = MemoryStore()
    crashed = await challenge(store)
    retry = await challenge(store)
    await admission.release(store, retry, reset_retained=True)
    replacement = await challenge(store, "0x02")
    await admission.release(store, crashed)
    assert await store.get(replacement.key) == replacement.value


@pytest.mark.asyncio
async def test_failed_cleanup_cas_keeps_ownership_and_has_a_retry_bound():
    from unittest.mock import AsyncMock

    store = MemoryStore()
    claim = await challenge(store)
    store.compare_and_set = AsyncMock(return_value=False)
    with pytest.raises(InternalPaymentError):
        await admission.release(store, claim)
    assert store.compare_and_set.await_count == 100
    assert await store.get(claim.key) == claim.value
