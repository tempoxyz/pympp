"""Session channel store: port of mppx server/ChannelStore.test.ts, plus backend concurrency."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import replace
from typing import Any

import pytest

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session.protocol import ChannelDescriptor, SignedVoucher
from mpp.methods.tempo.session.server import schedule, store
from mpp.methods.tempo.session.server.store import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    DeltaTooSmallError,
    IdempotencyKeyConflictError,
    PendingSettlement,
    RetainedVoucher,
    StoreChannelStore,
)
from mpp.store import CompareAndSetStore, MemoryStore
from mpp.stores.sqlite import SQLiteStore

REDIS_URL = os.environ.get("REDIS_URL")

CHANNEL_ID = "0x" + "00" * 31 + "01"
CHANNEL_ID_2 = "0x" + "00" * 31 + "02"
LOWER_ALIAS = "0x" + "ab" * 31 + "cd"
MIXED_ALIAS = "0x" + "".join(
    c.upper() if i % 2 == 0 and c.isalpha() else c for i, c in enumerate(LOWER_ALIAS[2:])
)
SIGNATURE = "0x" + "11" * 65

DESCRIPTOR = ChannelDescriptor(
    payer="0x0000000000000000000000000000000000000001",
    payee="0x0000000000000000000000000000000000000002",
    operator="0x0000000000000000000000000000000000000005",
    token="0x0000000000000000000000000000000000000003",
    salt="0x" + "11" * 32,
    authorized_signer="0x0000000000000000000000000000000000000004",
    expiring_nonce_hash="0x" + "22" * 32,
)


class OnChain:
    def __init__(self, deposit: int, settled: int, close_requested_at: int = 0) -> None:
        self.deposit = deposit
        self.settled = settled
        self.close_requested_at = close_requested_at


def make_channel(**overrides: Any) -> ChannelState:
    fields: dict[str, Any] = {
        "channel_id": CHANNEL_ID,
        "payer": DESCRIPTOR.payer,
        "payee": DESCRIPTOR.payee,
        "token": DESCRIPTOR.token,
        "authorized_signer": DESCRIPTOR.authorized_signer,
        "chain_id": 42431,
        "escrow_contract": "0x4d50500000000000000000000000000000000000",
        "deposit": 10_000_000,
        "settled_on_chain": 0,
        "highest_voucher_amount": 10_000_000,
        "highest_voucher": None,
        "spent": 0,
        "units": 0,
        "close_requested_at": 0,
        "finalized": False,
        "created_at": "2025-01-01T00:00:00.000Z",
        "backend": "precompile",
        "operator": DESCRIPTOR.operator,
        "salt": DESCRIPTOR.salt,
        "expiring_nonce_hash": DESCRIPTOR.expiring_nonce_hash,
        "descriptor": DESCRIPTOR,
    }
    fields.update(overrides)
    return ChannelState(**fields)


def voucher_at(amount: int, channel_id: str = CHANNEL_ID) -> SignedVoucher:
    return SignedVoucher(
        channel_id=channel_id, cumulative_amount=amount, signature="0x" + format(amount, "0130x")
    )


async def seed(cs: store.ChannelStore, **overrides: Any) -> ChannelState | None:
    return await cs.update_channel(CHANNEL_ID, lambda _: make_channel(**overrides))


class PlainStore:
    """A store without compare_and_set: the adapter falls back to an in-process lock."""

    def __init__(self, delay: float = 0) -> None:
        self._data: dict[str, Any] = {}
        self._delay = delay

    async def get(self, key: str) -> Any | None:
        await asyncio.sleep(self._delay)
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        await asyncio.sleep(self._delay)
        self._data[key] = value

    async def delete(self, key: str) -> None:
        await asyncio.sleep(self._delay)
        self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        if key in self._data:
            return False
        self._data[key] = value
        return True


class CustomChannelStore:
    """A ChannelStore with only get_channel/update_channel, like a custom adapter."""

    def __init__(self) -> None:
        self._inner = StoreChannelStore(MemoryStore())

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        return await self._inner.get_channel(channel_id)

    async def update_channel(
        self, channel_id: str, fn: Callable[[ChannelState | None], ChannelState | None]
    ) -> ChannelState | None:
        return await self._inner.update_channel(channel_id, fn)


ACCOUNTING_STORES: list[Any] = [
    pytest.param(lambda: store.from_store(MemoryStore()), id="atomic"),
    pytest.param(lambda: store.from_store(PlainStore()), id="lock-fallback"),
    pytest.param(CustomChannelStore, id="custom"),
]


# ---------- state updates ----------


def test_keep_greater() -> None:
    assert store.keep_greater(10, 5) == 10
    assert store.keep_greater(10, 15) == 15
    assert store.keep_greater_timestamp(10, 5) == 10
    assert store.keep_greater_timestamp(10, 15) == 15


def test_merge_active_on_chain_state_never_decreases() -> None:
    merged = store.merge_active_on_chain_state(
        make_channel(close_requested_at=7, deposit=100, settled_on_chain=20), OnChain(90, 25, 5)
    )
    assert merged == store.ActiveOnChainState(
        close_requested_at=7, deposit=100, settled_on_chain=25
    )


def test_resolve_highest_voucher() -> None:
    higher = store.resolve_highest_voucher(
        channel_id=CHANNEL_ID,
        current=store.HighestVoucher(10, None),
        cumulative_amount=20,
        signature=SIGNATURE,
    )
    assert higher.highest_voucher_amount == 20
    assert higher.highest_voucher == SignedVoucher(
        channel_id=CHANNEL_ID, cumulative_amount=20, signature=SIGNATURE
    )
    current = voucher_at(30)
    kept = store.resolve_highest_voucher(
        channel_id=CHANNEL_ID,
        current=store.HighestVoucher(30, current),
        cumulative_amount=20,
        signature=SIGNATURE,
    )
    assert kept == store.HighestVoucher(30, current)


def test_open_channel_state_preserves_higher_voucher() -> None:
    current = make_channel(
        deposit=100, highest_voucher_amount=80, highest_voucher=voucher_at(80), spent=25
    )
    escrow = "0x4D50500000000000000000000000000000000000"
    nxt = store.open_channel_state(
        authorized_signer=DESCRIPTOR.authorized_signer,
        chain_id=4217,
        channel_id=CHANNEL_ID,
        current=current,
        descriptor=DESCRIPTOR,
        escrow=escrow,
        expiring_nonce_hash=DESCRIPTOR.expiring_nonce_hash,
        cumulative_amount=60,
        signature=SIGNATURE,
        state=OnChain(120, 15),
    )
    assert nxt.backend == "precompile"
    assert nxt.highest_voucher_amount == 80
    assert nxt.highest_voucher == voucher_at(80)
    assert nxt.deposit == 120
    assert nxt.spent == 25
    assert nxt.escrow_contract == escrow
    assert nxt.chain_id == 4217


def test_open_channel_state_new_channel() -> None:
    nxt = store.open_channel_state(
        authorized_signer=DESCRIPTOR.authorized_signer,
        chain_id=4217,
        channel_id=CHANNEL_ID,
        current=None,
        descriptor=DESCRIPTOR,
        escrow=store.normalize_channel_id(CHANNEL_ID)[:42],
        expiring_nonce_hash=DESCRIPTOR.expiring_nonce_hash,
        cumulative_amount=60,
        signature=SIGNATURE,
        state=OnChain(120, 15),
    )
    assert nxt.highest_voucher_amount == 60
    assert nxt.spent == 15
    assert nxt.units == 0
    assert not nxt.finalized
    assert nxt.created_at.endswith("Z")
    assert nxt.retained_vouchers is None
    assert nxt.payer == DESCRIPTOR.payer and nxt.salt == DESCRIPTOR.salt


def test_top_up_only_increases() -> None:
    current = make_channel(deposit=100, settled_on_chain=30, close_requested_at=4)
    nxt = store.top_up_channel_state(current=current, state=OnChain(90, 20, 3))
    assert nxt is not None
    assert (nxt.deposit, nxt.settled_on_chain, nxt.close_requested_at) == (100, 30, 4)
    assert store.top_up_channel_state(current=None, state=OnChain(1, 0)) is None


def test_accept_voucher_state_update() -> None:
    nxt = store.accept_voucher_state_update(
        current=make_channel(deposit=100, highest_voucher_amount=50),
        voucher=voucher_at(70),
        channel_state=OnChain(120, 25),
        verified_at=1234,
    )
    assert nxt.highest_voucher_amount == 70
    assert nxt.deposit == 120
    assert nxt.settled_on_chain == 25
    assert nxt.on_chain_verified_at == 1234
    with pytest.raises(ChannelNotFoundError):
        store.accept_voucher_state_update(
            current=None, voucher=voucher_at(70), channel_state=OnChain(1, 0)
        )
    with pytest.raises(ChannelClosedError):
        store.accept_voucher_state_update(
            current=make_channel(finalized=True),
            voucher=voucher_at(70),
            channel_state=OnChain(1, 0),
        )
    with pytest.raises(ChannelClosedError):
        store.accept_voucher_state_update(
            current=make_channel(close_requested_at=1),
            voucher=voucher_at(70),
            channel_state=OnChain(1, 0),
        )


def test_accept_voucher_is_monotonic() -> None:
    current = make_channel(highest_voucher_amount=100, highest_voucher=voucher_at(100))
    nxt = store.accept_voucher_state_update(
        current=current, voucher=voucher_at(90), channel_state=OnChain(10_000_000, 0)
    )
    assert nxt.highest_voucher_amount == 100
    assert nxt.highest_voucher == voucher_at(100)


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, 0),
        ({"now": 1_055}, 1_000),
        ({"close_requested_at": 1_010}, 1_000),
        ({"deposit": 0}, 1_000),
    ],
)
def test_reconcile_expired_pending_close(overrides: dict[str, int], expected: int) -> None:
    options = {"close_requested_at": 0, "deposit": 100, "now": 1_056, **overrides}
    reconciled = store.reconcile_expired_pending_close(
        current=make_channel(close_requested_at=1_000),
        now=options["now"],
        state=OnChain(options["deposit"], 10, options["close_requested_at"]),
    )
    assert reconciled is not None
    assert reconciled.close_requested_at == expected


def test_reconcile_expired_pending_close_leaves_finalized_and_open() -> None:
    state = OnChain(100, 10)
    finalized = make_channel(close_requested_at=1_000, finalized=True)
    open_channel = make_channel()
    assert (
        store.reconcile_expired_pending_close(current=finalized, now=2_000, state=state)
        is finalized
    )
    assert (
        store.reconcile_expired_pending_close(current=open_channel, now=2_000, state=state)
        is open_channel
    )
    assert store.reconcile_expired_pending_close(current=None, now=2_000, state=state) is None


def test_mark_pending_close() -> None:
    nxt = store.mark_pending_close(
        close_requested_at=11,
        cumulative_amount=50,
        current=make_channel(spent=20),
        on_chain_deposit=100,
        on_chain_settled=30,
    )
    assert nxt.capture_amount == 30
    assert nxt.state is not None and nxt.state.close_requested_at == 11
    with pytest.raises(VerificationFailedError):
        store.mark_pending_close(
            close_requested_at=11,
            cumulative_amount=25,
            current=make_channel(spent=20),
            on_chain_deposit=100,
            on_chain_settled=30,
        )
    with pytest.raises(AmountExceedsDepositError):
        store.mark_pending_close(
            close_requested_at=11,
            cumulative_amount=50,
            current=make_channel(spent=40),
            on_chain_deposit=30,
            on_chain_settled=0,
        )
    with pytest.raises(ChannelClosedError):
        store.mark_pending_close(
            close_requested_at=11,
            cumulative_amount=50,
            current=make_channel(close_requested_at=3),
            on_chain_deposit=100,
            on_chain_settled=0,
        )
    empty = store.mark_pending_close(
        close_requested_at=11,
        cumulative_amount=50,
        current=None,
        on_chain_deposit=100,
        on_chain_settled=0,
    )
    assert empty == store.PendingCloseUpdate(0, None)


def test_resolve_close_capture_amount() -> None:
    capture = store.resolve_close_capture_amount
    assert capture(cumulative_amount=50, on_chain_deposit=100, on_chain_settled=30, spent=20) == 30
    assert capture(cumulative_amount=50, on_chain_deposit=100, on_chain_settled=10, spent=20) == 20
    with pytest.raises(VerificationFailedError, match="spent"):
        capture(cumulative_amount=19, on_chain_deposit=100, on_chain_settled=10, spent=20)
    with pytest.raises(VerificationFailedError, match="capture amount"):
        capture(cumulative_amount=25, on_chain_deposit=100, on_chain_settled=30, spent=20)
    with pytest.raises(AmountExceedsDepositError):
        capture(cumulative_amount=50, on_chain_deposit=30, on_chain_settled=0, spent=40)


def test_finalize_closed_channel_state() -> None:
    nxt = store.finalize_closed_channel_state(
        capture_amount=60,
        channel_id=CHANNEL_ID,
        cumulative_amount=70,
        current=make_channel(highest_voucher_amount=50, settled_on_chain=20),
        signature=SIGNATURE,
    )
    assert nxt is not None
    assert nxt.finalized
    assert (nxt.close_requested_at, nxt.deposit, nxt.settled_on_chain) == (0, 0, 60)
    assert nxt.highest_voucher_amount == 70
    assert nxt.highest_voucher == SignedVoucher(
        channel_id=CHANNEL_ID, cumulative_amount=70, signature=SIGNATURE
    )


def test_assert_voucher_amounts() -> None:
    channel = make_channel(highest_voucher_amount=50)
    on_chain = OnChain(100, 10)
    check = store.assert_voucher_amounts
    assert check(
        channel=channel, channel_state=on_chain, min_voucher_delta=0, cumulative_amount=50
    ).already_accepted
    assert not check(
        channel=channel, channel_state=on_chain, min_voucher_delta=5, cumulative_amount=60
    ).already_accepted
    with pytest.raises(AmountExceedsDepositError):
        check(channel=channel, channel_state=on_chain, min_voucher_delta=0, cumulative_amount=101)
    with pytest.raises(DeltaTooSmallError):
        check(channel=channel, channel_state=on_chain, min_voucher_delta=20, cumulative_amount=60)
    with pytest.raises(VerificationFailedError, match="strictly greater"):
        check(channel=channel, channel_state=on_chain, min_voucher_delta=0, cumulative_amount=40)
    with pytest.raises(VerificationFailedError, match="settled"):
        check(
            channel=make_channel(highest_voucher_amount=5),
            channel_state=on_chain,
            min_voucher_delta=0,
            cumulative_amount=10,
        )
    with pytest.raises(ChannelNotFoundError):
        check(
            channel=channel, channel_state=OnChain(0, 0), min_voucher_delta=0, cumulative_amount=60
        )
    with pytest.raises(ChannelClosedError):
        check(
            channel=channel,
            channel_state=OnChain(100, 0, 5),
            min_voucher_delta=0,
            cumulative_amount=60,
        )


def test_plan_voucher_acceptance_charges_only_when_covered() -> None:
    accepted = make_channel(highest_voucher_amount=100, spent=60)
    assert store.plan_voucher_acceptance(accepted=accepted) == store.VoucherAcceptance(
        accepted, False
    )
    charged = store.plan_voucher_acceptance(accepted=accepted, charge_amount=40)
    assert charged.charged and charged.channel.spent == 100 and charged.channel.units == 1
    refused = store.plan_voucher_acceptance(accepted=accepted, charge_amount=41)
    assert not refused.charged and refused.channel is accepted
    error = store.insufficient_balance_for_charge(accepted, 41)
    assert str(error) == "Insufficient balance: requested 41, available 40."


def test_session_error_problem_types() -> None:
    assert ChannelNotFoundError().status == 410
    assert ChannelNotFoundError("x").to_problem_details()["type"] == (
        "https://paymentauth.org/problems/session/channel-not-found"
    )
    assert ChannelClosedError().type.endswith("/session/channel-finalized")
    assert str(DeltaTooSmallError("d")) == "Delta too small: d."


# ---------- codec ----------


def test_codec_round_trips_every_field() -> None:
    state = make_channel(
        highest_voucher=voucher_at(10_000_000),
        deposit=999_999_999_999_999_999_999,
        on_chain_verified_at=123,
        stream_reservations={"s": store.StreamReservation(amount=5, units=1, expires_at=9)},
        scheduled_settlement_lease=store.ScheduledSettlementLease(expires_at=7, owner="o"),
        last_settlement_at="2025-01-02T00:00:00.000Z",
        last_settlement_spent=4,
        last_settlement_units=2,
        retained_vouchers=(RetainedVoucher(3, SIGNATURE),),
        pending_settlement=PendingSettlement(amount=3, expires_at=8),
        idempotency_markers={
            "credit:a": store.IdempotencyMarker(amount=1, expires_at=2, outcome="closing", units=1)
        },
        close_supervised_from_block=77,
    )
    encoded = store.encode_channel_state(state)
    assert (
        '"deposit":"999999999999999999999999"'.replace(
            "999999999999999999999999", str(state.deposit)
        )
        in encoded
    )
    assert store.decode_channel_state(encoded) == state
    assert store.decode_channel_state(encoded.encode()) == state
    assert store.decode_channel_state(store.channel_state_to_json(state)) == state
    # Canonical: re-encoding the decoded value gives the same bytes compare_and_set compares.
    assert store.encode_channel_state(store.decode_channel_state(encoded)) == encoded


# ---------- channel store ----------


async def test_get_channel_missing_and_malformed_ids() -> None:
    cs = store.from_store(MemoryStore())
    assert await cs.get_channel(CHANNEL_ID) is None
    with pytest.raises(ValueError, match="Invalid session channel ID"):
        await cs.get_channel("0x1234")
    with pytest.raises(ValueError, match="Invalid session channel ID"):
        await cs.update_channel("not-a-channel-id", lambda _: None)
    with pytest.raises(ValueError, match="Invalid session channel ID"):
        store.normalize_channel_id("0x1234")


async def test_from_store_returns_one_adapter_per_store() -> None:
    backing = MemoryStore()
    assert store.from_store(backing) is store.from_store(backing)
    assert store.from_store(backing).atomic
    assert not store.from_store(PlainStore()).atomic


async def test_update_creates_updates_and_deletes() -> None:
    cs = store.from_store(MemoryStore())
    seen: list[ChannelState | None] = []

    def create(current: ChannelState | None) -> ChannelState:
        seen.append(current)
        return make_channel()

    created = await cs.update_channel(CHANNEL_ID, create)
    assert seen == [None]
    assert created is not None and created.deposit == 10_000_000
    updated = await cs.update_channel(
        CHANNEL_ID, lambda c: replace(c, spent=c.spent + 1_000_000, units=c.units + 1) if c else c
    )
    assert updated is not None and (updated.spent, updated.units) == (1_000_000, 1)
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded == updated
    assert await cs.update_channel(CHANNEL_ID, lambda _: None) is None
    assert await cs.get_channel(CHANNEL_ID) is None


async def test_case_variant_ids_share_a_record() -> None:
    cs = store.from_store(MemoryStore())
    await cs.update_channel(MIXED_ALIAS, lambda _: make_channel(channel_id=MIXED_ALIAS))
    loaded = await cs.get_channel(LOWER_ALIAS)
    assert loaded is not None and loaded.channel_id == LOWER_ALIAS
    await cs.update_channel(LOWER_ALIAS, lambda c: replace(c, spent=1_000_000) if c else c)
    aliased = await cs.get_channel(MIXED_ALIAS)
    assert aliased is not None
    assert aliased.channel_id == LOWER_ALIAS and aliased.spent == 1_000_000


async def test_big_ints_and_descriptor_persist() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, deposit=999_999_999_999_999_999, settled_on_chain=123_456_789, spent=42)
    result = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000)
    assert result.ok
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None
    assert loaded.deposit == 999_999_999_999_999_999
    assert loaded.settled_on_chain == 123_456_789
    assert store.is_precompile_state(loaded)
    assert loaded.descriptor == DESCRIPTOR
    assert (loaded.spent, loaded.units) == (1_000_042, 1)


async def test_wait_for_update() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs)
    waiter = cs.wait_for_update(CHANNEL_ID)
    others = [cs.wait_for_update(CHANNEL_ID) for _ in range(2)]
    other_channel = cs.wait_for_update(CHANNEL_ID_2)
    await asyncio.sleep(0.01)
    assert not waiter.done()
    await cs.update_channel(CHANNEL_ID, lambda c: replace(c, spent=1) if c else c)
    await asyncio.wait_for(asyncio.gather(waiter, *others), 1)
    assert not other_channel.done()
    other_channel.cancel()
    await asyncio.sleep(0)
    assert CHANNEL_ID_2 not in cs._waiters  # pyright: ignore[reportPrivateUsage]

    after_deduct = cs.wait_for_update(CHANNEL_ID)
    assert (await store.deduct_from_channel(cs, CHANNEL_ID, 1)).ok
    await asyncio.wait_for(after_deduct, 1)

    # A refused deduction writes nothing, so it wakes nobody.
    idle = cs.wait_for_update(CHANNEL_ID)
    await cs.update_channel(CHANNEL_ID, lambda c: replace(c, finalized=True) if c else c)
    await idle
    idle = cs.wait_for_update(CHANNEL_ID)
    assert not (await store.deduct_from_channel(cs, CHANNEL_ID, 1)).ok
    await asyncio.sleep(0.01)
    assert not idle.done()
    idle.cancel()


# ---------- deductions ----------


async def test_deductions() -> None:
    cs = store.from_store(MemoryStore())
    with pytest.raises(ChannelNotFoundError, match="channel not found"):
        await store.deduct_from_channel(cs, CHANNEL_ID, 1)
    await seed(cs, highest_voucher_amount=5_000_000)
    for i in range(5):
        result = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000)
        assert result.ok
        assert (result.channel.spent, result.channel.units) == ((i + 1) * 1_000_000, i + 1)
    final = await store.deduct_from_channel(cs, CHANNEL_ID, 1)
    assert not final.ok and final.channel.spent == 5_000_000


async def test_insufficient_balance_leaves_state() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=1_000_000, spent=500_000)
    result = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000)
    assert not result.ok and result.channel.spent == 500_000


async def test_stream_reservations_limit_deductions() -> None:
    cs = store.from_store(MemoryStore())
    future = int(time.time() * 1000) + 60_000
    await seed(
        cs,
        highest_voucher_amount=10,
        stream_reservations={
            "live": store.StreamReservation(amount=6, units=1, expires_at=future),
            "expired": store.StreamReservation(amount=100, units=1, expires_at=1),
        },
    )
    assert not (await store.deduct_from_channel(cs, CHANNEL_ID, 5)).ok
    assert (await store.deduct_from_channel(cs, CHANNEL_ID, 4)).ok


@pytest.mark.parametrize("overrides", [{"finalized": True}, {"close_requested_at": 1}])
@pytest.mark.parametrize("make", ACCOUNTING_STORES)
async def test_rejects_deduction_on_closed_channels(
    make: Callable[[], store.ChannelStore], overrides: dict[str, Any]
) -> None:
    cs = make()
    await seed(cs, **overrides)
    result = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000)
    assert not result.ok
    assert (result.channel.spent, result.channel.units) == (0, 0)


async def test_exact_balance_succeeds() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=1_000_000)
    result = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000)
    assert result.ok and result.channel.spent == 1_000_000


# ---------- idempotent charges ----------


@pytest.mark.parametrize("make", ACCOUNTING_STORES)
async def test_charges_a_key_once(make: Callable[[], store.ChannelStore]) -> None:
    cs = make()
    await seed(cs, highest_voucher_amount=5_000_000)
    first = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="job-1")
    replay = await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="job-1")
    assert first.ok and not first.replayed and first.channel.spent == 1_000_000
    assert replay.ok and replay.replayed and replay.channel.spent == 1_000_000
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None and (loaded.spent, loaded.units) == (1_000_000, 1)


async def test_charge_key_reused_with_another_amount() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=5_000_000)
    await store.deduct_from_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="job-1")
    with pytest.raises(IdempotencyKeyConflictError) as raised:
        await store.deduct_from_channel(cs, CHANNEL_ID, 2_000_000, idempotency_key="job-1")
    assert raised.value.idempotency_key == "job-1"
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None and loaded.spent == 1_000_000


async def test_refused_charge_records_nothing() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=1_000_000, spent=1_000_000)
    refused = await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="job-1")
    await cs.update_channel(
        CHANNEL_ID, lambda c: replace(c, highest_voucher_amount=2_000_000) if c else c
    )
    charged = await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="job-1")
    assert not refused.ok
    assert charged.ok and not charged.replayed and charged.channel.spent == 1_000_001


async def test_forgets_expired_markers() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=5_000_000)
    await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="a", retention=1)
    await asyncio.sleep(0.005)
    await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="b")
    channel = await cs.get_channel(CHANNEL_ID)
    assert channel is not None
    assert list(channel.idempotency_markers or {}) == ["charge:b"]
    again = await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="a")
    assert not again.replayed and again.channel.spent == 3


def test_rejects_invalid_idempotency_options() -> None:
    with pytest.raises(ValueError, match="idempotency_key"):
        store.assert_idempotency_options(idempotency_key="")
    with pytest.raises(ValueError, match="retention"):
        store.assert_idempotency_options(retention=0)


# ---------- credits ----------


@pytest.mark.parametrize("make", ACCOUNTING_STORES)
async def test_credits_once_per_key(make: Callable[[], store.ChannelStore]) -> None:
    cs = make()
    await seed(cs, highest_voucher_amount=5_000_000, spent=3_000_000, units=3)
    first = await store.credit_channel(
        cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1", units=1
    )
    replay = await store.credit_channel(
        cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1", units=1
    )
    assert first.status == "credited" and not first.replayed
    assert first.channel is not None and (first.channel.spent, first.channel.units) == (
        2_000_000,
        2,
    )
    assert replay.status == "credited" and replay.replayed
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None and (loaded.spent, loaded.units) == (2_000_000, 2)


@pytest.mark.parametrize(
    ("reason", "overrides", "amount"),
    [
        ("closing", {"close_requested_at": 1}, 1),
        ("finalized", {"finalized": True}, 1),
        ("exceedsSpent", {}, 3_000_001),
        ("belowSettled", {"settled_on_chain": 2_500_000}, 600_000),
        (
            "belowSettled",
            {
                "pending_settlement": PendingSettlement(
                    amount=2_500_000,
                    expires_at=2**62,  # far future: parametrized at collection
                )
            },
            600_000,
        ),
    ],
)
async def test_declines_credit(reason: str, overrides: dict[str, Any], amount: int) -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=5_000_000, spent=3_000_000, **overrides)
    result = await store.credit_channel(cs, CHANNEL_ID, amount, idempotency_key="refund-1")
    assert (result.status, result.reason, result.replayed) == ("declined", reason, False)
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None and loaded.spent == 3_000_000


async def test_credits_once_pending_settlement_expired() -> None:
    cs = store.from_store(MemoryStore())
    await seed(
        cs,
        highest_voucher_amount=5_000_000,
        spent=3_000_000,
        pending_settlement=PendingSettlement(
            amount=3_000_000, expires_at=int(time.time() * 1000) - 1
        ),
    )
    result = await store.credit_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1")
    assert result.status == "credited"
    assert result.channel is not None and result.channel.spent == 2_000_000


async def test_keeps_first_credit_decision_after_reopen() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=5_000_000, spent=3_000_000, close_requested_at=1)
    await store.credit_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1")
    await cs.update_channel(CHANNEL_ID, lambda c: replace(c, close_requested_at=0) if c else c)
    result = await store.credit_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1")
    assert (result.status, result.reason, result.replayed) == ("declined", "closing", True)
    loaded = await cs.get_channel(CHANNEL_ID)
    assert loaded is not None and loaded.spent == 3_000_000


async def test_credit_key_reused_with_other_terms() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher_amount=5_000_000, spent=3_000_000)
    await store.credit_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1")
    with pytest.raises(IdempotencyKeyConflictError):
        await store.credit_channel(cs, CHANNEL_ID, 2_000_000, idempotency_key="refund-1")
    with pytest.raises(IdempotencyKeyConflictError):
        await store.credit_channel(cs, CHANNEL_ID, 1_000_000, idempotency_key="refund-1", units=1)
    # A charge key and a credit key with the same name are distinct.
    charged = await store.deduct_from_channel(cs, CHANNEL_ID, 1, idempotency_key="refund-1")
    assert charged.ok and not charged.replayed


async def test_credit_reports_unknown_when_the_write_fails() -> None:
    class Failing:
        async def get_channel(self, channel_id: str) -> ChannelState | None:
            return make_channel(spent=3_000_000)

        async def update_channel(
            self, channel_id: str, fn: Callable[[ChannelState | None], ChannelState | None]
        ) -> ChannelState | None:
            raise RuntimeError("store unavailable")

    result = await store.credit_channel(Failing(), CHANNEL_ID, 1, idempotency_key="refund-1")
    assert result.status == "unknown"
    assert isinstance(result.error, RuntimeError) and str(result.error) == "store unavailable"


async def test_credit_rejects_missing_channel_and_invalid_amounts() -> None:
    cs = store.from_store(MemoryStore())
    with pytest.raises(ChannelNotFoundError):
        await store.credit_channel(cs, CHANNEL_ID, 1, idempotency_key="refund-1")
    with pytest.raises(ValueError, match="positive"):
        await store.credit_channel(cs, CHANNEL_ID, 0, idempotency_key="refund-1")
    with pytest.raises(ValueError, match="units"):
        await store.credit_channel(cs, CHANNEL_ID, 1, idempotency_key="refund-1", units=-1)


# ---------- settleable vouchers ----------


def test_retains_superseded_voucher_for_settlement() -> None:
    current = make_channel(highest_voucher=voucher_at(100), highest_voucher_amount=100, spent=70)
    nxt = store.accept_voucher_state_update(
        current=current, voucher=voucher_at(200), channel_state=OnChain(10_000_000, 0)
    )
    assert nxt.retained_vouchers == (RetainedVoucher(100, voucher_at(100).signature),)
    assert store.resolve_settleable_voucher(nxt) is None
    assert store.resolve_settleable_voucher(replace(nxt, spent=150)) == voucher_at(100)
    assert store.resolve_settleable_voucher(replace(nxt, spent=200)) == voucher_at(200)
    assert store.resolve_settleable_voucher(replace(nxt, settled_on_chain=100, spent=150)) is None


def test_keeps_settling_a_long_credited_channel() -> None:
    channel = make_channel(highest_voucher=voucher_at(10), highest_voucher_amount=10, spent=10)
    settlements = 0
    for request in range(1, 1_001):
        # Each request signs 10 above the last voucher, is charged 10 and credits 4 back.
        channel = store.accept_voucher_state_update(
            current=channel,
            voucher=voucher_at(channel.highest_voucher_amount + 10),
            channel_state=OnChain(10_000_000, channel.settled_on_chain),
        )
        channel = replace(channel, spent=channel.spent + 10 - 4)
        if request % 20:
            continue
        settleable = store.resolve_settleable_voucher(channel)
        if settleable is None:
            continue
        assert settleable.cumulative_amount <= channel.spent
        channel = replace(channel, settled_on_chain=settleable.cumulative_amount)
        settlements += 1
    assert len(channel.retained_vouchers or ()) <= store.MAX_RETAINED_VOUCHERS
    assert channel.highest_voucher_amount - channel.spent == 4_000
    assert settlements > 25
    assert channel.spent - channel.settled_on_chain < 250


# ---------- scheduled settlement ----------


def test_resolve_settlement_schedule() -> None:
    assert schedule.resolve_settlement_schedule(None, 6) is None
    resolved = schedule.resolve_settlement_schedule(
        schedule.SettlementSchedule(amount="1.5", units=3, interval_ms=10), 6
    )
    assert resolved == schedule.ResolvedSettlementSchedule(
        amount=1_500_000, units=3, interval_ms=10
    )
    raw = schedule.resolve_settlement_schedule(schedule.SettlementSchedule(amount=7), 6)
    assert raw == schedule.ResolvedSettlementSchedule(amount=7)


def test_settlement_progress_and_due() -> None:
    settleable = make_channel(
        highest_voucher=voucher_at(100), highest_voucher_amount=100, spent=100, units=4
    )
    progress = schedule.resolve_settlement_progress(settleable)
    assert progress is not None
    assert (progress.amount, progress.units) == (100, 4)
    assert progress.elapsed_ms is not None and progress.elapsed_ms > 0
    # Nothing within spend to settle, or not precompile-backed: never scheduled.
    assert schedule.resolve_settlement_progress(replace(settleable, spent=50)) is None
    assert schedule.resolve_settlement_progress(replace(settleable, backend=None)) is None

    due = schedule.is_settlement_due
    resolved = schedule.ResolvedSettlementSchedule
    assert not due(settleable, None)
    assert due(settleable, resolved(units=4))
    assert not due(settleable, resolved(units=5))
    assert due(settleable, resolved(amount=100))
    assert not due(settleable, resolved(amount=101))
    assert due(settleable, resolved(interval_ms=1_000))
    recent = replace(settleable, last_settlement_at="2999-01-01T00:00:00.000Z")
    assert not due(recent, resolved(interval_ms=1_000))
    assert due(replace(settleable, close_requested_at=5), resolved(units=1_000))
    counted = replace(settleable, last_settlement_spent=60, last_settlement_units=3)
    assert not due(counted, resolved(units=2, amount=41))


async def test_scheduled_settlement_lease() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher=voucher_at(100), highest_voucher_amount=100, spent=100, units=2)
    due = schedule.ResolvedSettlementSchedule(units=1)
    assert (
        await schedule.claim_scheduled_settlement(
            channel_id=CHANNEL_ID, schedule=schedule.ResolvedSettlementSchedule(units=5), store=cs
        )
        is None
    )
    owner = await schedule.claim_scheduled_settlement(channel_id=CHANNEL_ID, schedule=due, store=cs)
    assert owner is not None
    assert (
        await schedule.claim_scheduled_settlement(channel_id=CHANNEL_ID, schedule=due, store=cs)
        is None
    )

    before = await cs.get_channel(CHANNEL_ID)
    assert before is not None and before.scheduled_settlement_lease is not None
    await schedule.renew_scheduled_settlement(
        channel_id=CHANNEL_ID, lease_owner="someone-else", store=cs, lease_ms=1
    )
    assert (await cs.get_channel(CHANNEL_ID)) == before
    await schedule.renew_scheduled_settlement(
        channel_id=CHANNEL_ID, lease_owner=owner, store=cs, lease_ms=10 * 60_000
    )
    renewed = await cs.get_channel(CHANNEL_ID)
    assert renewed is not None and renewed.scheduled_settlement_lease is not None
    assert (
        renewed.scheduled_settlement_lease.expires_at > before.scheduled_settlement_lease.expires_at
    )

    await schedule.release_scheduled_settlement(channel_id=CHANNEL_ID, lease_owner=owner, store=cs)
    released = await cs.get_channel(CHANNEL_ID)
    assert released is not None and released.scheduled_settlement_lease is None

    owner = await schedule.claim_scheduled_settlement(channel_id=CHANNEL_ID, schedule=due, store=cs)
    assert owner is not None
    await schedule.mark_settlement_complete(
        channel_id=CHANNEL_ID, lease_owner=owner, store=cs, settled_at="2025-02-02T00:00:00.000Z"
    )
    done = await cs.get_channel(CHANNEL_ID)
    assert done is not None
    assert done.scheduled_settlement_lease is None
    assert done.last_settlement_at == "2025-02-02T00:00:00.000Z"


async def test_expired_lease_can_be_reclaimed() -> None:
    cs = store.from_store(MemoryStore())
    await seed(cs, highest_voucher=voucher_at(100), highest_voucher_amount=100, spent=100, units=2)
    due = schedule.ResolvedSettlementSchedule(units=1)
    first = await schedule.claim_scheduled_settlement(
        channel_id=CHANNEL_ID, schedule=due, store=cs, lease_ms=1
    )
    await asyncio.sleep(0.005)
    second = await schedule.claim_scheduled_settlement(
        channel_id=CHANNEL_ID, schedule=due, store=cs
    )
    assert first is not None and second is not None and first != second


# ---------- concurrency across backends ----------

StoreFactory = Callable[[], Awaitable[Any]]


@pytest.fixture(
    params=[
        "memory",
        "lock-fallback",
        "sqlite",
        pytest.param(
            "redis",
            marks=[
                pytest.mark.redis,
                pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
            ],
        ),
        pytest.param(
            "redis-bytes",
            marks=[
                pytest.mark.redis,
                pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
            ],
        ),
    ]
)
async def backend(request: pytest.FixtureRequest, tmp_path: Any) -> AsyncIterator[StoreFactory]:
    """Each call opens a new connection to one shared backend, like a separate worker."""
    cleanups: list[Callable[[], Awaitable[Any]]] = []
    name: str = request.param
    if name in ("memory", "lock-fallback"):
        shared: Any = MemoryStore() if name == "memory" else PlainStore(delay=0.0005)

        async def make() -> Any:
            return shared

    elif name == "sqlite":
        path = str(tmp_path / "channels.db")

        async def make() -> Any:
            opened = await SQLiteStore.create(path)
            cleanups.append(opened.close)
            return opened

    else:
        from redis.asyncio import Redis

        from mpp.stores.redis import RedisStore

        url = REDIS_URL
        assert url is not None
        prefix = f"session-test:{uuid.uuid4().hex[:8]}:"
        decode = name == "redis"

        async def make() -> Any:
            client = Redis.from_url(url, decode_responses=decode)
            cleanups.append(client.aclose)
            return RedisStore(client, key_prefix=prefix)

        async def flush() -> None:
            client = Redis.from_url(url)
            keys = [key async for key in client.scan_iter(f"{prefix}*")]
            if keys:
                await client.delete(*keys)
            await client.aclose()

        cleanups.append(flush)

    yield make
    for cleanup in cleanups:
        await cleanup()


async def _workers(make: StoreFactory, count: int) -> list[StoreChannelStore]:
    # Separate adapters (and connections) per worker, so nothing serializes in-process
    # except what the backend itself does. A store without compare_and_set only serializes
    # within one adapter, so its workers share it.
    stores = [await make() for _ in range(count)]
    return [
        StoreChannelStore(s) if isinstance(s, CompareAndSetStore) else store.from_store(s)
        for s in stores
    ]


async def test_concurrent_deductions_never_lose_updates(backend: StoreFactory) -> None:
    workers = await _workers(backend, 5)
    await seed(workers[0], highest_voucher_amount=100_000_000)
    n = 40
    results = await asyncio.gather(
        *(store.deduct_from_channel(workers[i % 5], CHANNEL_ID, 1_000_000) for i in range(n))
    )
    assert all(r.ok for r in results)
    channel = await workers[0].get_channel(CHANNEL_ID)
    assert channel is not None
    assert (channel.spent, channel.units) == (n * 1_000_000, n)
    # Every success saw a distinct spend: no two deductions applied to the same state.
    assert sorted(r.channel.spent for r in results) == [(i + 1) * 1_000_000 for i in range(n)]


async def test_concurrent_deductions_never_overspend(backend: StoreFactory) -> None:
    workers = await _workers(backend, 5)
    await seed(workers[0], highest_voucher_amount=7_000_000)
    results = await asyncio.gather(
        *(store.deduct_from_channel(workers[i % 5], CHANNEL_ID, 1_000_000) for i in range(30))
    )
    assert sum(r.ok for r in results) == 7
    channel = await workers[0].get_channel(CHANNEL_ID)
    assert channel is not None and (channel.spent, channel.units) == (7_000_000, 7)


async def test_concurrent_keyed_charges_and_credits(backend: StoreFactory) -> None:
    workers = await _workers(backend, 4)
    await seed(workers[0], highest_voucher_amount=100, spent=50)
    charges = [
        store.deduct_from_channel(workers[i % 4], CHANNEL_ID, 1, idempotency_key=f"c{i % 10}")
        for i in range(30)
    ]
    credits = [
        store.credit_channel(workers[i % 4], CHANNEL_ID, 2, idempotency_key=f"r{i % 5}")
        for i in range(20)
    ]
    charged, credited = await asyncio.gather(asyncio.gather(*charges), asyncio.gather(*credits))
    assert all(r.ok for r in charged)
    assert sum(not r.replayed for r in charged) == 10
    assert all(r.status == "credited" for r in credited)
    assert sum(not r.replayed for r in credited) == 5
    channel = await workers[0].get_channel(CHANNEL_ID)
    assert channel is not None
    assert channel.spent == 50 + 10 - 10
    assert len(channel.idempotency_markers or {}) == 15


async def test_concurrent_lease_claims_have_one_winner(backend: StoreFactory) -> None:
    workers = await _workers(backend, 5)
    await seed(workers[0], highest_voucher=voucher_at(100), highest_voucher_amount=100, spent=100)
    due = schedule.ResolvedSettlementSchedule(units=0)
    owners = await asyncio.gather(
        *(
            schedule.claim_scheduled_settlement(channel_id=CHANNEL_ID, schedule=due, store=w)
            for w in workers * 4
        )
    )
    winners = [o for o in owners if o is not None]
    assert len(winners) == 1
    channel = await workers[0].get_channel(CHANNEL_ID)
    assert channel is not None and channel.scheduled_settlement_lease is not None
    assert channel.scheduled_settlement_lease.owner == winners[0]


async def test_sqlite_state_survives_restart(tmp_path: Any) -> None:
    path = str(tmp_path / "restart.db")
    first = await SQLiteStore.create(path)
    cs = StoreChannelStore(first)
    await seed(cs, highest_voucher=voucher_at(10_000_000), highest_voucher_amount=10_000_000)
    await store.deduct_from_channel(cs, CHANNEL_ID, 3, idempotency_key="job-1")
    await store.credit_channel(cs, CHANNEL_ID, 1, idempotency_key="refund-1")
    before = await cs.get_channel(CHANNEL_ID)
    await first.close()

    reopened = await SQLiteStore.create(path)
    try:
        cs = StoreChannelStore(reopened)
        assert await cs.get_channel(CHANNEL_ID) == before
        replay = await store.deduct_from_channel(cs, CHANNEL_ID, 3, idempotency_key="job-1")
        assert replay.replayed and replay.channel.spent == 2
        again = await store.credit_channel(cs, CHANNEL_ID, 1, idempotency_key="refund-1")
        assert again.replayed
        assert (await store.deduct_from_channel(cs, CHANNEL_ID, 5)).channel.spent == 7
    finally:
        await reopened.close()
