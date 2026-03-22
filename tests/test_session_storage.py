"""Tests for session/storage.py — MemoryChannelStore and deduct_from_channel."""

from __future__ import annotations

import asyncio

import pytest

from mpp.errors import VerificationError
from mpp.methods.tempo.session.storage import MemoryChannelStore, deduct_from_channel
from mpp.methods.tempo.session.types import ChannelState


def _make_channel(channel_id: str = "0xch", deposit: int = 100_000, voucher: int = 10_000) -> ChannelState:
    return ChannelState(
        channel_id=channel_id,
        chain_id=42431,
        escrow_contract="0xesc",
        payer="0xpayer",
        payee="0xpayee",
        token="0xtoken",
        authorized_signer="0xsigner",
        deposit=deposit,
        settled_on_chain=0,
        highest_voucher_amount=voucher,
        highest_voucher_signature=b"\x00" * 65,
    )


class TestMemoryChannelStore:
    async def test_get_returns_none_when_empty(self) -> None:
        store = MemoryChannelStore()
        assert await store.get_channel("0xnone") is None

    async def test_update_creates_channel(self) -> None:
        store = MemoryChannelStore()
        ch = _make_channel()
        result = await store.update_channel("0xch", lambda _: ch)
        assert result is not None
        assert result.channel_id == "0xch"
        assert await store.get_channel("0xch") is not None

    async def test_update_modifies_existing(self) -> None:
        store = MemoryChannelStore()
        ch = _make_channel()
        await store.update_channel("0xch", lambda _: ch)

        from dataclasses import replace
        result = await store.update_channel(
            "0xch", lambda c: replace(c, deposit=200_000) if c else None
        )
        assert result is not None
        assert result.deposit == 200_000

    async def test_update_with_none_deletes(self) -> None:
        store = MemoryChannelStore()
        ch = _make_channel()
        await store.update_channel("0xch", lambda _: ch)
        result = await store.update_channel("0xch", lambda _: None)
        assert result is None
        assert await store.get_channel("0xch") is None


class TestDeductFromChannel:
    async def test_success(self) -> None:
        store = MemoryChannelStore()
        ch = _make_channel(voucher=10_000)
        await store.update_channel("0xch", lambda _: ch)

        result = await deduct_from_channel(store, "0xch", 3_000)
        assert result.spent == 3_000
        assert result.units == 1

    async def test_insufficient_balance(self) -> None:
        store = MemoryChannelStore()
        ch = _make_channel(voucher=1_000)
        await store.update_channel("0xch", lambda _: ch)

        with pytest.raises(VerificationError, match="insufficient balance"):
            await deduct_from_channel(store, "0xch", 5_000)

    async def test_channel_not_found(self) -> None:
        store = MemoryChannelStore()
        with pytest.raises(VerificationError, match="channel not found"):
            await deduct_from_channel(store, "0xmissing", 100)

    async def test_concurrent_deductions_different_channels(self) -> None:
        store = MemoryChannelStore()
        ch1 = _make_channel("0xch1", voucher=10_000)
        ch2 = _make_channel("0xch2", voucher=10_000)
        await store.update_channel("0xch1", lambda _: ch1)
        await store.update_channel("0xch2", lambda _: ch2)

        r1, r2 = await asyncio.gather(
            deduct_from_channel(store, "0xch1", 3_000),
            deduct_from_channel(store, "0xch2", 5_000),
        )
        assert r1.spent == 3_000
        assert r2.spent == 5_000
