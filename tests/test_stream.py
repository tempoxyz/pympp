"""Comprehensive tests for stream payment intent.

Mirrors the TypeScript mpay server/Stream.test.ts test suite.
Uses mocked on-chain state to test business logic without a live node.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mpay import Credential
from mpay.methods.tempo.account import TempoAccount
from mpay.methods.tempo.intents import (
    StreamIntent,
    _accept_voucher,
    charge,
)
from mpay.methods.tempo.stream.chain import OnChainChannel
from mpay.methods.tempo.stream.errors import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelConflictError,
    ChannelNotFoundError,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
    StreamError,
)
from mpay.methods.tempo.stream.receipt import (
    create_stream_receipt,
    deserialize_stream_receipt,
    serialize_stream_receipt,
)
from mpay.methods.tempo.stream.storage import (
    ChannelState,
    MemoryStorage,
    SessionState,
)
from mpay.methods.tempo.stream.types import SignedVoucher, Voucher
from mpay.methods.tempo.stream.voucher import (
    parse_voucher_from_payload,
    sign_voucher,
    verify_voucher,
)

# ──────────────────────────────────────────────────────────────
# Test accounts and constants
# ──────────────────────────────────────────────────────────────

PAYER = TempoAccount.from_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CURRENCY = "0x20c0000000000000000000000000000000000000"
ESCROW = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
CHAIN_ID = 42431

# A different account for testing signature mismatches
OTHER_ACCOUNT = TempoAccount.from_key(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)


def make_challenge(
    *,
    id: str = "challenge-1",
    channel_id: str = "0x" + "00" * 32,
) -> Any:
    """Create a mock challenge object."""

    class MockChallenge:
        pass

    c = MockChallenge()
    c.id = id
    c.request = {
        "amount": "1000000",
        "unitType": "token",
        "currency": CURRENCY,
        "recipient": RECIPIENT,
        "methodDetails": {
            "escrowContract": ESCROW,
            "chainId": CHAIN_ID,
        },
    }
    return c


def make_on_chain(
    *,
    deposit: int = 10_000_000,
    settled: int = 0,
    finalized: bool = False,
    payer: str = "",
    payee: str = "",
    token: str = "",
    authorized_signer: str = "",
) -> OnChainChannel:
    return OnChainChannel(
        payer=payer or PAYER.address,
        payee=payee or RECIPIENT,
        token=token or CURRENCY,
        authorized_signer=authorized_signer or PAYER.address,
        deposit=deposit,
        settled=settled,
        close_requested_at=0,
        finalized=finalized,
    )


def sign_test_voucher(channel_id: str, amount: int) -> str:
    """Sign a voucher with the test payer account."""
    voucher = Voucher(channel_id=channel_id, cumulative_amount=amount)
    return sign_voucher(PAYER, voucher, ESCROW, CHAIN_ID)


# ──────────────────────────────────────────────────────────────
# Voucher signing/verification tests
# ──────────────────────────────────────────────────────────────


class TestVoucherSignVerify:
    def test_sign_and_verify(self) -> None:
        channel_id = "0x" + "01" * 32
        voucher = Voucher(channel_id=channel_id, cumulative_amount=1_000_000)
        sig = sign_voucher(PAYER, voucher, ESCROW, CHAIN_ID)

        signed = SignedVoucher(
            channel_id=channel_id,
            cumulative_amount=1_000_000,
            signature=sig,
        )
        assert verify_voucher(ESCROW, CHAIN_ID, signed, PAYER.address)

    def test_verify_wrong_signer(self) -> None:
        channel_id = "0x" + "01" * 32
        voucher = Voucher(channel_id=channel_id, cumulative_amount=1_000_000)
        sig = sign_voucher(PAYER, voucher, ESCROW, CHAIN_ID)

        signed = SignedVoucher(
            channel_id=channel_id,
            cumulative_amount=1_000_000,
            signature=sig,
        )
        assert not verify_voucher(ESCROW, CHAIN_ID, signed, OTHER_ACCOUNT.address)

    def test_verify_invalid_signature(self) -> None:
        signed = SignedVoucher(
            channel_id="0x" + "01" * 32,
            cumulative_amount=1_000_000,
            signature="0x" + "ab" * 65,
        )
        assert not verify_voucher(ESCROW, CHAIN_ID, signed, PAYER.address)

    def test_verify_short_signature(self) -> None:
        signed = SignedVoucher(
            channel_id="0x" + "01" * 32,
            cumulative_amount=1_000_000,
            signature="0x" + "ab" * 10,
        )
        assert not verify_voucher(ESCROW, CHAIN_ID, signed, PAYER.address)

    def test_parse_voucher_from_payload(self) -> None:
        v = parse_voucher_from_payload("0x" + "01" * 32, "1000000", "0x" + "ab" * 65)
        assert v.channel_id == "0x" + "01" * 32
        assert v.cumulative_amount == 1_000_000
        assert v.signature == "0x" + "ab" * 65


# ──────────────────────────────────────────────────────────────
# Storage tests
# ──────────────────────────────────────────────────────────────


class TestMemoryStorage:
    @pytest.mark.asyncio
    async def test_channel_crud(self) -> None:
        storage = MemoryStorage()
        ch_id = "0x" + "01" * 32

        assert await storage.get_channel(ch_id) is None

        channel = ChannelState(
            channel_id=ch_id,
            payer=PAYER.address,
            payee=RECIPIENT,
            token=CURRENCY,
            authorized_signer=PAYER.address,
            deposit=10_000_000,
            settled_on_chain=0,
            highest_voucher_amount=1_000_000,
            highest_voucher=None,
            finalized=False,
            created_at=datetime.now(UTC),
        )
        result = await storage.update_channel(ch_id, lambda _: channel)
        assert result == channel
        assert await storage.get_channel(ch_id) == channel

        # Delete
        await storage.update_channel(ch_id, lambda _: None)
        assert await storage.get_channel(ch_id) is None

    @pytest.mark.asyncio
    async def test_session_crud(self) -> None:
        storage = MemoryStorage()
        sid = "session-1"

        assert await storage.get_session(sid) is None

        session = SessionState(
            challenge_id=sid,
            channel_id="0x" + "01" * 32,
            accepted_cumulative=5_000_000,
            spent=0,
            units=0,
            created_at=datetime.now(UTC),
        )
        result = await storage.update_session(sid, lambda _: session)
        assert result == session

        # Delete
        await storage.update_session(sid, lambda _: None)
        assert await storage.get_session(sid) is None


# ──────────────────────────────────────────────────────────────
# Receipt tests
# ──────────────────────────────────────────────────────────────


class TestReceipt:
    def test_create_stream_receipt(self) -> None:
        receipt = create_stream_receipt(
            challenge_id="c1",
            channel_id="0x" + "01" * 32,
            accepted_cumulative=5_000_000,
            spent=2_000_000,
            units=3,
        )
        assert receipt.method == "tempo"
        assert receipt.intent == "stream"
        assert receipt.status == "success"
        assert receipt.accepted_cumulative == "5000000"
        assert receipt.spent == "2000000"
        assert receipt.units == 3
        assert receipt.reference == "0x" + "01" * 32

    def test_serialize_deserialize(self) -> None:
        receipt = create_stream_receipt(
            challenge_id="c1",
            channel_id="0x" + "01" * 32,
            accepted_cumulative=5_000_000,
            spent=2_000_000,
        )
        encoded = serialize_stream_receipt(receipt)
        decoded = deserialize_stream_receipt(encoded)
        assert decoded.challenge_id == receipt.challenge_id
        assert decoded.channel_id == receipt.channel_id
        assert decoded.accepted_cumulative == receipt.accepted_cumulative
        assert decoded.spent == receipt.spent

    def test_stream_receipt_to_dict_camel_case(self) -> None:
        receipt = create_stream_receipt(
            challenge_id="c1",
            channel_id="0xchannel",
            accepted_cumulative=100,
            spent=50,
            tx_hash="0xhash",
        )
        d = receipt.to_dict()
        assert "challengeId" in d
        assert "channelId" in d
        assert "acceptedCumulative" in d
        assert "txHash" in d
        assert d["txHash"] == "0xhash"

    def test_stream_receipt_to_dict_omits_none(self) -> None:
        receipt = create_stream_receipt(
            challenge_id="c1",
            channel_id="0xchannel",
            accepted_cumulative=100,
            spent=50,
        )
        d = receipt.to_dict()
        assert "units" not in d
        assert "txHash" not in d


# ──────────────────────────────────────────────────────────────
# Server-side stream intent tests
# ──────────────────────────────────────────────────────────────


def _make_credential(challenge: Any, payload: dict[str, Any]) -> Credential:
    """Create a Credential wrapping a mock challenge and payload."""
    return Credential(
        challenge=challenge,
        payload=payload,
    )


class TestStreamServerOpen:
    """Tests for the 'open' action handler."""

    @pytest.mark.asyncio
    async def test_accepts_valid_open(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32

        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )

            receipt = await intent.verify(credential, {})

            assert receipt.status == "success"
            assert receipt.reference == channel_id

            ch = await storage.get_channel(channel_id)
            assert ch is not None
            assert ch.highest_voucher_amount == 1_000_000

    @pytest.mark.asyncio
    async def test_rejects_voucher_exceeds_deposit(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        on_chain = make_on_chain(deposit=500_000)

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )

            with pytest.raises((AmountExceedsDepositError, InsufficientBalanceError)):
                await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_rejects_invalid_signature(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=False,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": "0x" + "ab" * 65,
                },
            )

            with pytest.raises(InvalidSignatureError):
                await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_reopen_with_higher_voucher(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            # First open
            credential1 = _make_credential(
                make_challenge(id="open-1", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )
            await intent.verify(credential1, {})

            # Clear active session
            await storage.update_channel(
                channel_id, lambda ch: replace(ch, active_session_id=None) if ch else None
            )

            ch1 = await storage.get_channel(channel_id)
            assert ch1 is not None
            assert ch1.highest_voucher_amount == 1_000_000

            # Reopen with higher voucher
            credential2 = _make_credential(
                make_challenge(id="open-2", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "5000000",
                    "signature": sign_test_voucher(channel_id, 5_000_000),
                },
            )
            receipt = await intent.verify(credential2, {})
            assert receipt.status == "success"

            ch2 = await storage.get_channel(channel_id)
            assert ch2 is not None
            assert ch2.highest_voucher_amount == 5_000_000

    @pytest.mark.asyncio
    async def test_rejects_concurrent_stream(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            # First open
            credential1 = _make_credential(
                make_challenge(id="c1", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )
            await intent.verify(credential1, {})

            # Second open on same channel (different challenge)
            credential2 = _make_credential(
                make_challenge(id="c2", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "2000000",
                    "signature": sign_test_voucher(channel_id, 2_000_000),
                },
            )

            with pytest.raises(ChannelConflictError):
                await intent.verify(credential2, {})

    @pytest.mark.asyncio
    async def test_allows_reopen_stale_session(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.broadcast_open_transaction",
                new_callable=AsyncMock,
            ) as mock_broadcast,
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            from mpay.methods.tempo.stream.chain import BroadcastResult

            mock_broadcast.return_value = BroadcastResult(tx_hash="0xtxhash", on_chain=on_chain)

            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            # First open
            credential1 = _make_credential(
                make_challenge(id="c1", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )
            await intent.verify(credential1, {})

            # Delete the session (simulating staleness)
            await storage.update_session("c1", lambda _: None)

            # Reopen should succeed
            credential2 = _make_credential(
                make_challenge(id="c2", channel_id=channel_id),
                {
                    "action": "open",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "cumulativeAmount": "2000000",
                    "signature": sign_test_voucher(channel_id, 2_000_000),
                },
            )
            receipt = await intent.verify(credential2, {})
            assert receipt.status == "success"


class TestStreamServerVoucher:
    """Tests for the 'voucher' action handler."""

    async def _seed_channel(self, storage: MemoryStorage, channel_id: str) -> None:
        """Seed a channel in storage for voucher tests."""
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=0,
                highest_voucher_amount=1_000_000,
                highest_voucher=SignedVoucher(
                    channel_id=channel_id,
                    cumulative_amount=1_000_000,
                    signature=sign_test_voucher(channel_id, 1_000_000),
                ),
                active_session_id="open-challenge",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )
        await storage.update_session(
            "open-challenge",
            lambda _: SessionState(
                challenge_id="open-challenge",
                channel_id=channel_id,
                accepted_cumulative=1_000_000,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

    @pytest.mark.asyncio
    async def test_accepts_increasing_voucher(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)

        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.get_on_chain_channel",
                new_callable=AsyncMock,
                return_value=on_chain,
            ),
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "voucher",
                    "channelId": channel_id,
                    "cumulativeAmount": "2000000",
                    "signature": sign_test_voucher(channel_id, 2_000_000),
                },
            )

            receipt = await intent.verify(credential, {})
            assert receipt.status == "success"

            ch = await storage.get_channel(channel_id)
            assert ch is not None
            assert ch.highest_voucher_amount == 2_000_000

    @pytest.mark.asyncio
    async def test_idempotent_non_increasing_voucher(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)

        on_chain = make_on_chain()

        with patch(
            "mpay.methods.tempo.intents.get_on_chain_channel",
            new_callable=AsyncMock,
            return_value=on_chain,
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "voucher",
                    "channelId": channel_id,
                    "cumulativeAmount": "500000",
                    "signature": sign_test_voucher(channel_id, 500_000),
                },
            )

            receipt = await intent.verify(credential, {})
            assert receipt.status == "success"
            # Should return the highest known amount, not the submitted one
            assert receipt.extra["acceptedCumulative"] == "1000000"

    @pytest.mark.asyncio
    async def test_rejects_voucher_exceeding_deposit(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)

        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.get_on_chain_channel",
                new_callable=AsyncMock,
                return_value=on_chain,
            ),
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "voucher",
                    "channelId": channel_id,
                    "cumulativeAmount": "99999999",
                    "signature": sign_test_voucher(channel_id, 99_999_999),
                },
            )

            with pytest.raises(AmountExceedsDepositError):
                await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_rejects_voucher_below_min_delta(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)

        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.get_on_chain_channel",
                new_callable=AsyncMock,
                return_value=on_chain,
            ),
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
                min_voucher_delta=2_000_000,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "voucher",
                    "channelId": channel_id,
                    "cumulativeAmount": "1500000",
                    "signature": sign_test_voucher(channel_id, 1_500_000),
                },
            )

            with pytest.raises(DeltaTooSmallError, match="500000 below minimum 2000000"):
                await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_rejects_voucher_unknown_channel(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32

        intent = StreamIntent(
            storage=storage,
            escrow_contract=ESCROW,
            chain_id=CHAIN_ID,
        )

        credential = _make_credential(
            make_challenge(channel_id=channel_id),
            {
                "action": "voucher",
                "channelId": channel_id,
                "cumulativeAmount": "1000000",
                "signature": sign_test_voucher(channel_id, 1_000_000),
            },
        )

        with pytest.raises(ChannelNotFoundError):
            await intent.verify(credential, {})


class TestStreamServerClose:
    """Tests for the 'close' action handler."""

    async def _seed_channel(self, storage: MemoryStorage, channel_id: str) -> None:
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=0,
                highest_voucher_amount=1_000_000,
                highest_voucher=SignedVoucher(
                    channel_id=channel_id,
                    cumulative_amount=1_000_000,
                    signature=sign_test_voucher(channel_id, 1_000_000),
                ),
                active_session_id="open-challenge",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )

    @pytest.mark.asyncio
    async def test_accepts_close(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.get_on_chain_channel",
                new_callable=AsyncMock,
                return_value=on_chain,
            ),
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "close",
                    "channelId": channel_id,
                    "cumulativeAmount": "1000000",
                    "signature": sign_test_voucher(channel_id, 1_000_000),
                },
            )

            receipt = await intent.verify(credential, {})
            assert receipt.status == "success"

            ch = await storage.get_channel(channel_id)
            assert ch is not None
            assert ch.finalized is True
            assert ch.active_session_id is None

            # Session should be cleaned up
            session = await storage.get_session("challenge-2")
            assert session is None

    @pytest.mark.asyncio
    async def test_rejects_close_below_highest(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        # Seed with highest_voucher_amount = 3_000_000
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=0,
                highest_voucher_amount=3_000_000,
                highest_voucher=None,
                active_session_id=None,
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )

        intent = StreamIntent(
            storage=storage,
            escrow_contract=ESCROW,
            chain_id=CHAIN_ID,
        )

        credential = _make_credential(
            make_challenge(id="challenge-2", channel_id=channel_id),
            {
                "action": "close",
                "channelId": channel_id,
                "cumulativeAmount": "2000000",
                "signature": sign_test_voucher(channel_id, 2_000_000),
            },
        )

        with pytest.raises(StreamError, match="close voucher amount must be >= highest"):
            await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_rejects_close_exceeding_deposit(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)
        on_chain = make_on_chain()

        with (
            patch(
                "mpay.methods.tempo.intents.get_on_chain_channel",
                new_callable=AsyncMock,
                return_value=on_chain,
            ),
            patch(
                "mpay.methods.tempo.intents.verify_voucher",
                return_value=True,
            ),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "close",
                    "channelId": channel_id,
                    "cumulativeAmount": "99999999",
                    "signature": sign_test_voucher(channel_id, 99_999_999),
                },
            )

            with pytest.raises(AmountExceedsDepositError):
                await intent.verify(credential, {})

    @pytest.mark.asyncio
    async def test_rejects_close_unknown_channel(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32

        intent = StreamIntent(
            storage=storage,
            escrow_contract=ESCROW,
            chain_id=CHAIN_ID,
        )

        credential = _make_credential(
            make_challenge(channel_id=channel_id),
            {
                "action": "close",
                "channelId": channel_id,
                "cumulativeAmount": "1000000",
                "signature": sign_test_voucher(channel_id, 1_000_000),
            },
        )

        with pytest.raises(ChannelNotFoundError):
            await intent.verify(credential, {})


class TestStreamServerTopUp:
    """Tests for the 'topUp' action handler."""

    async def _seed_channel(self, storage: MemoryStorage, channel_id: str) -> None:
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=0,
                highest_voucher_amount=1_000_000,
                highest_voucher=None,
                active_session_id="open-challenge",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )

    @pytest.mark.asyncio
    async def test_accepts_top_up(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await self._seed_channel(storage, channel_id)

        with patch(
            "mpay.methods.tempo.intents.broadcast_top_up_transaction",
            new_callable=AsyncMock,
            return_value=("0xtxhash", 20_000_000),
        ):
            intent = StreamIntent(
                storage=storage,
                escrow_contract=ESCROW,
                chain_id=CHAIN_ID,
            )

            credential = _make_credential(
                make_challenge(id="challenge-2", channel_id=channel_id),
                {
                    "action": "topUp",
                    "type": "transaction",
                    "channelId": channel_id,
                    "transaction": "0xfake",
                    "additionalDeposit": "10000000",
                },
            )

            receipt = await intent.verify(credential, {})
            assert receipt.status == "success"

            ch = await storage.get_channel(channel_id)
            assert ch is not None
            assert ch.deposit == 20_000_000

    @pytest.mark.asyncio
    async def test_rejects_top_up_unknown_channel(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32

        intent = StreamIntent(
            storage=storage,
            escrow_contract=ESCROW,
            chain_id=CHAIN_ID,
        )

        credential = _make_credential(
            make_challenge(channel_id=channel_id),
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": channel_id,
                "transaction": "0xfake",
                "additionalDeposit": "5000000",
            },
        )

        with pytest.raises(ChannelNotFoundError):
            await intent.verify(credential, {})


# ──────────────────────────────────────────────────────────────
# Charge and settle tests
# ──────────────────────────────────────────────────────────────


class TestCharge:
    @pytest.mark.asyncio
    async def test_deducts_balance(self) -> None:
        storage = MemoryStorage()
        await storage.update_session(
            "s1",
            lambda _: SessionState(
                challenge_id="s1",
                channel_id="0x" + "01" * 32,
                accepted_cumulative=5_000_000,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        session = await charge(storage, "s1", 1_000_000)
        assert session.spent == 1_000_000
        assert session.units == 1

        session2 = await charge(storage, "s1", 2_000_000)
        assert session2.spent == 3_000_000
        assert session2.units == 2

    @pytest.mark.asyncio
    async def test_rejects_overdraft(self) -> None:
        storage = MemoryStorage()
        await storage.update_session(
            "s1",
            lambda _: SessionState(
                challenge_id="s1",
                channel_id="0x" + "01" * 32,
                accepted_cumulative=1_000_000,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        with pytest.raises(InsufficientBalanceError):
            await charge(storage, "s1", 2_000_000)

    @pytest.mark.asyncio
    async def test_rejects_missing_session(self) -> None:
        storage = MemoryStorage()
        with pytest.raises(ChannelClosedError):
            await charge(storage, "nonexistent", 100)


# ──────────────────────────────────────────────────────────────
# Monotonicity / TOCTOU unit tests
# ──────────────────────────────────────────────────────────────


class TestMonotonicity:
    @pytest.mark.asyncio
    async def test_charge_does_not_decrease_accepted(self) -> None:
        storage = MemoryStorage()
        await storage.update_session(
            "s1",
            lambda _: SessionState(
                challenge_id="s1",
                channel_id="0x" + "01" * 32,
                accepted_cumulative=5_000_000,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        session = await charge(storage, "s1", 1_000_000)
        assert session.spent == 1_000_000
        assert session.accepted_cumulative == 5_000_000

    @pytest.mark.asyncio
    async def test_settle_max_does_not_regress(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=3_000_000,
                highest_voucher_amount=5_000_000,
                highest_voucher=None,
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )

        # Attempt to set settled to a lower value
        from mpay.methods.tempo.intents import _settle_update

        result = _settle_update(await storage.get_channel(channel_id), 2_000_000)
        assert result is not None
        assert result.settled_on_chain == 3_000_000

    @pytest.mark.asyncio
    async def test_settle_updates_when_higher(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32
        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=1_000_000,
                highest_voucher_amount=5_000_000,
                highest_voucher=None,
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )

        from mpay.methods.tempo.intents import _settle_update

        result = _settle_update(await storage.get_channel(channel_id), 5_000_000)
        assert result is not None
        assert result.settled_on_chain == 5_000_000

    @pytest.mark.asyncio
    async def test_accept_voucher_monotonic(self) -> None:
        storage = MemoryStorage()
        await storage.update_session(
            "s1",
            lambda _: SessionState(
                challenge_id="s1",
                channel_id="0x" + "01" * 32,
                accepted_cumulative=5_000_000,
                spent=2_000_000,
                units=3,
                created_at=datetime.now(UTC),
            ),
        )

        # Accept with lower amount — should not decrease
        session = await _accept_voucher(storage, "s1", "0x" + "01" * 32, 3_000_000)
        assert session is not None
        assert session.accepted_cumulative == 5_000_000
        assert session.spent == 2_000_000
        assert session.units == 3

    @pytest.mark.asyncio
    async def test_session_cleanup_on_conflict(self) -> None:
        storage = MemoryStorage()
        channel_id = "0x" + "01" * 32

        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=PAYER.address,
                payee=RECIPIENT,
                token=CURRENCY,
                authorized_signer=PAYER.address,
                deposit=10_000_000,
                settled_on_chain=0,
                highest_voucher_amount=5_000_000,
                highest_voucher=None,
                active_session_id="existing-session",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )
        await storage.update_session(
            "existing-session",
            lambda _: SessionState(
                challenge_id="existing-session",
                channel_id=channel_id,
                accepted_cumulative=5_000_000,
                spent=1_000_000,
                units=3,
                created_at=datetime.now(UTC),
            ),
        )

        # Pre-create new session
        await storage.update_session(
            "new-session",
            lambda _: SessionState(
                challenge_id="new-session",
                channel_id=channel_id,
                accepted_cumulative=2_000_000,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        # Attempt channel update — should raise conflict
        def _conflict_update(existing):
            if (
                existing
                and existing.active_session_id
                and existing.active_session_id != "new-session"
            ):
                raise ChannelConflictError("another stream is active on this channel")
            if existing:
                return replace(existing, active_session_id="new-session")
            return None

        try:
            await storage.update_channel(channel_id, _conflict_update)
        except ChannelConflictError:
            # Clean up pre-created session
            await storage.update_session("new-session", lambda _: None)

        # Pre-created session should be cleaned up
        assert await storage.get_session("new-session") is None
        # Original session should still exist
        assert await storage.get_session("existing-session") is not None


# ──────────────────────────────────────────────────────────────
# Error type tests
# ──────────────────────────────────────────────────────────────


class TestErrors:
    def test_channel_not_found_status(self) -> None:
        err = ChannelNotFoundError("channel not found")
        assert err.status == 410

    def test_invalid_signature_status(self) -> None:
        err = InvalidSignatureError("bad sig")
        assert err.status == 402

    def test_channel_conflict_status(self) -> None:
        err = ChannelConflictError("conflict")
        assert err.status == 409

    def test_channel_closed_status(self) -> None:
        err = ChannelClosedError("finalized")
        assert err.status == 410

    def test_insufficient_balance_status(self) -> None:
        err = InsufficientBalanceError("not enough")
        assert err.status == 402

    def test_problem_details(self) -> None:
        err = ChannelNotFoundError("channel not found")
        pd = err.to_problem_details(challenge_id="c1")
        assert pd["type"] == "https://paymentauth.org/problems/stream/channel-not-found"
        assert pd["status"] == 410
        assert pd["challengeId"] == "c1"
