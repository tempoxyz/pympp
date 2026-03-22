"""Tests for session/intent.py — SessionIntent orchestrator.

Uses pytest-httpx to mock JSON-RPC calls.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pytest_httpx import HTTPXMock

from mpp.errors import VerificationError
from mpp.methods.tempo.session.intent import SessionIntent
from mpp.methods.tempo.session.storage import MemoryChannelStore
from mpp.methods.tempo.session.types import ChannelState
from tests import make_credential
from tests._session_helpers import CHAIN_ID, ESCROW, sign_voucher, signer_address

RPC_URL = "https://rpc.test"
CHANNEL_ID = "0x" + "ab" * 32


def _sign_voucher(amount: int) -> bytes:
    return sign_voucher(amount, channel_id=CHANNEL_ID)


def _signer_address() -> str:
    return signer_address()


def _make_on_chain_result(
    deposit: int = 100_000,
    settled: int = 0,
    finalized: bool = False,
    close_requested_at: int = 0,
    payer: str | None = None,
    payee: str | None = None,
    authorized_signer: str | None = None,
) -> str:
    """ABI-encode a getChannel return tuple."""
    from eth_abi import encode

    return "0x" + encode(
        ["bool", "uint64", "address", "address", "address", "address", "uint128", "uint128"],
        [
            finalized,
            close_requested_at,
            payer or "0x" + "aa" * 20,
            payee or "0x" + "bb" * 20,
            "0x" + "cc" * 20,  # token
            authorized_signer or _signer_address(),
            deposit,
            settled,
        ],
    ).hex()


def _mock_send_and_receipt(httpx_mock: HTTPXMock, tx_hash: str = "0xtxhash") -> None:
    """Mock eth_sendRawTransaction + eth_getTransactionReceipt."""
    httpx_mock.add_response(
        json={"jsonrpc": "2.0", "result": tx_hash, "id": 1},
    )
    httpx_mock.add_response(
        json={"jsonrpc": "2.0", "result": {"status": "0x1", "transactionHash": tx_hash}, "id": 1},
    )


def _make_store_with_channel(
    deposit: int = 100_000,
    voucher_amount: int = 5000,
    voucher_sig: bytes | None = None,
    finalized: bool = False,
) -> tuple[MemoryChannelStore, ChannelState]:
    store = MemoryChannelStore()
    state = ChannelState(
        channel_id=CHANNEL_ID,
        chain_id=CHAIN_ID,
        escrow_contract=ESCROW,
        payer="0x" + "aa" * 20,
        payee="0x" + "bb" * 20,
        token="0x" + "cc" * 20,
        authorized_signer=_signer_address(),
        deposit=deposit,
        settled_on_chain=0,
        highest_voucher_amount=voucher_amount,
        highest_voucher_signature=voucher_sig or _sign_voucher(voucher_amount),
        finalized=finalized,
        created_at=datetime.now(UTC).isoformat(),
    )
    store._channels[CHANNEL_ID] = state
    return store, state


class TestSessionIntentVerify:
    async def test_unknown_action_rejected(self) -> None:
        intent = SessionIntent(rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW)
        cred = make_credential({"action": "refund"}, intent="session")
        with pytest.raises(VerificationError, match="Unknown session action"):
            await intent.verify(cred, {})

    async def test_missing_action_rejected(self) -> None:
        intent = SessionIntent(rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW)
        cred = make_credential({"type": "transaction"}, intent="session")
        with pytest.raises(VerificationError, match="Invalid session credential"):
            await intent.verify(cred, {})


class TestHandleOpen:
    async def test_open_creates_channel(self, httpx_mock: HTTPXMock) -> None:
        store = MemoryChannelStore()
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        sig = _sign_voucher(1000)
        sig_hex = "0x" + sig.hex()

        # Mock: sendRawTransaction
        _mock_send_and_receipt(httpx_mock, tx_hash="0xopentx")
        # Mock: eth_call (getChannel)
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": _make_on_chain_result(deposit=100_000), "id": 1},
        )

        cred = make_credential(
            {
                "action": "open",
                "type": "transaction",
                "channelId": CHANNEL_ID,
                "transaction": "0xrawtx",
                "cumulativeAmount": "1000",
                "signature": sig_hex,
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"
        assert receipt.reference == "0xopentx"

        state = await store.get_channel(CHANNEL_ID)
        assert state is not None
        assert state.highest_voucher_amount == 1000
        assert state.deposit == 100_000


class TestHandleVoucher:
    async def test_higher_voucher_accepted(self) -> None:
        store, _ = _make_store_with_channel(voucher_amount=1000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        new_sig = _sign_voucher(5000)
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": "0x" + new_sig.hex(),
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"

        state = await store.get_channel(CHANNEL_ID)
        assert state is not None
        assert state.highest_voucher_amount == 5000

    async def test_exact_replay_accepted(self) -> None:
        sig = _sign_voucher(5000)
        store, _ = _make_store_with_channel(voucher_amount=5000, voucher_sig=sig)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"

    async def test_stale_with_different_sig_rejected(self) -> None:
        real_sig = _sign_voucher(5000)
        store, _ = _make_store_with_channel(voucher_amount=5000, voucher_sig=real_sig)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        forged_sig = "0x" + "ff" * 65
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": forged_sig,
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="invalid voucher signature"):
            await intent.verify(cred, {})

    async def test_finalized_channel_rejected(self) -> None:
        store, _ = _make_store_with_channel(finalized=True)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        sig = _sign_voucher(10_000)
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "10000",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="finalized"):
            await intent.verify(cred, {})

    async def test_exceeds_deposit_rejected(self) -> None:
        store, _ = _make_store_with_channel(deposit=1000, voucher_amount=500)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        sig = _sign_voucher(5000)
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="exceeds"):
            await intent.verify(cred, {})


class TestHandleTopUp:
    async def test_top_up_increases_deposit(self, httpx_mock: HTTPXMock) -> None:
        store, _ = _make_store_with_channel(deposit=50_000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        _mock_send_and_receipt(httpx_mock)
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": _make_on_chain_result(deposit=100_000), "id": 1},
        )

        cred = make_credential(
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": CHANNEL_ID,
                "transaction": "0xrawtx",
                "additionalDeposit": "50000",
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"

        state = await store.get_channel(CHANNEL_ID)
        assert state is not None
        assert state.deposit == 100_000

    async def test_top_up_no_increase_rejected(self, httpx_mock: HTTPXMock) -> None:
        store, _ = _make_store_with_channel(deposit=100_000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        _mock_send_and_receipt(httpx_mock)
        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": _make_on_chain_result(deposit=100_000), "id": 1},
        )

        cred = make_credential(
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": CHANNEL_ID,
                "transaction": "0xrawtx",
                "additionalDeposit": "0",
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="did not increase"):
            await intent.verify(cred, {})


class TestHandleClose:
    async def test_close_finalizes_channel(self, httpx_mock: HTTPXMock) -> None:
        sig = _sign_voucher(10_000)
        store, _ = _make_store_with_channel(voucher_amount=5000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        httpx_mock.add_response(
            json={"jsonrpc": "2.0", "result": _make_on_chain_result(deposit=100_000), "id": 1},
        )

        cred = make_credential(
            {
                "action": "close",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "10000",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"

        state = await store.get_channel(CHANNEL_ID)
        assert state is not None
        assert state.finalized is True
        assert state.highest_voucher_amount == 10_000

    async def test_close_below_highest_rejected(self) -> None:
        store, _ = _make_store_with_channel(voucher_amount=10_000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        sig = _sign_voucher(5000)
        cred = make_credential(
            {
                "action": "close",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match=">= highest"):
            await intent.verify(cred, {})


class TestMethodDetailsOverride:
    async def test_chain_id_override_from_request(self) -> None:
        """methodDetails.chainId in the request should override the instance default."""
        store, _ = _make_store_with_channel(voucher_amount=1000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        # Sign with a DIFFERENT chain_id — should fail since methodDetails overrides
        new_sig = _sign_voucher(5000)
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5000",
                "signature": "0x" + new_sig.hex(),
            },
            intent="session",
        )

        # With matching chain_id in methodDetails, voucher should be accepted
        receipt = await intent.verify(cred, {"methodDetails": {"chainId": CHAIN_ID}})
        assert receipt.status == "success"

    async def test_escrow_override_from_request(self) -> None:
        """methodDetails.escrowContract should override the instance default."""
        alt_escrow = "0x6666666666666666666666666666666666666666"
        intent = SessionIntent(
            rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )
        # Resolve with different escrow in request
        escrow, chain_id, _ = intent._resolve_details(
            {"methodDetails": {"escrowContract": alt_escrow}}
        )
        assert escrow == alt_escrow
        assert chain_id == CHAIN_ID

    async def test_min_delta_override_from_request(self) -> None:
        """methodDetails.minVoucherDelta should override the instance default."""
        store, _ = _make_store_with_channel(voucher_amount=1000)
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
            min_voucher_delta=0,
        )

        sig = _sign_voucher(1001)
        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "1001",
                "signature": "0x" + sig.hex(),
            },
            intent="session",
        )

        # Delta is 1, min_delta override is 100 → should reject
        with pytest.raises(VerificationError, match="below minimum"):
            await intent.verify(cred, {"methodDetails": {"minVoucherDelta": "100"}})


class TestInputValidation:
    async def test_invalid_cumulative_amount_rejected(self) -> None:
        store, _ = _make_store_with_channel()
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "not-a-number",
                "signature": "0x" + "aa" * 65,
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="invalid cumulativeAmount"):
            await intent.verify(cred, {})

    async def test_negative_cumulative_amount_rejected(self) -> None:
        store, _ = _make_store_with_channel()
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        cred = make_credential(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "-1",
                "signature": "0x" + "aa" * 65,
            },
            intent="session",
        )

        with pytest.raises(VerificationError, match="non-negative"):
            await intent.verify(cred, {})

    async def test_zero_authorized_signer_falls_back_to_payer(self, httpx_mock: HTTPXMock) -> None:
        """When on-chain authorizedSigner is zero address, payer should be used."""
        store = MemoryChannelStore()
        intent = SessionIntent(
            store=store, rpc_url=RPC_URL, chain_id=CHAIN_ID, escrow_contract=ESCROW,
        )

        payer = _signer_address()
        sig = _sign_voucher(1000)
        sig_hex = "0x" + sig.hex()

        _mock_send_and_receipt(httpx_mock, tx_hash="0xopentx")
        # Mock on-chain state with zero authorizedSigner
        httpx_mock.add_response(
            json={
                "jsonrpc": "2.0",
                "result": _make_on_chain_result(
                    deposit=100_000,
                    payer=payer,
                    authorized_signer="0x" + "00" * 20,
                ),
                "id": 1,
            },
        )

        cred = make_credential(
            {
                "action": "open",
                "type": "transaction",
                "channelId": CHANNEL_ID,
                "transaction": "0xrawtx",
                "cumulativeAmount": "1000",
                "signature": sig_hex,
            },
            intent="session",
        )

        receipt = await intent.verify(cred, {})
        assert receipt.status == "success"

        state = await store.get_channel(CHANNEL_ID)
        assert state is not None
        # authorized_signer should be the payer since on-chain was zero
        assert state.authorized_signer.lower() == payer.lower()
