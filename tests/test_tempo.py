"""Tests for Tempo payment method."""

import json
import os
import re
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import rlp
from pytest_httpx import HTTPXMock

from mpp import Challenge
from mpp.methods.tempo import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    TESTNET_CHAIN_ID,
    TempoAccount,
    escrow_contract_for_chain,
    tempo,
)
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import CHAIN_RPC_URLS
from mpp.methods.tempo.client import TempoMethod
from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope
from mpp.methods.tempo.fee_payer_policy import get_policy
from mpp.methods.tempo.intents import (
    APPROVE_SELECTOR,
    STABLECOIN_DEX,
    SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    TRANSFER_SELECTOR,
    TRANSFER_TOPIC,
    TRANSFER_WITH_MEMO_SELECTOR,
    TRANSFER_WITH_MEMO_TOPIC,
    ChargeIntent,
    _match_single_transfer_calldata,
    _match_transfer_calldata,
    _parse_memo_bytes,
    _raw_transaction_hash,
    _rpc_error_msg,
    get_transfers,
)
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    HashCredentialPayload,
    MethodDetails,
    Split,
    TransactionCredentialPayload,
)
from mpp.server.intent import VerificationError
from tests import make_credential

# Valid test private key (must be < secp256k1 order)
TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def mock_response(status_code: int = 200, json: dict | None = None) -> httpx.Response:
    """Create a mock response with a request attached."""
    request = httpx.Request("POST", "https://rpc.test")
    response = httpx.Response(status_code, json=json, request=request)
    return response


def amount_data(amount: int) -> str:
    return "0x" + hex(amount)[2:].zfill(64)


class TestTempoAccount:
    def test_from_key(self) -> None:
        """Should create account from private key."""
        key = "0x" + "a" * 64
        account = TempoAccount.from_key(key)
        assert account.address.startswith("0x")
        assert len(account.address) == 42

    def test_from_env(self) -> None:
        """Should create account from environment variable."""
        key = "0x" + "b" * 64
        with patch.dict(os.environ, {"TEST_KEY": key}):
            account = TempoAccount.from_env("TEST_KEY")
            assert account.address.startswith("0x")

    def test_from_env_missing(self) -> None:
        """Should raise if env var not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MISSING_KEY", None)
            with pytest.raises(ValueError, match="not set"):
                TempoAccount.from_env("MISSING_KEY")

    def test_sign_hash(self) -> None:
        """Should sign a 32-byte hash."""
        key = "0x" + "c" * 64
        account = TempoAccount.from_key(key)
        msg_hash = b"\x00" * 32
        signature = account.sign_hash(msg_hash)
        assert len(signature) == 65


class TestTempoMethod:
    def test_tempo_factory(self) -> None:
        """tempo() should create a TempoMethod."""
        method = tempo(intents={"charge": ChargeIntent()})
        assert isinstance(method, TempoMethod)
        assert method.name == "tempo"

    def test_tempo_with_account(self) -> None:
        """tempo() should accept account and rpc_url."""
        key = "0x" + "d" * 64
        account = TempoAccount.from_key(key)
        method = tempo(
            account=account,
            rpc_url="https://custom.rpc",
            intents={"charge": ChargeIntent()},
        )
        assert method.account == account
        assert method.rpc_url == "https://custom.rpc"

    def test_tempo_propagates_rpc_url_to_intents(self) -> None:
        """tempo() should propagate rpc_url to intents that don't set one."""
        intent = ChargeIntent()
        assert intent.rpc_url is None
        method = tempo(
            rpc_url="https://custom.rpc",
            intents={"charge": intent},
        )
        assert cast(ChargeIntent, method.intents["charge"]).rpc_url == "https://custom.rpc"

    def test_tempo_does_not_override_explicit_intent_rpc_url(self) -> None:
        """tempo() should not override an intent's explicitly-set rpc_url."""
        intent = ChargeIntent(rpc_url="https://intent.rpc")
        method = tempo(
            rpc_url="https://method.rpc",
            intents={"charge": intent},
        )
        assert cast(ChargeIntent, method.intents["charge"]).rpc_url == "https://intent.rpc"

    def test_intents_property(self) -> None:
        """Should have only the intents explicitly provided."""
        method = tempo(intents={"charge": ChargeIntent()})
        assert "charge" in method.intents
        assert isinstance(method.intents["charge"], ChargeIntent)

    @pytest.mark.asyncio
    async def test_create_credential_no_account(self) -> None:
        """Should raise if no account configured."""
        method = tempo(intents={"charge": ChargeIntent()})
        challenge = Challenge(
            id="test",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "currency": "0x123", "recipient": "0x456"},
        )
        with pytest.raises(ValueError, match="No account configured"):
            await method.create_credential(challenge)

    @pytest.mark.asyncio
    async def test_create_credential_unsupported_intent(self) -> None:
        """Should raise for unsupported intent."""
        key = "0x" + "e" * 64
        account = TempoAccount.from_key(key)
        method = tempo(account=account, intents={"charge": ChargeIntent()})
        challenge = Challenge(
            id="test",
            method="tempo",
            intent="subscribe",
            request={},
        )
        with pytest.raises(ValueError, match="Unsupported intent"):
            await method.create_credential(challenge)

    def test_encode_transfer(self) -> None:
        """Should encode TIP-20 transfer correctly."""
        method = tempo(intents={"charge": ChargeIntent()})
        data = method._encode_transfer("0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", 1000000)
        assert data.startswith("0xa9059cbb")
        assert len(data) == 138

    @pytest.mark.asyncio
    async def test_create_credential_caches_chain_id_per_rpc_url(self) -> None:
        """Should reuse eth_chainId results for repeated calls to the same RPC URL."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="test-cache-chain-id",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
            realm="test.example.com",
            request_b64="e30",
        )

        rpc_methods: list[str] = []
        nonces = iter(["0x1", "0x2"])

        async def fake_rpc_call(
            rpc_url: str,
            method_name: str,
            params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del params, client
            assert rpc_url == "https://rpc.test"
            rpc_methods.append(method_name)
            if method_name == "eth_chainId":
                return "0x1079"
            if method_name == "eth_getTransactionCount":
                return next(nonces)
            if method_name == "eth_gasPrice":
                return "0x1"
            raise AssertionError(f"Unexpected RPC method: {method_name}")

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=0x186A0)),
        ):
            first = await method.create_credential(challenge)
            second = await method.create_credential(challenge)

        assert first.payload["type"] == "transaction"
        assert second.payload["type"] == "transaction"
        assert rpc_methods.count("eth_chainId") == 1
        assert rpc_methods.count("eth_getTransactionCount") == 2
        assert rpc_methods.count("eth_gasPrice") == 2

    @pytest.mark.asyncio
    async def test_create_credential_reuses_cached_rpc_chain_id_for_rejected_switch(self) -> None:
        """Should reject switched chains without refetching an already-cached RPC chain ID."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.main",
            intents={"charge": ChargeIntent()},
        )
        initial_challenge = Challenge(
            id="test-mainnet-cache",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
            realm="test.example.com",
            request_b64="e30",
        )
        switched_challenge = Challenge(
            id="test-testnet-cache",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": 42431},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        rpc_calls: list[tuple[str, str]] = []
        nonces = iter(["0x1"])

        async def fake_rpc_call(
            rpc_url: str,
            method_name: str,
            params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del params, client
            rpc_calls.append((rpc_url, method_name))
            if method_name == "eth_chainId":
                return "0x1079"
            if method_name == "eth_getTransactionCount":
                return next(nonces)
            if method_name == "eth_gasPrice":
                return "0x1"
            raise AssertionError(f"Unexpected RPC call: {rpc_url} {method_name}")

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=0x186A0)),
        ):
            await method.create_credential(initial_challenge)
            with pytest.raises(ValueError, match="client is restricted to 4217"):
                await method.create_credential(switched_challenge)

        chain_id_calls = [call for call in rpc_calls if call[1] == "eth_chainId"]
        assert chain_id_calls == [("https://rpc.main", "eth_chainId")]

    @pytest.mark.asyncio
    async def test_create_credential_binds_auto_memo_to_challenge(self) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(account=account, client_id="client-app", intents={"charge": ChargeIntent()})
        challenge = Challenge(
            id="challenge-123",
            method="tempo",
            intent="charge",
            realm="api.example.com",
            request={
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        with (
            patch(
                "mpp.methods.tempo.client.encode_attribution",
                return_value="0x" + "11" * 32,
            ) as encode_mock,
            patch.object(
                method,
                "_build_tempo_transfer",
                AsyncMock(return_value=("0xdeadbeef", 4217)),
            ) as build_mock,
        ):
            await method.create_credential(challenge)

        encode_mock.assert_called_once_with(
            challenge_id="challenge-123",
            server_id="api.example.com",
            client_id="client-app",
        )
        await_args = build_mock.await_args
        assert await_args is not None
        assert await_args.kwargs["memo"] == "0x" + "11" * 32

    @pytest.mark.asyncio
    async def test_create_credential_treats_empty_memo_as_absent(self) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(account=account, client_id="client-app", intents={"charge": ChargeIntent()})
        challenge = Challenge(
            id="challenge-123",
            method="tempo",
            intent="charge",
            realm="api.example.com",
            request={
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"memo": ""},
            },
        )

        with (
            patch(
                "mpp.methods.tempo.client.encode_attribution",
                return_value="0x" + "22" * 32,
            ) as encode_mock,
            patch.object(
                method,
                "_build_tempo_transfer",
                AsyncMock(return_value=("0xdeadbeef", 4217)),
            ) as build_mock,
        ):
            await method.create_credential(challenge)

        encode_mock.assert_called_once_with(
            challenge_id="challenge-123",
            server_id="api.example.com",
            client_id="client-app",
        )
        await_args = build_mock.await_args
        assert await_args is not None
        assert await_args.kwargs["memo"] == "0x" + "22" * 32

    @pytest.mark.asyncio
    async def test_create_credential_caps_fee_payer_priority_fee_to_policy(self) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=1337,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="test-sponsored-priority-cap",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"feePayer": True, "chainId": 1337},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        async def fake_rpc_call(
            rpc_url: str,
            method_name: str,
            params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del params, client
            assert rpc_url == "https://rpc.test"
            if method_name == "eth_chainId":
                return hex(1337)
            if method_name == "eth_getTransactionCount":
                return "0x1"
            if method_name == "eth_gasPrice":
                return hex(20_000_000_000)
            raise AssertionError(f"Unexpected RPC method: {method_name}")

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=0x186A0)),
        ):
            credential = await method.create_credential(challenge)

        decoded, _, _, _ = decode_fee_payer_envelope(
            bytes.fromhex(credential.payload["signature"][2:])
        )
        max_priority_fee_per_gas = int.from_bytes(decoded[1], "big") if decoded[1] else 0
        assert max_priority_fee_per_gas == get_policy(1337).max_priority_fee_per_gas


class TestChargeIntent:
    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Should work as async context manager."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        async with intent:
            assert intent.name == "charge"

    @pytest.mark.asyncio
    async def test_external_client(self) -> None:
        """Should accept external HTTP client."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        intent = ChargeIntent(http_client=mock_client)
        assert intent._owns_client is False
        await intent.aclose()

    @pytest.mark.asyncio
    async def test_verify_expired_request(self) -> None:
        """Should reject expired requests."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        expired = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        credential = make_credential(payload={"type": "hash", "hash": "0x123"}, expires=expired)

        with pytest.raises(VerificationError, match="expired"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_missing_expires_rejected(self) -> None:
        """Should reject credentials with no expires (fail-closed)."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(payload={"type": "hash", "hash": "0x123"}, expires=None)

        with pytest.raises(VerificationError, match="no expires"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_invalid_payload(self) -> None:
        """Should reject invalid credential payload."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        credential = make_credential(payload="not-a-dict", expires=future)  # type: ignore[arg-type]

        with pytest.raises(VerificationError, match="Invalid credential payload"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_unknown_credential_type(self) -> None:
        """Should reject unknown credential types."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        credential = make_credential(payload={"type": "unknown"}, expires=future)

        with pytest.raises(VerificationError, match="Invalid credential type"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_success(self) -> None:
        """Should verify hash credential with matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")
        realm = "api.example.com"
        challenge_id = "challenge-123"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                    memo,
                                ],
                                "data": amount_data(1000),
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )
        receipt = await intent.verify(
            credential,
            {
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_verify_hash_rejects_plain_transfer_without_challenge_bound_memo(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                ],
                                "data": amount_data(1000),
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_rejects_wrong_challenge_nonce(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")
        memo = encode_attribution(challenge_id="challenge-a", server_id="api.example.com")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                    memo,
                                ],
                                "data": amount_data(1000),
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-b",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_rejects_non_mpp_memo(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                    "0x" + "ab" * 32,
                                ],
                                "data": amount_data(1000),
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_rejects_binding_on_dust_transfer(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")
        realm = "api.example.com"
        challenge_id = "challenge-123"
        correct_memo = encode_attribution(challenge_id=challenge_id, server_id=realm)
        wrong_memo = encode_attribution(challenge_id="challenge-other", server_id=realm)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x0000000000000000000000001111111111111111111111111111111111111111",
                                    correct_memo,
                                ],
                                "data": amount_data(1),
                            },
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                    wrong_memo,
                                ],
                                "data": amount_data(1000),
                            },
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_accepts_explicit_memo_without_challenge_binding(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")
        explicit_memo = "0x" + "ab" * 32

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "logs": [
                            {
                                "address": "0x20c0000000000000000000000000000000000000",
                                "topics": [
                                    TRANSFER_WITH_MEMO_TOPIC,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                    explicit_memo,
                                ],
                                "data": amount_data(1000),
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"memo": explicit_memo},
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_verify_hash_tx_failed(self) -> None:
        """Should raise VerificationError for failed transaction."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {"jsonrpc": "2.0", "result": {"status": "0x0", "logs": []}, "id": 1},
            )
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"}, expires=future)
        with pytest.raises(VerificationError, match="Transaction reverted"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_no_matching_logs(self) -> None:
        """Should reject when no matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {"jsonrpc": "2.0", "result": {"status": "0x1", "logs": []}, "id": 1},
            )
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"}, expires=future)
        with pytest.raises(VerificationError, match="Transfer log"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_duplicate_rejects_without_receipt_fetch(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        tx_hash = "0xabc123"
        await store.put_if_absent(f"mpp:charge:{tx_hash}", tx_hash)
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock()
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": tx_hash}, expires=future)

        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        mock_client.post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_hash_releases_reservation_on_validation_error(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        tx_hash = "0xabc123"
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {"jsonrpc": "2.0", "result": {"status": "0x0", "logs": []}, "id": 1},
            )
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": tx_hash}, expires=future)

        with pytest.raises(VerificationError, match="Transaction reverted"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert await store.get(f"mpp:charge:{tx_hash}") is None

    @pytest.mark.asyncio
    async def test_verify_transaction_success(self) -> None:
        """Should verify transaction credential with matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000
        challenge_id = "challenge-transaction-success"
        realm = "api.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)

        from_topic = "0x" + "0" * 24 + "abcd" * 10
        to_topic = "0x" + "0" * 24 + destination[2:]

        receipt_with_logs = {
            "transactionHash": "0xtxhash123",
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [TRANSFER_WITH_MEMO_TOPIC, from_topic, to_topic, memo],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )
        receipt = await intent.verify(
            credential,
            {
                "amount": str(amount),
                "currency": asset,
                "recipient": destination,
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xtxhash123"
        assert mock_client.post.await_args is not None
        assert mock_client.post.await_args.kwargs["json"]["method"] == "eth_sendRawTransactionSync"

    @pytest.mark.asyncio
    async def test_verify_transaction_accepts_transfer_with_memo_logs(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000
        explicit_memo = "0x" + "ab" * 32

        receipt_with_logs = {
            "transactionHash": "0xtxhash123",
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        explicit_memo,
                    ],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            expires=future,
        )
        receipt = await intent.verify(
            credential,
            {
                "amount": str(amount),
                "currency": asset,
                "recipient": destination,
                "methodDetails": {"memo": explicit_memo},
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xtxhash123"

    @pytest.mark.asyncio
    async def test_verify_transaction_rejects_plain_transfer_without_challenge_bound_memo(
        self,
    ) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000

        receipt_with_logs = {
            "transactionHash": "0xtxhash123",
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                    ],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": str(amount),
                    "currency": asset,
                    "recipient": destination,
                },
            )

    @pytest.mark.asyncio
    async def test_verify_transaction_rejects_wrong_challenge_bound_memo(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000
        memo = encode_attribution(challenge_id="challenge-a", server_id="api.example.com")

        receipt_with_logs = {
            "transactionHash": "0xtxhash123",
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        memo,
                    ],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            challenge_id="challenge-b",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await intent.verify(
                credential,
                {
                    "amount": str(amount),
                    "currency": asset,
                    "recipient": destination,
                },
            )

    @pytest.mark.asyncio
    async def test_verify_transaction_records_hash_and_blocks_hash_reuse(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)
        memo = encode_attribution(
            challenge_id="challenge-123",
            server_id="api.example.com",
        )
        receipt_with_logs = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        memo,
                    ],
                    "data": amount_data(1000),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
        )
        intent._http_client = mock_client

        transaction_credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )
        request = {
            "amount": "1000",
            "currency": asset,
            "recipient": destination,
        }

        receipt = await intent.verify(transaction_credential, request)
        assert receipt.status == "success"
        assert receipt.reference == tx_hash
        assert await store.get(f"mpp:charge:{tx_hash}") is not None

        hash_credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(hash_credential, request)

    @pytest.mark.asyncio
    async def test_verify_transaction_duplicate_fetches_receipt_without_rebroadcast(
        self,
    ) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)
        challenge_id = "challenge-123"
        realm = "api.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)
        receipt_with_logs = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        memo,
                    ],
                    "data": amount_data(1000),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )
        request = {
            "amount": "1000",
            "currency": asset,
            "recipient": destination,
        }

        first_receipt = await intent.verify(credential, request)
        second_receipt = await intent.verify(credential, request)

        assert first_receipt.reference == tx_hash
        assert second_receipt.reference == tx_hash
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync", "eth_getTransactionReceipt"]

    @pytest.mark.asyncio
    async def test_verify_transaction_pre_reserves_hash_on_failed_receipt(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "result": {"transactionHash": tx_hash, "status": "0x0", "logs": []},
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            expires=future,
        )

        with pytest.raises(VerificationError, match="Transaction reverted"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert await store.get(f"mpp:charge:{tx_hash}") is not None

    @pytest.mark.asyncio
    async def test_verify_transaction_rpc_error(self) -> None:
        """Should raise on RPC error."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {"jsonrpc": "2.0", "error": {"message": "insufficient funds"}, "id": 1},
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            expires=future,
        )
        with pytest.raises(VerificationError, match="Transaction submission failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

    @pytest.mark.asyncio
    async def test_verify_transaction_releases_reservation_on_rpc_error(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {"jsonrpc": "2.0", "error": {"message": "insufficient funds"}, "id": 1},
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            expires=future,
        )

        with pytest.raises(VerificationError, match="Transaction submission failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert await store.get(f"mpp:charge:{tx_hash}") is None

    @pytest.mark.asyncio
    async def test_verify_transaction_unknown_type_error_releases_reservation(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "error": {"message": "unknown transaction type"},
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            expires=future,
        )

        with pytest.raises(VerificationError, match="Transaction submission failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert await store.get(f"mpp:charge:{tx_hash}") is None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync"]

    @pytest.mark.asyncio
    async def test_verify_transaction_already_known_error_fetches_receipt(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)
        challenge_id = "challenge-123"
        realm = "api.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)
        receipt_with_logs = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        memo,
                    ],
                    "data": amount_data(1000),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(
                    200,
                    {"jsonrpc": "2.0", "error": {"message": "already known"}, "id": 1},
                ),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )
        request = {
            "amount": "1000",
            "currency": asset,
            "recipient": destination,
        }

        receipt = await intent.verify(credential, request)

        assert receipt.reference == tx_hash
        assert await store.get(f"mpp:charge:{tx_hash}") is not None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync", "eth_getTransactionReceipt"]

    @pytest.mark.asyncio
    async def test_verify_transaction_missing_receipt(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(200, {"jsonrpc": "2.0", "result": None, "id": 1})
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            expires=future,
        )

        with pytest.raises(VerificationError, match="No transaction receipt returned"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )


class TestSponsoredTransfer:
    @pytest.mark.asyncio
    async def test_client_builds_sponsored_transaction(self, httpx_mock: HTTPXMock) -> None:
        """Client should build and return raw tx when fee_payer=True."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )

        # eth_chainId
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        # eth_estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x186a0", "id": 1},
        )

        challenge = Challenge(
            id="test-sponsored",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {
                    "feePayer": True,
                    "feePayerUrl": "https://sponsor.test",
                },
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)

        assert credential.challenge.id == "test-sponsored"
        assert credential.payload["type"] == "transaction"
        assert credential.payload["signature"].startswith("0x78")

    @pytest.mark.asyncio
    async def test_server_submits_sponsored_transaction(self, httpx_mock: HTTPXMock) -> None:
        """Server should submit sponsored tx via external fee payer service."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        challenge_id = "test-sponsored"
        realm = "test.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)

        # External fee payer signs and returns co-signed tx
        httpx_mock.add_response(
            url="https://sponsor.test",
            json={"jsonrpc": "2.0", "result": "0x76cosigned", "id": 1},
        )

        # eth_sendRawTransactionSync to RPC
        httpx_mock.add_response(
            url="https://rpc.test",
            json={
                "jsonrpc": "2.0",
                "result": {
                    "transactionHash": "0xsponsored_hash",
                    "status": "0x1",
                    "logs": [
                        {
                            "address": "0x20c0000000000000000000000000000000000000",
                            "topics": [
                                TRANSFER_WITH_MEMO_TOPIC,
                                "0x000000000000000000000000sender00000000000000000000000000000000",
                                "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                memo,
                            ],
                            "data": amount_data(1000000),
                        }
                    ],
                },
                "id": 1,
            },
        )

        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(
            payload={"type": "transaction", "signature": "0x76abcdef"},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {
                    "feePayer": True,
                    "feePayerUrl": "https://sponsor.test",
                },
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xsponsored_hash"

        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        body = requests[1].read().decode()
        assert '"method":"eth_sendRawTransactionSync"' in body

    @pytest.mark.asyncio
    async def test_server_fee_payer_error(self, httpx_mock: HTTPXMock) -> None:
        """Server should raise VerificationError when external fee payer fails."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        httpx_mock.add_response(
            url="https://sponsor.test",
            json={
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "insufficient funds"},
                "id": 1,
            },
        )

        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(
            payload={"type": "transaction", "signature": "0x76abcdef"},
            expires=future,
        )

        with pytest.raises(VerificationError, match="Fee payer signing failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                    "methodDetails": {
                        "feePayer": True,
                        "feePayerUrl": "https://sponsor.test",
                    },
                },
            )


class TestCosignAsFeePayer:
    """Tests for local fee payer co-signing."""

    def _make_intent(self) -> ChargeIntent:
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})
        return intent

    def _encode_transfer_data(
        self,
        recipient: str,
        amount: int,
        memo: str | None = None,
    ) -> str:
        selector = TRANSFER_WITH_MEMO_SELECTOR if memo is not None else TRANSFER_SELECTOR
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        data = f"0x{selector}{to_padded}{amount_padded}"
        if memo is not None:
            data += memo[2:] if memo.startswith("0x") else memo
        return data

    def _encode_approve_data(self, spender: str, amount: int) -> str:
        spender_padded = spender[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        return f"0x{APPROVE_SELECTOR}{spender_padded}{amount_padded}"

    def _encode_swap_data(
        self,
        token_in: str,
        token_out: str,
        amount_out: int,
        max_amount_in: int,
    ) -> str:
        return (
            f"0x{SWAP_EXACT_AMOUNT_OUT_SELECTOR}"
            f"{token_in[2:].lower().zfill(64)}"
            f"{token_out[2:].lower().zfill(64)}"
            f"{hex(amount_out)[2:].zfill(64)}"
            f"{hex(max_amount_in)[2:].zfill(64)}"
        )

    def _build_client_tx(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        chain_id: int = 42431,
        calls: tuple | None = None,
        access_list: tuple = (),
        gas_limit: int = 100000,
        max_fee_per_gas: int = 1,
        max_priority_fee_per_gas: int = 1,
        valid_before: int | None = None,
        with_memo: str | None = None,
    ) -> str:
        """Build a client-signed fee-payer-awaiting transaction."""
        from pytempo import Call, TempoTransaction

        if calls is None:
            calls = (
                Call.create(
                    to=currency,
                    value=0,
                    data=self._encode_transfer_data(recipient, amount, with_memo),
                ),
            )

        if valid_before is None:
            valid_before = int(datetime.now(UTC).timestamp()) + 300

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            fee_token=None,
            awaiting_fee_payer=True,
            valid_before=valid_before,
            calls=calls,
            access_list=access_list,
        )

        signed = tx.sign(TEST_PRIVATE_KEY)

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        return "0x" + encode_fee_payer_envelope(signed).hex()

    def test_cosign_roundtrip(self) -> None:
        """Should successfully co-sign a valid client transaction."""
        intent = self._make_intent()

        raw_tx = self._build_client_tx()
        result, _ = intent._cosign_as_fee_payer(
            raw_tx, "0x20c0000000000000000000000000000000000000"
        )

        assert result.startswith("0x76")
        assert len(result) > len(raw_tx)

    def test_cosign_rejects_wrong_tx_type(self) -> None:
        """Should reject transactions that aren't type 0x78."""
        intent = self._make_intent()

        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0x02abcdef", "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_malformed_hex(self) -> None:
        """Should reject non-hex input."""
        intent = self._make_intent()

        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0xZZZZ", "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_no_fee_payer(self) -> None:
        """Should raise when no fee payer account is configured."""
        intent = ChargeIntent(rpc_url="https://rpc.test")

        with pytest.raises(VerificationError, match="No fee payer account configured"):
            intent._cosign_as_fee_payer("0x76abcdef", "0x20c0000000000000000000000000000000000000")

    def test_cosign_validates_call_target(self) -> None:
        """Should reject tx targeting wrong currency when request is provided."""
        intent = self._make_intent()

        raw_tx = self._build_client_tx(
            currency="0x20c0000000000000000000000000000000000000",
            amount=1000000,
        )

        request = ChargeRequest(
            amount="1000000",
            currency="0xDEAD000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_validates_amount(self) -> None:
        """Should reject tx with wrong amount when request is provided."""
        intent = self._make_intent()

        raw_tx = self._build_client_tx(amount=1000000)

        request = ChargeRequest(
            amount="9999999",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_validates_recipient(self) -> None:
        """Should reject tx with wrong recipient when request is provided."""
        intent = self._make_intent()

        raw_tx = self._build_client_tx(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00")

        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0xDEAD000000000000000000000000000000000000",
        )

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_accepts_matching_request(self) -> None:
        """Should succeed when tx matches request parameters."""
        intent = self._make_intent()

        raw_tx = self._build_client_tx(
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            amount=1000000,
        )

        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        result, _ = intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)
        assert result.startswith("0x76")

    def test_cosign_rejects_extra_trailing_call(self) -> None:
        """Should reject sponsored transactions with extra trailing calls."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", 1000000
                    ),
                ),
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x1111111111111111111111111111111111111111", 1
                    ),
                ),
            )
        )
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="unauthorized extra calls"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_rejects_extra_leading_call(self) -> None:
        """Should reject sponsored transactions with extra leading calls."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x1111111111111111111111111111111111111111", 1
                    ),
                ),
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", 1000000
                    ),
                ),
            )
        )
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="unauthorized extra calls"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_rejects_disallowed_selector(self) -> None:
        """Should reject sponsored transactions with non-payment selectors."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data="0xdeadbeef",
                ),
            )
        )
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="disallowed call pattern"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_rejects_approve_binding_mismatch(self) -> None:
        """Should reject swap prefixes whose approval is bound to the wrong token."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x0000000000000000000000000000000000000004",
                    value=0,
                    data=self._encode_approve_data(STABLECOIN_DEX, 2000000),
                ),
                Call.create(
                    to=STABLECOIN_DEX,
                    value=0,
                    data=self._encode_swap_data(
                        "0x0000000000000000000000000000000000000003",
                        "0x20c0000000000000000000000000000000000000",
                        1000000,
                        2000000,
                    ),
                ),
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", 1000000
                    ),
                ),
            )
        )
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        with pytest.raises(VerificationError, match="approve target does not match"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_rejects_gas_over_policy(self) -> None:
        """Should reject sponsored transactions above the gas limit policy."""
        intent = self._make_intent()
        raw_tx = self._build_client_tx(gas_limit=2_000_001)

        with pytest.raises(VerificationError, match="gas limit exceeds sponsor policy"):
            intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_max_fee_over_policy(self) -> None:
        """Should reject sponsored transactions above the max fee per gas policy."""
        intent = self._make_intent()
        raw_tx = self._build_client_tx(max_fee_per_gas=100_000_000_001)

        with pytest.raises(VerificationError, match="max fee per gas exceeds sponsor policy"):
            intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_priority_fee_above_max_fee(self) -> None:
        """Should reject inconsistent fee caps."""
        intent = self._make_intent()
        with patch("pytempo.models.TempoTransaction.validate", return_value=None):
            raw_tx = self._build_client_tx(max_fee_per_gas=5, max_priority_fee_per_gas=6)

        with pytest.raises(VerificationError, match="max priority fee per gas exceeds max fee"):
            intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_total_fee_budget_over_policy(self) -> None:
        """Should reject sponsored transactions above the total fee budget."""
        intent = self._make_intent()
        raw_tx = self._build_client_tx(gas_limit=1_000_000, max_fee_per_gas=60_000_000_000)

        with pytest.raises(VerificationError, match="total fee budget exceeds sponsor policy"):
            intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_validity_window_over_policy(self) -> None:
        """Should reject sponsored transactions whose validity window is too long."""
        intent = self._make_intent()
        with patch("mpp.methods.tempo.intents.time.time", return_value=1_700_000_000):
            raw_tx = self._build_client_tx(valid_before=1_700_000_000 + 901)
            with pytest.raises(VerificationError, match="validity window exceeds sponsor policy"):
                intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_non_empty_access_list(self) -> None:
        """Should reject sponsored transactions with access lists."""
        from pytempo import AccessListItem

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            access_list=(
                AccessListItem.create(
                    address="0x1111111111111111111111111111111111111111",
                    storage_keys=(b"\x00" * 32,),
                ),
            )
        )

        with pytest.raises(VerificationError, match="access list is not allowed"):
            intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

    def test_cosign_accepts_swap_prefix_when_bound_correctly(self) -> None:
        """Should accept approve + swap + transfer when the swap is bound correctly."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x0000000000000000000000000000000000000003",
                    value=0,
                    data=self._encode_approve_data(STABLECOIN_DEX, 2000000),
                ),
                Call.create(
                    to=STABLECOIN_DEX,
                    value=0,
                    data=self._encode_swap_data(
                        "0x0000000000000000000000000000000000000003",
                        "0x20c0000000000000000000000000000000000000",
                        1000000,
                        2000000,
                    ),
                ),
                Call.create(
                    to="0x20c0000000000000000000000000000000000000",
                    value=0,
                    data=self._encode_transfer_data(
                        "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", 1000000
                    ),
                ),
            )
        )
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        result, _ = intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)
        assert result.startswith("0x76")

    # The simulate payload must target the co-signed tx: the recovered sender as
    # `from`, the sponsor fields the node needs (feeToken, feePayerSignature), the
    # payment calls, the expiring nonceKey, the validity window, and validation off.
    def test_cosign_returns_simulate_payload_with_sponsor_abi(self) -> None:
        intent = self._make_intent()
        currency = "0x20c0000000000000000000000000000000000000"

        raw_tx = self._build_client_tx(currency=currency)
        _result, payload = intent._cosign_as_fee_payer(raw_tx, currency)
        tx_request = payload["blockStateCalls"][0]["calls"][0]

        sender = TempoAccount.from_key(TEST_PRIVATE_KEY).address
        assert payload["validation"] is False
        assert tx_request["type"] == "0x76"
        assert tx_request["from"].lower() == sender.lower()
        assert tx_request["feeToken"].lower() == currency.lower()
        sig = tx_request["feePayerSignature"]
        assert set(sig) == {"r", "s", "yParity"}
        assert re.fullmatch(r"0x[0-9a-f]{64}", sig["r"])
        assert re.fullmatch(r"0x[0-9a-f]{64}", sig["s"])
        assert sig["yParity"] in ("0x0", "0x1")
        assert tx_request["nonceKey"].startswith("0x")
        assert tx_request["validBefore"].startswith("0x")
        # Top-level payment call (with `data`, not `input`) so it isn't a CREATE.
        assert tx_request["to"].lower() == currency.lower()
        assert tx_request["data"].startswith("0x")
        assert tx_request["value"].startswith("0x")
        # A single-call charge needs no nested batch.
        assert "calls" not in tx_request

    # The node appends the top-level call after `calls[]`, so the final call
    # goes top-level and the leading calls in `calls`, preserving order.
    def test_build_simulate_payload_multi_call_preserves_order(self) -> None:
        from types import SimpleNamespace

        intent = self._make_intent()

        def _call(byte: int) -> SimpleNamespace:
            return SimpleNamespace(
                to=bytes([byte]) * 20,
                value=0,
                data=bytes([byte]) * 4,
            )

        calls = (_call(0xA1), _call(0xB2), _call(0xC3))
        tx = SimpleNamespace(
            fee_payer_signature=SimpleNamespace(r=1, s=2, v=27),
            chain_id=42431,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            fee_token=bytes(20),
            calls=calls,
            valid_before=None,
            valid_after=None,
        )

        payload = intent._build_simulate_payload(tx, "0x" + "11" * 20)
        tx_request = payload["blockStateCalls"][0]["calls"][0]

        assert tx_request["to"] == "0x" + "c3" * 20
        assert tx_request["data"] == "0x" + "c3" * 4
        assert [c["to"] for c in tx_request["calls"]] == [
            "0x" + "a1" * 20,
            "0x" + "b2" * 20,
        ]
        assert all("data" in c and "input" not in c for c in tx_request["calls"])

    def _cosign_payload(self, intent: ChargeIntent) -> dict:
        currency = "0x20c0000000000000000000000000000000000000"
        raw_tx = self._build_client_tx(currency=currency)
        _result, payload = intent._cosign_as_fee_payer(raw_tx, currency)
        return payload

    # A reverting simulation must block the broadcast so the sponsor never pays
    # gas for a failing transaction.
    @pytest.mark.asyncio
    async def test_simulate_before_broadcast_rejects_revert(self) -> None:
        intent = self._make_intent()
        payload = self._cosign_payload(intent)
        revert = {
            "jsonrpc": "2.0",
            "result": {
                "blocks": [
                    {"calls": [{"status": "0x0", "error": {"message": "execution reverted"}}]}
                ]
            },
            "id": 1,
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response(200, revert))

        with pytest.raises(VerificationError, match="would revert"):
            await intent._simulate_before_broadcast(mock_client, payload, "https://rpc.test")
        sent = mock_client.post.await_args.kwargs["json"]
        assert sent["method"] == "tempo_simulateV1"
        assert sent["params"][1] == "latest"

    # A successful simulation must let the broadcast proceed.
    @pytest.mark.asyncio
    async def test_simulate_before_broadcast_accepts_success(self) -> None:
        intent = self._make_intent()
        payload = self._cosign_payload(intent)
        success = {
            "jsonrpc": "2.0",
            "result": {"blocks": [{"calls": [{"status": "0x1"}]}]},
            "id": 1,
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response(200, success))

        assert (
            await intent._simulate_before_broadcast(mock_client, payload, "https://rpc.test")
            is None
        )

    # If the simulation RPC itself errors, fail closed.
    @pytest.mark.asyncio
    async def test_simulate_before_broadcast_fails_closed_on_rpc_error(self) -> None:
        intent = self._make_intent()
        payload = self._cosign_payload(intent)
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=RuntimeError("node unavailable"))

        with pytest.raises(VerificationError, match="Pre-broadcast simulation failed"):
            await intent._simulate_before_broadcast(mock_client, payload, "https://rpc.test")

    # End-to-end: a reverting simulation for a locally co-signed sponsored charge
    # must abort `verify` before the tx is broadcast, so the sponsor never pays
    # gas. We register only the simulate response; if the code wrongly attempted
    # eth_sendRawTransactionSync, no response would match and the test would fail.
    @pytest.mark.asyncio
    async def test_verify_local_fee_payer_revert_does_not_broadcast(
        self, httpx_mock: HTTPXMock
    ) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

        intent = self._make_intent()
        raw_tx = self._build_client_tx(currency=currency, recipient=recipient, amount=1000000)
        credential = make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            expires=future,
        )

        # tempo_simulateV1 reports the co-signed tx would revert.
        httpx_mock.add_response(
            url="https://rpc.test",
            json={
                "jsonrpc": "2.0",
                "result": {
                    "blocks": [
                        {"calls": [{"status": "0x0", "error": {"message": "execution reverted"}}]}
                    ]
                },
                "id": 1,
            },
        )

        with pytest.raises(VerificationError, match="would revert"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": currency,
                    "recipient": recipient,
                    "methodDetails": {"feePayer": True},
                },
            )

        # Exactly one RPC call (the simulation); no broadcast was attempted.
        requests = httpx_mock.get_requests()
        methods = [json.loads(r.read().decode())["method"] for r in requests]
        assert methods == ["tempo_simulateV1"]
        assert "eth_sendRawTransactionSync" not in methods

    # An already-reserved charge fetches the existing receipt without simulating.
    @pytest.mark.asyncio
    async def test_verify_duplicate_skips_simulation_and_fetches_receipt(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        challenge_id = "challenge-dup"
        realm = "api.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)

        intent = self._make_intent()
        store = MemoryStore()
        intent._store = store

        # Reserve the co-signed tx hash that verify() will compute.
        raw_tx = self._build_client_tx(currency=currency, recipient=recipient, amount=1000000)
        cosigned_raw, _ = intent._cosign_as_fee_payer(raw_tx, currency)
        tx_hash = _raw_transaction_hash(cosigned_raw)
        await store.put_if_absent(f"mpp:charge:{tx_hash.lower()}", tx_hash)

        receipt_with_logs = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "logs": [
                {
                    "address": currency,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + recipient[2:],
                        memo,
                    ],
                    "data": amount_data(1000000),
                }
            ],
        }

        def _post(*_args: object, **kwargs: object) -> httpx.Response:
            method = cast(dict, kwargs["json"])["method"]
            if method == "tempo_simulateV1":
                return mock_response(200, {"jsonrpc": "2.0", "error": {"message": "node busy"}})
            if method == "eth_getTransactionReceipt":
                return mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1})
            raise AssertionError(f"unexpected RPC method: {method}")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=_post)
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000000",
                "currency": currency,
                "recipient": recipient,
                "methodDetails": {"feePayer": True},
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == tx_hash
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_getTransactionReceipt"]
        assert "tempo_simulateV1" not in methods

    # A simulation failure releases the reservation and does not broadcast.
    @pytest.mark.asyncio
    async def test_verify_simulation_failure_releases_reservation(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

        intent = self._make_intent()
        store = MemoryStore()
        intent._store = store

        raw_tx = self._build_client_tx(currency=currency, recipient=recipient, amount=1000000)
        cosigned_raw, _ = intent._cosign_as_fee_payer(raw_tx, currency)
        tx_hash = _raw_transaction_hash(cosigned_raw)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200, {"jsonrpc": "2.0", "error": {"message": "node busy"}, "id": 1}
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            expires=future,
        )

        with pytest.raises(VerificationError, match="Pre-broadcast simulation failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": currency,
                    "recipient": recipient,
                    "methodDetails": {"feePayer": True},
                },
            )

        assert await store.get(f"mpp:charge:{tx_hash.lower()}") is None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["tempo_simulateV1"]
        assert "eth_sendRawTransactionSync" not in methods


class TestValidateTransactionPayload:
    """Tests for _validate_transaction_payload with both 0x76 and 0x78."""

    def _encode_transfer_data(
        self,
        recipient: str,
        amount: int,
        memo: str | None = None,
    ) -> str:
        selector = TRANSFER_WITH_MEMO_SELECTOR if memo is not None else TRANSFER_SELECTOR
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        data = f"0x{selector}{to_padded}{amount_padded}"
        if memo is not None:
            data += memo[2:] if memo.startswith("0x") else memo
        return data

    def _build_0x78_envelope(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        memo: str | None = None,
    ) -> str:
        """Build a 0x78 fee payer envelope."""
        from pytempo import Call, TempoTransaction

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        transfer_data = self._encode_transfer_data(recipient, amount, memo)

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            fee_token=None,
            awaiting_fee_payer=True,
            valid_before=9999999999,
            calls=(Call.create(to=currency, value=0, data=transfer_data),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        return "0x" + encode_fee_payer_envelope(signed).hex()

    def _build_0x76_tx(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        memo: str | None = None,
    ) -> str:
        """Build a standard 0x76 transaction."""
        import attrs
        from pytempo import Call, TempoTransaction
        from pytempo.models import Signature

        transfer_data = self._encode_transfer_data(recipient, amount, memo)

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=0,
            fee_token=currency,
            calls=(Call.create(to=currency, value=0, data=transfer_data),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        signed = attrs.evolve(signed, fee_payer_signature=Signature(r=1, s=1, v=27))
        return "0x" + signed.encode().hex()

    def test_accepts_0x78_with_matching_call(self) -> None:
        """Should accept a 0x78 envelope with a valid payment call."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x78_envelope()
        # Should not raise
        intent._validate_transaction_payload(sig, request)

    def test_accepts_0x78_with_transfer_with_memo_when_no_server_memo(self) -> None:
        """Should accept 0x78 envelopes with client attribution memos."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        memo = encode_attribution(challenge_id="challenge-123", server_id="api.example.com")
        sig = self._build_0x78_envelope(memo=memo)

        intent._validate_transaction_payload(sig, request)

    def test_rejects_0x78_with_wrong_amount(self) -> None:
        """Should reject a 0x78 envelope with mismatched amount."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="9999999",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x78_envelope(amount=1000000)
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(sig, request)

    def test_rejects_0x78_with_wrong_currency(self) -> None:
        """Should reject a 0x78 envelope targeting wrong currency."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0xDEAD000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x78_envelope()
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(sig, request)

    def test_rejects_0x78_with_extra_call(self) -> None:
        """Should reject a 0x78 envelope with unauthorized extra calls."""
        from pytempo import Call, TempoTransaction

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            fee_token=None,
            awaiting_fee_payer=True,
            valid_before=9999999999,
            calls=(
                Call.create(
                    to=request.currency,
                    value=0,
                    data=self._encode_transfer_data(request.recipient, 1000000),
                ),
                Call.create(
                    to=request.currency,
                    value=0,
                    data=self._encode_transfer_data(
                        "0x1111111111111111111111111111111111111111", 1
                    ),
                ),
            ),
        )
        sig = "0x" + encode_fee_payer_envelope(tx.sign(TEST_PRIVATE_KEY)).hex()

        with pytest.raises(VerificationError, match="unauthorized extra calls"):
            intent._validate_transaction_payload(sig, request)

    def test_accepts_0x76_with_matching_call(self) -> None:
        """Should still accept standard 0x76 transactions."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x76_tx()
        # Should not raise
        intent._validate_transaction_payload(sig, request)

    def test_silently_skips_unknown_prefix(self) -> None:
        """Should silently skip transactions with unrecognized type prefix."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        # 0x02 prefix — should silently skip (not raise)
        intent._validate_transaction_payload("0x02abcdef", request)


class TestFeePayerPropagation:
    """Tests for fee_payer propagation through tempo() factory."""

    def test_tempo_propagates_fee_payer(self) -> None:
        """tempo() should propagate fee_payer to intents via _method backlink."""
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent()
        tempo(
            fee_payer=fee_payer,
            rpc_url="https://rpc.test",
            intents={"charge": intent},
        )
        assert intent.fee_payer is fee_payer

    def test_fee_payer_none_by_default(self) -> None:
        """ChargeIntent should have no fee_payer when tempo() is called without one."""
        intent = ChargeIntent()
        tempo(rpc_url="https://rpc.test", intents={"charge": intent})
        assert intent.fee_payer is None

    def test_fee_payer_none_standalone(self) -> None:
        """ChargeIntent should have no fee_payer when used standalone."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        assert intent.fee_payer is None


class TestSchemas:
    def test_charge_request_valid(self) -> None:
        """Should validate charge request with default methodDetails."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        assert req.amount == "1000"
        assert req.methodDetails.feePayer is False
        assert req.methodDetails.chainId == 4217

    def test_charge_request_with_fee_payer(self) -> None:
        """Should accept methodDetails with feePayer and feePayerUrl."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            methodDetails=MethodDetails(
                feePayer=True,
                feePayerUrl="https://sponsor.test",
            ),
        )
        assert req.methodDetails.feePayer is True
        assert req.methodDetails.feePayerUrl == "https://sponsor.test"

    def test_hash_credential_payload(self) -> None:
        """Should validate hash credential payload."""
        payload = HashCredentialPayload(type="hash", hash="0xabc123")
        assert payload.type == "hash"
        assert payload.hash == "0xabc123"

    def test_transaction_credential_payload(self) -> None:
        """Should validate transaction credential payload."""
        payload = TransactionCredentialPayload(type="transaction", signature="0xdef456")
        assert payload.type == "transaction"
        assert payload.signature == "0xdef456"

    def test_charge_request_with_description(self) -> None:
        """Should accept optional description field."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            description="Payment for API access",
        )
        assert req.description == "Payment for API access"

    def test_charge_request_with_external_id(self) -> None:
        """Should accept optional externalId field."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            externalId="order-12345",
        )
        assert req.externalId == "order-12345"

    def test_charge_request_description_and_external_id_default_none(self) -> None:
        """description and externalId should default to None."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        assert req.description is None
        assert req.externalId is None

    def test_charge_request_serializes_optional_fields(self) -> None:
        """Optional fields should appear in model_dump when set."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            description="Test payment",
            externalId="ext-001",
        )
        data = req.model_dump()
        assert data["description"] == "Test payment"
        assert data["externalId"] == "ext-001"


class TestDefaults:
    """Tests for chain-aware defaults and exports."""

    def test_chain_id_constants(self) -> None:
        """CHAIN_ID and TESTNET_CHAIN_ID should be exported and correct."""
        assert CHAIN_ID == 4217
        assert TESTNET_CHAIN_ID == 42431

    def test_escrow_contracts_per_chain(self) -> None:
        """ESCROW_CONTRACTS should map both mainnet and testnet."""
        assert CHAIN_ID in ESCROW_CONTRACTS
        assert TESTNET_CHAIN_ID in ESCROW_CONTRACTS
        assert ESCROW_CONTRACTS[CHAIN_ID] == "0x33b901018174DDabE4841042ab76ba85D4e24f25"
        assert ESCROW_CONTRACTS[TESTNET_CHAIN_ID] == "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"

    def test_escrow_contract_for_chain_mainnet(self) -> None:
        """escrow_contract_for_chain should return mainnet address."""
        addr = escrow_contract_for_chain(4217)
        assert addr == "0x33b901018174DDabE4841042ab76ba85D4e24f25"

    def test_escrow_contract_for_chain_testnet(self) -> None:
        """escrow_contract_for_chain should return testnet address."""
        addr = escrow_contract_for_chain(42431)
        assert addr == "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"

    def test_escrow_contract_for_chain_unknown(self) -> None:
        """escrow_contract_for_chain should raise for unknown chain."""
        with pytest.raises(ValueError, match="Unknown chain_id 99999"):
            escrow_contract_for_chain(99999)

    def test_chain_rpc_urls_matches_escrow_contracts(self) -> None:
        """CHAIN_RPC_URLS and ESCROW_CONTRACTS should cover the same chains."""
        assert set(CHAIN_RPC_URLS.keys()) == set(ESCROW_CONTRACTS.keys())


class TestChainIdPropagation:
    """Tests for chain_id propagation through tempo() factory and Mpp."""

    def test_tempo_factory_stores_chain_id(self) -> None:
        """tempo(chain_id=...) should store chain_id on the method."""
        method = tempo(chain_id=42431, intents={"charge": ChargeIntent()})
        assert method.chain_id == 42431

    def test_tempo_factory_chain_id_defaults_mainnet(self) -> None:
        """tempo() without chain_id should default to 4217 (mainnet)."""
        method = tempo(intents={"charge": ChargeIntent()})
        assert method.chain_id == 4217

    def test_tempo_factory_chain_id_resolves_rpc(self) -> None:
        """tempo(chain_id=42431) should resolve testnet RPC URL."""
        method = tempo(chain_id=42431, intents={"charge": ChargeIntent()})
        assert method.rpc_url == "https://rpc.moderato.tempo.xyz"

    def test_tempo_factory_rpc_url_overrides_chain_id(self) -> None:
        """Explicit rpc_url should override chain_id resolution."""
        method = tempo(
            chain_id=42431,
            rpc_url="https://custom.rpc",
            intents={"charge": ChargeIntent()},
        )
        assert method.rpc_url == "https://custom.rpc"

    @pytest.mark.asyncio
    async def test_client_rejects_challenge_chain_id_that_switches_default_network(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Client should reject challenges that try to switch away from its default chain."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="test-chain-switch-default",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": 42431},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        with pytest.raises(ValueError, match="client is restricted to 4217"):
            await method.create_credential(challenge)

        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_client_rejects_challenge_chain_id_that_switches_explicit_rpc(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Client should reject challenges that try to switch away from a pinned RPC."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.custom",
            intents={"charge": ChargeIntent()},
        )
        get_chain_id = AsyncMock(return_value=TESTNET_CHAIN_ID)
        monkeypatch.setattr(method, "_get_chain_id", get_chain_id)

        challenge = Challenge(
            id="test-chain-switch-explicit-rpc",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": CHAIN_ID},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        with pytest.raises(ValueError, match=rf"client is restricted to {TESTNET_CHAIN_ID}"):
            await method.create_credential(challenge)

        get_chain_id.assert_awaited_once_with("https://rpc.custom")

    @pytest.mark.asyncio
    async def test_client_ignores_non_numeric_chain_id(self, httpx_mock: HTTPXMock) -> None:
        """Client should ignore non-numeric chainId and fall back to method rpc_url."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.custom",
            intents={"charge": ChargeIntent()},
        )

        # eth_chainId
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x186a0", "id": 1},
        )

        challenge = Challenge(
            id="test-bad-chain-id",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": "not-a-number"},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)
        assert credential.payload["type"] == "transaction"

    @pytest.mark.asyncio
    async def test_client_chain_id_mismatch_raises(self, httpx_mock: HTTPXMock) -> None:
        """Client should raise TransactionError when RPC chain ID != challenge chain ID."""
        from mpp.methods.tempo.client import TransactionError

        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=TESTNET_CHAIN_ID,
            rpc_url="https://rpc.custom",
            intents={"charge": ChargeIntent()},
        )

        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},  # 4217, wrong!
        )
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.custom",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )

        challenge = Challenge(
            id="test-mismatch",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": TESTNET_CHAIN_ID},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        with pytest.raises(TransactionError, match="Chain ID mismatch"):
            await method.create_credential(challenge)


class TestAccessKeySigning:
    """Tests for access key (root_account) signing flow."""

    @pytest.mark.asyncio
    async def test_access_key_builds_keychain_signature(self, httpx_mock: HTTPXMock) -> None:
        """When root_account is set, should use sign_tx_access_key."""
        access_key = TempoAccount.from_key(TEST_PRIVATE_KEY)
        root = "0x975937feafc6869a260c176854dda8764a78e122"
        method = tempo(
            account=access_key,
            root_account=root,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )

        # Mock RPC: chain_id (4217=0x1079), nonce, gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(3):
            httpx_mock.add_response(
                url="https://rpc.test",
                json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
            )

        challenge = Challenge(
            id="test-access-key",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)

        assert credential.payload["type"] == "transaction"
        # source should be the root account, not the access key
        assert credential.source is not None
        assert root.lower() in credential.source.lower()
        assert access_key.address.lower() not in credential.source.lower()

    @pytest.mark.asyncio
    async def test_access_key_with_fee_payer(self, httpx_mock: HTTPXMock) -> None:
        """Access key + feePayer should produce a 0x78 envelope with keychain sig."""
        access_key = TempoAccount.from_key(TEST_PRIVATE_KEY)
        root = "0x975937feafc6869a260c176854dda8764a78e122"
        method = tempo(
            account=access_key,
            root_account=root,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )

        # Mock RPC: chain_id (4217=0x1079), nonce, gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(3):
            httpx_mock.add_response(
                url="https://rpc.test",
                json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
            )

        challenge = Challenge(
            id="test-access-key-sponsored",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"feePayer": True, "chainId": 4217},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)

        assert credential.payload["type"] == "transaction"
        assert credential.payload["signature"].startswith("0x78")
        assert credential.source is not None
        assert root.lower() in credential.source.lower()

    @pytest.mark.asyncio
    async def test_no_root_account_uses_regular_signing(self, httpx_mock: HTTPXMock) -> None:
        """Without root_account, should use regular tx.sign()."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )

        # Mock RPC: chain_id (4217=0x1079), nonce, gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(3):
            httpx_mock.add_response(
                url="https://rpc.test",
                json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
            )

        challenge = Challenge(
            id="test-no-root",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)

        assert credential.payload["type"] == "transaction"
        assert credential.source is not None
        assert account.address in credential.source


class TestMatchTransferCalldataWithMemo:
    """Tests for _match_transfer_calldata with memo field."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    AMOUNT = 1000000
    MEMO = "0x" + "ab" * 32

    def _make_request(self, memo: str | None = None) -> ChargeRequest:
        return ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(memo=memo),
        )

    def _build_calldata(self, selector: str, recipient: str, amount: int, memo: str = "") -> str:
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        memo_part = memo[2:] if memo.startswith("0x") else memo
        return f"{selector}{to_padded}{amount_padded}{memo_part}"

    def test_memo_requires_transfer_with_memo_selector(self) -> None:
        """When memo is set, plain transfer selector should be rejected."""
        request = self._make_request(memo=self.MEMO)
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO)
        assert _match_transfer_calldata(calldata, request) is False

    def test_memo_accepts_correct_selector(self) -> None:
        """When memo is set, transferWithMemo selector should be accepted."""
        request = self._make_request(memo=self.MEMO)
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
        )
        assert _match_transfer_calldata(calldata, request) is True

    def test_memo_wrong_memo_value(self) -> None:
        """Wrong memo value should be rejected."""
        request = self._make_request(memo=self.MEMO)
        wrong_memo = "0x" + "cc" * 32
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, wrong_memo
        )
        assert _match_transfer_calldata(calldata, request) is False

    def test_memo_short_calldata_rejected(self) -> None:
        """Calldata shorter than 200 hex chars should be rejected when memo expected."""
        request = self._make_request(memo=self.MEMO)
        # Only selector + to + amount = 136 chars, no memo
        to_padded = self.RECIPIENT[2:].lower().zfill(64)
        amount_padded = hex(self.AMOUNT)[2:].zfill(64)
        calldata = f"{TRANSFER_WITH_MEMO_SELECTOR}{to_padded}{amount_padded}"
        assert _match_transfer_calldata(calldata, request) is False

    def test_memo_normalization_no_0x_prefix(self) -> None:
        """Memo without 0x prefix should be normalized and matched."""
        memo_no_prefix = "ab" * 32
        request = self._make_request(memo=memo_no_prefix)
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, "0x" + memo_no_prefix
        )
        assert _match_transfer_calldata(calldata, request) is True

    def test_no_memo_accepts_plain_transfer_and_transfer_with_memo(self) -> None:
        """When no memo, plain transfer and transferWithMemo should be accepted."""
        request = self._make_request(memo=None)
        calldata_plain = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        calldata_memo = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
        )
        assert _match_transfer_calldata(calldata_plain, request) is True
        assert _match_transfer_calldata(calldata_memo, request) is True

    def test_no_memo_rejects_short_transfer_with_memo_calldata(self) -> None:
        """When no memo, truncated transferWithMemo calldata should still be rejected."""
        request = self._make_request(memo=None)
        calldata = self._build_calldata(TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_transfer_calldata(calldata, request) is False

    def test_short_calldata_rejected(self) -> None:
        """Calldata shorter than 136 chars should always be rejected."""
        request = self._make_request()
        assert _match_transfer_calldata("a9059cbb", request) is False

    def test_wrong_selector_rejected(self) -> None:
        """A completely bogus selector should be rejected."""
        request = self._make_request()
        calldata = self._build_calldata("deadbeef", self.RECIPIENT, self.AMOUNT)
        assert _match_transfer_calldata(calldata, request) is False

    def test_uppercase_hex_normalization(self) -> None:
        """Uppercase hex in recipient/amount should still match (case-insensitive)."""
        request = self._make_request()
        to_padded = self.RECIPIENT[2:].upper().zfill(64)
        amount_padded = hex(self.AMOUNT)[2:].upper().zfill(64)
        calldata = f"{TRANSFER_SELECTOR}{to_padded}{amount_padded}"
        assert _match_transfer_calldata(calldata, request) is True


class TestVerifyTransferLogsWithMemo:
    """Tests for _verify_transfer_logs with memo field."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    AMOUNT = 1000000
    MEMO = "0x" + "ab" * 32

    def _make_receipt(self, logs: list) -> dict:
        return {"status": "0x1", "logs": logs}

    def _make_request(self, memo: str | None = None) -> ChargeRequest:
        return ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(memo=memo),
        )

    def test_empty_memo_normalizes_to_none(self) -> None:
        request = self._make_request(memo="")
        assert request.methodDetails.memo is None

    def test_memo_log_accepted(self) -> None:
        """TransferWithMemo log with correct memo should be accepted."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request(memo=self.MEMO)
        receipt = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                        self.MEMO,
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                }
            ]
        )
        matched_logs = intent._verify_transfer_logs(receipt, request)
        assert len(matched_logs) == 1
        assert matched_logs[0].kind == "memo"
        assert matched_logs[0].memo == self.MEMO

    def test_memo_log_wrong_memo_rejected(self) -> None:
        """TransferWithMemo log with wrong memo should be rejected."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request(memo=self.MEMO)
        receipt = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                        "0x" + "cc" * 32,
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                }
            ]
        )
        assert intent._verify_transfer_logs(receipt, request) == []

    def test_memo_log_too_few_topics_rejected(self) -> None:
        """TransferWithMemo log with < 4 topics should be skipped."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request(memo=self.MEMO)
        receipt = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                }
            ]
        )
        assert intent._verify_transfer_logs(receipt, request) == []

    def test_no_memo_accepts_transfer_and_transfer_with_memo_logs(self) -> None:
        """When no memo is configured, both matching log types should be accepted."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request(memo=None)

        receipt_memo_topic = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                        self.MEMO,
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                }
            ]
        )
        matched_memo_logs = intent._verify_transfer_logs(receipt_memo_topic, request)
        assert len(matched_memo_logs) == 1
        assert matched_memo_logs[0].kind == "memo"

        receipt_plain = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                }
            ]
        )
        matched_plain_logs = intent._verify_transfer_logs(receipt_plain, request)
        assert len(matched_plain_logs) == 1
        assert matched_plain_logs[0].kind == "transfer"

    def test_no_memo_prefers_matching_memo_logs_over_plain_transfer_logs(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request(memo=None)
        receipt = self._make_receipt(
            [
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                },
                {
                    "address": self.CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + self.RECIPIENT[2:].lower(),
                        self.MEMO,
                    ],
                    "data": "0x" + hex(self.AMOUNT)[2:].zfill(64),
                },
            ]
        )

        matched_logs = intent._verify_transfer_logs(receipt, request)
        assert [matched_log.kind for matched_log in matched_logs] == ["memo", "transfer"]


class TestValidateTransactionPayload0x76:
    """Tests for _validate_transaction_payload with 0x76 transactions."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

    def _make_request(self) -> ChargeRequest:
        return ChargeRequest(
            amount="1000000",
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
        )

    def test_non_tempo_tx_returns_silently(self) -> None:
        """Non-0x76 prefix transaction should be silently skipped."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()
        # 0x02 is a standard EIP-1559 tx prefix
        intent._validate_transaction_payload("0x02abcdef", request)

    def test_invalid_hex_returns_silently(self) -> None:
        """Non-hex signature should be silently skipped."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()
        intent._validate_transaction_payload("0xZZZZ", request)

    def test_empty_calls_raises(self) -> None:
        """Transaction with no calls should raise VerificationError."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()

        # Build minimal RLP: [chain_id, mpfpg, mfpg, gas, calls=[], ...]
        decoded = [b"\x01", b"\x01", b"\x01", b"\x01", [], b"", b"", b"\x00", b"", b"", b""]
        payload = b"\x76" + bytes(rlp.encode(decoded))
        sig = "0x" + payload.hex()

        with pytest.raises(VerificationError, match="no calls"):
            intent._validate_transaction_payload(sig, request)

    def test_valid_tx_with_matching_call_passes(self) -> None:
        """Transaction with a matching transfer call should not raise."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()

        selector = bytes.fromhex("a9059cbb")
        to_padded = bytes.fromhex(self.RECIPIENT[2:].lower().zfill(64))
        amount_padded = bytes.fromhex(hex(1000000)[2:].zfill(64))
        call_data = selector + to_padded + amount_padded

        currency_bytes = bytes.fromhex(self.CURRENCY[2:])
        call = [currency_bytes, b"", call_data]
        decoded = [b"\x01", b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
        payload = b"\x76" + rlp.encode(decoded)  # type: ignore[operator]
        sig = "0x" + payload.hex()

        intent._validate_transaction_payload(sig, request)

    def test_valid_tx_with_transfer_with_memo_passes_when_no_server_memo(self) -> None:
        """Transaction credentials should allow client attribution memos."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()
        memo = encode_attribution(challenge_id="challenge-123", server_id="api.example.com")

        selector = bytes.fromhex(TRANSFER_WITH_MEMO_SELECTOR)
        to_padded = bytes.fromhex(self.RECIPIENT[2:].lower().zfill(64))
        amount_padded = bytes.fromhex(hex(1000000)[2:].zfill(64))
        call_data = selector + to_padded + amount_padded + bytes.fromhex(memo[2:])

        currency_bytes = bytes.fromhex(self.CURRENCY[2:])
        call = [currency_bytes, b"", call_data]
        decoded = [b"\x01", b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
        payload = b"\x76" + rlp.encode(decoded)  # type: ignore[operator]
        sig = "0x" + payload.hex()

        intent._validate_transaction_payload(sig, request)

    def test_no_matching_call_raises(self) -> None:
        """Transaction with no matching call should raise VerificationError."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()

        # Call targeting wrong currency
        wrong_currency = bytes.fromhex("dead" + "00" * 18)
        selector = bytes.fromhex("a9059cbb")
        to_padded = bytes.fromhex(self.RECIPIENT[2:].lower().zfill(64))
        amount_padded = bytes.fromhex(hex(1000000)[2:].zfill(64))
        call_data = selector + to_padded + amount_padded

        call = [wrong_currency, b"", call_data]
        decoded = [b"\x01", b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
        payload = b"\x76" + rlp.encode(decoded)  # type: ignore[operator]
        sig = "0x" + payload.hex()

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(sig, request)


class TestRpcErrorMsg:
    """Tests for _rpc_error_msg helper."""

    def test_dict_error_with_message_and_data(self) -> None:
        result = {"error": {"message": "insufficient funds", "data": "0xdead"}}
        msg = _rpc_error_msg(result)
        assert "insufficient funds" in msg
        assert "0xdead" in msg

    def test_dict_error_message_only(self) -> None:
        result = {"error": {"message": "nonce too low"}}
        msg = _rpc_error_msg(result)
        assert msg == "nonce too low"

    def test_dict_error_name_fallback(self) -> None:
        result = {"error": {"name": "SomeError"}}
        msg = _rpc_error_msg(result)
        assert "SomeError" in msg

    def test_string_error(self) -> None:
        result = {"error": "something broke"}
        msg = _rpc_error_msg(result)
        assert msg == "something broke"


class TestDefaultsImmutability:
    """Tests for read-only defaults dicts."""

    def test_escrow_contracts_is_immutable(self) -> None:
        """ESCROW_CONTRACTS should reject mutation."""
        with pytest.raises(TypeError):
            ESCROW_CONTRACTS[9999] = "0xdead"  # type: ignore[index]

    def test_chain_rpc_urls_is_immutable(self) -> None:
        """CHAIN_RPC_URLS should reject mutation."""
        with pytest.raises(TypeError):
            CHAIN_RPC_URLS[9999] = "https://evil.rpc"  # type: ignore[index]


class TestGetTransfers:
    """Tests for get_transfers() split computation."""

    def test_no_splits_returns_single_transfer(self) -> None:
        transfers = get_transfers(1_000_000, "0x01", None, None)
        assert len(transfers) == 1
        assert transfers[0].amount == 1_000_000
        assert transfers[0].recipient == "0x01"
        assert transfers[0].memo is None

    def test_empty_splits_returns_single_transfer(self) -> None:
        transfers = get_transfers(1_000_000, "0x01", None, [])
        assert len(transfers) == 1

    def test_single_split(self) -> None:
        splits = [
            Split(
                amount="300000",
                recipient="0x1111111111111111111111111111111111111111",
            )
        ]
        transfers = get_transfers(
            1_000_000,
            "0x2222222222222222222222222222222222222222",
            None,
            splits,
        )
        assert len(transfers) == 2
        assert transfers[0].amount == 700_000  # primary gets remainder
        assert transfers[1].amount == 300_000

    def test_primary_inherits_memo(self) -> None:
        memo = "0x" + "ab" * 32
        splits = [
            Split(
                amount="100000",
                recipient="0x1111111111111111111111111111111111111111",
            )
        ]
        transfers = get_transfers(
            1_000_000,
            "0x2222222222222222222222222222222222222222",
            memo,
            splits,
        )
        assert transfers[0].memo is not None
        assert transfers[1].memo is None

    def test_split_with_memo(self) -> None:
        split_memo = "0x" + "cd" * 32
        splits = [
            Split(
                amount="100000",
                recipient="0x1111111111111111111111111111111111111111",
                memo=split_memo,
            )
        ]
        transfers = get_transfers(
            1_000_000,
            "0x2222222222222222222222222222222222222222",
            None,
            splits,
        )
        assert transfers[1].memo is not None
        assert transfers[1].memo[0] == 0xCD

    def test_multiple_splits_preserve_order(self) -> None:
        splits = [
            Split(amount="100000", recipient="0x1111111111111111111111111111111111111111"),
            Split(amount="200000", recipient="0x2222222222222222222222222222222222222222"),
            Split(amount="50000", recipient="0x3333333333333333333333333333333333333333"),
        ]
        transfers = get_transfers(
            1_000_000,
            "0x4444444444444444444444444444444444444444",
            None,
            splits,
        )
        assert len(transfers) == 4
        assert transfers[0].amount == 650_000  # primary
        assert transfers[1].amount == 100_000
        assert transfers[2].amount == 200_000
        assert transfers[3].amount == 50_000

    def test_rejects_sum_equals_total(self) -> None:
        splits = [Split(amount="1000000", recipient="0x1111111111111111111111111111111111111111")]
        with pytest.raises(VerificationError, match="must be less than"):
            get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", None, splits)

    def test_rejects_sum_exceeds_total(self) -> None:
        splits = [Split(amount="1500000", recipient="0x1111111111111111111111111111111111111111")]
        with pytest.raises(VerificationError):
            get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", None, splits)

    def test_rejects_zero_split_amount(self) -> None:
        splits = [Split(amount="0", recipient="0x1111111111111111111111111111111111111111")]
        with pytest.raises(VerificationError, match="greater than zero"):
            get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", None, splits)

    def test_rejects_too_many_splits(self) -> None:
        splits = [
            Split(amount="1000", recipient=f"0x{hex(i + 2)[2:].zfill(40)}") for i in range(11)
        ]
        with pytest.raises(VerificationError, match="Too many splits"):
            get_transfers(1_000_000, "0x0000000000000000000000000000000000000001", None, splits)

    def test_max_splits_allowed(self) -> None:
        splits = [
            Split(amount="1000", recipient=f"0x{hex(i + 2)[2:].zfill(40)}") for i in range(10)
        ]
        transfers = get_transfers(
            1_000_000,
            "0x0000000000000000000000000000000000000001",
            None,
            splits,
        )
        assert len(transfers) == 11
        assert transfers[0].amount == 990_000


class TestVerifyTransferLogsWithSplits:
    """Tests for _verify_transfer_logs with split payments."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    SPLIT_RECIPIENT = "0x1111111111111111111111111111111111111111"
    AMOUNT = 1000000
    SENDER = "0x" + "ab" * 20

    def _make_transfer_log(self, recipient: str, amount: int, memo: str | None = None) -> dict:
        to_padded = "0x" + "0" * 24 + recipient[2:].lower()
        from_padded = "0x" + "0" * 24 + self.SENDER[2:].lower()
        if memo:
            return {
                "address": self.CURRENCY,
                "topics": [TRANSFER_WITH_MEMO_TOPIC, from_padded, to_padded, memo],
                "data": "0x" + hex(amount)[2:].zfill(64),
            }
        return {
            "address": self.CURRENCY,
            "topics": [TRANSFER_TOPIC, from_padded, to_padded],
            "data": "0x" + hex(amount)[2:].zfill(64),
        }

    def test_split_logs_accepted(self) -> None:
        """Receipt with matching split logs should be accepted."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT)]
            ),
        )
        receipt = {
            "status": "0x1",
            "logs": [
                self._make_transfer_log(self.RECIPIENT, 700000),  # primary
                self._make_transfer_log(self.SPLIT_RECIPIENT, 300000),  # split
            ],
        }
        assert intent._verify_transfer_logs(receipt, request)

    def test_split_logs_wrong_amount_rejected(self) -> None:
        """Receipt with wrong split amount should be rejected."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT)]
            ),
        )
        receipt = {
            "status": "0x1",
            "logs": [
                self._make_transfer_log(self.RECIPIENT, 700000),
                self._make_transfer_log(self.SPLIT_RECIPIENT, 200000),  # wrong
            ],
        }
        assert not intent._verify_transfer_logs(receipt, request)

    def test_split_logs_missing_split_rejected(self) -> None:
        """Receipt missing a split log should be rejected."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT)]
            ),
        )
        receipt = {
            "status": "0x1",
            "logs": [self._make_transfer_log(self.RECIPIENT, 700000)],
        }
        assert not intent._verify_transfer_logs(receipt, request)

    def test_split_with_memo_accepted(self) -> None:
        """Split with memo should match TransferWithMemo log."""
        split_memo = "0x" + "dd" * 32
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT, memo=split_memo)]
            ),
        )
        receipt = {
            "status": "0x1",
            "logs": [
                self._make_transfer_log(self.RECIPIENT, 700000),
                self._make_transfer_log(self.SPLIT_RECIPIENT, 300000, memo=split_memo),
            ],
        }
        assert intent._verify_transfer_logs(receipt, request)

    def test_split_order_insensitive(self) -> None:
        """Logs in different order from splits should still match."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        split2 = "0x2222222222222222222222222222222222222222"
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[
                    Split(amount="200000", recipient=self.SPLIT_RECIPIENT),
                    Split(amount="100000", recipient=split2),
                ]
            ),
        )
        receipt = {
            "status": "0x1",
            "logs": [
                self._make_transfer_log(split2, 100000),  # split2 first
                self._make_transfer_log(self.RECIPIENT, 700000),
                self._make_transfer_log(self.SPLIT_RECIPIENT, 200000),
            ],
        }
        assert intent._verify_transfer_logs(receipt, request)


class TestSplitSchemas:
    """Tests for Split schema."""

    def test_split_model(self) -> None:
        s = Split(amount="300000", recipient="0x1111111111111111111111111111111111111111")
        assert s.amount == "300000"
        assert s.memo is None

    def test_split_with_memo(self) -> None:
        s = Split(amount="300000", recipient="0x1111", memo="0x" + "ab" * 32)
        assert s.memo is not None

    def test_method_details_with_splits(self) -> None:
        md = MethodDetails(
            splits=[Split(amount="300000", recipient="0x1111111111111111111111111111111111111111")]
        )
        assert md.splits is not None
        assert len(md.splits) == 1

    def test_method_details_splits_serialization(self) -> None:
        md = MethodDetails(
            splits=[Split(amount="300000", recipient="0x1111111111111111111111111111111111111111")]
        )
        data = md.model_dump()
        assert "splits" in data
        assert data["splits"][0]["amount"] == "300000"

    def test_charge_request_with_splits(self) -> None:
        req = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            methodDetails=MethodDetails(
                splits=[
                    Split(amount="300000", recipient="0x1111111111111111111111111111111111111111"),
                    Split(amount="200000", recipient="0x2222222222222222222222222222222222222222"),
                ]
            ),
        )
        assert req.methodDetails.splits is not None
        assert len(req.methodDetails.splits) == 2


class TestParseMemoBytes:
    """Tests for _parse_memo_bytes fail-closed behavior."""

    def test_none_returns_none(self) -> None:
        assert _parse_memo_bytes(None) is None

    def test_valid_32_byte_hex(self) -> None:
        memo = "0x" + "ab" * 32
        result = _parse_memo_bytes(memo)
        assert result is not None
        assert len(result) == 32
        assert result[0] == 0xAB

    def test_valid_without_0x_prefix(self) -> None:
        memo = "cd" * 32
        result = _parse_memo_bytes(memo)
        assert result is not None
        assert len(result) == 32

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(VerificationError, match="Invalid memo hex"):
            _parse_memo_bytes("0xnothex")

    def test_short_memo_raises(self) -> None:
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            _parse_memo_bytes("0x" + "ab" * 16)

    def test_long_memo_raises(self) -> None:
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            _parse_memo_bytes("0x" + "ab" * 33)

    def test_empty_hex_raises(self) -> None:
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            _parse_memo_bytes("0x")


class TestMatchSingleTransferCalldata:
    """Tests for _match_single_transfer_calldata memo strictness."""

    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    AMOUNT = 1000000
    MEMO = bytes.fromhex("ab" * 32)

    def _build_calldata(
        self,
        selector: str,
        recipient: str,
        amount: int,
        memo_hex: str = "",
    ) -> str:
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        return f"{selector}{to_padded}{amount_padded}{memo_hex}"

    def test_memo_requires_transfer_with_memo_selector(self) -> None:
        calldata = self._build_calldata(
            TRANSFER_SELECTOR,
            self.RECIPIENT,
            self.AMOUNT,
            "ab" * 32,
        )
        assert (
            _match_single_transfer_calldata(
                calldata,
                self.RECIPIENT,
                self.AMOUNT,
                self.MEMO,
            )
            is False
        )

    def test_memo_accepts_correct_selector(self) -> None:
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR,
            self.RECIPIENT,
            self.AMOUNT,
            "ab" * 32,
        )
        assert (
            _match_single_transfer_calldata(
                calldata,
                self.RECIPIENT,
                self.AMOUNT,
                self.MEMO,
            )
            is True
        )

    def test_no_memo_accepts_transfer_with_memo_selector(self) -> None:
        """When no memo expected, transferWithMemo calldata should be accepted."""
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR,
            self.RECIPIENT,
            self.AMOUNT,
            "ab" * 32,
        )
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is True

    def test_no_memo_rejects_short_transfer_with_memo_calldata(self) -> None:
        """When no memo expected, truncated transferWithMemo calldata should be rejected."""
        calldata = self._build_calldata(TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is False

    def test_no_memo_accepts_plain_transfer(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is True


class TestSplitLogMemoStrictness:
    """Tests that memo-less split logs can still preserve attribution memos."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    SPLIT_RECIPIENT = "0x1111111111111111111111111111111111111111"
    AMOUNT = 1000000
    SENDER = "0x" + "ab" * 20

    def _make_log(self, topic: str, recipient: str, amount: int, memo: str | None = None) -> dict:
        to_padded = "0x" + "0" * 24 + recipient[2:].lower()
        from_padded = "0x" + "0" * 24 + self.SENDER[2:].lower()
        topics = [topic, from_padded, to_padded]
        if memo:
            topics.append(memo)
        return {
            "address": self.CURRENCY,
            "topics": topics,
            "data": "0x" + hex(amount)[2:].zfill(64),
        }

    def test_single_transfer_accepts_transfer_with_memo_log(self) -> None:
        """A memo-less single transfer accepts TransferWithMemo logs.

        When memo=None the single-transfer path matches TransferWithMemo
        events (memo binding is checked later by _assert_challenge_bound_memo).
        """
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(),
        )
        receipt = {
            "logs": [
                self._make_log(
                    TRANSFER_WITH_MEMO_TOPIC,
                    self.RECIPIENT,
                    self.AMOUNT,
                    memo="0x" + "ff" * 32,
                )
            ],
        }
        assert intent._verify_transfer_logs(receipt, request)

    def test_multi_split_accepts_transfer_with_memo_log_for_memoless(self) -> None:
        """Memo-less split legs should accept TransferWithMemo logs."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT)]
            ),
        )
        receipt = {
            "logs": [
                # primary as Transfer (correct)
                self._make_log(TRANSFER_TOPIC, self.RECIPIENT, 700000),
                # split as TransferWithMemo (accepted; challenge binding is checked later)
                self._make_log(
                    TRANSFER_WITH_MEMO_TOPIC,
                    self.SPLIT_RECIPIENT,
                    300000,
                    memo="0x" + "ff" * 32,
                ),
            ],
        }
        matched_logs = intent._verify_transfer_logs(receipt, request)
        assert [matched_log.kind for matched_log in matched_logs] == ["transfer", "memo"]

    def test_multi_split_prefers_transfer_with_memo_log_for_memoless(self) -> None:
        """Memo-less split legs should prefer memo logs over plain transfers when both exist."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[Split(amount="300000", recipient=self.SPLIT_RECIPIENT)]
            ),
        )
        receipt = {
            "logs": [
                self._make_log(TRANSFER_TOPIC, self.RECIPIENT, 700000),
                self._make_log(TRANSFER_TOPIC, self.SPLIT_RECIPIENT, 300000),
                self._make_log(
                    TRANSFER_WITH_MEMO_TOPIC,
                    self.SPLIT_RECIPIENT,
                    300000,
                    memo="0x" + "ee" * 32,
                ),
            ],
        }
        matched_logs = intent._verify_transfer_logs(receipt, request)
        assert [matched_log.kind for matched_log in matched_logs] == ["transfer", "memo"]


class TestSplitsFeePayerRejection:
    """Test that splits + fee_payer raises."""

    @pytest.mark.anyio
    async def test_splits_with_fee_payer_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mpp.methods.tempo import tempo
        from mpp.server import Mpp

        monkeypatch.setenv("MPP_SECRET_KEY", "test-secret-key")
        server = Mpp.create(
            method=tempo(
                intents={"charge": ChargeIntent(rpc_url="https://rpc.test")},
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
        )
        with pytest.raises(ValueError, match="splits and fee_payer cannot be used together"):
            await server.charge(
                authorization=None,
                amount="1.00",
                splits=[
                    {
                        "amount": "300000",
                        "recipient": "0x1111111111111111111111111111111111111111",
                    }
                ],
                fee_payer=True,
            )


class TestGetTransfersInvalidMemo:
    """Tests that get_transfers rejects invalid memos (fail-closed)."""

    def test_invalid_primary_memo_raises(self) -> None:
        with pytest.raises(VerificationError, match="Invalid memo hex"):
            get_transfers(1_000_000, "0x01", "not-hex", None)

    def test_short_primary_memo_raises(self) -> None:
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            get_transfers(1_000_000, "0x01", "0x" + "ab" * 10, None)

    def test_invalid_split_memo_raises(self) -> None:
        splits = [
            Split(
                amount="100000",
                recipient="0x1111111111111111111111111111111111111111",
                memo="badhex",
            )
        ]
        with pytest.raises(VerificationError, match="Invalid memo hex"):
            get_transfers(1_000_000, "0x01", None, splits)

    def test_short_split_memo_raises(self) -> None:
        splits = [
            Split(
                amount="100000",
                recipient="0x1111111111111111111111111111111111111111",
                memo="0x" + "ab" * 5,
            )
        ]
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            get_transfers(1_000_000, "0x01", None, splits)


class TestHashCredentialSourceValidation:
    """Hash credential source validation (did:pkh) and validate_sender hook."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    CHAIN_ID = 4217
    SOURCE_ADDR = "0x00000000000000000000000000000000000000aa"
    RELAYER = "0x00000000000000000000000000000000000000bb"

    def _topic(self, address: str) -> str:
        return "0x" + address.lower().removeprefix("0x").zfill(64)

    def _memo_log(self, frm: str, memo: str, amount: int = 1000) -> dict:
        return {
            "address": self.CURRENCY,
            "topics": [
                TRANSFER_WITH_MEMO_TOPIC,
                self._topic(frm),
                self._topic(self.RECIPIENT),
                memo,
            ],
            "data": amount_data(amount),
        }

    def _did(self, chain_id: int, address: str) -> str:
        return f"did:pkh:eip155:{chain_id}:{address}"

    def _intent(self, receipt: dict, *, validate_sender=None, store=None) -> ChargeIntent:
        intent = ChargeIntent(
            rpc_url="https://rpc.test", validate_sender=validate_sender, store=store
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(200, {"jsonrpc": "2.0", "result": receipt, "id": 1})
        )
        intent._http_client = mock_client
        return intent

    async def _verify(self, intent: ChargeIntent, source: str | None, memo_value=None):
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        request: dict = {
            "amount": "1000",
            "currency": self.CURRENCY,
            "recipient": self.RECIPIENT,
        }
        if memo_value is not None:
            request["methodDetails"] = {"memo": memo_value}
        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            realm="api.example.com",
            expires=future,
            source=source,
        )
        return await intent.verify(credential, request)

    @property
    def _bound_memo(self) -> str:
        return encode_attribution(challenge_id="challenge-123", server_id="api.example.com")

    # ---- parse unit tests ----

    def test_parse_absent_is_none(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        assert intent._parse_hash_credential_source(None, self.CHAIN_ID) is None

    def test_parse_valid_returns_address(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        source = self._did(self.CHAIN_ID, self.SOURCE_ADDR)
        assert intent._parse_hash_credential_source(source, self.CHAIN_ID) == self.SOURCE_ADDR

    def test_parse_chain_mismatch_raises(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        with pytest.raises(VerificationError, match="Hash credential source is invalid"):
            intent._parse_hash_credential_source(self._did(1, self.SOURCE_ADDR), self.CHAIN_ID)

    def test_parse_malformed_variants_raise(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        cases = [
            "not-a-valid-did",
            f"did:pkh:solana:{self.CHAIN_ID}:{self.SOURCE_ADDR}",
            f"did:pkh:eip155:04217:{self.SOURCE_ADDR}",
            f"did:pkh:eip155:not-a-number:{self.SOURCE_ADDR}",
            f"did:pkh:eip155:{self.CHAIN_ID}:extra:{self.SOURCE_ADDR}",
            f"did:pkh:eip155:{self.CHAIN_ID}:not-an-address",
        ]
        for source in cases:
            with pytest.raises(VerificationError, match="Hash credential source is invalid"):
                intent._parse_hash_credential_source(source, self.CHAIN_ID)

    def test_parse_rejects_non_ascii_chain_digits(self) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        source = f"did:pkh:eip155:4\uff1217:{self.SOURCE_ADDR}"  # full-width digits
        with pytest.raises(VerificationError, match="Hash credential source is invalid"):
            intent._parse_hash_credential_source(source, self.CHAIN_ID)

    # ---- end-to-end verify tests ----

    @pytest.mark.asyncio
    async def test_hash_accepts_source_matching_transfer_sender(self) -> None:
        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.SOURCE_ADDR, self._bound_memo)],
        }
        intent = self._intent(receipt)
        result = await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))
        assert result.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_hash_accepts_source_when_receipt_sender_differs(self) -> None:
        # Relayer submitted the tx (receipt.from = RELAYER) but the transfer is
        # from the declared source.
        receipt = {
            "status": "0x1",
            "from": self.RELAYER,
            "logs": [self._memo_log(self.SOURCE_ADDR, self._bound_memo)],
        }
        intent = self._intent(receipt)
        result = await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))
        assert result.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_hash_rejects_source_differing_from_transfer_sender(self) -> None:
        receipt = {
            "status": "0x1",
            "from": self.RELAYER,
            "logs": [self._memo_log(self.RELAYER, self._bound_memo)],
        }
        intent = self._intent(receipt)
        with pytest.raises(VerificationError, match="must contain a Transfer log"):
            await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))

    @pytest.mark.asyncio
    async def test_hash_validate_sender_override_allows_mismatch(self) -> None:
        seen: dict = {}

        def validate_sender(v) -> bool:
            seen["v"] = v
            return True

        receipt = {
            "status": "0x1",
            "from": self.RELAYER,
            "logs": [self._memo_log(self.RELAYER, self._bound_memo)],
        }
        intent = self._intent(receipt, validate_sender=validate_sender)
        source = self._did(self.CHAIN_ID, self.SOURCE_ADDR)
        result = await self._verify(intent, source=source)

        assert result.reference == "0xabc123"
        assert seen["v"].expected_sender.lower() == self.SOURCE_ADDR.lower()
        assert seen["v"].sender.lower() == self.RELAYER.lower()
        assert seen["v"].source == source

    @pytest.mark.asyncio
    async def test_hash_validate_sender_returning_false_rejects(self) -> None:
        receipt = {
            "status": "0x1",
            "from": self.RELAYER,
            "logs": [self._memo_log(self.RELAYER, self._bound_memo)],
        }
        intent = self._intent(receipt, validate_sender=lambda v: False)
        with pytest.raises(VerificationError, match="must contain a Transfer log"):
            await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))

    @pytest.mark.asyncio
    async def test_hash_validate_sender_not_called_when_sender_matches(self) -> None:
        def boom(v) -> bool:
            raise AssertionError("validate_sender must not be called")

        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.SOURCE_ADDR, self._bound_memo)],
        }
        intent = self._intent(receipt, validate_sender=boom)
        result = await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))
        assert result.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_hash_validate_sender_not_called_for_non_candidate_logs(self) -> None:
        def boom(v) -> bool:
            raise AssertionError("validate_sender must not be called")

        explicit_memo = "0x" + "ab" * 32
        other_memo = "0x" + "cd" * 32
        # First log has a wrong sender and a non-matching memo (non-candidate);
        # second log matches fully, so the callback is never reached.
        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [
                self._memo_log(self.RELAYER, other_memo),
                self._memo_log(self.SOURCE_ADDR, explicit_memo),
            ],
        }
        intent = self._intent(receipt, validate_sender=boom)
        result = await self._verify(
            intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR), memo_value=explicit_memo
        )
        assert result.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_hash_rejects_source_from_different_chain(self) -> None:
        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.SOURCE_ADDR, self._bound_memo)],
        }
        intent = self._intent(receipt)
        with pytest.raises(VerificationError, match="Hash credential source is invalid"):
            await self._verify(intent, source=self._did(1, self.SOURCE_ADDR))

    @pytest.mark.asyncio
    async def test_hash_malformed_source_does_not_consume_hash(self) -> None:
        from mpp.store import MemoryStore

        store = MemoryStore()
        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.SOURCE_ADDR, self._bound_memo)],
        }
        intent = self._intent(receipt, store=store)

        # Malformed source is rejected before the hash is reserved.
        with pytest.raises(VerificationError, match="Hash credential source is invalid"):
            await self._verify(intent, source="not-a-valid-did")
        assert await store.get("mpp:charge:0xabc123") is None

        # A valid retry then succeeds.
        result = await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))
        assert result.reference == "0xabc123"

    def test_public_types_are_exported(self) -> None:
        from mpp.methods.tempo import SenderValidation, ValidateSender  # noqa: F401

        validation = SenderValidation(
            expected_sender=self.SOURCE_ADDR, sender=self.RELAYER, source=None
        )
        assert validation.expected_sender == self.SOURCE_ADDR

    @pytest.mark.asyncio
    async def test_broadcast_path_does_not_bind_sender(self) -> None:
        # No source is threaded through the broadcast path, so a transfer whose
        # `from` differs from the receipt sender still passes and the
        # validate_sender callback is never consulted.
        def boom(v) -> bool:
            raise AssertionError("validate_sender must not be called on the broadcast path")

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        receipt = {
            "transactionHash": "0xtxhash123",
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.RELAYER, self._bound_memo)],
        }
        intent = self._intent(receipt, validate_sender=boom)
        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            challenge_id="challenge-123",
            realm="api.example.com",
            expires=future,
        )
        result = await intent.verify(
            credential,
            {"amount": "1000", "currency": self.CURRENCY, "recipient": self.RECIPIENT},
        )
        assert result.reference == "0xtxhash123"

    @pytest.mark.asyncio
    async def test_hash_without_source_does_not_bind_sender(self) -> None:
        # Hash credential with no source: the transfer sender differs from the
        # receipt sender but there is nothing to bind against, so it passes.
        def boom(v) -> bool:
            raise AssertionError("validate_sender must not be called without a source")

        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [self._memo_log(self.RELAYER, self._bound_memo)],
        }
        intent = self._intent(receipt, validate_sender=boom)
        result = await self._verify(intent, source=None)
        assert result.reference == "0xabc123"
