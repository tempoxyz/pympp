"""Tests for Tempo payment method."""

import os
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
from mpp.methods.tempo.intents import (
    TRANSFER_SELECTOR,
    TRANSFER_TOPIC,
    TRANSFER_WITH_MEMO_SELECTOR,
    TRANSFER_WITH_MEMO_TOPIC,
    ChargeIntent,
    Transfer,
    _match_single_transfer_calldata,
    _match_transfer_calldata,
    _parse_memo_bytes,
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
    async def test_verify_hash_rejects_replayed_hash(self) -> None:
        """Should reject a replayed transaction hash when store is configured."""
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        memo = encode_attribution(challenge_id="challenge-123", server_id="api.example.com")

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
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )
        request = {
            "amount": "1000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        }

        # First verification should succeed
        receipt = await intent.verify(credential, request)
        assert receipt.status == "success"

        # Second verification with same hash should fail
        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(credential, request)

    @pytest.mark.asyncio
    async def test_verify_hash_allows_replay_without_store(self) -> None:
        """Should allow same hash twice when no store is configured."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")  # no store
        memo = encode_attribution(challenge_id="challenge-123", server_id="api.example.com")

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
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )
        request = {
            "amount": "1000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        }

        # Both should succeed without store
        receipt1 = await intent.verify(credential, request)
        assert receipt1.status == "success"
        receipt2 = await intent.verify(credential, request)
        assert receipt2.status == "success"

    @pytest.mark.asyncio
    async def test_verify_hash_store_records_on_success(self) -> None:
        """Should record hash in store after successful verification."""
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        memo = encode_attribution(challenge_id="challenge-123", server_id="api.example.com")

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
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )
        request = {
            "amount": "1000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        }

        # Before verification, store should be empty
        assert await store.get("mpp:charge:0xabc123") is None

        await intent.verify(credential, request)

        # After verification, hash should be recorded
        assert await store.get("mpp:charge:0xabc123") is not None

    @pytest.mark.asyncio
    async def test_verify_hash_does_not_record_hash_on_binding_failure(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

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

        assert await store.get("mpp:charge:0xabc123") is None

    @pytest.mark.asyncio
    async def test_verify_hash_tx_not_found(self) -> None:
        """Should reject when transaction not found."""
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(200, {"jsonrpc": "2.0", "result": None, "id": 1})
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"}, expires=future)
        with pytest.raises(VerificationError, match="Transaction not found"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert await store.get("mpp:charge:0xabc") is None

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
    async def test_verify_transaction_success(self) -> None:
        """Should verify transaction credential with matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000

        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        from_topic = "0x" + "0" * 24 + "abcd" * 10
        to_topic = "0x" + "0" * 24 + destination[2:]

        receipt_with_logs = {
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [transfer_topic, from_topic, to_topic],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash123", "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
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
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xtxhash123"

    @pytest.mark.asyncio
    async def test_verify_transaction_accepts_transfer_with_memo_logs(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000

        receipt_with_logs = {
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        "0x" + "ab" * 32,
                    ],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash123", "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
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
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xtxhash123"

    @pytest.mark.asyncio
    async def test_verify_transaction_records_hash_and_blocks_hash_reuse(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        memo = encode_attribution(
            challenge_id="challenge-123",
            server_id="api.example.com",
        )
        receipt_with_logs = {
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
                mock_response(200, {"jsonrpc": "2.0", "result": "0xabc123", "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
                mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1}),
            ]
        )
        intent._http_client = mock_client

        transaction_credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
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
        assert receipt.reference == "0xabc123"
        assert await store.get("mpp:charge:0xabc123") is not None

        hash_credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            expires=future,
            realm="api.example.com",
        )

        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(hash_credential, request)

    @pytest.mark.asyncio
    async def test_verify_transaction_does_not_record_hash_on_failure(self) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash123", "id": 1}),
                mock_response(
                    200,
                    {"jsonrpc": "2.0", "result": {"status": "0x0", "logs": []}, "id": 1},
                ),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
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

        assert await store.get("mpp:charge:0xtxhash123") is None

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

        # External fee payer signs and returns co-signed tx
        httpx_mock.add_response(
            url="https://sponsor.test",
            json={"jsonrpc": "2.0", "result": "0x76cosigned", "id": 1},
        )

        # eth_sendRawTransaction to RPC
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0xsponsored_hash", "id": 1},
        )

        # eth_getTransactionReceipt
        httpx_mock.add_response(
            url="https://rpc.test",
            json={
                "jsonrpc": "2.0",
                "result": {
                    "status": "0x1",
                    "logs": [
                        {
                            "address": "0x20c0000000000000000000000000000000000000",
                            "topics": [
                                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                "0x000000000000000000000000sender00000000000000000000000000000000",
                                "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                            ],
                            "data": (
                                "0x000000000000000000000000000000000000"
                                "00000000000000000000000000000f4240"
                            ),
                        }
                    ],
                },
                "id": 1,
            },
        )

        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(
            payload={"type": "transaction", "signature": "0x76abcdef"},
            expires=future,
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

    def _build_client_tx(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        chain_id: int = 42431,
        with_memo: str | None = None,
    ) -> str:
        """Build a client-signed fee-payer-awaiting transaction."""
        from pytempo import Call, TempoTransaction

        if with_memo:
            selector = "95777d59"
            to_padded = recipient[2:].lower().zfill(64)
            amount_padded = hex(amount)[2:].zfill(64)
            memo_clean = with_memo[2:] if with_memo.startswith("0x") else with_memo
            transfer_data = f"0x{selector}{to_padded}{amount_padded}{memo_clean.lower()}"
        else:
            selector = "a9059cbb"
            to_padded = recipient[2:].lower().zfill(64)
            amount_padded = hex(amount)[2:].zfill(64)
            transfer_data = f"0x{selector}{to_padded}{amount_padded}"

        tx = TempoTransaction.create(
            chain_id=chain_id,
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

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        return "0x" + encode_fee_payer_envelope(signed).hex()

    def test_cosign_roundtrip(self) -> None:
        """Should successfully co-sign a valid client transaction."""
        fee_payer_key = "0x" + "ab" * 32
        fee_payer = TempoAccount.from_key(fee_payer_key)

        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(
            fee_payer=fee_payer,
            rpc_url="https://rpc.test",
            intents={"charge": intent},
        )

        raw_tx = self._build_client_tx()
        result = intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")

        assert result.startswith("0x76")
        assert len(result) > len(raw_tx)

    def test_cosign_rejects_wrong_tx_type(self) -> None:
        """Should reject transactions that aren't type 0x78."""
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0x02abcdef", "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_malformed_hex(self) -> None:
        """Should reject non-hex input."""
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0xZZZZ", "0x20c0000000000000000000000000000000000000")

    def test_cosign_rejects_no_fee_payer(self) -> None:
        """Should raise when no fee payer account is configured."""
        intent = ChargeIntent(rpc_url="https://rpc.test")

        with pytest.raises(VerificationError, match="No fee payer account configured"):
            intent._cosign_as_fee_payer("0x76abcdef", "0x20c0000000000000000000000000000000000000")

    def test_cosign_validates_call_target(self) -> None:
        """Should reject tx targeting wrong currency when request is provided."""
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

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
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

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
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

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
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

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

        result = intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)
        assert result.startswith("0x76")


class TestValidateTransactionPayload:
    """Tests for _validate_transaction_payload with both 0x76 and 0x78."""

    def _build_0x78_envelope(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
    ) -> str:
        """Build a 0x78 fee payer envelope."""
        from pytempo import Call, TempoTransaction

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        selector = "a9059cbb"
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        transfer_data = f"0x{selector}{to_padded}{amount_padded}"

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
    ) -> str:
        """Build a standard 0x76 transaction."""
        import attrs
        from pytempo import Call, TempoTransaction

        selector = "a9059cbb"
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        transfer_data = f"0x{selector}{to_padded}{amount_padded}"

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
        signed = attrs.evolve(signed, fee_payer_signature=b"\x00")
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
    async def test_client_resolves_rpc_from_challenge_chain_id(self, httpx_mock: HTTPXMock) -> None:
        """Client should use RPC URL matching challenge's methodDetails.chainId."""
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        # Method defaults to mainnet RPC
        method = tempo(
            account=account,
            intents={"charge": ChargeIntent()},
        )
        assert method.rpc_url == "https://rpc.tempo.xyz"

        # Mock testnet RPC responses (chain_id, nonce, gas_price, estimateGas)
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0xa5bf", "id": 1},  # chain_id 42431
        )
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x186a0", "id": 1},
        )

        # Challenge says chainId=42431 in methodDetails
        challenge = Challenge(
            id="test-chain-resolve",
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

        credential = await method.create_credential(challenge)

        # Should have called testnet RPC, not mainnet
        requests = httpx_mock.get_requests()
        assert len(requests) > 0
        for r in requests:
            assert "rpc.moderato.tempo.xyz" in str(r.url)
        assert credential.payload["type"] == "transaction"

    @pytest.mark.asyncio
    async def test_client_falls_back_to_method_rpc_for_unknown_chain(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Client should fall back to method's rpc_url for unknown chainIds."""
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
            id="test-unknown-chain",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"chainId": 99999},
            },
            realm="test.example.com",
            request_b64="e30",
        )

        credential = await method.create_credential(challenge)
        requests = httpx_mock.get_requests()
        assert len(requests) > 0
        for r in requests:
            assert "rpc.custom" in str(r.url)
        assert credential.payload["type"] == "transaction"

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
            intents={"charge": ChargeIntent()},
        )

        # RPC returns chain_id=4217 (mainnet) but challenge says 42431 (testnet)
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},  # 4217, wrong!
        )
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.moderato.tempo.xyz",
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
                "methodDetails": {"chainId": 42431},
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
        # Challenge chainId=4217 resolves to rpc.tempo.xyz
        httpx_mock.add_response(
            url="https://rpc.tempo.xyz",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(3):
            httpx_mock.add_response(
                url="https://rpc.tempo.xyz",
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

    def test_no_memo_accepts_only_transfer_selector(self) -> None:
        """When no memo, only plain transfer selector should be accepted."""
        request = self._make_request(memo=None)
        calldata_plain = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        calldata_memo = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT
        )
        assert _match_transfer_calldata(calldata_plain, request) is True
        assert _match_transfer_calldata(calldata_memo, request) is False

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
        splits = [Split(amount="300000", recipient="0x1111111111111111111111111111111111111111")]
        transfers = get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", None, splits)
        assert len(transfers) == 2
        assert transfers[0].amount == 700_000  # primary gets remainder
        assert transfers[1].amount == 300_000

    def test_primary_inherits_memo(self) -> None:
        memo = "0x" + "ab" * 32
        splits = [Split(amount="100000", recipient="0x1111111111111111111111111111111111111111")]
        transfers = get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", memo, splits)
        assert transfers[0].memo is not None
        assert transfers[1].memo is None

    def test_split_with_memo(self) -> None:
        split_memo = "0x" + "cd" * 32
        splits = [Split(amount="100000", recipient="0x1111111111111111111111111111111111111111", memo=split_memo)]
        transfers = get_transfers(1_000_000, "0x2222222222222222222222222222222222222222", None, splits)
        assert transfers[1].memo is not None
        assert transfers[1].memo[0] == 0xCD

    def test_multiple_splits_preserve_order(self) -> None:
        splits = [
            Split(amount="100000", recipient="0x1111111111111111111111111111111111111111"),
            Split(amount="200000", recipient="0x2222222222222222222222222222222222222222"),
            Split(amount="50000", recipient="0x3333333333333333333333333333333333333333"),
        ]
        transfers = get_transfers(1_000_000, "0x4444444444444444444444444444444444444444", None, splits)
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
            Split(amount="1000", recipient=f"0x{hex(i + 2)[2:].zfill(40)}")
            for i in range(11)
        ]
        with pytest.raises(VerificationError, match="Too many splits"):
            get_transfers(1_000_000, "0x0000000000000000000000000000000000000001", None, splits)

    def test_max_splits_allowed(self) -> None:
        splits = [
            Split(amount="1000", recipient=f"0x{hex(i + 2)[2:].zfill(40)}")
            for i in range(10)
        ]
        transfers = get_transfers(1_000_000, "0x0000000000000000000000000000000000000001", None, splits)
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
        assert intent._verify_transfer_logs(receipt, request) is True

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
        assert intent._verify_transfer_logs(receipt, request) is False

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
        assert intent._verify_transfer_logs(receipt, request) is False

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
        assert intent._verify_transfer_logs(receipt, request) is True

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
        assert intent._verify_transfer_logs(receipt, request) is True


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

    def _build_calldata(self, selector: str, recipient: str, amount: int, memo_hex: str = "") -> str:
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        return f"{selector}{to_padded}{amount_padded}{memo_hex}"

    def test_memo_requires_transfer_with_memo_selector(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT, "ab" * 32)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, self.MEMO) is False

    def test_memo_accepts_correct_selector(self) -> None:
        calldata = self._build_calldata(TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, "ab" * 32)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, self.MEMO) is True

    def test_no_memo_rejects_transfer_with_memo_selector(self) -> None:
        """When no memo expected, transferWithMemo calldata must be rejected."""
        calldata = self._build_calldata(TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is False

    def test_no_memo_accepts_plain_transfer(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is True


class TestSplitLogMemoStrictness:
    """Tests that memo-less split logs reject transferWithMemo events."""

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

    def test_single_transfer_rejects_transfer_with_memo_log(self) -> None:
        """A memo-less single transfer must reject TransferWithMemo logs."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(),
        )
        receipt = {
            "logs": [self._make_log(
                TRANSFER_WITH_MEMO_TOPIC, self.RECIPIENT, self.AMOUNT,
                memo="0x" + "ff" * 32,
            )],
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_multi_split_rejects_transfer_with_memo_log_for_memoless(self) -> None:
        """Memo-less split legs must reject TransferWithMemo logs."""
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
                # split as TransferWithMemo (should be rejected)
                self._make_log(
                    TRANSFER_WITH_MEMO_TOPIC, self.SPLIT_RECIPIENT, 300000,
                    memo="0x" + "ff" * 32,
                ),
            ],
        }
        assert intent._verify_transfer_logs(receipt, request) is False


class TestSplitsFeePayerRejection:
    """Test that splits + fee_payer raises."""

    @pytest.mark.anyio
    async def test_splits_with_fee_payer_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mpp.server import Mpp
        from mpp.methods.tempo import tempo

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
                splits=[{"amount": "300000", "recipient": "0x1111111111111111111111111111111111111111"}],
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
        splits = [Split(amount="100000", recipient="0x1111111111111111111111111111111111111111", memo="badhex")]
        with pytest.raises(VerificationError, match="Invalid memo hex"):
            get_transfers(1_000_000, "0x01", None, splits)

    def test_short_split_memo_raises(self) -> None:
        splits = [Split(amount="100000", recipient="0x1111111111111111111111111111111111111111", memo="0x" + "ab" * 5)]
        with pytest.raises(VerificationError, match="exactly 32 bytes"):
            get_transfers(1_000_000, "0x01", None, splits)
