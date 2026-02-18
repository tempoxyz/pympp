"""Tests for Tempo payment method."""

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest
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
from mpp.methods.tempo._defaults import CHAIN_RPC_URLS
from mpp.methods.tempo.client import TempoMethod
from mpp.methods.tempo.intents import ChargeIntent
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    HashCredentialPayload,
    MethodDetails,
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
        assert method.intents["charge"].rpc_url == "https://custom.rpc"

    def test_tempo_does_not_override_explicit_intent_rpc_url(self) -> None:
        """tempo() should not override an intent's explicitly-set rpc_url."""
        intent = ChargeIntent(rpc_url="https://intent.rpc")
        method = tempo(
            rpc_url="https://method.rpc",
            intents={"charge": intent},
        )
        assert method.intents["charge"].rpc_url == "https://intent.rpc"

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
        credential = make_credential(payload={"type": "hash", "hash": "0x123"})
        expired = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

        with pytest.raises(VerificationError, match="expired"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                    "expires": expired,
                },
            )

    @pytest.mark.asyncio
    async def test_verify_invalid_payload(self) -> None:
        """Should reject invalid credential payload."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(payload="not-a-dict")
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        with pytest.raises(VerificationError, match="Invalid credential payload"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_verify_unknown_credential_type(self) -> None:
        """Should reject unknown credential types."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(payload={"type": "unknown"})
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        with pytest.raises(VerificationError, match="Invalid credential type"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x123",
                    "recipient": "0x456",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_verify_hash_success(self) -> None:
        """Should verify hash credential with matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
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
                                    transfer_topic,
                                    "0x0000000000000000000000001234567890123456789012345678901234567890",
                                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                                ],
                                "data": "0x"
                                + "00000000000000000000000000000000"
                                + "00000000000000000000000000000000000003e8",
                            }
                        ],
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc123"})
        receipt = await intent.verify(
            credential,
            {
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "expires": future,
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xabc123"

    @pytest.mark.asyncio
    async def test_verify_hash_tx_not_found(self) -> None:
        """Should reject when transaction not found."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(200, {"jsonrpc": "2.0", "result": None, "id": 1})
        )
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"})
        with pytest.raises(VerificationError, match="Transaction not found"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )

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

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"})
        with pytest.raises(VerificationError, match="Transaction reverted"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
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

        credential = make_credential(payload={"type": "hash", "hash": "0xabc"})
        with pytest.raises(VerificationError, match="Transfer log"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
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
        )
        receipt = await intent.verify(
            credential,
            {
                "amount": str(amount),
                "currency": asset,
                "recipient": destination,
                "expires": future,
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xtxhash123"

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
        )
        with pytest.raises(VerificationError, match="Transaction submission failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
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

        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
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
        assert credential.payload["signature"].startswith("0x76")

    @pytest.mark.asyncio
    async def test_server_submits_sponsored_transaction(self, httpx_mock: HTTPXMock) -> None:
        """Server should get fee payer co-signature then broadcast."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        # Fee payer signs the transaction
        httpx_mock.add_response(
            url="https://sponsor.test",
            json={"jsonrpc": "2.0", "result": "0x76cosigned_tx", "id": 1},
        )

        # Server broadcasts co-signed tx to RPC
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0xsponsored_hash", "id": 1},
        )

        # Receipt check
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
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "expires": future,
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
        """Server should raise VerificationError when fee payer fails."""
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
        )

        with pytest.raises(VerificationError, match="Fee payer signing failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                    "expires": future,
                    "methodDetails": {
                        "feePayer": True,
                        "feePayerUrl": "https://sponsor.test",
                    },
                },
            )


class TestFeePayerPropagation:
    """Tests for fee_payer reading from the parent method via _method back-reference."""

    def test_fee_payer_reads_from_method(self) -> None:
        """ChargeIntent.fee_payer should read from the parent method."""
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent()
        method = tempo(
            fee_payer=fee_payer,
            intents={"charge": intent},
        )
        assert intent.fee_payer is fee_payer

    def test_fee_payer_none_without_method(self) -> None:
        """ChargeIntent.fee_payer should be None when no method is set."""
        intent = ChargeIntent()
        assert intent.fee_payer is None

    def test_fee_payer_none_when_method_has_no_fee_payer(self) -> None:
        """ChargeIntent.fee_payer should be None when method has no fee_payer."""
        intent = ChargeIntent()
        method = tempo(intents={"charge": intent})
        assert intent.fee_payer is None

    def test_multiple_intents_share_fee_payer(self) -> None:
        """All intents should read the same fee_payer from the method."""
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        charge = ChargeIntent()
        charge2 = ChargeIntent()
        method = tempo(
            fee_payer=fee_payer,
            intents={"charge": charge, "charge2": charge2},
        )
        assert charge.fee_payer is fee_payer
        assert charge2.fee_payer is fee_payer


class TestFeePayerChallengeEmission:
    """Tests for Mpp emitting feePayer flag in challenge methodDetails."""

    @pytest.mark.asyncio
    async def test_charge_emits_fee_payer_in_method_details(self) -> None:
        """Mpp.charge(fee_payer=True) should include feePayer in methodDetails."""
        from mpp.server import Mpp

        srv = Mpp.create(
            method=tempo(
                chain_id=TESTNET_CHAIN_ID,
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="0.50", fee_payer=True)
        assert isinstance(result, Challenge)
        assert result.request["methodDetails"]["feePayer"] is True

    @pytest.mark.asyncio
    async def test_charge_no_fee_payer_flag(self) -> None:
        """Mpp.charge() without fee_payer should not set feePayer in methodDetails."""
        from mpp.server import Mpp

        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert "methodDetails" not in result.request

    @pytest.mark.asyncio
    async def test_pay_decorator_emits_fee_payer(self) -> None:
        """server.pay(fee_payer=True) should emit feePayer in challenge."""
        from mpp.server import Mpp

        srv = Mpp.create(
            method=tempo(
                chain_id=TESTNET_CHAIN_ID,
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )

        @srv.pay(amount="0.50", fee_payer=True)
        async def handler(request, credential, receipt):
            return {"data": "paid"}

        # Simulate a request with no authorization
        class FakeRequest:
            headers = {}
            query_params = {}

        result = await handler(FakeRequest())
        # The result should be a 402 challenge response
        challenge = Challenge.from_www_authenticate(result.headers["WWW-Authenticate"])
        assert challenge.request["methodDetails"]["feePayer"] is True


class TestFeePayerExternalFallback:
    """Tests for external fee payer service fallback."""

    @pytest.mark.asyncio
    async def test_uses_default_fee_payer_url(self, httpx_mock: HTTPXMock) -> None:
        """Should fall back to DEFAULT_FEE_PAYER_URL when no feePayerUrl in request."""
        from mpp.methods.tempo._defaults import DEFAULT_FEE_PAYER_URL

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        # Default fee payer URL signing
        httpx_mock.add_response(
            url=DEFAULT_FEE_PAYER_URL,
            json={"jsonrpc": "2.0", "result": "0x76cosigned", "id": 1},
        )
        # Broadcast
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0xtxhash", "id": 1},
        )
        # Receipt
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
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "expires": future,
                "methodDetails": {"feePayer": True},
            },
        )

        assert receipt.status == "success"
        # Verify the default URL was called
        requests = httpx_mock.get_requests()
        assert any(DEFAULT_FEE_PAYER_URL in str(r.url) for r in requests)

    @pytest.mark.asyncio
    async def test_external_fee_payer_empty_result(self, httpx_mock: HTTPXMock) -> None:
        """Should raise when external fee payer returns no signed transaction."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        httpx_mock.add_response(
            url="https://sponsor.test",
            json={"jsonrpc": "2.0", "result": None, "id": 1},
        )

        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(
            payload={"type": "transaction", "signature": "0x76abcdef"},
        )

        with pytest.raises(VerificationError, match="no signed transaction"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                    "expires": future,
                    "methodDetails": {
                        "feePayer": True,
                        "feePayerUrl": "https://sponsor.test",
                    },
                },
            )

    @pytest.mark.asyncio
    async def test_external_fee_payer_string_error(self, httpx_mock: HTTPXMock) -> None:
        """Should handle non-dict error from external fee payer."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        httpx_mock.add_response(
            url="https://sponsor.test",
            json={"jsonrpc": "2.0", "error": "something went wrong", "id": 1},
        )

        intent = ChargeIntent(rpc_url="https://rpc.test")
        credential = make_credential(
            payload={"type": "transaction", "signature": "0x76abcdef"},
        )

        with pytest.raises(VerificationError, match="Fee payer signing failed"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                    "expires": future,
                    "methodDetails": {
                        "feePayer": True,
                        "feePayerUrl": "https://sponsor.test",
                    },
                },
            )


class TestFeePayerNotUsedWithoutFlag:
    """Tests that fee payer is NOT invoked when feePayer=False."""

    @pytest.mark.asyncio
    async def test_transaction_submitted_directly_without_fee_payer(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """When feePayer is False, transaction should be sent directly to RPC."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        # Direct broadcast — no fee payer call
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0xdirect_hash", "id": 1},
        )
        # Receipt
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

        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        # Even with fee_payer on the method, feePayer=False in request means no co-signing
        method = tempo(
            fee_payer=fee_payer,
            intents={"charge": intent},
        )

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )

        receipt = await intent.verify(
            credential,
            {
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "expires": future,
            },
        )

        assert receipt.status == "success"
        assert receipt.reference == "0xdirect_hash"
        # Should have only called rpc.test, never a sponsor URL
        requests = httpx_mock.get_requests()
        assert all("rpc.test" in str(r.url) for r in requests)


class TestSchemas:
    def test_charge_request_valid(self) -> None:
        """Should validate charge request with default methodDetails."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            expires="2030-01-20T12:00:00Z",
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
            expires="2030-01-20T12:00:00Z",
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
            expires="2030-01-20T12:00:00Z",
            description="Payment for API access",
        )
        assert req.description == "Payment for API access"

    def test_charge_request_with_external_id(self) -> None:
        """Should accept optional externalId field."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            expires="2030-01-20T12:00:00Z",
            externalId="order-12345",
        )
        assert req.externalId == "order-12345"

    def test_charge_request_description_and_external_id_default_none(self) -> None:
        """description and externalId should default to None."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            expires="2030-01-20T12:00:00Z",
        )
        assert req.description is None
        assert req.externalId is None

    def test_charge_request_serializes_optional_fields(self) -> None:
        """Optional fields should appear in model_dump when set."""
        req = ChargeRequest(
            amount="1000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            expires="2030-01-20T12:00:00Z",
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
        assert ESCROW_CONTRACTS[CHAIN_ID] == "0x0901aED692C755b870F9605E56BAA66c35BEfF69"
        assert ESCROW_CONTRACTS[TESTNET_CHAIN_ID] == "0x542831e3E4Ace07559b7C8787395f4Fb99F70787"

    def test_escrow_contract_for_chain_mainnet(self) -> None:
        """escrow_contract_for_chain should return mainnet address."""
        addr = escrow_contract_for_chain(4217)
        assert addr == "0x0901aED692C755b870F9605E56BAA66c35BEfF69"

    def test_escrow_contract_for_chain_testnet(self) -> None:
        """escrow_contract_for_chain should return testnet address."""
        addr = escrow_contract_for_chain(42431)
        assert addr == "0x542831e3E4Ace07559b7C8787395f4Fb99F70787"

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

    def test_tempo_factory_chain_id_defaults_none(self) -> None:
        """tempo() without chain_id should default to None."""
        method = tempo(intents={"charge": ChargeIntent()})
        assert method.chain_id is None

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


class TestValidateTransactionPayload:
    """Tests for _validate_transaction_payload pre-broadcast validation."""

    def _make_intent(self) -> ChargeIntent:
        return ChargeIntent(rpc_url="https://rpc.test")

    def _make_request(self, **overrides: Any) -> ChargeRequest:
        defaults = {
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            "expires": "2030-01-01T00:00:00Z",
        }
        defaults.update(overrides)
        return ChargeRequest.model_validate(defaults)

    def _build_valid_tx_hex(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        memo: str | None = None,
    ) -> str:
        """Build a minimal valid 0x76-prefixed RLP-encoded transaction."""
        import rlp

        if memo:
            selector = bytes.fromhex("95777d59")
            to_padded = bytes.fromhex(recipient[2:].lower().zfill(64))
            amount_padded = amount.to_bytes(32, "big")
            memo_bytes = bytes.fromhex(memo[2:] if memo.startswith("0x") else memo)
            call_data = selector + to_padded + amount_padded + memo_bytes
        else:
            selector = bytes.fromhex("a9059cbb")
            to_padded = bytes.fromhex(recipient[2:].lower().zfill(64))
            amount_padded = amount.to_bytes(32, "big")
            call_data = selector + to_padded + amount_padded

        currency_bytes = bytes.fromhex(currency[2:])
        call = [currency_bytes, b"", call_data]
        # Minimal tx structure: [chain_id, max_prio_fee, max_fee, gas_limit, calls, ...]
        tx_fields = [
            b"\x01",  # chain_id
            b"\x01",  # max_priority_fee
            b"\x01",  # max_fee
            b"\x01",  # gas_limit
            [call],   # calls
            b"",      # access_list placeholder
            b"",      # nonce_key
            b"\x01",  # nonce
            b"",      # placeholder
            b"",      # placeholder
            b"",      # fee_token
            b"\x00" * 65,  # sender_sig
        ]
        encoded = rlp.encode(tx_fields)
        return "0x76" + encoded.hex()

    def test_valid_transfer_passes(self) -> None:
        """Valid transfer tx should pass validation."""
        intent = self._make_intent()
        request = self._make_request()
        tx_hex = self._build_valid_tx_hex()
        intent._validate_transaction_payload(tx_hex, request)

    def test_wrong_recipient_rejected(self) -> None:
        """Tx with wrong recipient should be rejected."""
        intent = self._make_intent()
        request = self._make_request()
        tx_hex = self._build_valid_tx_hex(
            recipient="0x0000000000000000000000000000000000000001"
        )
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(tx_hex, request)

    def test_wrong_amount_rejected(self) -> None:
        """Tx with wrong amount should be rejected."""
        intent = self._make_intent()
        request = self._make_request()
        tx_hex = self._build_valid_tx_hex(amount=999999)
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(tx_hex, request)

    def test_wrong_currency_rejected(self) -> None:
        """Tx calling wrong contract should be rejected."""
        intent = self._make_intent()
        request = self._make_request()
        tx_hex = self._build_valid_tx_hex(
            currency="0x0000000000000000000000000000000000000001"
        )
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(tx_hex, request)

    def test_empty_calls_rejected(self) -> None:
        """Tx with no calls should be rejected."""
        import rlp

        tx_fields = [b"\x01", b"\x01", b"\x01", b"\x01", [], b"", b"", b"\x01"]
        encoded = rlp.encode(tx_fields)
        tx_hex = "0x76" + encoded.hex()

        intent = self._make_intent()
        request = self._make_request()
        with pytest.raises(VerificationError, match="no calls"):
            intent._validate_transaction_payload(tx_hex, request)

    def test_non_0x76_prefix_skipped(self) -> None:
        """Non-Tempo tx should be silently skipped (not validated)."""
        intent = self._make_intent()
        request = self._make_request()
        intent._validate_transaction_payload("0xdeadbeef", request)

    def test_invalid_hex_skipped(self) -> None:
        """Invalid hex string should be silently skipped."""
        intent = self._make_intent()
        request = self._make_request()
        intent._validate_transaction_payload("0xnothex", request)

    def test_valid_transfer_with_memo_passes(self) -> None:
        """Valid transferWithMemo tx should pass when memo matches."""
        memo = "0x" + "ab" * 32
        intent = self._make_intent()
        request = self._make_request(
            methodDetails={"memo": memo},
        )
        tx_hex = self._build_valid_tx_hex(memo=memo)
        intent._validate_transaction_payload(tx_hex, request)

    def test_wrong_memo_rejected(self) -> None:
        """Tx with wrong memo should be rejected."""
        intent = self._make_intent()
        request = self._make_request(
            methodDetails={"memo": "0x" + "ab" * 32},
        )
        tx_hex = self._build_valid_tx_hex(memo="0x" + "cd" * 32)
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(tx_hex, request)

    def test_memo_expected_but_transfer_selector_rejected(self) -> None:
        """When memo is expected, plain transfer selector should be rejected."""
        intent = self._make_intent()
        request = self._make_request(
            methodDetails={"memo": "0x" + "ab" * 32},
        )
        # Build tx with plain transfer (no memo)
        tx_hex = self._build_valid_tx_hex()
        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(tx_hex, request)


class TestVerifyTransferLogs:
    """Tests for _verify_transfer_logs edge cases."""

    def _make_intent(self) -> ChargeIntent:
        return ChargeIntent(rpc_url="https://rpc.test")

    def _make_request(self, **overrides: Any) -> ChargeRequest:
        defaults = {
            "amount": "1000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            "expires": "2030-01-01T00:00:00Z",
        }
        defaults.update(overrides)
        return ChargeRequest.model_validate(defaults)

    def test_empty_logs(self) -> None:
        """Should return False for empty logs."""
        intent = self._make_intent()
        request = self._make_request()
        assert intent._verify_transfer_logs({"logs": []}, request) is False

    def test_wrong_contract_address(self) -> None:
        """Should skip logs from wrong contract."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x0000000000000000000000000000000000000001",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_insufficient_topics(self) -> None:
        """Should skip logs with fewer than 3 topics."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_wrong_recipient_in_log(self) -> None:
        """Should skip logs with wrong recipient."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x" + "0" * 24 + "b" * 40,  # wrong recipient
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_wrong_amount_in_log(self) -> None:
        """Should return False when amount doesn't match."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                    ],
                    "data": "0x" + hex(9999)[2:].zfill(64),
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_expected_sender_mismatch(self) -> None:
        """Should reject when expected_sender doesn't match log from address."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,  # from
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert (
            intent._verify_transfer_logs(
                receipt, request, expected_sender="0x" + "b" * 40
            )
            is False
        )

    def test_expected_sender_match(self) -> None:
        """Should return True when expected_sender matches."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert (
            intent._verify_transfer_logs(
                receipt, request, expected_sender="0x" + "a" * 40
            )
            is True
        )

    def test_short_data_skipped(self) -> None:
        """Should skip logs with data too short to contain amount."""
        intent = self._make_intent()
        request = self._make_request()
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                    ],
                    "data": "0x",  # too short
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False

    def test_transfer_with_memo_topic_needs_4_topics(self) -> None:
        """TransferWithMemo log needs 4 topics (from, to, memo)."""
        intent = self._make_intent()
        memo = "0x" + "ab" * 32
        request = self._make_request(methodDetails={"memo": memo})
        receipt = {
            "logs": [
                {
                    "address": "0x20c0000000000000000000000000000000000000",
                    "topics": [
                        "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0",
                        "0x" + "0" * 24 + "a" * 40,
                        "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe00",
                        # missing 4th topic (memo)
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ]
        }
        assert intent._verify_transfer_logs(receipt, request) is False


class TestLocalFeePayerPriority:
    """Tests that local fee payer takes priority over external when both are configured."""

    @pytest.mark.asyncio
    async def test_local_fee_payer_not_calls_external_url(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """When local fee_payer is set, should NOT call feePayerUrl even if provided."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        method = tempo(
            fee_payer=fee_payer,
            intents={"charge": intent},
        )

        # Build a real sponsored tx so _cosign_as_fee_payer can decode it.
        # Use a separate RPC URL for client tx building to avoid mock collision.
        account = TempoAccount.from_key("0x" + "aa" * 32)
        client_method = tempo(
            account=account,
            rpc_url="https://rpc.client",
            intents={"charge": ChargeIntent()},
        )
        # Mock RPC for client tx building (chain_id, nonce, gas_price, estimateGas)
        httpx_mock.add_response(
            url="https://rpc.client",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.client",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.client",
            json={"jsonrpc": "2.0", "result": "0x1", "id": 1},
        )
        httpx_mock.add_response(
            url="https://rpc.client",
            json={"jsonrpc": "2.0", "result": "0x186a0", "id": 1},
        )

        challenge = Challenge(
            id="test-local-priority",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {
                    "feePayer": True,
                    "feePayerUrl": "https://evil-sponsor.test",
                },
            },
            realm="test.example.com",
            request_b64="e30",
        )

        cred = await client_method.create_credential(challenge)

        # Mock the broadcast + receipt for the server-side verify (local cosign path)
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0xlocal_hash", "id": 1},
        )
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
                                "0x" + "0" * 24 + "a" * 40,
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

        receipt = await intent.verify(
            make_credential(
                payload=cred.payload,
            ),
            {
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "expires": future,
                "methodDetails": {
                    "feePayer": True,
                    "feePayerUrl": "https://evil-sponsor.test",
                },
            },
        )

        assert receipt.status == "success"
        # Should never have called the evil sponsor URL
        requests = httpx_mock.get_requests()
        assert not any("evil-sponsor" in str(r.url) for r in requests)


class TestCosignAsFeePayer:
    """Tests for _cosign_as_fee_payer edge cases."""

    def test_cosign_no_fee_payer_raises(self) -> None:
        """Should raise VerificationError when no fee payer is configured."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        assert intent.fee_payer is None
        with pytest.raises(VerificationError, match="No fee payer account configured"):
            intent._cosign_as_fee_payer("0x76deadbeef")

    def test_cosign_non_0x76_raises(self) -> None:
        """Should raise VerificationError for non-Tempo transaction."""
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        method = tempo(fee_payer=fee_payer, intents={"charge": intent})
        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0xdeadbeef")

    def test_cosign_invalid_rlp_raises(self) -> None:
        """Should raise VerificationError for invalid RLP data."""
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        method = tempo(fee_payer=fee_payer, intents={"charge": intent})
        # 0x76 prefix with garbage
        with pytest.raises(VerificationError, match="Failed to deserialize|Fee payer signing failed"):
            intent._cosign_as_fee_payer("0x76ff")

    def test_cosign_empty_tx_raises(self) -> None:
        """Should raise VerificationError for empty transaction bytes."""
        fee_payer = TempoAccount.from_key(TEST_PRIVATE_KEY)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        method = tempo(fee_payer=fee_payer, intents={"charge": intent})
        with pytest.raises(VerificationError, match="Failed to deserialize"):
            intent._cosign_as_fee_payer("0x")


class TestReceiptPollingEdgeCases:
    """Tests for receipt polling error paths in _verify_transaction."""

    @pytest.mark.asyncio
    async def test_receipt_rpc_error_raises(self) -> None:
        """Should raise when receipt polling returns RPC error."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        intent = ChargeIntent(rpc_url="https://rpc.test")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                # Broadcast success
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash", "id": 1}),
                # Receipt poll returns error
                mock_response(
                    200,
                    {"jsonrpc": "2.0", "error": {"message": "internal error"}, "id": 1},
                ),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )
        with pytest.raises(VerificationError, match="Failed to fetch transaction receipt"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_no_tx_hash_returned_raises(self) -> None:
        """Should raise when broadcast returns no transaction hash."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        intent = ChargeIntent(rpc_url="https://rpc.test")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(200, {"jsonrpc": "2.0", "result": None, "id": 1})
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )
        with pytest.raises(VerificationError, match="No transaction hash returned"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_reverted_transaction_raises(self) -> None:
        """Should raise when submitted transaction reverts."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        intent = ChargeIntent(rpc_url="https://rpc.test")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash", "id": 1}),
                mock_response(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "result": {"status": "0x0", "logs": []},
                        "id": 1,
                    },
                ),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )
        with pytest.raises(VerificationError, match="Transaction reverted"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_transaction_no_matching_logs_after_broadcast(self) -> None:
        """Should raise when broadcast tx receipt has no matching transfer logs."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        intent = ChargeIntent(rpc_url="https://rpc.test")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                mock_response(200, {"jsonrpc": "2.0", "result": "0xtxhash", "id": 1}),
                mock_response(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "result": {"status": "0x1", "logs": []},
                        "id": 1,
                    },
                ),
            ]
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )
        with pytest.raises(VerificationError, match="Transfer log"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )

    @pytest.mark.asyncio
    async def test_broadcast_error_with_data_field(self) -> None:
        """Should include error data in VerificationError message."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        intent = ChargeIntent(rpc_url="https://rpc.test")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=mock_response(
                200,
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "message": "execution reverted",
                        "data": "0xdeadbeef",
                    },
                    "id": 1,
                },
            )
        )
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
        )
        with pytest.raises(VerificationError, match="execution reverted.*0xdeadbeef"):
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                    "expires": future,
                },
            )


class TestMppPayDecoratorMemo:
    """Tests for memo passing through Mpp.charge()."""

    @pytest.mark.asyncio
    async def test_charge_emits_memo_in_method_details(self) -> None:
        """Mpp.charge(memo=...) should include memo in methodDetails."""
        from mpp.server import Mpp

        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        memo = "0x" + "ab" * 32
        result = await srv.charge(authorization=None, amount="0.50", memo=memo)
        assert isinstance(result, Challenge)
        assert result.request["methodDetails"]["memo"] == memo

    @pytest.mark.asyncio
    async def test_charge_chain_id_in_method_details(self) -> None:
        """Mpp.charge(chain_id=...) should include chainId in methodDetails."""
        from mpp.server import Mpp

        srv = Mpp.create(
            method=tempo(
                chain_id=42431,
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert result.request["methodDetails"]["chainId"] == 42431
