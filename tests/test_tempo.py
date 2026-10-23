"""Tests for Tempo payment method."""

import asyncio
import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import rlp
from pytest_httpx import HTTPXMock

from mpp import Challenge
from mpp.errors import CredentialReplayedError, InternalPaymentError
from mpp.methods.tempo import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    MACH,
    OUSD,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    TempoAccount,
    escrow_contract_for_chain,
    fee_tokens_for_chain,
    tempo,
)
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import CHAIN_RPC_URLS
from mpp.methods.tempo._rpc import _tip20_balance
from mpp.methods.tempo.client import (
    EXPIRING_NONCE_KEY,
    EXPIRING_NONCE_VALID_BEFORE_SECS,
    TempoMethod,
    TransactionError,
    _expiring_valid_before,
)
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
    _is_ambiguous_broadcast_error,
    _match_single_transfer_calldata,
    _match_transfer_calldata,
    _parse_memo_bytes,
    _raw_transaction_hash,
    _rpc_error_msg,
    _transaction_valid_before,
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
from tests import internal_cause, make_credential

# Valid test private key (must be < secp256k1 order)
TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def mock_response(status_code: int = 200, json: dict | None = None) -> httpx.Response:
    """Create a mock response with a request attached."""
    request = httpx.Request("POST", "https://rpc.test")
    response = httpx.Response(status_code, json=json, request=request)
    return response


def assert_unconfirmed_after_broadcast(error: BaseException, cause_match: str) -> None:
    """Post-broadcast failures are internal and chain the original verification error."""
    cause = internal_cause(error)
    assert isinstance(cause, VerificationError)
    assert re.search(cause_match, str(cause))


def with_chain_id(mock_client: AsyncMock) -> AsyncMock:
    """Answer chain identity before delegating existing receipt RPC mocks."""
    original_post = mock_client.post

    async def post(url: str, *, json: dict) -> httpx.Response:
        if json["method"] == "eth_chainId":
            return mock_response(200, {"jsonrpc": "2.0", "result": hex(CHAIN_ID), "id": 1})
        return await original_post(url, json=json)

    mock_client.post = AsyncMock(side_effect=post)
    return mock_client


def amount_data(amount: int) -> str:
    return "0x" + hex(amount)[2:].zfill(64)


def http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://rpc.test")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(f"HTTP {status_code}", request=request, response=response)


def chained(error: Exception, cause: Exception) -> Exception:
    error.__cause__ = cause
    return error


def tempo_tx(valid_before: int | None, type_id: str = "76") -> str:
    """Serialize a minimal Tempo transaction carrying ``valid_before``."""
    fields = [42431, 0, 0, 0, [], [], 0, 0, valid_before or b""]
    return "0x" + type_id + bytes(rlp.encode(fields)).hex()


@pytest.mark.asyncio
async def test_tip20_balance() -> None:
    client = AsyncMock()
    client.post.return_value = mock_response(json={"result": "0x2a"})
    address = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

    balance = await _tip20_balance(
        "https://rpc.test",
        "0x20c0000000000000000000000000000000000000",
        address,
        client=client,
    )

    assert balance == 42
    client.post.assert_awaited_once_with(
        "https://rpc.test",
        json={
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": "0x20c0000000000000000000000000000000000000",
                    "data": "0x70a08231" + "0" * 24 + address[2:].lower(),
                },
                "latest",
            ],
            "id": 1,
        },
    )


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
    def test_mach_metadata_and_fee_tokens_are_public(self) -> None:
        assert MACH == "0x20c000000000000000000000f37de3740ADec032"
        assert fee_tokens_for_chain(CHAIN_ID) == (PATH_USD, USDC)
        assert fee_tokens_for_chain(TESTNET_CHAIN_ID) == (PATH_USD,)

    def test_tempo_factory(self) -> None:
        """tempo() should create a TempoMethod."""
        method = tempo(intents={"charge": ChargeIntent()})
        assert isinstance(method, TempoMethod)
        assert method.name == "tempo"

    def test_tempo_default_currency_is_not_a_client_constraint(self) -> None:
        method = tempo(intents={"charge": ChargeIntent()})

        assert method._currency_explicit is False

    def test_tempo_provided_currency_is_a_client_constraint(self) -> None:
        method = tempo(currency="0xUsdc", intents={"charge": ChargeIntent()})

        assert method._currency_explicit is True

    @pytest.mark.parametrize("sponsored", [False, True])
    def test_transaction_hash_for_signed_transaction(self, sponsored: bool) -> None:
        """Unsponsored hashes match settlement; sponsored ones await the fee payer."""
        from pytempo import Call, TempoTransaction

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        tx = TempoTransaction.create(
            chain_id=CHAIN_ID,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=0,
            fee_token=None if sponsored else PATH_USD,
            awaiting_fee_payer=sponsored,
            calls=(Call.create(to=PATH_USD, value=0, data="0x"),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        raw_tx = "0x" + (encode_fee_payer_envelope(signed) if sponsored else signed.encode()).hex()
        credential = make_credential(payload={"type": "transaction", "signature": raw_tx})

        trailing = make_credential(payload={"type": "transaction", "signature": raw_tx + "00"})

        expected = None if sponsored else _raw_transaction_hash(raw_tx)
        assert TempoMethod().transaction_hash(credential) == expected
        assert TempoMethod().transaction_hash(trailing) is None

    @pytest.mark.parametrize(
        "payload",
        [
            {"type": "hash", "hash": "0xabc"},
            {"type": "transaction"},
            {"type": "transaction", "signature": ""},
            {"type": "transaction", "signature": "0xnothex"},
            {"type": "transaction", "signature": "0x01"},
            {"type": "transaction", "signature": "0x02" + "c0"},
            {"type": "transaction", "signature": "0x76"},
            {"type": "transaction", "signature": "0x76ff"},
            {"type": "transaction", "signature": "0x76" + bytes(rlp.encode(b"\x01")).hex()},
            {"type": "transaction", "signature": "0x76" + bytes(rlp.encode([b"\x01"] * 14)).hex()},
            {
                "type": "transaction",
                "signature": "0x76" + bytes(rlp.encode([b"\x01"] * 4 + [[]] + [b"\x01"] * 9)).hex(),
            },
            {
                "type": "transaction",
                "signature": "0x76"
                + bytes(rlp.encode([b"\x01"] * 4 + [[[b"\x01"]]] + [b""] * 9)).hex(),
            },
        ],
        ids=[
            "hash-payload",
            "missing",
            "empty",
            "not-hex",
            "unknown-type",
            "eip1559",
            "no-body",
            "malformed-rlp",
            "not-a-list",
            "calls-not-a-list",
            "no-calls",
            "unsigned",
        ],
    )
    def test_transaction_hash_unknown_without_signed_transaction(self, payload: dict) -> None:
        credential = make_credential(payload=payload)

        assert TempoMethod().transaction_hash(credential) is None

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

    @pytest.mark.asyncio
    @pytest.mark.parametrize("currency", [MACH, OUSD])
    async def test_mach_access_key_uses_root_balance_for_fee_token(self, currency: str) -> None:
        access_key = TempoAccount.from_key(TEST_PRIVATE_KEY)
        root = "0x975937feafc6869a260c176854dda8764a78e122"
        method = tempo(
            account=access_key,
            root_account=root,
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="mach-fee-token",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": currency,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            return {
                "eth_chainId": hex(CHAIN_ID),
                "eth_gasPrice": "0x1",
            }[method_name]

        async def fake_balance(_rpc_url: str, token: str, address: str) -> int:
            assert address == root
            return 1 if token.lower() == PATH_USD.lower() else 0

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", side_effect=fake_balance),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        ):
            credential = await method.create_credential(challenge)

        decoded = rlp.decode(bytes.fromhex(credential.payload["signature"][2:])[1:])
        assert decoded[10] == bytes.fromhex(PATH_USD[2:])
        assert credential.source is not None
        assert credential.source.endswith(f":{root}")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("currency", [MACH, OUSD])
    @pytest.mark.parametrize("chain_id,fee_token", [(CHAIN_ID, USDC), (TESTNET_CHAIN_ID, PATH_USD)])
    async def test_charge_selects_funded_supported_fee_token(
        self, currency: str, chain_id: int, fee_token: str
    ) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=chain_id,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="mach-usdc-fee-token",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": currency,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            return {
                "eth_chainId": hex(chain_id),
                "eth_gasPrice": "0x1",
            }[method_name]

        async def fake_balance(_rpc_url: str, token: str, _address: str) -> int:
            return 1 if token.lower() == fee_token.lower() else 0

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", side_effect=fake_balance),
            patch(
                "mpp.methods.tempo.client.estimate_gas",
                new=AsyncMock(return_value=100_000),
            ),
        ):
            credential = await method.create_credential(challenge)

        decoded = rlp.decode(bytes.fromhex(credential.payload["signature"][2:])[1:])
        assert decoded[10] == bytes.fromhex(fee_token[2:])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("currency", [MACH, OUSD])
    async def test_mach_charge_skips_fee_token_that_cannot_cover_max_fee(
        self, currency: str
    ) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="mach-fee-token-balance",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": currency,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            return {
                "eth_chainId": hex(CHAIN_ID),
                # 1,000,000 gas at this price costs 1,000 microdollars.
                "eth_gasPrice": hex(1_000_000_000),
            }[method_name]

        async def fake_balance(_rpc_url: str, token: str, _address: str) -> int:
            return 1 if token.lower() == PATH_USD.lower() else 1_000

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", side_effect=fake_balance),
            patch(
                "mpp.methods.tempo.client.estimate_gas",
                new=AsyncMock(return_value=100_000),
            ),
        ):
            credential = await method.create_credential(challenge)

        decoded = rlp.decode(bytes.fromhex(credential.payload["signature"][2:])[1:])
        assert decoded[10] == bytes.fromhex(USDC[2:])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("currency", [MACH, OUSD])
    async def test_sponsored_mach_charge_defers_fee_token_to_fee_payer(self, currency: str) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="mach-sponsored",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": currency,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"feePayer": True, "chainId": CHAIN_ID},
            },
        )

        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            return {
                "eth_chainId": hex(CHAIN_ID),
                "eth_gasPrice": "0x1",
            }[method_name]

        balance = AsyncMock(return_value=0)
        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", new=balance),
            patch(
                "mpp.methods.tempo.client.estimate_gas",
                new=AsyncMock(return_value=100_000),
            ),
        ):
            credential = await method.create_credential(challenge)

        decoded, _, _, _ = decode_fee_payer_envelope(
            bytes.fromhex(credential.payload["signature"][2:])
        )
        assert decoded[10] == b""
        balance.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("currency", [MACH, OUSD])
    async def test_mach_charge_requires_a_funded_stablecoin_fee_token(self, currency: str) -> None:
        account = TempoAccount.from_key(TEST_PRIVATE_KEY)
        method = tempo(
            account=account,
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="mach-no-fee-token",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": currency,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
        )

        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            return {
                "eth_chainId": hex(CHAIN_ID),
                "eth_gasPrice": "0x1",
            }[method_name]

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", new=AsyncMock(return_value=0)),
        ):
            with pytest.raises(TransactionError, match="funded supported stablecoin"):
                await method.create_credential(challenge)

    def test_tempo_propagates_rpc_url_to_intents(self, currency: str) -> None:
        """tempo() should propagate rpc_url to intents that don't set one."""
        intent = ChargeIntent()
        assert intent.rpc_url is None
        method = tempo(
            rpc_url="https://custom.rpc",
            intents={"charge": intent},
        )
        assert cast(ChargeIntent, method.intents["charge"]).rpc_url == "https://custom.rpc"

    def test_tempo_does_not_override_explicit_intent_rpc_url(self, currency: str) -> None:
        """tempo() should not override an intent's explicitly-set rpc_url."""
        intent = ChargeIntent(rpc_url="https://intent.rpc")
        method = tempo(
            rpc_url="https://method.rpc",
            intents={"charge": intent},
        )
        assert cast(ChargeIntent, method.intents["charge"]).rpc_url == "https://intent.rpc"

    def test_intents_property(self, currency: str) -> None:
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
        assert "eth_getTransactionCount" not in rpc_methods
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
    @pytest.mark.parametrize("legacy_memo", ["", "0x" + "ab" * 32])
    async def test_create_credential_uses_attribution_memo(self, legacy_memo: str) -> None:
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
                "methodDetails": {"memo": legacy_memo},
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


def _decode_signed_charge(signature: str) -> list:
    """Decode the RLP fields of a signed 0x76 tx or 0x78 fee payer envelope."""
    raw = bytes.fromhex(signature.removeprefix("0x"))
    if raw[0] == 0x78:
        decoded, _, _, _ = decode_fee_payer_envelope(raw)
        return decoded
    return rlp.decode(raw[1:])


_NOW = 1_800_000_000


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


class TestExpiringNonce:
    """Charges sign with expiring nonces instead of sequential account nonces."""

    @staticmethod
    def _challenge(
        challenge_id: str,
        *,
        fee_payer: bool,
        expires: str | None = None,
        extra: dict | None = None,
    ) -> Challenge:
        return Challenge(
            id=challenge_id,
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": PATH_USD,
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": {"feePayer": fee_payer, "chainId": CHAIN_ID},
                **(extra or {}),
            },
            realm="api.example.com",
            expires=expires,
        )

    @staticmethod
    def _fake_rpc(rpc_methods: list[str]):
        async def fake_rpc_call(
            _rpc_url: str,
            method_name: str,
            _params: list[object],
            *,
            client: object | None = None,
        ) -> str:
            del client
            rpc_methods.append(method_name)
            return {"eth_chainId": hex(CHAIN_ID), "eth_gasPrice": "0x1"}[method_name]

        return fake_rpc_call

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "fee_payer,expires_in,extra",
        [
            pytest.param(False, None, None, id="unsponsored"),
            pytest.param(True, None, None, id="sponsored"),
            pytest.param(False, 10, None, id="unsponsored-capped-by-challenge-expiry"),
            pytest.param(True, 10, None, id="sponsored-capped-by-challenge-expiry"),
            pytest.param(False, None, {"nonce_key": "0x5"}, id="ignores-challenge-nonce-key"),
        ],
    )
    async def test_charge_signs_with_expiring_nonce(
        self, fee_payer: bool, expires_in: int | None, extra: dict | None
    ) -> None:
        method = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        start = time.time()
        expires = None
        window = EXPIRING_NONCE_VALID_BEFORE_SECS
        if expires_in is not None:
            expires = datetime.fromtimestamp(start + expires_in, UTC).isoformat()
            window = min(window, expires_in + 1)
        rpc_methods: list[str] = []

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=self._fake_rpc(rpc_methods)),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        ):
            credential = await method.create_credential(
                self._challenge("expiring", fee_payer=fee_payer, expires=expires, extra=extra)
            )

        decoded = _decode_signed_charge(credential.payload["signature"])
        assert int.from_bytes(decoded[6], "big") == EXPIRING_NONCE_KEY
        assert int.from_bytes(decoded[7], "big") == 0
        valid_before = int.from_bytes(decoded[8], "big")
        assert int(start) + window <= valid_before <= int(time.time()) + window
        assert "eth_getTransactionCount" not in rpc_methods
        signature = credential.payload["signature"]
        expected_hash = None if fee_payer else _raw_transaction_hash(signature)
        assert method.transaction_hash(credential) == expected_hash

    @pytest.mark.asyncio
    async def test_valid_before_is_set_after_slow_rpc_preparation(self) -> None:
        method = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        clock = [float(_NOW)]

        async def slow_rpc(_url: str, method_name: str, *_: object, **__: object) -> str:
            clock[0] += 30
            return {"eth_chainId": hex(CHAIN_ID), "eth_gasPrice": "0x1"}[method_name]

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=slow_rpc),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
            patch("mpp.methods.tempo.client.time.time", side_effect=lambda: clock[0]),
        ):
            credential = await method.create_credential(self._challenge("slow", fee_payer=False))

        decoded = _decode_signed_charge(credential.payload["signature"])
        assert int.from_bytes(decoded[8], "big") == int(clock[0]) + EXPIRING_NONCE_VALID_BEFORE_SECS

    @pytest.mark.parametrize(
        "now,expires,expected",
        [
            pytest.param(_NOW, None, _NOW + EXPIRING_NONCE_VALID_BEFORE_SECS, id="no-expiry"),
            pytest.param(
                _NOW,
                _iso(_NOW + 60),
                _NOW + EXPIRING_NONCE_VALID_BEFORE_SECS,
                id="expiry-after-window",
            ),
            pytest.param(_NOW, _iso(_NOW + 10), _NOW + 11, id="expiry-inside-window"),
            pytest.param(_NOW, _iso(_NOW + 10.5), _NOW + 11, id="fractional-expiry"),
            pytest.param(_NOW + 0.2, _iso(_NOW + 0.5), _NOW + 1, id="sub-second-expiry"),
            pytest.param(_NOW + 0.5, _iso(_NOW + 0.5), _NOW + 1, id="expiry-is-now"),
            pytest.param(_NOW, _iso(_NOW), _NOW + 1, id="whole-second-expiry-is-now"),
            pytest.param(
                _NOW + 0.999,
                "2027-01-15T08:00:00.999999Z",
                _NOW + 1,
                id="microsecond-expiry",
            ),
            pytest.param(
                _NOW, "not-a-date", _NOW + EXPIRING_NONCE_VALID_BEFORE_SECS, id="unparsable"
            ),
        ],
    )
    def test_valid_before_is_capped_at_challenge_expiry(
        self, now: float, expires: str | None, expected: int
    ) -> None:
        with patch("mpp.methods.tempo.client.time.time", return_value=now):
            valid_before = _expiring_valid_before(expires)
        assert valid_before == expected
        # Still valid at signing time, even when the challenge expires this second.
        assert valid_before > now

    @pytest.mark.asyncio
    @pytest.mark.parametrize("fee_payer", [False, True], ids=["unsponsored", "sponsored"])
    async def test_concurrent_charges_do_not_share_a_sequential_nonce(
        self, fee_payer: bool
    ) -> None:
        method = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=CHAIN_ID,
            rpc_url="https://rpc.test",
            intents={"charge": ChargeIntent()},
        )
        rpc_methods: list[str] = []
        challenges = [self._challenge(f"concurrent-{i}", fee_payer=fee_payer) for i in range(5)]

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=self._fake_rpc(rpc_methods)),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        ):
            credentials = await asyncio.gather(
                *(method.create_credential(challenge) for challenge in challenges)
            )

        signatures = [credential.payload["signature"] for credential in credentials]
        assert len({_raw_transaction_hash(signature) for signature in signatures}) == len(
            challenges
        )
        for signature in signatures:
            decoded = _decode_signed_charge(signature)
            assert int.from_bytes(decoded[6], "big") == EXPIRING_NONCE_KEY
            assert int.from_bytes(decoded[7], "big") == 0
        assert "eth_getTransactionCount" not in rpc_methods


class TestInFlightSigning:
    """Concurrent calls for one challenge share an in-flight signing."""

    @staticmethod
    def _method() -> tuple[TempoMethod, AsyncMock]:
        method = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=CHAIN_ID,
            intents={"charge": ChargeIntent()},
        )
        signings = iter(range(1_000))

        async def build(**_: object) -> tuple[str, int]:
            await asyncio.sleep(0)
            return f"0x76{next(signings):04x}", CHAIN_ID

        return method, AsyncMock(side_effect=build)

    @staticmethod
    def _challenge(challenge_id: str = "shared", recipient: str | None = None) -> Challenge:
        return Challenge(
            id=challenge_id,
            method="tempo",
            intent="charge",
            request={
                "amount": "1000",
                "currency": PATH_USD,
                "recipient": recipient or "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            },
            realm="api.example.com",
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "concurrent,other_id,signings",
        [
            pytest.param(True, "shared", 1, id="concurrent-same-challenge"),
            pytest.param(False, "shared", 2, id="sequential-same-challenge"),
            pytest.param(True, "other", 2, id="concurrent-different-challenge"),
        ],
    )
    async def test_signings(self, concurrent: bool, other_id: str, signings: int) -> None:
        method, build = self._method()

        with patch.object(method, "_build_tempo_transfer", build):
            if concurrent:
                first, second = await asyncio.gather(
                    method.create_credential(self._challenge()),
                    method.create_credential(self._challenge(other_id)),
                )
            else:
                first = await method.create_credential(self._challenge())
                second = await method.create_credential(self._challenge(other_id))

        assert build.await_count == signings
        assert (first == second) is (signings == 1)
        assert method._signing == {}

    @pytest.mark.asyncio
    async def test_failed_signing_is_not_shared_with_a_later_call(self) -> None:
        method, build = self._method()
        build.side_effect = [TransactionError("rpc down"), ("0x76ok", CHAIN_ID)]

        with patch.object(method, "_build_tempo_transfer", build):
            with pytest.raises(TransactionError):
                await method.create_credential(self._challenge())
            credential = await method.create_credential(self._challenge())

        assert build.await_count == 2
        assert credential.payload["signature"] == "0x76ok"

    @pytest.mark.asyncio
    async def test_policy_is_enforced_when_joining_a_signing(self) -> None:
        method, build = self._method()
        method.expected_recipients = ("0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",)

        with patch.object(method, "_build_tempo_transfer", build):
            results = await asyncio.gather(
                method.create_credential(self._challenge()),
                method.create_credential(self._challenge(recipient="0x" + "44" * 20)),
                return_exceptions=True,
            )

        first, second = results
        assert not isinstance(first, BaseException)
        assert first.payload["type"] == "transaction"
        assert isinstance(second, ValueError)
        assert build.await_count == 1


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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
        with_chain_id(mock_client)

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
    @pytest.mark.parametrize(
        ("store_source", "expected_warnings"),
        [("default", 1), ("intent", 0), ("server", 0)],
    )
    async def test_default_memory_store_warns_once_per_process(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
        store_source: str,
        expected_warnings: int,
    ) -> None:
        from mpp.server import Mpp
        from mpp.store import MemoryStore

        monkeypatch.setattr("mpp.methods.tempo.intents._warned_fallback_stores", set())
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        request = {
            "amount": "1000",
            "currency": "0x1234567890123456789012345678901234567890",
            "recipient": "0x4567890123456789012345678901234567890123",
        }
        credential = make_credential(payload={"type": "hash", "hash": "0xabc123"}, expires=future)

        for _ in range(2):
            store = MemoryStore()
            intent = ChargeIntent(
                rpc_url="https://rpc.test",
                store=store if store_source == "intent" else None,
            )
            if store_source == "server":
                Mpp.create(
                    method=tempo(
                        intents={"charge": intent},
                        currency=request["currency"],
                        recipient=request["recipient"],
                    ),
                    realm="test.com",
                    secret_key="test-secret",
                    store=store,
                )
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                return_value=mock_response(
                    200,
                    {"jsonrpc": "2.0", "result": {"status": "0x0", "logs": []}, "id": 1},
                )
            )
            intent._http_client = mock_client
            with_chain_id(mock_client)

            for _ in range(2):
                with pytest.raises(VerificationError, match="Transaction reverted"):
                    await intent.broadcast(credential, request)

            assert (intent._store is store) == (store_source != "default")
            assert isinstance(intent._store, MemoryStore)

        warnings = [r for r in caplog.records if "in-memory store" in r.getMessage()]
        assert len(warnings) == expected_warnings
        assert all("tempo.charge has no store configured" in r.getMessage() for r in warnings)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lookup", "cause", "cause_text"),
        [
            (httpx.ReadTimeout("timed out"), httpx.ReadTimeout, "timed out"),
            (mock_response(500), httpx.HTTPStatusError, "500"),
            (
                mock_response(200, {"error": {"message": "header not found"}}),
                RuntimeError,
                "header not found",
            ),
            (mock_response(200, {"result": None}), RuntimeError, "Transaction not found"),
            (mock_response(200, {"result": "0x1"}), RuntimeError, "Invalid transaction receipt"),
        ],
        ids=["transport", "http", "rpc", "missing", "malformed"],
    )
    async def test_verify_hash_receipt_lookup_failure_is_internal(
        self,
        lookup: httpx.Response | Exception,
        cause: type[Exception],
        cause_text: str,
    ) -> None:
        """A failed receipt lookup cannot prove a pushed payment invalid."""
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        tx_hash = "0xabc123"
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[lookup])
        intent._http_client = mock_client
        with_chain_id(mock_client)

        credential = make_credential(payload={"type": "hash", "hash": tx_hash}, expires=future)

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        error = internal_cause(raised.value)
        assert isinstance(error, cause)
        assert cause_text in str(error)
        assert await store.get(f"mpp:charge:{tx_hash}") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("chain_id", "cause", "cause_text"),
        [
            (httpx.ConnectError("connection refused"), httpx.ConnectError, "refused"),
            (mock_response(503), httpx.HTTPStatusError, "503"),
            (
                mock_response(200, {"error": {"message": "upstream down"}}),
                RuntimeError,
                "upstream down",
            ),
            (mock_response(200, {"jsonrpc": "2.0", "id": 1}), KeyError, "result"),
            (mock_response(200, {"result": "0xzz"}), ValueError, "0xzz"),
            (mock_response(200, {"result": hex(CHAIN_ID + 1)}), RuntimeError, "does not match"),
        ],
        ids=["transport", "http", "rpc", "missing", "malformed", "mismatch"],
    )
    async def test_validate_hash_chain_id_failure_is_internal(
        self,
        chain_id: httpx.Response | Exception,
        cause: type[Exception],
        cause_text: str,
    ) -> None:
        """A settlement RPC that cannot confirm its chain is a server fault."""
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[chain_id])
        intent._http_client = mock_client

        credential = make_credential(payload={"type": "hash", "hash": "0xabc123"}, expires=future)

        with pytest.raises(InternalPaymentError) as raised:
            await intent.validate(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        error = internal_cause(raised.value)
        assert isinstance(error, cause)
        assert cause_text in str(error)
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_chainId"]

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
            "transactionHash": _raw_transaction_hash("0xabcdef1234567890"),
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
        assert receipt.reference == _raw_transaction_hash("0xabcdef1234567890")
        assert mock_client.post.await_args is not None
        assert mock_client.post.await_args.kwargs["json"]["method"] == "eth_sendRawTransactionSync"

    @pytest.mark.asyncio
    async def test_verify_transaction_accepts_transfer_with_memo_logs(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        amount = 1000
        memo = encode_attribution(challenge_id="test", server_id="test.example.com")

        receipt_with_logs = {
            "transactionHash": _raw_transaction_hash("0xabcdef1234567890"),
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
        assert receipt.reference == _raw_transaction_hash("0xabcdef1234567890")

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

        # The transfer landed, so this is a final answer rather than an internal error.
        with pytest.raises(CredentialReplayedError, match="memo is not bound to this challenge"):
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

        # The transfer landed, so this is a final answer rather than an internal error.
        with pytest.raises(CredentialReplayedError, match="memo is not bound to this challenge"):
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
    @pytest.mark.parametrize("explicit_store", [False, True])
    async def test_verify_transaction_rejects_duplicate_without_rpc(
        self,
        explicit_store: bool,
    ) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store if explicit_store else None)

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

        started = asyncio.Event()
        finish = asyncio.Event()

        async def broadcast(*args, **kwargs):
            started.set()
            await finish.wait()
            return mock_response(200, {"jsonrpc": "2.0", "result": receipt_with_logs, "id": 1})

        mock_client.post.side_effect = broadcast
        first = asyncio.create_task(intent.verify(credential, request))
        await started.wait()
        try:
            with pytest.raises(VerificationError, match="Transaction hash already used"):
                await asyncio.wait_for(intent.verify(credential, request), timeout=1)
        finally:
            finish.set()
        first_receipt = await first
        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await asyncio.wait_for(intent.verify(credential, request), timeout=1)

        assert first_receipt.reference == tx_hash
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync"]

        if not explicit_store:
            assert intent._store is not None
            for index in range(9_999):
                assert await intent._store.put_if_absent(f"reserved:{index}", "hash")
            with pytest.raises(RuntimeError, match="Replay store capacity reached"):
                await intent._store.put_if_absent("overflow", "hash")
            with pytest.raises(VerificationError, match="Transaction hash already used"):
                await intent.verify(credential, request)

    @pytest.mark.asyncio
    async def test_verify_transaction_releases_hash_on_failed_receipt(self) -> None:
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

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )
        assert_unconfirmed_after_broadcast(raised.value, "Transaction reverted")

        assert await store.get(f"mpp:charge:{tx_hash}") is None

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
        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )
        assert_unconfirmed_after_broadcast(raised.value, "Transaction submission failed")

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

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )
        assert_unconfirmed_after_broadcast(raised.value, "Transaction submission failed")

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

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )
        assert_unconfirmed_after_broadcast(raised.value, "Transaction submission failed")

        assert await store.get(f"mpp:charge:{tx_hash}") is None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "lookup_failure",
        [None, "rpc", "transport", "cancelled", "initial_missing", "initial_malformed"],
    )
    async def test_verify_transaction_already_known_error_fetches_receipt(
        self,
        lookup_failure: str | None,
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

        if lookup_failure is not None:
            failed_lookup = {
                "rpc": mock_response(200, {"error": {"message": "temporarily unavailable"}}),
                "transport": httpx.ReadTimeout("receipt lookup timed out"),
                "cancelled": asyncio.CancelledError(),
                "initial_missing": mock_response(200, {"result": None}),
                "initial_malformed": mock_response(200, {"result": "invalid"}),
            }[lookup_failure]
            mock_client.post.side_effect = [
                mock_response(200, {"error": {"message": "already known"}}),
                failed_lookup,
                mock_response(200, {"error": {"message": "already known"}}),
                mock_response(200, {"result": receipt_with_logs}),
            ]
            if lookup_failure.startswith("initial_"):
                mock_client.post.side_effect = [
                    failed_lookup,
                    mock_response(200, {"error": {"message": "already known"}}),
                    mock_response(200, {"result": receipt_with_logs}),
                ]
            with pytest.raises((InternalPaymentError, asyncio.CancelledError)):
                await intent.verify(credential, request)
            assert await store.get(f"mpp:charge:{tx_hash}") is None

        receipt = await intent.verify(credential, request)
        with pytest.raises(CredentialReplayedError):
            await intent.verify(credential, request)

        assert receipt.reference == tx_hash
        assert await store.get(f"mpp:charge:{tx_hash}") is not None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        expected_methods = ["eth_sendRawTransactionSync", "eth_getTransactionReceipt"]
        if lookup_failure:
            expected_methods = (
                ["eth_sendRawTransactionSync"]
                if lookup_failure.startswith("initial_")
                else expected_methods
            ) + expected_methods
        assert methods == expected_methods

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            pytest.param(httpx.ReadTimeout("read timed out"), True, id="read-timeout"),
            pytest.param(httpx.WriteTimeout("write timed out"), True, id="write-timeout"),
            pytest.param(httpx.ReadError("connection reset"), True, id="read-error"),
            pytest.param(httpx.RemoteProtocolError("disconnected"), True, id="disconnect"),
            pytest.param(TimeoutError("deadline"), True, id="local-deadline"),
            pytest.param(http_status_error(502), True, id="http-502"),
            pytest.param(
                chained(VerificationError("send failed"), httpx.ReadTimeout("read timed out")),
                True,
                id="chained-timeout",
            ),
            pytest.param(VerificationError("AlreadyKnown"), True, id="already-known-exception"),
            pytest.param({"error": {"code": -32000, "message": "already known"}}, True),
            pytest.param({"error": {"code": -32010, "message": "Known transaction: 0xab"}}, True),
            pytest.param({"error": {"code": 4, "message": "not confirmed"}}, True, id="eip-7966"),
            pytest.param(httpx.ConnectError("connection refused"), False, id="connect-error"),
            pytest.param(httpx.ConnectTimeout("connect timed out"), False, id="connect-timeout"),
            pytest.param(httpx.PoolTimeout("pool exhausted"), False, id="pool-timeout"),
            pytest.param(http_status_error(429), False, id="http-429"),
            pytest.param(
                chained(VerificationError("send failed"), httpx.ConnectError("refused")),
                False,
                id="chained-connect-error",
            ),
            pytest.param(VerificationError("invalid signature"), False, id="other-exception"),
            pytest.param({"error": {"code": -32601, "message": "method not found"}}, False),
            pytest.param({"error": {"code": -32602, "message": "invalid params"}}, False),
            pytest.param({"error": {"code": -32000, "message": "insufficient funds"}}, False),
            pytest.param({"error": {"code": -32000, "message": "invalid signature"}}, False),
            pytest.param({"error": {"code": -32000, "message": "execution reverted"}}, False),
            pytest.param({"error": {"code": -32000, "message": "unknown transaction type"}}, False),
        ],
    )
    def test_is_ambiguous_broadcast_error(self, error: Exception | dict, expected: bool) -> None:
        assert _is_ambiguous_broadcast_error(error) is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("send", "lookup_plan", "expected_error", "expected_lookups"),
        [
            pytest.param("already_known", ["pending", "mined"], None, 2, id="already-known-mined"),
            pytest.param("sync_timeout", ["pending", "mined"], None, 2, id="sync-timeout-mined"),
            pytest.param("read_timeout", ["pending", "mined"], None, 2, id="read-timeout-mined"),
            pytest.param("disconnect", ["mined"], None, 1, id="disconnect-mined"),
            pytest.param("gateway", ["mined"], None, 1, id="http-5xx-mined"),
            pytest.param("hang", ["mined"], None, 1, id="send-budget-exhausted-mined"),
            pytest.param(
                "already_known",
                ["pending"],
                (VerificationError, "already known"),
                2,
                id="already-known-never-mined",
            ),
            pytest.param(
                "read_timeout",
                ["pending"],
                (httpx.ReadTimeout, "send timed out"),
                2,
                id="read-timeout-never-mined",
            ),
            pytest.param(
                "hang",
                ["pending"],
                (TimeoutError, "timed out after 0.2s"),
                2,
                id="send-budget-exhausted-polls-reserved-window",
            ),
            pytest.param(
                "already_known",
                ["rpc_error"],
                (VerificationError, "already known"),
                1,
                id="lookup-rpc-error-keeps-broadcast-error",
            ),
            pytest.param(
                "read_timeout",
                ["transport_error"],
                (httpx.ReadTimeout, "send timed out"),
                1,
                id="lookup-transport-error-keeps-broadcast-error",
            ),
            pytest.param(
                "already_known",
                ["hang"],
                (VerificationError, "already known"),
                1,
                id="lookup-bounded-by-deadline",
            ),
            pytest.param(
                "already_known",
                ["wrong_hash"],
                (VerificationError, "does not match submitted transaction"),
                1,
                id="receipt-hash-mismatch",
            ),
        ],
    )
    async def test_verify_transaction_recovers_receipt_after_ambiguous_send(
        self,
        monkeypatch: pytest.MonkeyPatch,
        send: str,
        lookup_plan: list[str],
        expected_error: tuple[type[Exception], str | None] | None,
        expected_lookups: int,
    ) -> None:
        from mpp.store import MemoryStore

        monkeypatch.setattr("mpp.methods.tempo.intents.RECEIPT_POLL_INTERVAL", 0.01)
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store, confirmation_timeout=0.3)

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
        send_results: dict[str, httpx.Response | Exception] = {
            "already_known": mock_response(200, {"error": {"message": "already known"}}),
            "sync_timeout": mock_response(
                200, {"error": {"code": 4, "message": "wasn't confirmed within 200ms"}}
            ),
            "read_timeout": httpx.ReadTimeout("send timed out"),
            "disconnect": httpx.RemoteProtocolError("server disconnected"),
            "gateway": mock_response(502, {}),
        }
        lookup_results = {
            "pending": {"result": None},
            "mined": {"result": receipt_with_logs},
            "wrong_hash": {"result": {**receipt_with_logs, "transactionHash": "0x" + "12" * 32}},
            "rpc_error": {"error": {"message": "lookup unavailable"}},
        }
        sync_params: list[list] = []
        lookups: list[str] = []

        async def post(url: str, *, json: dict) -> httpx.Response:
            if json["method"] == "eth_sendRawTransactionSync":
                sync_params.append(json["params"])
                if send == "hang":
                    await asyncio.sleep(10)
                result = send_results[send]
                if isinstance(result, Exception):
                    raise result
                return result
            assert json["method"] == "eth_getTransactionReceipt"
            assert json["params"] == [tx_hash]
            outcome = lookup_plan[min(len(lookups), len(lookup_plan) - 1)]
            lookups.append(outcome)
            if outcome == "hang":
                await asyncio.sleep(10)
            if outcome == "transport_error":
                raise httpx.ConnectError("lookup unavailable")
            return mock_response(200, lookup_results[outcome])

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=post)
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )
        request = {"amount": "1000", "currency": asset, "recipient": destination}

        started = time.monotonic()
        if expected_error is None:
            receipt = await intent.verify(credential, request)
            assert receipt.reference == tx_hash
            assert len(lookups) == expected_lookups
            assert await store.get(f"mpp:charge:{tx_hash}") is not None
        else:
            # After broadcast, giving up surfaces the original broadcast error as the cause.
            error_type, error_match = expected_error
            with pytest.raises(InternalPaymentError) as raised:
                await intent.verify(credential, request)
            cause = internal_cause(raised.value)
            assert isinstance(cause, error_type)
            assert re.search(error_match or "", str(cause))
            assert len(lookups) >= expected_lookups
            assert await store.get(f"mpp:charge:{tx_hash}") is None
        assert time.monotonic() - started < 1
        assert sync_params == [[raw_signature, 200]]

    @pytest.mark.parametrize(
        ("raw_tx", "expected"),
        [
            pytest.param(tempo_tx(1_700_000_000), 1_700_000_000, id="0x76"),
            pytest.param(tempo_tx(1_700_000_000, type_id="78"), 1_700_000_000, id="0x78"),
            pytest.param(tempo_tx(None), None, id="no-valid-before"),
            pytest.param(tempo_tx(1, type_id="02"), None, id="not-tempo"),
            pytest.param("0x76" + bytes(rlp.encode([1, 2])).hex(), None, id="short"),
            pytest.param("0x76ff", None, id="malformed-rlp"),
            pytest.param("0x76zz", None, id="malformed-hex"),
        ],
    )
    def test_transaction_valid_before(self, raw_tx: str, expected: int | None) -> None:
        assert _transaction_valid_before(raw_tx) == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("validity_left", "deadline_left", "lookup", "expected_lookups", "elapsed"),
        [
            pytest.param(None, 0.3, "pending", None, (0.29, 0.6), id="no-valid-before"),
            pytest.param(3600.0, 0.3, "pending", None, (0.29, 0.6), id="long-validity"),
            pytest.param(0.1, 0.3, "pending", None, (0.09, 0.25), id="cap-ends-polling"),
            pytest.param(0.1, 0.3, "late", None, (0.09, 0.25), id="cap-final-lookup-mined"),
            pytest.param(3600.0, 0.3, "mined", 1, (0.0, 0.1), id="valid-mined"),
            pytest.param(-8.0, 0.3, "mined", 1, (0.0, 0.05), id="expired-final-lookup-mined"),
            pytest.param(-8.0, 0.3, "pending", 1, (0.0, 0.05), id="expired-final-lookup-pending"),
            pytest.param(-8.0, 0.3, "error", 1, (0.0, 0.05), id="expired-final-lookup-error"),
            pytest.param(-8.0, -1.0, "mined", 1, (0.0, 0.05), id="expired-no-deadline-left"),
        ],
    )
    async def test_recover_receipt_stops_after_transaction_expiry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        validity_left: float | None,
        deadline_left: float,
        lookup: str,
        expected_lookups: int | None,
        elapsed: tuple[float, float],
    ) -> None:
        from types import SimpleNamespace

        from mpp.methods.tempo.intents import VALID_BEFORE_GRACE

        # Pin wall-clock time so ``valid_before + grace`` is ``validity_left`` away.
        valid_before = 1_000_000
        now = valid_before + VALID_BEFORE_GRACE - (validity_left or 0.0)
        monkeypatch.setattr(
            "mpp.methods.tempo.intents.time",
            SimpleNamespace(time=lambda: now, monotonic=time.monotonic),
        )
        monkeypatch.setattr("mpp.methods.tempo.intents.RECEIPT_POLL_INTERVAL", 0.01)

        asset = "0x1234567890123456789012345678901234567890"
        destination = "0x4567890123456789012345678901234567890123"
        challenge_id = "challenge-123"
        realm = "api.example.com"
        raw_tx = tempo_tx(None if validity_left is None else valid_before)
        tx_hash = _raw_transaction_hash(raw_tx)
        receipt = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "logs": [
                {
                    "address": asset,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + "0" * 24 + "abcd" * 10,
                        "0x" + "0" * 24 + destination[2:],
                        encode_attribution(challenge_id=challenge_id, server_id=realm),
                    ],
                    "data": amount_data(1000),
                }
            ],
        }
        started = time.monotonic()

        async def post(url: str, *, json: dict) -> httpx.Response:
            if lookup == "error":
                raise httpx.ReadError("lookup unavailable")
            # "late" receipts only appear once the validity cap has ended polling.
            mined = lookup == "mined" or (
                lookup == "late" and time.monotonic() >= started + (validity_left or 0.0)
            )
            return mock_response(200, {"result": receipt if mined else None})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=post)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        error = VerificationError("Transaction submission failed: already known")
        request = ChargeRequest.model_validate(
            {"amount": "1000", "currency": asset, "recipient": destination}
        )

        recovery = intent._recover_broadcast_receipt(
            mock_client,
            raw_tx,
            tx_hash,
            request,
            challenge_id=challenge_id,
            realm=realm,
            deadline=started + deadline_left,
            error=error,
        )
        if lookup in ("mined", "late"):
            assert (await recovery).reference == tx_hash
        else:
            with pytest.raises(VerificationError) as exc_info:
                await recovery
            assert exc_info.value is error
        assert elapsed[0] <= time.monotonic() - started < elapsed[1]
        if expected_lookups is None:
            assert mock_client.post.await_count > 1
        else:
            assert mock_client.post.await_count == expected_lookups

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "send_result",
        [
            pytest.param(httpx.ConnectError("connection refused"), id="connect-error"),
            pytest.param(httpx.PoolTimeout("pool exhausted"), id="pool-timeout"),
            pytest.param({"error": {"code": -32601, "message": "method not found"}}, id="-32601"),
            pytest.param({"error": {"code": -32602, "message": "invalid params"}}, id="-32602"),
            pytest.param(
                {"error": {"code": -32000, "message": "invalid signature"}}, id="invalid-signature"
            ),
            pytest.param(
                {"error": {"code": -32000, "message": "execution reverted"}}, id="generic-32000"
            ),
            pytest.param(429, id="http-429"),
        ],
    )
    async def test_verify_transaction_definitive_send_failure_skips_receipt_lookup(
        self, send_result: Exception | dict | int
    ) -> None:
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)

        mock_client = AsyncMock()
        if isinstance(send_result, Exception):
            mock_client.post = AsyncMock(side_effect=send_result)
        elif isinstance(send_result, int):
            mock_client.post = AsyncMock(return_value=mock_response(send_result, {}))
        else:
            mock_client.post = AsyncMock(return_value=mock_response(200, send_result))
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            expires=future,
        )

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert isinstance(internal_cause(raised.value), (VerificationError, httpx.HTTPError))
        assert await store.get(f"mpp:charge:{tx_hash}") is None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["eth_sendRawTransactionSync"]

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

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )
        assert_unconfirmed_after_broadcast(raised.value, "No transaction receipt returned")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("sent", "cause"),
        [
            (httpx.ReadTimeout("send timed out"), httpx.ReadTimeout),
            (mock_response(502), httpx.HTTPStatusError),
            (
                httpx.Response(
                    200, content=b"not json", request=httpx.Request("POST", "https://rpc.test")
                ),
                json.JSONDecodeError,
            ),
        ],
        ids=["timeout", "http", "invalid-json"],
    )
    async def test_verify_transaction_post_broadcast_failure_is_internal(
        self, sent: httpx.Response | Exception, cause: type[Exception]
    ) -> None:
        """Any failure once the transaction was sent may hide a landed payment."""
        from mpp.store import MemoryStore

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store = MemoryStore()
        intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
        raw_signature = "0xabcdef1234567890"
        tx_hash = _raw_transaction_hash(raw_signature)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[sent])
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": raw_signature},
            expires=future,
        )

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000",
                    "currency": "0x1234567890123456789012345678901234567890",
                    "recipient": "0x4567890123456789012345678901234567890123",
                },
            )

        assert isinstance(internal_cause(raised.value), cause)
        assert await store.get(f"mpp:charge:{tx_hash}") is None

    @pytest.mark.asyncio
    async def test_verify_transaction_cancelled_broadcast_is_not_wrapped(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        intent = ChargeIntent(rpc_url="https://rpc.test")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=asyncio.CancelledError())
        intent._http_client = mock_client

        credential = make_credential(
            payload={"type": "transaction", "signature": "0xabcdef1234567890"},
            expires=future,
        )

        with pytest.raises(asyncio.CancelledError):
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
            json={"jsonrpc": "2.0", "result": "0x76abcdef01", "id": 1},
        )

        # eth_sendRawTransactionSync to RPC
        httpx_mock.add_response(
            url="https://rpc.test",
            json={
                "jsonrpc": "2.0",
                "result": {
                    "transactionHash": _raw_transaction_hash("0x76abcdef01"),
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
        assert receipt.reference == _raw_transaction_hash("0x76abcdef01")

        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        body = requests[1].read().decode()
        assert '"method":"eth_sendRawTransactionSync"' in body

    @pytest.mark.asyncio
    async def test_server_fee_payer_error(self, httpx_mock: HTTPXMock) -> None:
        """External fee payer failures are internal errors, not verification failures."""
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

        with pytest.raises(InternalPaymentError) as raised:
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
        assert "Fee payer signing failed" in str(internal_cause(raised.value))


class TestCosignAsFeePayer:
    """Tests for local fee payer co-signing."""

    def _make_intent(self) -> ChargeIntent:
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        # Pin the fee token so these RPC mocks don't need fee payer balance lookups.
        tempo(
            fee_payer=fee_payer,
            fee_token=PATH_USD,
            rpc_url="https://rpc.test",
            intents={"charge": intent},
        )
        return intent

    def _encode_transfer_data(
        self,
        recipient: str,
        amount: int,
        memo: str | None = None,
        padding: str = "",
    ) -> str:
        selector = TRANSFER_WITH_MEMO_SELECTOR if memo is not None else TRANSFER_SELECTOR
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        data = f"0x{selector}{to_padded}{amount_padded}"
        if memo is not None:
            data += memo[2:] if memo.startswith("0x") else memo
        data += padding
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
        tempo_authorization_list: tuple[bytes, ...] = (),
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
            tempo_authorization_list=tempo_authorization_list,
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

        with pytest.raises(InternalPaymentError) as raised:
            intent._cosign_as_fee_payer("0x76abcdef", "0x20c0000000000000000000000000000000000000")
        assert "No fee payer account configured" in str(internal_cause(raised.value))

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

    def test_cosign_rejects_padded_transfer_calldata(self) -> None:
        """Should reject padded calldata before fee payer signing."""
        from pytempo import Call

        intent = self._make_intent()
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to=currency,
                    value=0,
                    data=self._encode_transfer_data(recipient, 1000000, padding="01" * 5500),
                ),
            )
        )
        request = ChargeRequest(amount="1000000", currency=currency, recipient=recipient)

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

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

    def test_cosign_rejects_padded_approve_calldata(self) -> None:
        """Should reject padded approve calldata before co-signing."""
        from pytempo import Call

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to="0x0000000000000000000000000000000000000003",
                    value=0,
                    data=self._encode_approve_data(STABLECOIN_DEX, 2000000) + "00",
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

        with pytest.raises(VerificationError, match="malformed approve call data"):
            intent._cosign_as_fee_payer(raw_tx, request.currency, request=request)

    def test_cosign_rejects_padded_swap_calldata(self) -> None:
        """Should reject padded swap calldata before co-signing."""
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
                    )
                    + "00",
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

        with pytest.raises(VerificationError, match="malformed swap call data"):
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

    @pytest.mark.parametrize(
        ("milliseconds", "remaining", "accepted"),
        [(0, 14, False), (0, 15, True), (1, 15, False), (1, 16, True), (999, 16, True)],
    )
    def test_cosign_requires_minimum_remaining_validity(
        self, milliseconds: int, remaining: int, accepted: bool
    ) -> None:
        """Should require 15 seconds of remaining validity before sponsoring."""
        intent = self._make_intent()
        now = 2_000_000_000 + milliseconds / 1000
        raw_tx = self._build_client_tx(valid_before=2_000_000_000 + remaining)
        with patch("mpp.methods.tempo.intents.time.time", return_value=now):
            if accepted:
                intent._cosign_as_fee_payer(raw_tx, "0x20c0000000000000000000000000000000000000")
            else:
                with pytest.raises(VerificationError, match="at least 15 seconds"):
                    intent._cosign_as_fee_payer(
                        raw_tx, "0x20c0000000000000000000000000000000000000"
                    )

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

    @pytest.mark.parametrize(
        ("amount_out", "max_input", "approval", "token_out", "error"),
        [
            (1, 2, 2, None, None),
            (500000, 600000, 600000, None, None),
            (0, 1, 1, None, "swap output must be positive"),
            (1000001, 2000000, 2000000, None, "not exceed payment"),
            (1000000, 0, 0, None, "positive swap maximum input"),
            (1000000, 2000000, 3000000, None, "approval must match"),
            (
                1000000,
                2000000,
                2000000,
                "0x0000000000000000000000000000000000000004",
                "output token",
            ),
        ],
    )
    def test_cosign_bounds_swap_amounts(
        self,
        amount_out: int,
        max_input: int,
        approval: int,
        token_out: str | None,
        error: str | None,
    ) -> None:
        from pytempo import Call

        currency = "0x20c0000000000000000000000000000000000000"
        token_in = "0x0000000000000000000000000000000000000003"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        raw_tx = self._build_client_tx(
            calls=(
                Call.create(
                    to=token_in, value=0, data=self._encode_approve_data(STABLECOIN_DEX, approval)
                ),
                Call.create(
                    to=STABLECOIN_DEX,
                    value=0,
                    data=self._encode_swap_data(
                        token_in, token_out or currency, amount_out, max_input
                    ),
                ),
                Call.create(
                    to=currency, value=0, data=self._encode_transfer_data(recipient, 1000000)
                ),
            )
        )
        request = ChargeRequest(amount="1000000", currency=currency, recipient=recipient)
        intent = self._make_intent()
        if error:
            with pytest.raises(VerificationError, match=error):
                intent._cosign_as_fee_payer(raw_tx, currency, request=request)
        else:
            result, _ = intent._cosign_as_fee_payer(raw_tx, currency, request=request)
            assert result.startswith("0x76")

    # The simulate payload must target the co-signed tx: the recovered sender as
    # `from`, the sponsor fields the node needs (feeToken, feePayerSignature), the
    # payment calls, the expiring nonceKey, the validity window, and validation off.
    def test_cosign_returns_simulate_payload_with_sponsor_abi(self) -> None:
        intent = self._make_intent()
        currency = "0x20c0000000000000000000000000000000000000"

        raw_tx = self._build_client_tx(currency=currency)
        _result, payload = intent._cosign_as_fee_payer(raw_tx, currency)
        assert payload is not None
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
        assert payload is not None
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

        with pytest.raises(InternalPaymentError) as raised:
            await intent._simulate_before_broadcast(mock_client, payload, "https://rpc.test")
        assert str(internal_cause(raised.value)) == "node unavailable"

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
                    "methodDetails": {"feePayer": True, "chainId": TESTNET_CHAIN_ID},
                },
            )

        # Exactly one RPC call (the simulation); no broadcast was attempted.
        requests = httpx_mock.get_requests()
        methods = [json.loads(r.read().decode())["method"] for r in requests]
        assert methods == ["tempo_simulateV1"]
        assert "eth_sendRawTransactionSync" not in methods

    @pytest.mark.asyncio
    async def test_verify_local_fee_payer_rejects_unsimulatable_authorization(
        self, httpx_mock: HTTPXMock
    ) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        amount = 1000000
        challenge_id = "challenge-auth-bearing"
        realm = "api.example.com"
        memo = encode_attribution(challenge_id=challenge_id, server_id=realm)

        intent = self._make_intent()
        raw_tx = self._build_client_tx(
            currency=currency,
            recipient=recipient,
            amount=amount,
            with_memo=memo,
            tempo_authorization_list=(b"\x77" * 20, b"\x88" * 32),
        )
        credential = make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            challenge_id=challenge_id,
            expires=future,
            realm=realm,
        )

        with pytest.raises(VerificationError, match="Authorization-bearing transactions"):
            await intent.verify(
                credential,
                {
                    "amount": str(amount),
                    "currency": currency,
                    "recipient": recipient,
                    "methodDetails": {"feePayer": True, "chainId": TESTNET_CHAIN_ID},
                },
            )

        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_verify_duplicate_rejects_without_simulation_or_receipt_fetch(self) -> None:
        from mpp.store import MemoryStore

        intent = self._make_intent()
        store = MemoryStore()
        intent._store = store
        currency = "0x20c0000000000000000000000000000000000000"
        recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        raw_tx = self._build_client_tx(currency=currency, recipient=recipient, amount=1000000)
        cosigned_raw, _ = intent._cosign_as_fee_payer(raw_tx, currency)
        tx_hash = _raw_transaction_hash(cosigned_raw)
        await store.put_if_absent(f"mpp:charge:{tx_hash.lower()}", tx_hash)
        mock_client = AsyncMock()
        intent._http_client = mock_client
        credential = make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        )
        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": currency,
                    "recipient": recipient,
                    "methodDetails": {"feePayer": True, "chainId": TESTNET_CHAIN_ID},
                },
            )
        mock_client.post.assert_not_awaited()

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

        with pytest.raises(InternalPaymentError) as raised:
            await intent.verify(
                credential,
                {
                    "amount": "1000000",
                    "currency": currency,
                    "recipient": recipient,
                    "methodDetails": {"feePayer": True, "chainId": TESTNET_CHAIN_ID},
                },
            )
        assert "Pre-broadcast simulation failed: node busy" in str(internal_cause(raised.value))

        assert await store.get(f"mpp:charge:{tx_hash.lower()}") is None
        methods = [call.kwargs["json"]["method"] for call in mock_client.post.await_args_list]
        assert methods == ["tempo_simulateV1"]
        assert "eth_sendRawTransactionSync" not in methods


class TestValidateTransactionPayload:
    """Tests for _validate_transaction_payload with both 0x76 and 0x78."""

    @pytest.mark.parametrize("envelope", ["0x76", "0x78"])
    def test_rejects_transaction_on_other_chain(self, envelope: str) -> None:
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency=PATH_USD,
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            methodDetails=MethodDetails(chainId=TESTNET_CHAIN_ID),
        )
        signature = self._build_0x76_tx() if envelope == "0x76" else self._build_0x78_envelope()

        with pytest.raises(VerificationError, match="Transaction chain ID"):
            intent._validate_transaction_payload(signature, request, strict=True)

    def _encode_transfer_data(
        self,
        recipient: str,
        amount: int,
        memo: str | None = None,
        padding: str = "",
    ) -> str:
        selector = TRANSFER_WITH_MEMO_SELECTOR if memo is not None else TRANSFER_SELECTOR
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        data = f"0x{selector}{to_padded}{amount_padded}"
        if memo is not None:
            data += memo[2:] if memo.startswith("0x") else memo
        data += padding
        return data

    def _build_0x78_envelope(
        self,
        currency: str = "0x20c0000000000000000000000000000000000000",
        recipient: str = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        amount: int = 1000000,
        memo: str | None = None,
        padding: str = "",
    ) -> str:
        """Build a 0x78 fee payer envelope."""
        from pytempo import Call, TempoTransaction

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        transfer_data = self._encode_transfer_data(recipient, amount, memo, padding)

        tx = TempoTransaction.create(
            chain_id=CHAIN_ID,
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
        padding: str = "",
    ) -> str:
        """Build a standard 0x76 transaction."""
        import attrs
        from pytempo import Call, TempoTransaction
        from pytempo.models import Signature

        transfer_data = self._encode_transfer_data(recipient, amount, memo, padding)

        tx = TempoTransaction.create(
            chain_id=CHAIN_ID,
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

    def test_rejects_0x78_with_padded_transfer_calldata(self) -> None:
        """Should reject ABI calldata with trailing bytes."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x78_envelope(padding="01" * 5500)

        with pytest.raises(VerificationError, match="no matching payment call"):
            intent._validate_transaction_payload(sig, request)

    def test_rejects_0x76_with_padded_transfer_calldata(self) -> None:
        """Should reject padded calldata for standard Tempo transactions too."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest(
            amount="1000000",
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        sig = self._build_0x76_tx(padding="01" * 5500)

        with pytest.raises(VerificationError, match="no matching payment call"):
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
            chain_id=CHAIN_ID,
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

        # Mock RPC: chain_id (4217=0x1079), gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(2):
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

        # Mock RPC: chain_id (4217=0x1079), gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(2):
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

        # Mock RPC: chain_id (4217=0x1079), gas_price, estimateGas
        httpx_mock.add_response(
            url="https://rpc.test",
            json={"jsonrpc": "2.0", "result": "0x1079", "id": 1},
        )
        for _ in range(2):
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
    """Tests for transfer calldata shape and payment parameters."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    AMOUNT = 1000000
    MEMO = "0x" + "ab" * 32

    def _make_request(self) -> ChargeRequest:
        return ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(),
        )

    def _build_calldata(self, selector: str, recipient: str, amount: int, memo: str = "") -> str:
        to_padded = recipient[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        memo_part = memo[2:] if memo.startswith("0x") else memo
        return f"{selector}{to_padded}{amount_padded}{memo_part}"

    def test_plain_transfer_rejects_extra_memo_word(self) -> None:
        """Plain transfer calldata cannot include an extra ABI word."""
        request = self._make_request()
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO)
        assert _match_transfer_calldata(calldata, request) is False

    def test_memo_accepts_correct_selector(self) -> None:
        """Well-formed transferWithMemo calldata matches the payment parameters."""
        request = self._make_request()
        calldata = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
        )
        assert _match_transfer_calldata(calldata, request) is True

    def test_memo_rejects_trailing_padding(self) -> None:
        """transferWithMemo calldata must be exactly selector + 3 ABI words."""
        request = self._make_request()
        calldata = (
            self._build_calldata(
                TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
            )
            + "01"
        )
        assert _match_transfer_calldata(calldata, request) is False

    def test_memo_short_calldata_rejected(self) -> None:
        """Calldata shorter than 200 hex chars should be rejected when memo expected."""
        request = self._make_request()
        # Only selector + to + amount = 136 chars, no memo
        to_padded = self.RECIPIENT[2:].lower().zfill(64)
        amount_padded = hex(self.AMOUNT)[2:].zfill(64)
        calldata = f"{TRANSFER_WITH_MEMO_SELECTOR}{to_padded}{amount_padded}"
        assert _match_transfer_calldata(calldata, request) is False

    def test_no_memo_accepts_plain_transfer_and_transfer_with_memo(self) -> None:
        """When no memo, plain transfer and transferWithMemo should be accepted."""
        request = self._make_request()
        calldata_plain = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        calldata_memo = self._build_calldata(
            TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
        )
        assert _match_transfer_calldata(calldata_plain, request) is True
        assert _match_transfer_calldata(calldata_memo, request) is True

    def test_no_memo_rejects_plain_transfer_trailing_padding(self) -> None:
        """Plain transfer calldata must be exactly selector + 2 ABI words."""
        request = self._make_request()
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT) + "01"
        assert _match_transfer_calldata(calldata, request) is False

    def test_no_memo_rejects_short_transfer_with_memo_calldata(self) -> None:
        """When no memo, truncated transferWithMemo calldata should still be rejected."""
        request = self._make_request()
        calldata = self._build_calldata(TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_transfer_calldata(calldata, request) is False

    def test_rejects_padded_transfer_calldata(self) -> None:
        """Trailing bytes after a valid transfer must be rejected."""
        request = self._make_request()
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT) + "00"
        assert _match_transfer_calldata(calldata, request) is False

    def test_rejects_padded_transfer_with_memo_calldata(self) -> None:
        """Trailing bytes after a valid transferWithMemo must be rejected."""
        request = self._make_request()
        calldata = (
            self._build_calldata(
                TRANSFER_WITH_MEMO_SELECTOR, self.RECIPIENT, self.AMOUNT, self.MEMO
            )
            + "00"
        )
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
    """Tests for matching transfer logs before challenge-binding verification."""

    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    AMOUNT = 1000000
    MEMO = "0x" + "ab" * 32

    def _make_receipt(self, logs: list) -> dict:
        return {"status": "0x1", "logs": logs}

    def _make_request(self) -> ChargeRequest:
        return ChargeRequest(
            amount=str(self.AMOUNT),
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(),
        )

    def test_primary_memo_is_not_a_method_detail(self) -> None:
        request = self._make_request()
        assert "memo" not in request.methodDetails.model_dump()

    def test_memo_log_accepted(self) -> None:
        """TransferWithMemo log with correct memo should be accepted."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()
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

    def test_memo_log_too_few_topics_rejected(self) -> None:
        """TransferWithMemo log with < 4 topics should be skipped."""
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = self._make_request()
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
        request = self._make_request()

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
        request = self._make_request()
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
        chain = CHAIN_ID.to_bytes(2, "big")
        decoded = [chain, b"\x01", b"\x01", b"\x01", [], b"", b"", b"\x00", b"", b"", b""]
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
        chain = CHAIN_ID.to_bytes(2, "big")
        decoded = [chain, b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
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
        chain = CHAIN_ID.to_bytes(2, "big")
        decoded = [chain, b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
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
        chain = CHAIN_ID.to_bytes(2, "big")
        decoded = [chain, b"\x01", b"\x01", b"\x01", [call], b"", b"", b"\x00", b"", b"", b""]
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

    def test_memo_rejects_trailing_padding(self) -> None:
        calldata = (
            self._build_calldata(
                TRANSFER_WITH_MEMO_SELECTOR,
                self.RECIPIENT,
                self.AMOUNT,
                "ab" * 32,
            )
            + "01"
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

    def test_rejects_padded_transfer_calldata(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT) + "00"
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is False

    def test_rejects_padded_transfer_with_memo_calldata(self) -> None:
        calldata = (
            self._build_calldata(
                TRANSFER_WITH_MEMO_SELECTOR,
                self.RECIPIENT,
                self.AMOUNT,
                "ab" * 32,
            )
            + "00"
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

    def test_no_memo_accepts_plain_transfer(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT)
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is True

    def test_no_memo_rejects_plain_transfer_trailing_padding(self) -> None:
        calldata = self._build_calldata(TRANSFER_SELECTOR, self.RECIPIENT, self.AMOUNT) + "01"
        assert _match_single_transfer_calldata(calldata, self.RECIPIENT, self.AMOUNT, None) is False


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

    @pytest.mark.parametrize("movements", [1, 2, 3])
    @pytest.mark.parametrize("plain_first", [False, True])
    @pytest.mark.parametrize("explicit_memo", [False, True])
    def test_companion_events_count_as_one_split_payment(
        self, movements: int, plain_first: bool, explicit_memo: bool
    ) -> None:
        memo = "0x" + "ff" * 32
        request = ChargeRequest(
            amount="2000000",
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[
                    Split(
                        amount="1000000",
                        recipient=self.RECIPIENT,
                        memo=memo if explicit_memo else None,
                    )
                ]
            ),
        )
        logs = []
        for _ in range(movements):
            pair = [
                self._make_log(TRANSFER_TOPIC, self.RECIPIENT, 1000000),
                self._make_log(TRANSFER_WITH_MEMO_TOPIC, self.RECIPIENT, 1000000, memo),
            ]
            logs.extend(pair if plain_first else pair[::-1])
        matches = ChargeIntent(rpc_url="https://rpc.test")._verify_transfer_logs(
            {"logs": logs}, request
        )
        assert bool(matches) == (movements >= 2)

    def test_plain_transfer_and_memo_movement_can_pay_equal_splits(self) -> None:
        request = ChargeRequest(
            amount="2000000",
            currency=self.CURRENCY,
            recipient=self.RECIPIENT,
            methodDetails=MethodDetails(
                splits=[
                    Split(
                        amount="1000000",
                        recipient=self.RECIPIENT,
                    )
                ]
            ),
        )
        logs = [
            self._make_log(TRANSFER_TOPIC, self.RECIPIENT, 1000000),
            self._make_log(TRANSFER_TOPIC, self.RECIPIENT, 1000000),
            self._make_log(TRANSFER_WITH_MEMO_TOPIC, self.RECIPIENT, 1000000, "0x" + "ff" * 32),
        ]
        assert ChargeIntent(rpc_url="https://rpc.test")._verify_transfer_logs(
            {"logs": logs}, request
        )

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
        with_chain_id(mock_client)
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

        # First log has a wrong sender and a non-matching amount (non-candidate);
        # second log matches fully, so the callback is never reached.
        receipt = {
            "status": "0x1",
            "from": self.SOURCE_ADDR,
            "logs": [
                {**self._memo_log(self.RELAYER, self._bound_memo), "data": amount_data(1)},
                self._memo_log(self.SOURCE_ADDR, self._bound_memo),
            ],
        }
        intent = self._intent(receipt, validate_sender=boom)
        result = await self._verify(intent, source=self._did(self.CHAIN_ID, self.SOURCE_ADDR))
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
            "transactionHash": _raw_transaction_hash("0xabcdef1234567890"),
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
        assert result.reference == _raw_transaction_hash("0xabcdef1234567890")

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

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("source", "log_senders", "accept_other", "expected"),
        [
            (True, [SOURCE_ADDR], False, SOURCE_ADDR),
            (False, [SOURCE_ADDR], False, SOURCE_ADDR),
            (True, [RELAYER], True, RELAYER),
            (False, [SOURCE_ADDR, RELAYER], False, None),
        ],
    )
    async def test_validate_reports_debited_account_as_payer(
        self, source: bool, log_senders: list[str], accept_other: bool, expected: str | None
    ) -> None:
        # The payer is the sender of the matched transfers, not the transaction
        # submitter (a relayer here), and is unset when matched senders differ.
        receipt = {
            "status": "0x1",
            "from": self.RELAYER if not accept_other else self.SOURCE_ADDR,
            "logs": [self._memo_log(sender, self._bound_memo) for sender in log_senders],
        }
        intent = self._intent(receipt, validate_sender=(lambda v: True) if accept_other else None)
        credential = make_credential(
            payload={"type": "hash", "hash": "0xabc123"},
            challenge_id="challenge-123",
            realm="api.example.com",
            expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            source=self._did(self.CHAIN_ID, self.SOURCE_ADDR) if source else None,
        )
        request = {"amount": "1000", "currency": self.CURRENCY, "recipient": self.RECIPIENT}

        validation = await intent.validate(credential, request)

        assert validation.payer == expected


PKH_ADDRESS = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (f"did:pkh:eip155:4217:{PKH_ADDRESS}", (PKH_ADDRESS, 4217)),
        (f"did:pkh:eip155:1:{PKH_ADDRESS.lower()}", (PKH_ADDRESS.lower(), 1)),
        (f"did:pkh:eip155:0:0x{PKH_ADDRESS[2:].upper()}", (f"0x{PKH_ADDRESS[2:].upper()}", 0)),
        (f"did:pkh:eip155:{2**53 - 1}:{PKH_ADDRESS}", (PKH_ADDRESS, 2**53 - 1)),
        (f"did:pkh:eip155:{2**53}:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:{'9' * 17}:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:{'9' * 5000}:{PKH_ADDRESS}", None),
        ("", None),
        ("did:example:client", None),
        (f"did:pkh:solana:4217:{PKH_ADDRESS}", None),
        (f"DID:PKH:EIP155:4217:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:04217:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:-1:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155::{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:4\uff1217:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:4217:extra:{PKH_ADDRESS}", None),
        (f"did:pkh:eip155:4217:{PKH_ADDRESS[2:]}", None),
        (f"did:pkh:eip155:4217:{PKH_ADDRESS[:-1]}", None),
        (f"did:pkh:eip155:4217:{PKH_ADDRESS}0", None),
        (f"did:pkh:eip155:4217:0x{'g' * 40}", None),
        (f"did:pkh:eip155:4217:{PKH_ADDRESS}\n", None),
        (f" did:pkh:eip155:4217:{PKH_ADDRESS}", None),
    ],
)
def test_parse_pkh_source(source: str, expected: tuple[str, int] | None) -> None:
    from mpp.methods.tempo import PkhSource, parse_pkh_source

    parsed = parse_pkh_source(source)

    assert parsed == expected
    assert parsed is None or isinstance(parsed, PkhSource)


@pytest.mark.asyncio
async def test_oversized_hash_source_chain_id_is_rejected() -> None:
    credential = make_credential(
        payload={"type": "hash", "hash": "0x" + "ab" * 32},
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        source=f"did:pkh:eip155:{'9' * 5000}:{PKH_ADDRESS}",
    )
    request = {"amount": "1000", "currency": PATH_USD, "recipient": PKH_ADDRESS}

    with pytest.raises(VerificationError, match="Hash credential source is invalid"):
        await ChargeIntent(rpc_url="https://rpc.test").validate(credential, request)


class TestTransactionCredentialPayer:
    """Pull-mode credentials report the transaction sender as the verified payer."""

    CHAIN_ID = 42431
    CURRENCY = "0x20c0000000000000000000000000000000000000"
    RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    CHALLENGE_ID = "challenge-123"
    REALM = "api.example.com"
    ACCESS_KEY = "0x" + "11" * 32
    FEE_PAYER_KEY = "0x" + "22" * 32
    OTHER_KEY = "0x" + "33" * 32
    ROOT = "0x00000000000000000000000000000000000000aa"
    OTHER = "0x00000000000000000000000000000000000000bb"
    PUBKEY = bytes(range(64))
    KINDS = [
        "secp256k1",
        "key_authorization",
        "sponsored",
        "envelope",
        "keychain",
        "keychain_envelope",
        "p256",
        "webauthn",
        "multisig",
    ]

    @property
    def _memo(self) -> str:
        return encode_attribution(challenge_id=self.CHALLENGE_ID, server_id=self.REALM)

    def _tx(self, **overrides):
        from pytempo import Call, TempoTransaction

        to = self.RECIPIENT[2:].lower().zfill(64)
        data = f"0x{TRANSFER_WITH_MEMO_SELECTOR}{to}{1000:064x}{self._memo[2:]}"
        fields = {
            "chain_id": self.CHAIN_ID,
            "gas_limit": 100_000,
            "max_fee_per_gas": 1,
            "max_priority_fee_per_gas": 1,
            "calls": (Call.create(to=self.CURRENCY, value=0, data=data),),
        }
        return TempoTransaction.create(**{**fields, **overrides})

    def _replace_field(self, raw_tx: str, index: int, value: bytes) -> str:
        tx_bytes = bytes.fromhex(raw_tx[2:])
        fields = rlp.decode(tx_bytes[1:])
        fields[index] = value
        return "0x" + tx_bytes[:1].hex() + bytes(rlp.encode(fields)).hex()

    def _envelope(self, private_key: str = TEST_PRIVATE_KEY) -> str:
        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        tx = self._tx(awaiting_fee_payer=True).sign(private_key)
        return "0x" + encode_fee_payer_envelope(tx).hex()

    def _signed(self, kind: str) -> tuple[str, str]:
        """Return ``(raw_tx, expected_sender)`` for a signature kind."""
        from eth_account import Account
        from eth_hash.auto import keccak
        from pytempo.keychain import KeyAuthorization

        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        payer = Account.from_key(TEST_PRIVATE_KEY).address
        pubkey_address = "0x" + keccak(self.PUBKEY)[-20:].hex()
        base = "0x" + self._tx().sign(TEST_PRIVATE_KEY).encode().hex()
        rs = b"\x01" * 64

        if kind == "secp256k1":
            return base, payer
        if kind == "key_authorization":
            key_id = Account.from_key(self.ACCESS_KEY).address
            auth = KeyAuthorization(key_id=key_id, chain_id=self.CHAIN_ID).sign(TEST_PRIVATE_KEY)
            tx = self._tx(key_authorization=auth).sign(TEST_PRIVATE_KEY)
            return "0x" + tx.encode().hex(), payer
        if kind == "sponsored":
            tx = self._tx(awaiting_fee_payer=True).sign(TEST_PRIVATE_KEY)
            return "0x" + tx.sign(self.FEE_PAYER_KEY, for_fee_payer=True).encode().hex(), payer
        if kind == "envelope":
            return self._envelope(), payer
        if kind == "keychain":
            tx = self._tx().sign_access_key(self.ACCESS_KEY, self.ROOT)
            return "0x" + tx.encode().hex(), self.ROOT
        if kind == "keychain_envelope":
            tx = self._tx(awaiting_fee_payer=True).sign_access_key(self.ACCESS_KEY, self.ROOT)
            return "0x" + encode_fee_payer_envelope(tx).hex(), self.ROOT
        if kind == "p256":
            signature = b"\x01" + rs + self.PUBKEY + b"\x00"
            return self._replace_field(base, -1, signature), pubkey_address
        if kind == "webauthn":
            webauthn_data = b"\x00" * 37 + b'{"type":"webauthn.get"}'
            signature = b"\x02" + webauthn_data + rs + self.PUBKEY
            return self._replace_field(base, -1, signature), pubkey_address
        if kind == "multisig":
            account = bytes.fromhex(self.ROOT[2:])
            signature = b"\x05" + bytes(rlp.encode([account, b"\x01", [], b""]))
            return self._replace_field(base, -1, signature), self.ROOT
        raise AssertionError(kind)

    def _credential(self, raw_tx: str, source: str | None):
        return make_credential(
            payload={"type": "transaction", "signature": raw_tx},
            challenge_id=self.CHALLENGE_ID,
            realm=self.REALM,
            expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            source=source,
        )

    def _did(self, address: str) -> str:
        return f"did:pkh:eip155:{self.CHAIN_ID}:{address}"

    def _request(self, **method_details) -> dict:
        return {
            "amount": "1000",
            "currency": self.CURRENCY,
            "recipient": self.RECIPIENT,
            "methodDetails": {"chainId": self.CHAIN_ID, **method_details},
        }

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", KINDS)
    @pytest.mark.parametrize("source", ["match", "match_lowercase", None])
    async def test_validate_reports_sender(self, kind: str, source: str | None) -> None:
        raw_tx, sender = self._signed(kind)
        did = None
        if source == "match":
            did = self._did(sender)
        elif source == "match_lowercase":
            did = self._did(sender.lower())

        validation = await ChargeIntent(rpc_url="https://rpc.test").validate(
            self._credential(raw_tx, did), self._request()
        )

        assert validation.details["mode"] == "pull"
        assert validation.payer == sender.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", KINDS)
    @pytest.mark.parametrize(
        ("source", "error"),
        [
            (f"did:pkh:eip155:{CHAIN_ID}:{OTHER}", "source does not match the sender"),
            ("did:pkh:eip155:4217:{sender}", "source is invalid"),
            (f"did:pkh:eip155:{'9' * 5000}:{{sender}}", "source is invalid"),
            ("did:example:client", "source is invalid"),
            (f"did:pkh:eip155:{CHAIN_ID}:not-an-address", "source is invalid"),
        ],
    )
    async def test_validate_rejects_source(self, kind: str, source: str, error: str) -> None:
        raw_tx, sender = self._signed(kind)
        credential = self._credential(raw_tx, source.format(sender=sender))

        with pytest.raises(VerificationError, match=f"Transaction credential {error}"):
            await ChargeIntent(rpc_url="https://rpc.test").validate(credential, self._request())

    @pytest.mark.asyncio
    @pytest.mark.parametrize("claimed", ["victim", "signer"])
    async def test_envelope_sender_slot_must_match_signer(self, claimed: str) -> None:
        from eth_account import Account

        signer = Account.from_key(self.OTHER_KEY).address
        victim = Account.from_key(TEST_PRIVATE_KEY).address
        forged = self._replace_field(self._envelope(self.OTHER_KEY), 11, bytes.fromhex(victim[2:]))
        intent = ChargeIntent(rpc_url="https://rpc.test")

        source = self._did(victim if claimed == "victim" else signer)
        with pytest.raises(VerificationError, match="source does not match the sender"):
            await intent.validate(self._credential(forged, source), self._request())
        validation = await intent.validate(self._credential(forged, None), self._request())
        assert validation.payer is None

    @pytest.mark.parametrize(
        "raw_tx",
        [
            "0x76abcdef",
            "0x77" + bytes(rlp.encode([b""] * 14)).hex(),
            "0x76" + bytes(rlp.encode([b""] * 14)).hex(),
            "0x78" + bytes(rlp.encode([b""] * 14)).hex(),
            "0x76" + bytes(rlp.encode([b""] * 13 + [b"\x06" + b"\x00" * 20])).hex(),
        ],
    )
    def test_unknown_sender(self, raw_tx: str) -> None:
        assert ChargeIntent._transaction_payer(raw_tx, None, self.CHAIN_ID) is None
        with pytest.raises(VerificationError, match="does not match the sender"):
            ChargeIntent._transaction_payer(raw_tx, self._did(self.ROOT), self.CHAIN_ID)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["match", None])
    @pytest.mark.parametrize("cosigner", ["sender", "other"])
    async def test_external_fee_payer_cannot_change_sender(
        self, source: str | None, cosigner: str
    ) -> None:
        from eth_account import Account

        from mpp.server.intent import broadcast_credential

        sender = Account.from_key(TEST_PRIVATE_KEY).address
        signer_key = TEST_PRIVATE_KEY if cosigner == "sender" else self.OTHER_KEY
        signed = self._tx(awaiting_fee_payer=True).sign(signer_key)
        cosigned = "0x" + signed.sign(self.FEE_PAYER_KEY, for_fee_payer=True).encode().hex()
        log = {
            "address": self.CURRENCY,
            "topics": [
                TRANSFER_WITH_MEMO_TOPIC,
                "0x" + sender[2:].lower().zfill(64),
                "0x" + self.RECIPIENT[2:].lower().zfill(64),
                self._memo,
            ],
            "data": amount_data(1000),
        }
        methods: list[str] = []

        def rpc(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            methods.append(body["method"])
            if body["method"] == "eth_signRawTransaction":
                result: object = cosigned
            else:
                tx_hash = _raw_transaction_hash(body["params"][0])
                result = {"status": "0x1", "transactionHash": tx_hash, "logs": [log]}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

        async with httpx.AsyncClient(transport=httpx.MockTransport(rpc)) as client:
            intent = ChargeIntent(rpc_url="https://rpc.test", http_client=client)
            credential = self._credential(
                self._envelope(), None if source is None else self._did(sender)
            )
            request = self._request(feePayer=True, feePayerUrl="https://fee-payer.test")

            if cosigner == "other":
                with pytest.raises(VerificationError, match="Fee payer transaction sender"):
                    await broadcast_credential(
                        intent=intent, credential=credential, request=request
                    )
                assert methods == ["eth_signRawTransaction"]
                return

            receipt = await broadcast_credential(
                intent=intent, credential=credential, request=request
            )

        assert receipt.payer == sender.lower()
        assert methods == ["eth_signRawTransaction", "eth_sendRawTransactionSync"]
