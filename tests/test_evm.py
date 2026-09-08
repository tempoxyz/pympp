"""Tests for the EVM payment method."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import Challenge
from mpp.errors import VerificationError
from mpp.methods.evm import (
    BASE_CHAIN_ID,
    BASE_RPC_URL,
    BASE_SEPOLIA_CHAIN_ID,
    BASE_SEPOLIA_RPC_URL,
    BASE_SEPOLIA_USDC,
    BASE_USDC,
    ChargeIntent,
    EvmAccount,
    EvmMethod,
    TransactionError,
    default_currency_for_chain,
    evm,
    rpc_url_for_chain,
)
from mpp.methods.evm.client import _encode_transfer
from mpp.stores import MemoryStore
from tests import make_bound_credential, make_credential

TEST_PRIVATE_KEY = "0x" + "11" * 32
CURRENCY = "0x" + "22" * 20
RECIPIENT = "0x" + "33" * 20
SENDER = "0x" + "44" * 20

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def amount_hex(amount: int) -> str:
    return "0x" + hex(amount)[2:].zfill(64)


def address_topic(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def mock_response(status_code: int = 200, json: dict | None = None) -> httpx.Response:
    request = httpx.Request("POST", "https://rpc.test")
    return httpx.Response(status_code, json=json, request=request)


def build_signed_transfer_tx(
    *,
    account: EvmAccount,
    chain_id: int = BASE_CHAIN_ID,
    currency: str = CURRENCY,
    recipient: str = RECIPIENT,
    amount: int = 1_000_000,
    nonce: int = 0,
    gas: int = 100_000,
    max_fee_per_gas: int = 100,
    max_priority_fee_per_gas: int = 1,
    value: int = 0,
    data: str | None = None,
) -> str:
    """Build and sign a plain EIP-1559 ERC-20 transfer transaction for tests."""
    from eth_account import Account

    tx = {
        "chainId": chain_id,
        "nonce": nonce,
        "maxPriorityFeePerGas": max_priority_fee_per_gas,
        "maxFeePerGas": max_fee_per_gas,
        "gas": gas,
        "to": currency,
        "value": value,
        "data": data if data is not None else _encode_transfer(recipient, amount),
        "type": 2,
    }
    signed = Account.sign_transaction(tx, account.private_key)
    return "0x" + signed.raw_transaction.hex()


def transfer_log(
    *,
    currency: str = CURRENCY,
    recipient: str = RECIPIENT,
    amount: int = 1_000_000,
    sender: str = SENDER,
) -> dict[str, Any]:
    return {
        "address": currency,
        "topics": [TRANSFER_TOPIC, address_topic(sender), address_topic(recipient)],
        "data": amount_hex(amount),
    }


# ──────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────


class TestDefaults:
    def test_rpc_url_for_known_chain(self) -> None:
        assert rpc_url_for_chain(BASE_CHAIN_ID) == BASE_RPC_URL
        assert rpc_url_for_chain(BASE_SEPOLIA_CHAIN_ID) == BASE_SEPOLIA_RPC_URL

    def test_rpc_url_for_unknown_chain_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown chain_id"):
            rpc_url_for_chain(999999)

    def test_default_currency_for_known_chain(self) -> None:
        assert default_currency_for_chain(BASE_CHAIN_ID) == BASE_USDC
        assert default_currency_for_chain(BASE_SEPOLIA_CHAIN_ID) == BASE_SEPOLIA_USDC

    def test_default_currency_for_unknown_or_none_chain(self) -> None:
        assert default_currency_for_chain(None) is None
        assert default_currency_for_chain(999999) is None


# ──────────────────────────────────────────────────────────────────
# EvmAccount
# ──────────────────────────────────────────────────────────────────


class TestEvmAccount:
    def test_from_key(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        assert account.address.startswith("0x")
        assert len(account.address) == 42

    def test_from_env(self) -> None:
        with patch.dict(os.environ, {"TEST_EVM_KEY": TEST_PRIVATE_KEY}):
            account = EvmAccount.from_env("TEST_EVM_KEY")
            assert account.address.startswith("0x")

    def test_from_env_missing_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match=r"\$EVM_PRIVATE_KEY not set"):
                EvmAccount.from_env()

    def test_from_file(self, tmp_path) -> None:
        key_file = tmp_path / "key"
        key_file.write_text(f"  {TEST_PRIVATE_KEY}  \n")
        account = EvmAccount.from_file(str(key_file))
        assert account.address == EvmAccount.from_key(TEST_PRIVATE_KEY).address

    def test_from_file_empty_raises(self, tmp_path) -> None:
        key_file = tmp_path / "key"
        key_file.write_text("   \n")
        with pytest.raises(ValueError, match="is empty"):
            EvmAccount.from_file(str(key_file))

    def test_from_file_missing_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            EvmAccount.from_file(str(tmp_path / "nope"))

    def test_private_key_round_trip(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        # Re-derive an account from the exposed private key and confirm it matches.
        assert EvmAccount.from_key(account.private_key).address == account.address


# ──────────────────────────────────────────────────────────────────
# _encode_transfer
# ──────────────────────────────────────────────────────────────────


def test_encode_transfer() -> None:
    data = _encode_transfer(RECIPIENT, 1_000_000)
    assert data.startswith("0xa9059cbb")
    assert len(data) == 2 + 8 + 64 + 64
    assert data[10:74] == "0" * 24 + RECIPIENT[2:].lower()
    assert int(data[74:], 16) == 1_000_000


# ──────────────────────────────────────────────────────────────────
# evm() factory
# ──────────────────────────────────────────────────────────────────


class TestEvmFactory:
    def test_defaults_to_base_mainnet(self) -> None:
        method = evm(intents={})
        assert method.chain_id == BASE_CHAIN_ID
        assert method.rpc_url == BASE_RPC_URL
        assert method.currency == BASE_USDC

    def test_explicit_chain_id_resolves_rpc_and_currency(self) -> None:
        method = evm(intents={}, chain_id=BASE_SEPOLIA_CHAIN_ID)
        assert method.rpc_url == BASE_SEPOLIA_RPC_URL
        assert method.currency == BASE_SEPOLIA_USDC

    def test_explicit_rpc_url_overrides_chain_default(self) -> None:
        method = evm(intents={}, rpc_url="https://custom.example.com")
        assert method.rpc_url == "https://custom.example.com"
        # currency defaulting still follows chain_id (defaults to Base mainnet).
        assert method.currency == BASE_USDC

    def test_none_chain_id_without_rpc_url_raises(self) -> None:
        with pytest.raises(ValueError, match="chain_id or rpc_url is required"):
            evm(intents={}, chain_id=None)

    def test_none_chain_id_with_rpc_url_has_no_default_currency(self) -> None:
        method = evm(intents={}, chain_id=None, rpc_url="https://custom.example.com")
        assert method.currency is None

    def test_unknown_chain_id_without_rpc_url_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown chain_id"):
            evm(intents={}, chain_id=999999)

    def test_explicit_currency_is_preserved(self) -> None:
        custom_currency = "0x" + "55" * 20
        method = evm(intents={}, currency=custom_currency)
        assert method.currency == custom_currency

    def test_wires_rpc_url_and_method_into_intents(self) -> None:
        intent = ChargeIntent()
        method = evm(intents={"charge": intent}, chain_id=BASE_SEPOLIA_CHAIN_ID)
        assert intent.rpc_url == BASE_SEPOLIA_RPC_URL
        assert intent._method is method
        assert method.intents == {"charge": intent}

    def test_does_not_override_explicit_intent_rpc_url(self) -> None:
        intent = ChargeIntent(rpc_url="https://pinned.example.com")
        evm(intents={"charge": intent}, chain_id=BASE_SEPOLIA_CHAIN_ID)
        assert intent.rpc_url == "https://pinned.example.com"

    def test_name_and_account(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        method = evm(intents={}, account=account)
        assert method.name == "evm"
        assert method.account is account


# ──────────────────────────────────────────────────────────────────
# EvmMethod.create_credential (client-side)
# ──────────────────────────────────────────────────────────────────


def make_charge_challenge(
    *,
    amount: str = "1000000",
    currency: str = CURRENCY,
    recipient: str = RECIPIENT,
    method_details: dict[str, Any] | None = None,
) -> Challenge:
    request: dict[str, Any] = {"amount": amount, "currency": currency, "recipient": recipient}
    if method_details is not None:
        request["methodDetails"] = method_details
    return Challenge(id="c1", method="evm", intent="charge", request=request, realm="test")


class TestCreateCredential:
    async def test_requires_account(self) -> None:
        method = EvmMethod()
        with pytest.raises(ValueError, match="No account configured"):
            await method.create_credential(make_charge_challenge())

    async def test_requires_charge_intent(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        method = EvmMethod(account=account)
        challenge = Challenge(id="c1", method="evm", intent="authorize", request={}, realm="test")
        with pytest.raises(ValueError, match="Unsupported intent"):
            await method.create_credential(challenge)

    async def test_builds_signed_credential(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        method = evm(intents={}, account=account, chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": hex(BASE_CHAIN_ID)})
        httpx_mock.add_response(json={"result": "0x0"})
        httpx_mock.add_response(json={"result": "0x1"})
        httpx_mock.add_response(json={"result": {"baseFeePerGas": "0x64"}})
        httpx_mock.add_response(json={"result": "0x5208"})

        credential = await method.create_credential(make_charge_challenge())

        assert credential.payload["type"] == "transaction"
        assert isinstance(credential.payload["signature"], str)
        assert credential.payload["signature"].startswith("0x")
        assert credential.source == f"did:pkh:eip155:{BASE_CHAIN_ID}:{account.address}"

    async def test_gas_estimation_failure_falls_back_to_default(
        self, httpx_mock: HTTPXMock
    ) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        method = evm(intents={}, account=account, chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": hex(BASE_CHAIN_ID)})
        httpx_mock.add_response(json={"result": "0x0"})
        httpx_mock.add_response(json={"result": "0x1"})
        httpx_mock.add_response(json={"result": {"baseFeePerGas": "0x64"}})
        httpx_mock.add_response(status_code=500)

        credential = await method.create_credential(make_charge_challenge())
        assert credential.payload["signature"].startswith("0x")

    async def test_chain_id_mismatch_raises(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        method = evm(intents={}, account=account, chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": hex(BASE_SEPOLIA_CHAIN_ID)})
        httpx_mock.add_response(json={"result": "0x0"})
        httpx_mock.add_response(json={"result": "0x1"})
        httpx_mock.add_response(json={"result": {"baseFeePerGas": "0x64"}})

        with pytest.raises(TransactionError, match="Chain ID mismatch"):
            await method.create_credential(make_charge_challenge())

    async def test_challenge_chain_id_overrides_expected(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        # Method is pinned to mainnet, but the challenge requests Sepolia — the
        # client should validate against the challenge's chainId, not its own.
        method = evm(intents={}, account=account, chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": hex(BASE_SEPOLIA_CHAIN_ID)})
        httpx_mock.add_response(json={"result": "0x0"})
        httpx_mock.add_response(json={"result": "0x1"})
        httpx_mock.add_response(json={"result": {"baseFeePerGas": "0x64"}})
        httpx_mock.add_response(json={"result": "0x5208"})

        challenge = make_charge_challenge(method_details={"chainId": BASE_SEPOLIA_CHAIN_ID})
        credential = await method.create_credential(challenge)
        assert credential.source == f"did:pkh:eip155:{BASE_SEPOLIA_CHAIN_ID}:{account.address}"


# ──────────────────────────────────────────────────────────────────
# ChargeIntent (server-side)
# ──────────────────────────────────────────────────────────────────


def make_charge_request(
    *,
    amount: str = "1000000",
    currency: str = CURRENCY,
    recipient: str = RECIPIENT,
) -> dict[str, Any]:
    return {"amount": amount, "currency": currency, "recipient": recipient}


def make_expires(delta: timedelta = timedelta(hours=1)) -> str:
    return (datetime.now(UTC) + delta).isoformat().replace("+00:00", "Z")


class TestChargeIntentValidation:
    def test_requires_rpc_url(self) -> None:
        intent = ChargeIntent()
        with pytest.raises(VerificationError, match="No rpc_url configured"):
            intent._get_rpc_url()

    def test_chain_id_resolves_rpc_url(self) -> None:
        intent = ChargeIntent(chain_id=BASE_SEPOLIA_CHAIN_ID)
        assert intent.rpc_url == BASE_SEPOLIA_RPC_URL

    async def test_expired_challenge(self) -> None:
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": "0xdeadbeef"},
            method="evm",
            expires=make_expires(timedelta(hours=-1)),
        )
        with pytest.raises(VerificationError, match="expired"):
            await intent.verify(credential, make_charge_request())

    async def test_missing_expires(self) -> None:
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": "0xdeadbeef"}, method="evm"
        )
        with pytest.raises(VerificationError, match="no expires"):
            await intent.verify(credential, make_charge_request())

    async def test_invalid_payload_type(self) -> None:
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "hash", "hash": "0xabc"}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="Invalid credential payload"):
            await intent.verify(credential, make_charge_request())

    async def test_non_string_signature(self) -> None:
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": 123}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="Invalid credential payload"):
            await intent.verify(credential, make_charge_request())

    async def test_malformed_transaction(self) -> None:
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": "0xnot-a-real-tx"},
            method="evm",
            expires=make_expires(),
        )
        with pytest.raises(VerificationError, match="Invalid serialized transaction"):
            await intent.verify(credential, make_charge_request())

    async def test_wrong_currency(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        other_currency = "0x" + "99" * 20
        raw_tx = build_signed_transfer_tx(account=account, currency=other_currency)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="does not call the expected currency"):
            await intent.verify(credential, make_charge_request())

    async def test_nonzero_native_value(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account, value=1)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="must not transfer native value"):
            await intent.verify(credential, make_charge_request())

    async def test_wrong_call_data_length(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account, data="0xa9059cbb1234")
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="unexpected call data"):
            await intent.verify(credential, make_charge_request())

    async def test_wrong_selector(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        bad_data = "0x" + "aaaaaaaa" + "0" * 128
        raw_tx = build_signed_transfer_tx(account=account, data=bad_data)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="not an ERC-20 transfer"):
            await intent.verify(credential, make_charge_request())

    async def test_wrong_recipient_in_calldata(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account, recipient="0x" + "77" * 20)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="recipient does not match"):
            await intent.verify(credential, make_charge_request())

    async def test_wrong_amount_in_calldata(self) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account, amount=42)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="amount does not match"):
            await intent.verify(credential, make_charge_request())


class TestChargeIntentBroadcast:
    def _credential(self, raw_tx: str):
        return make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )

    async def test_successful_charge(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        receipt = await intent.verify(self._credential(raw_tx), make_charge_request())
        assert receipt.status == "success"
        assert receipt.method == "evm"

    async def test_reverted_transaction(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x0", "logs": []}})

        with pytest.raises(VerificationError, match="reverted"):
            await intent.verify(self._credential(raw_tx), make_charge_request())

    async def test_missing_transfer_log(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": []}})

        with pytest.raises(VerificationError, match="Transfer log"):
            await intent.verify(self._credential(raw_tx), make_charge_request())

    async def test_receipt_polling_retries_until_mined(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": None})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        with patch("asyncio.sleep", return_value=None):
            receipt = await intent.verify(self._credential(raw_tx), make_charge_request())
        assert receipt.status == "success"

    async def test_timeout_waiting_for_receipt(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID, timeout=-1)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": None})

        with pytest.raises(VerificationError, match="Timed out"):
            await intent.verify(self._credential(raw_tx), make_charge_request())

    async def test_already_known_submission_error_is_tolerated(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"error": {"code": -32000, "message": "already known"}})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        receipt = await intent.verify(self._credential(raw_tx), make_charge_request())
        assert receipt.status == "success"

    async def test_submission_error_raises(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)

        httpx_mock.add_response(json={"error": {"code": -32000, "message": "insufficient funds"}})

        with pytest.raises(VerificationError, match="Transaction submission failed"):
            await intent.verify(self._credential(raw_tx), make_charge_request())


class TestChargeIntentReplayProtection:
    async def test_rejects_reused_transaction_hash(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        store = MemoryStore()
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID, store=store)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        first = await intent.verify(credential, make_charge_request())
        assert first.status == "success"

        with pytest.raises(VerificationError, match="already used"):
            await intent.verify(credential, make_charge_request())

    async def test_releases_reservation_on_failed_broadcast(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        raw_tx = build_signed_transfer_tx(account=account)
        store = MemoryStore()
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID, store=store)

        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x0", "logs": []}})
        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        credential = make_credential(
            {"type": "transaction", "signature": raw_tx}, method="evm", expires=make_expires()
        )
        with pytest.raises(VerificationError, match="reverted"):
            await intent.verify(credential, make_charge_request())

        # A retry after the store key was released should be allowed through again.
        receipt = await intent.verify(credential, make_charge_request())
        assert receipt.status == "success"


# ──────────────────────────────────────────────────────────────────
# End-to-end: client-built credential verified by the server intent
# ──────────────────────────────────────────────────────────────────


class TestEndToEnd:
    async def test_client_credential_verifies_on_server(self, httpx_mock: HTTPXMock) -> None:
        account = EvmAccount.from_key(TEST_PRIVATE_KEY)
        client_method = evm(intents={}, account=account, chain_id=BASE_CHAIN_ID)

        # Client-side transaction build RPCs.
        httpx_mock.add_response(json={"result": hex(BASE_CHAIN_ID)})
        httpx_mock.add_response(json={"result": "0x0"})
        httpx_mock.add_response(json={"result": "0x1"})
        httpx_mock.add_response(json={"result": {"baseFeePerGas": "0x64"}})
        httpx_mock.add_response(json={"result": "0x5208"})

        challenge = make_charge_challenge()
        credential = await client_method.create_credential(challenge)

        # Server-side broadcast + receipt RPCs.
        httpx_mock.add_response(json={"result": "0x" + "aa" * 32})
        httpx_mock.add_response(json={"result": {"status": "0x1", "logs": [transfer_log()]}})

        server_credential = make_bound_credential(
            credential.payload,
            challenge.request,
            method="evm",
            source=credential.source,
        )
        server_intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
        receipt = await server_intent.verify(server_credential, challenge.request)
        assert receipt.status == "success"
        assert receipt.method == "evm"
