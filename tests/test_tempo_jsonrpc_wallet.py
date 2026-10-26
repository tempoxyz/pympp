"""Tests for paying Tempo charges with a JSON-RPC wallet account."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mpp import Challenge
from mpp.errors import PaymentOutcomeUnknownError
from mpp.methods.tempo import JsonRpcAccount
from mpp.methods.tempo import client as tempo
from mpp.methods.tempo._rpc import RpcError
from mpp.methods.tempo._wallet import CallsStatusError, send_calls_sync
from mpp.methods.tempo.client import _tempo_method
from mpp.runtime import CredentialParams

WALLET = "0x00000000000000000000000000000000000000aa"
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
TX_HASH = "0x" + "ab" * 32


def _expires_in(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _challenge(**method_details: Any) -> Challenge:
    return Challenge(
        id="wallet-challenge",
        method="tempo",
        intent="charge",
        request={
            "amount": "1000000",
            "currency": CURRENCY,
            "recipient": RECIPIENT,
            "methodDetails": {"chainId": 4217, **method_details},
        },
        realm="api.example.com",
        request_b64="e30",
        expires=_expires_in(300),
    )


class FakeWallet:
    """Records wallet requests and answers them from `responses`."""

    def __init__(self, **responses: Any) -> None:
        self.responses = responses
        self.requests: list[tuple[str, list[Any]]] = []

    async def __call__(self, method: str, params: list[Any]) -> Any:
        self.requests.append((method, params))
        response = self.responses[method]
        if isinstance(response, Exception):
            raise response
        return response

    def methods(self) -> list[str]:
        return [method for method, _ in self.requests]


async def _node(rpc_url: str, method: str, params: list[Any], *, client: Any = None) -> Any:
    del rpc_url, params, client
    return {"eth_chainId": hex(4217), "eth_gasPrice": "0x1"}[method]


async def _pay(account: JsonRpcAccount, challenge: Challenge, node: Any = _node) -> Any:
    method = _tempo_method(account=account, chain_id=4217, rpc_url="https://rpc.test")
    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=node),
        patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=0x186A0)),
    ):
        return await method.create_credential(challenge)


@pytest.mark.asyncio
async def test_wallet_prefers_push_with_wallet_send_calls() -> None:
    wallet = FakeWallet(
        wallet_sendCalls={"id": "bundle-1"},
        wallet_getCallsStatus={"status": 200, "receipts": [{"transactionHash": TX_HASH}]},
    )

    credential = await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())

    assert credential.payload == {"type": "hash", "hash": TX_HASH}
    assert credential.source == f"did:pkh:eip155:4217:{WALLET}"
    assert wallet.methods() == ["wallet_sendCalls", "wallet_getCallsStatus"]
    params = wallet.requests[0][1][0]
    assert params["atomicRequired"] is False
    assert params["chainId"] == hex(4217)
    assert params["from"] == WALLET
    assert params["version"] == "2.0.0"
    assert "capabilities" not in params
    assert [call["to"] for call in params["calls"]] == [CURRENCY]
    assert params["calls"][0]["data"].startswith("0x95777d59")
    assert wallet.requests[1][1] == ["bundle-1"]


@pytest.mark.asyncio
async def test_wallet_send_calls_is_atomic_for_splits() -> None:
    wallet = FakeWallet(
        wallet_sendCalls="bundle-2",
        wallet_getCallsStatus={"status": "CONFIRMED", "receipts": [{"transactionHash": TX_HASH}]},
    )
    challenge = _challenge(splits=[{"amount": "100000", "recipient": WALLET}])

    credential = await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)

    assert credential.payload["hash"] == TX_HASH
    params = wallet.requests[0][1][0]
    assert params["atomicRequired"] is True
    assert len(params["calls"]) == 2


@pytest.mark.asyncio
async def test_wallet_without_eip5792_falls_back_to_eth_send_transaction() -> None:
    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
        eth_sendTransaction=TX_HASH,
        eth_getTransactionReceipt={"status": "0x1", "transactionHash": TX_HASH},
    )

    credential = await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())

    assert credential.payload == {"type": "hash", "hash": TX_HASH}
    assert wallet.methods() == [
        "wallet_sendCalls",
        "eth_sendTransaction",
        "eth_getTransactionReceipt",
    ]
    sent = wallet.requests[1][1][0]
    assert sent["from"] == WALLET
    assert sent["to"] == CURRENCY
    assert sent["chainId"] == hex(4217)


@pytest.mark.asyncio
async def test_wallet_rejection_does_not_fall_back() -> None:
    wallet = FakeWallet(wallet_sendCalls=RpcError({"code": 4001, "message": "User rejected"}))

    with pytest.raises(RpcError, match="User rejected"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())
    assert wallet.methods() == ["wallet_sendCalls"]


@pytest.mark.asyncio
async def test_send_calls_sync_waits_for_pending_bundle() -> None:
    statuses = iter([{"status": 100}, {"status": 200, "receipts": [{"transactionHash": TX_HASH}]}])

    async def wallet(method: str, params: list[Any]) -> Any:
        del params
        return "bundle-3" if method == "wallet_sendCalls" else next(statuses)

    from pytempo import Call

    status = await send_calls_sync(
        wallet,
        address=WALLET,
        chain_id=4217,
        calls=[Call.create(to=CURRENCY, value=0, data="0x")],
        polling_interval=0,
    )

    assert status["statusCode"] == 200
    assert status["receipts"] == [{"transactionHash": TX_HASH}]


def _signed_transaction(*, sponsored: bool) -> Any:
    from pytempo import Call, TempoTransaction

    from mpp.methods.tempo import TempoAccount

    tx = TempoTransaction.create(
        chain_id=4217,
        gas_limit=0x186A0,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        nonce=0,
        nonce_key=(1 << 256) - 1,
        fee_token=None if sponsored else CURRENCY,
        awaiting_fee_payer=sponsored,
        valid_before=2_000_000_000,
        calls=(Call.create(to=CURRENCY, value=0, data="0x"),),
    )
    return tx.sign(TempoAccount.from_key("0x" + "11" * 32).private_key)


@pytest.mark.asyncio
@pytest.mark.parametrize("sponsored", [False, True])
async def test_wallet_signs_pull_only_challenge_with_eth_sign_transaction(
    sponsored: bool,
) -> None:
    from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

    signed = _signed_transaction(sponsored=sponsored)
    raw_tx = "0x" + signed.encode().hex()
    address = "0x" + bytes(signed.sender_address).hex()
    wallet = FakeWallet(eth_signTransaction=raw_tx)
    challenge = _challenge(supportedModes=["pull"], feePayer=sponsored)

    credential = await _pay(JsonRpcAccount(address, request=wallet), challenge)

    # A fee-paying server takes the sponsored transaction as a 0x78 envelope.
    expected = "0x" + encode_fee_payer_envelope(signed).hex() if sponsored else raw_tx
    assert credential.payload == {"type": "transaction", "signature": expected}
    assert wallet.methods() == ["eth_signTransaction"]
    request = wallet.requests[0][1][0]
    assert request["type"] == "0x76"
    assert request["from"] == address
    assert request["chainId"] == hex(4217)
    assert request["nonceKey"] == hex((1 << 256) - 1)
    assert [call["to"] for call in request["calls"]] == [CURRENCY]
    if sponsored:
        assert request["feePayer"] is True
        assert "feeToken" not in request
    else:
        assert "feePayer" not in request
        assert request["feeToken"] == CURRENCY


@pytest.mark.asyncio
async def test_address_account_sends_wallet_requests_to_rpc_url() -> None:
    calls: list[str] = []

    async def node(rpc_url: str, method: str, params: list[Any], *, client: Any = None) -> Any:
        assert rpc_url == "https://rpc.test"
        calls.append(method)
        if method == "wallet_sendCalls":
            return "bundle-4"
        if method == "wallet_getCallsStatus":
            return {"status": 200, "receipts": [{"transactionHash": TX_HASH}]}
        return await _node(rpc_url, method, params, client=client)

    client_method = tempo.charge(account=WALLET, chain_id=4217, rpc_url="https://rpc.test")
    with patch("mpp.methods.tempo.client._rpc_call", side_effect=node):
        authorization = await client_method.create_credential(
            CredentialParams(challenge=_challenge())
        )

    assert authorization.startswith("Payment ")
    assert calls == ["eth_chainId", "wallet_sendCalls", "wallet_getCallsStatus"]


def test_root_account_requires_local_account() -> None:
    with pytest.raises(ValueError, match="root_account"):
        tempo.charge(account=JsonRpcAccount(WALLET), root_account=WALLET)


def test_wallet_account_rejects_a_private_key() -> None:
    with pytest.raises(ValueError, match="not a private key"):
        tempo.charge(account="0x" + "11" * 32)
    with pytest.raises(ValueError, match="40 hex"):
        JsonRpcAccount("wallet")


@pytest.mark.asyncio
async def test_sponsored_wallet_signature_must_await_fee_payer() -> None:
    wallet = FakeWallet(eth_signTransaction="0x76c0ffee")

    with pytest.raises(tempo.TransactionError, match="awaiting a fee payer"):
        await _pay(
            JsonRpcAccount(WALLET, request=wallet),
            _challenge(supportedModes=["pull"], feePayer=True),
        )


@pytest.mark.asyncio
async def test_fallback_carries_fee_token() -> None:
    from mpp.methods.tempo._defaults import OUSD

    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
        eth_sendTransaction=TX_HASH,
        eth_getTransactionReceipt={"status": "0x1", "transactionHash": TX_HASH},
    )
    challenge = _challenge()
    challenge.request["currency"] = OUSD

    with patch("mpp.methods.tempo.client._tip20_balance", new=AsyncMock(return_value=10**6)):
        credential = await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)

    assert credential.payload == {"type": "hash", "hash": TX_HASH}
    assert (
        wallet.requests[1][1][0]["feeToken"] == wallet.requests[0][1][0]["capabilities"]["feeToken"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        {"status": 500, "receipts": [{"transactionHash": TX_HASH}]},
        {"status": 600, "receipts": [{"transactionHash": TX_HASH}]},
        {
            "status": 200,
            "receipts": [{"transactionHash": TX_HASH}, {"transactionHash": "0x" + "cd" * 32}],
        },
    ],
)
async def test_wallet_payment_without_one_confirmed_transaction_fails(
    status: dict[str, Any],
) -> None:
    wallet = FakeWallet(wallet_sendCalls="bundle-5", wallet_getCallsStatus=status)
    challenge = _challenge(splits=[{"amount": "100000", "recipient": WALLET}])

    with pytest.raises(tempo.TransactionError):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)


@pytest.mark.asyncio
async def test_reverted_fallback_transaction_fails() -> None:
    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
        eth_sendTransaction=TX_HASH,
        eth_getTransactionReceipt={"status": "0x0", "transactionHash": TX_HASH},
    )

    with pytest.raises(tempo.TransactionError, match="status 500"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())


@pytest.mark.asyncio
async def test_push_refuses_a_challenge_about_to_expire() -> None:
    from datetime import UTC, datetime, timedelta

    from mpp.errors import PaymentExpiredError

    wallet = FakeWallet()
    challenge = _challenge()
    expires = (datetime.now(UTC) + timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    challenge = Challenge(
        id=challenge.id,
        method=challenge.method,
        intent=challenge.intent,
        request=challenge.request,
        realm=challenge.realm,
        request_b64=challenge.request_b64,
        expires=expires,
    )

    with pytest.raises(PaymentExpiredError):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)
    assert wallet.requests == []


@pytest.mark.asyncio
async def test_send_calls_timeout_keeps_the_bundle_id() -> None:
    from pytempo import Call

    from mpp.methods.tempo._wallet import WaitForCallsStatusTimeoutError

    wallet = FakeWallet(wallet_sendCalls="bundle-6", wallet_getCallsStatus={"status": 100})

    with pytest.raises(WaitForCallsStatusTimeoutError) as error:
        await send_calls_sync(
            wallet,
            address=WALLET,
            chain_id=4217,
            calls=[Call.create(to=CURRENCY, value=0, data="0x")],
            polling_interval=0,
            timeout=0.01,
        )
    assert error.value.id == "bundle-6"


def test_transaction_hash_reads_push_credential() -> None:
    from mpp import Credential

    credential = Credential(
        challenge=_challenge().to_echo(), payload={"type": "hash", "hash": TX_HASH}
    )

    assert _tempo_method(account=JsonRpcAccount(WALLET)).transaction_hash(credential) == TX_HASH


def _with_expires(challenge: Challenge, expires: str | None) -> Challenge:
    return Challenge(
        id=challenge.id,
        method=challenge.method,
        intent=challenge.intent,
        request=challenge.request,
        realm=challenge.realm,
        request_b64=challenge.request_b64,
        expires=expires,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("expires", [None, "not-a-date"])
async def test_push_refuses_a_challenge_without_valid_expires(expires: str | None) -> None:
    wallet = FakeWallet()

    with pytest.raises(ValueError, match="no valid expires"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _with_expires(_challenge(), expires))
    assert wallet.requests == []


@pytest.mark.asyncio
async def test_push_rechecks_expiry_after_fee_token_resolution() -> None:
    import time

    from mpp.errors import PaymentExpiredError
    from mpp.methods.tempo._defaults import OUSD

    wallet = FakeWallet()
    challenge = _with_expires(_challenge(), _expires_in(20))
    challenge.request["currency"] = OUSD
    clock = {"offset": 0.0}

    async def slow_balance(*args: Any, **kwargs: Any) -> int:
        clock["offset"] = 10.0  # The balance lookups take 10s.
        return 10**6

    with (
        patch("mpp.methods.tempo.client._tip20_balance", new=slow_balance),
        patch(
            "mpp.methods.tempo.client.time",
            new=SimpleNamespace(time=lambda: time.time() + clock["offset"]),
        ),
        pytest.raises(PaymentExpiredError),
    ):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)
    assert wallet.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fallback", [False, True])
async def test_status_failure_after_sending_is_an_unknown_outcome(fallback: bool) -> None:
    unavailable = RpcError({"code": -32603, "message": "Internal error"})
    if fallback:
        wallet = FakeWallet(
            wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
            eth_sendTransaction=TX_HASH,
            eth_getTransactionReceipt=unavailable,
        )
    else:
        wallet = FakeWallet(wallet_sendCalls="bundle-7", wallet_getCallsStatus=unavailable)

    with (
        patch("mpp.methods.tempo._wallet._STATUS_RETRY_COUNT", 0),
        pytest.raises(PaymentOutcomeUnknownError) as error,
    ):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())
    assert error.value.transaction_hash == (TX_HASH if fallback else None)
    assert isinstance(error.value.cause, CallsStatusError)
    assert error.value.cause.id == (TX_HASH if fallback else "bundle-7")


@pytest.mark.asyncio
async def test_push_refuses_a_malformed_recipient() -> None:
    wallet = FakeWallet()
    challenge = _challenge()
    challenge.request["recipient"] = "0x1234"

    with pytest.raises(ValueError, match="Invalid recipient address"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)
    assert wallet.requests == []
