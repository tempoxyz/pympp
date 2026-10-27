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
        self.responses = {"eth_chainId": hex(4217), **responses}
        self.requests: list[tuple[str, list[Any]]] = []
        self.chain_id_queries = 0

    async def __call__(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            self.chain_id_queries += 1
        else:
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
    expires = (datetime.now(UTC) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
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
async def test_push_pays_a_short_lived_unsponsored_challenge() -> None:
    wallet = FakeWallet(
        wallet_sendCalls={"id": "bundle-short"},
        wallet_getCallsStatus={"status": 200, "receipts": [{"transactionHash": TX_HASH}]},
    )
    challenge = _with_expires(_challenge(), _expires_in(10))

    credential = await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)

    assert credential.payload == {"type": "hash", "hash": TX_HASH}


@pytest.mark.asyncio
async def test_push_keeps_the_cosign_floor_for_a_sponsored_challenge() -> None:
    from mpp.errors import PaymentExpiredError

    wallet = FakeWallet()
    challenge = _with_expires(_challenge(feePayer=True), _expires_in(10))

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
        clock["offset"] = 19.0  # The balance lookups take 19s.
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "receipts",
    [[], [{"transactionHash": TX_HASH}, {"transactionHash": "0x" + "cd" * 32}]],
)
async def test_confirmed_bundle_without_one_transaction_is_an_unknown_outcome(
    receipts: list[dict[str, Any]],
) -> None:
    wallet = FakeWallet(
        wallet_sendCalls="bundle-8",
        wallet_getCallsStatus={"status": 200, "receipts": receipts},
    )
    challenge = _challenge(splits=[{"amount": "100000", "recipient": WALLET}])

    with pytest.raises(PaymentOutcomeUnknownError) as error:
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)
    assert isinstance(error.value.cause, tempo.TransactionError)


@pytest.mark.asyncio
async def test_retry_after_unknown_outcome_follows_the_sent_bundle() -> None:
    unavailable = RpcError({"code": -32603, "message": "Internal error"})
    wallet = FakeWallet(wallet_sendCalls="bundle-9", wallet_getCallsStatus=unavailable)
    method = _tempo_method(
        account=JsonRpcAccount(WALLET, request=wallet), chain_id=4217, rpc_url="https://rpc.test"
    )
    challenge = _challenge()

    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=_node),
        patch("mpp.methods.tempo._wallet._STATUS_RETRY_COUNT", 0),
    ):
        with pytest.raises(PaymentOutcomeUnknownError):
            await method.create_credential(challenge)
        # The status read recovers: the retry follows bundle-9 instead of paying again.
        wallet.responses["wallet_getCallsStatus"] = {
            "status": 200,
            "receipts": [{"transactionHash": TX_HASH}],
        }
        credential = await method.create_credential(challenge)

    assert credential.payload == {"type": "hash", "hash": TX_HASH}
    assert wallet.methods().count("wallet_sendCalls") == 1
    assert wallet.requests[-1] == ("wallet_getCallsStatus", ["bundle-9"])


@pytest.mark.asyncio
async def test_push_fee_token_covers_the_fee_not_one_unit() -> None:
    from mpp.methods.tempo._defaults import OUSD, fee_tokens_for_chain

    dust_token, funded_token = fee_tokens_for_chain(4217)[:2]
    wallet = FakeWallet(
        wallet_sendCalls="bundle-10",
        wallet_getCallsStatus={"status": 200, "receipts": [{"transactionHash": TX_HASH}]},
    )
    challenge = _challenge()
    challenge.request["currency"] = OUSD

    async def node(rpc_url: str, method: str, params: list[Any], *, client: Any = None) -> Any:
        if method == "eth_gasPrice":
            return hex(20 * 10**9)  # 1M gas costs 0.02 at this price.
        return await _node(rpc_url, method, params, client=client)

    async def balance(rpc_url: str, token: str, account: str) -> int:
        return 1 if token == dust_token else 10**6

    with patch("mpp.methods.tempo.client._tip20_balance", new=balance):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge, node=node)

    assert wallet.requests[0][1][0]["capabilities"] == {"feeToken": funded_token}


class GatewayError(Exception):
    """A transport error that carries an HTTP status as its code."""

    code = 502


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [RpcError({"code": 1001, "message": "Relay unavailable"}), GatewayError("Bad gateway")]
)
async def test_unknown_send_calls_error_does_not_fall_back(error: Exception) -> None:
    wallet = FakeWallet(wallet_sendCalls=error, eth_sendTransaction=TX_HASH)

    with pytest.raises(type(error)):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())
    assert wallet.methods() == ["wallet_sendCalls"]


@pytest.mark.asyncio
async def test_generic_send_transaction_error_is_not_retried() -> None:
    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
        eth_sendTransaction=RpcError({"code": -32000, "message": "nonce too low"}),
        wallet_sendTransaction=TX_HASH,
    )

    with pytest.raises(RpcError, match="nonce too low"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())
    assert wallet.methods() == ["wallet_sendCalls", "eth_sendTransaction"]


@pytest.mark.asyncio
async def test_unsupported_method_code_4200_falls_back() -> None:
    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": 4200, "message": "Unsupported method"}),
        eth_sendTransaction=TX_HASH,
        eth_getTransactionReceipt={"status": "0x1", "transactionHash": TX_HASH},
    )

    credential = await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())

    assert credential.payload == {"type": "hash", "hash": TX_HASH}


def test_push_floor_covers_the_confirmation_wait() -> None:
    from mpp.methods.tempo._wallet import SEND_CALLS_TIMEOUT

    assert tempo.PUSH_MIN_REMAINING_VALIDITY_SECONDS > SEND_CALLS_TIMEOUT


@pytest.mark.asyncio
async def test_push_refuses_a_challenge_shorter_than_the_confirmation_wait() -> None:
    from mpp.errors import PaymentExpiredError

    wallet = FakeWallet()
    challenge = _with_expires(_challenge(), _expires_in(4))

    with pytest.raises(PaymentExpiredError):
        await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)
    assert wallet.requests == []


@pytest.mark.asyncio
async def test_fallback_transaction_is_bounded_by_the_challenge_expiry() -> None:
    wallet = FakeWallet(
        wallet_sendCalls=RpcError({"code": -32601, "message": "Method not found"}),
        eth_sendTransaction=TX_HASH,
        eth_getTransactionReceipt={"status": "0x1", "transactionHash": TX_HASH},
    )
    expires = datetime.now(UTC) + timedelta(seconds=30)
    challenge = _with_expires(_challenge(), expires.isoformat().replace("+00:00", "Z"))

    await _pay(JsonRpcAccount(WALLET, request=wallet), challenge)

    assert int(wallet.requests[1][1][0]["validBefore"], 16) == int(expires.timestamp()) + 1


@pytest.mark.asyncio
async def test_push_refuses_a_wallet_on_another_chain() -> None:
    wallet = FakeWallet(eth_chainId=hex(42431))

    with pytest.raises(tempo.TransactionError, match="wallet is on 42431"):
        await _pay(JsonRpcAccount(WALLET, request=wallet), _challenge())
    assert wallet.requests == []


def _with_signature(raw_tx: str, transform: Any) -> str:
    import rlp

    tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
    fields = rlp.decode(tx_bytes[1:])
    return "0x" + (tx_bytes[:1] + rlp.encode(transform(fields))).hex()


def _raw_recovery_id(fields: list[Any]) -> list[Any]:
    signature = fields[-1]
    return [*fields[:-1], signature[:64] + bytes([signature[64] - 27])]


@pytest.mark.asyncio
async def test_wallet_signature_with_raw_recovery_id_is_canonicalised() -> None:
    from eth_hash.auto import keccak

    signed = _signed_transaction(sponsored=False)
    canonical = "0x" + signed.encode().hex()
    address = "0x" + bytes(signed.sender_address).hex()
    wallet = FakeWallet(eth_signTransaction=_with_signature(canonical, _raw_recovery_id))

    credential = await _pay(
        JsonRpcAccount(address, request=wallet), _challenge(supportedModes=["pull"])
    )

    assert credential.payload["signature"] == canonical
    method = _tempo_method(account=JsonRpcAccount(address))
    assert method.transaction_hash(credential) == "0x" + keccak(bytes.fromhex(canonical[2:])).hex()


def test_transaction_hash_canonicalises_and_skips_fee_payer_slot() -> None:
    from eth_hash.auto import keccak

    from mpp import Credential

    canonical = "0x" + _signed_transaction(sponsored=False).encode().hex()
    method = _tempo_method(account=JsonRpcAccount(WALLET))

    def credential(raw_tx: str) -> Credential:
        return Credential(
            challenge=_challenge().to_echo(), payload={"type": "transaction", "signature": raw_tx}
        )

    raw = _with_signature(canonical, _raw_recovery_id)
    expected = "0x" + keccak(bytes.fromhex(canonical[2:])).hex()
    assert method.transaction_hash(credential(raw)) == expected
    placeholder = _with_signature(canonical, lambda f: [*f[:11], b"\x00", *f[12:]])
    assert method.transaction_hash(credential(placeholder)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["chain", "sender", "fee_payer_slot", "not_tempo"])
async def test_wallet_signed_transaction_is_checked(problem: str) -> None:
    signed = _signed_transaction(sponsored=False)
    raw_tx = "0x" + signed.encode().hex()
    address = "0x" + bytes(signed.sender_address).hex()
    if problem == "chain":
        raw_tx = _with_signature(raw_tx, lambda f: [(42431).to_bytes(2, "big"), *f[1:]])
    elif problem == "sender":
        address = WALLET
    elif problem == "fee_payer_slot":
        raw_tx = _with_signature(raw_tx, lambda f: [*f[:11], b"\x00", *f[12:]])
    else:
        raw_tx = "0x02" + raw_tx[4:]
    wallet = FakeWallet(eth_signTransaction=raw_tx)

    with pytest.raises(tempo.TransactionError):
        await _pay(JsonRpcAccount(address, request=wallet), _challenge(supportedModes=["pull"]))
