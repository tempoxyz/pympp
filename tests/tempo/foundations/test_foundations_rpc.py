"""JSON-RPC client and contract actions against a mocked node."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pytempo import Call, TempoTransaction

from mpp.tempo._internal import abi, actions
from mpp.tempo._internal.rpc import (
    RpcClient,
    RpcError,
    RpcTransportError,
    TransactionReceiptNotFoundError,
    TransactionReceiptTimeoutError,
    call_request,
)
from mpp.tempo.chains import ACCOUNT_KEYCHAIN, FEE_MANAGER

ACCOUNT = "0x1111111111111111111111111111111111111111"
TOKEN = "0x20c0000000000000000000000000000000000000"
HASH = "0x" + "aa" * 32


def mock_client(
    respond: Callable[[str, list[Any]], Any], requests: list[dict[str, Any]] | None = None
) -> RpcClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if requests is not None:
            requests.append(body)
        result = respond(body["method"], body["params"])
        if isinstance(result, httpx.Response):
            return result
        if isinstance(result, RpcError):
            error = {"code": result.code, "message": result.message}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": error})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return RpcClient(
        "http://tempo.invalid",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        polling_interval=0.01,
    )


async def test_request_sends_json_rpc() -> None:
    requests: list[dict[str, Any]] = []
    async with mock_client(lambda method, params: "0xa5bf", requests) as client:
        assert await client.chain_id() == 42431
    assert requests == [{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}]


async def test_rpc_errors_and_transport_errors() -> None:
    async with mock_client(lambda m, p: RpcError(-32000, "nonce too low")) as client:
        with pytest.raises(RpcError, match="nonce too low") as info:
            await client.send_raw_transaction("0x76")
        assert info.value.code == -32000
    async with mock_client(lambda m, p: httpx.Response(502, text="bad gateway")) as client:
        with pytest.raises(RpcTransportError) as transport:
            await client.chain_id()
        assert transport.value.status == 502


async def test_receipts() -> None:
    raw = {
        "transactionHash": HASH,
        "status": "0x1",
        "from": ACCOUNT,
        "blockNumber": "0x10",
        "feePayer": TOKEN,
        "logs": [{"address": TOKEN, "topics": ["0x01"], "data": "0x", "logIndex": "0x2"}],
    }
    async with mock_client(lambda m, p: raw) as client:
        receipt = await client.get_transaction_receipt(HASH)
    assert receipt.status == "success"
    assert receipt.sender == ACCOUNT
    assert receipt.block_number == 16
    assert receipt.fee_payer == TOKEN
    assert receipt.logs[0].log_index == 2
    async with mock_client(lambda m, p: {**raw, "status": "0x0"}) as client:
        assert (await client.get_transaction_receipt(HASH)).status == "reverted"
    async with mock_client(lambda m, p: None) as client:
        with pytest.raises(TransactionReceiptNotFoundError):
            await client.get_transaction_receipt(HASH)


async def test_wait_for_receipt_polls_until_found() -> None:
    calls = 0

    def respond(method: str, params: list[Any]) -> Any:
        nonlocal calls
        calls += 1
        return None if calls < 3 else {"transactionHash": HASH, "status": "0x1", "logs": []}

    async with mock_client(respond) as client:
        receipt = await client.wait_for_transaction_receipt(HASH, timeout_seconds=1)
    assert receipt.transaction_hash == HASH
    assert calls == 3
    async with mock_client(lambda m, p: None) as client:
        with pytest.raises(TransactionReceiptTimeoutError):
            await client.wait_for_transaction_receipt(HASH, timeout_seconds=0.03)


async def test_send_raw_transaction_sync() -> None:
    requests: list[dict[str, Any]] = []
    receipt = {"transactionHash": HASH, "status": "0x1", "logs": []}
    async with mock_client(lambda m, p: receipt, requests) as client:
        result = await client.send_raw_transaction_sync("0x76ab", timeout_ms=2000)
    assert result.transaction_hash == HASH
    assert requests[0]["method"] == "eth_sendRawTransactionSync"
    assert requests[0]["params"] == ["0x76ab", 2000]


def test_call_request_shapes() -> None:
    assert call_request(to=TOKEN, data="0x1234") == {"to": TOKEN, "data": "0x1234"}
    assert call_request(sender=ACCOUNT, calls=[Call(to=TOKEN, data="0xab")]) == {
        "calls": [{"to": TOKEN, "value": "0x", "data": "0xab"}],
        "type": "0x76",
        "from": ACCOUNT,
    }
    transaction = TempoTransaction(
        chain_id=4217,
        calls=(Call(to=TOKEN, value=5),),
        gas_limit=100,
        nonce=0,
        nonce_key=2**256 - 1,
        valid_before=10,
        fee_token=TOKEN,
        sender_address=ACCOUNT,
    )
    assert call_request(transaction=transaction, fee_payer=ACCOUNT) == {
        "chainId": "0x1079",
        "gas": "0x64",
        "nonce": "0x0",
        "nonceKey": hex(2**256 - 1),
        "validBefore": "0xa",
        "calls": [{"to": TOKEN, "value": "0x5", "data": "0x"}],
        "feeToken": TOKEN,
        "type": "0x76",
        "from": ACCOUNT,
        "feePayer": ACCOUNT,
    }


async def test_actions_read_without_sender() -> None:
    requests: list[dict[str, Any]] = []

    def respond(method: str, params: list[Any]) -> Any:
        request = params[0]
        assert method == "eth_call"
        assert "from" not in request
        selector = request["data"][:10]
        if selector == abi.BALANCE_OF.selector:
            return "0x" + (1234).to_bytes(32, "big").hex()
        if selector == abi.USER_TOKENS.selector:
            assert request["to"] == FEE_MANAGER
            return "0x" + "00" * 32
        if selector == abi.GET_KEY.selector:
            assert request["to"] == ACCOUNT_KEYCHAIN
            words = [1, int(ACCOUNT, 16), 2**40, 1, 0]
            return "0x" + b"".join(w.to_bytes(32, "big") for w in words).hex()
        raise AssertionError(selector)

    async with mock_client(respond, requests) as client:
        assert await actions.get_balance(client, token=TOKEN, account=ACCOUNT) == 1234
        assert await actions.get_user_fee_token(client, account=ACCOUNT) is None
        metadata = await actions.get_access_key_metadata(
            client, account=ACCOUNT, access_key=ACCOUNT
        )
        assert metadata.key_type == "p256"
        assert metadata.enforce_limits
        assert not metadata.is_revoked
        assert await actions.is_active_access_key(client, account=ACCOUNT, access_key=ACCOUNT)
    assert len(requests) == 4


async def test_inactive_access_keys() -> None:
    async with mock_client(lambda m, p: RpcError(3, "execution reverted")) as client:
        assert not await actions.is_active_access_key(client, account=ACCOUNT, access_key=ACCOUNT)

    def expired(method: str, params: list[Any]) -> Any:
        words = [0, int(ACCOUNT, 16), 1, 0, 0]
        return "0x" + b"".join(w.to_bytes(32, "big") for w in words).hex()

    async with mock_client(expired) as client:
        assert not await actions.is_active_access_key(client, account=ACCOUNT, access_key=ACCOUNT)
