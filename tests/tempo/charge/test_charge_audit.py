"""Regression tests for the tempo-charge audit (docs/audit/tempo-charge.json)."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest
from _charge_node import (
    CURRENCY,
    build_transaction,
    credential,
    memo_for,
    payer,
    sign,
    transfer_call,
)
from _charge_setup import challenge_of, funded_node, make_server, problem, request

from mpp.challenge import Challenge
from mpp.tempo import methods
from mpp.tempo._internal.address import is_address
from mpp.tempo._internal.fee_payer import FeePayerValidationError, assert_allowed_fee_token
from mpp.tempo._internal.hexutil import to_bytes
from mpp.tempo._internal.proof import parse_pkh_source
from mpp.tempo._internal.rpc import RpcClient, RpcError, RpcTransportError
from mpp.tempo._internal.units import parse_units
from mpp.tempo.client import charge as client_charge

ADDRESS = "0x" + "ab" * 20
AR = [chr(0x0660 + i) for i in range(10)]
"""Arabic-Indic digits (Unicode ``\\d`` but not ASCII)."""


# -- 1. RPC retries (viem http transport) -------------------------------------------------------


class Script:
    """A JSON-RPC endpoint answering from a list of scripted responses, then success."""

    def __init__(self, *responses: Any, result: Any = "0x1079") -> None:
        self.responses = list(responses)
        self.result = result
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            if isinstance(response, int):
                return httpx.Response(response, text="error")
            if isinstance(response, httpx.Response):
                return response
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": response})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": self.result})

    def client(self) -> RpcClient:
        return RpcClient(
            "http://node",
            http=httpx.AsyncClient(transport=httpx.MockTransport(self)),
            retry_delay=0.001,
        )


@pytest.mark.parametrize(
    "failure",
    [
        503,
        429,
        500,
        502,
        504,
        408,
        403,
        413,
        {"code": -32603, "message": "internal"},
        {"code": -32005, "message": "limit exceeded"},
        {"code": 429, "message": "too many"},
        {"code": -32007, "message": "quota"},
        {"code": -1, "message": "unknown"},
        "network",
    ],
)
async def test_transient_failures_are_retried(failure: Any) -> None:
    error = (
        httpx.ConnectError("blip", request=httpx.Request("POST", "http://node"))
        if failure == "network"
        else failure
    )
    script = Script(error)
    assert await script.client().chain_id() == 4217
    assert len(script.requests) == 2


@pytest.mark.parametrize(
    "failure", [400, 404, {"code": -32000, "message": "nope"}, {"code": 3, "message": "reverted"}]
)
async def test_definitive_failures_are_not_retried(failure: Any) -> None:
    script = Script(failure)
    with pytest.raises((RpcError, RpcTransportError)):
        await script.client().chain_id()
    assert len(script.requests) == 1


async def test_retries_at_most_three_times_with_backoff() -> None:
    script = Script(503, 503, 503, 503)
    started = time.monotonic()
    client = RpcClient("http://node", http=httpx.AsyncClient(transport=httpx.MockTransport(script)))
    with pytest.raises(RpcTransportError) as caught:
        await client.chain_id()
    assert caught.value.status == 503
    assert len(script.requests) == 4
    # viem backoff: 150 + 300 + 600 ms.
    assert time.monotonic() - started >= 1.0


async def test_honors_retry_after() -> None:
    script = Script(httpx.Response(429, headers={"Retry-After": "0"}))
    client = RpcClient("http://node", http=httpx.AsyncClient(transport=httpx.MockTransport(script)))
    started = time.monotonic()
    assert await client.chain_id() == 4217
    assert time.monotonic() - started < 0.1


@pytest.mark.parametrize("method", ["eth_sendRawTransaction", "eth_sendRawTransactionSync"])
async def test_broadcasts_are_never_retried(method: str) -> None:
    script = Script(503)
    with pytest.raises(RpcTransportError):
        await script.client().request(method, ["0x76"])
    assert len(script.requests) == 1


async def test_non_2xx_json_rpc_error_bodies_flow_through_rpc_errors() -> None:
    """viem returns a valid JSON-RPC error body even on a non-2xx status."""
    revert = {"code": 3, "message": "execution reverted", "data": "0x08c379a0"}
    script = Script(httpx.Response(500, json={"jsonrpc": "2.0", "id": 1, "error": revert}))
    with pytest.raises(RpcError) as caught:
        await script.client().chain_id()
    assert (caught.value.code, caught.value.data) == (3, "0x08c379a0")
    assert len(script.requests) == 1

    internal = {"code": -32603, "message": "internal"}
    script = Script(httpx.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": internal}))
    assert await script.client().chain_id() == 4217
    assert len(script.requests) == 2


async def test_non_json_bodies() -> None:
    script = Script(httpx.Response(400, text="bad gateway"))
    with pytest.raises(RpcTransportError) as caught:
        await script.client().chain_id()
    assert caught.value.status == 400
    assert len(script.requests) == 1

    # An unparseable 2xx body is a status-less HTTP error, which viem retries.
    script = Script(httpx.Response(200, text="<html>"))
    assert await script.client().chain_id() == 4217
    assert len(script.requests) == 2


async def test_hash_credential_survives_a_transient_receipt_failure() -> None:
    node = funded_node()
    server = make_server(node)
    challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    tx_hash = node.handle(
        "eth_sendRawTransaction",
        [
            sign(
                payer(),
                build_transaction(
                    [
                        transfer_call(
                            CURRENCY, challenge.request["recipient"], 1_000_000, memo_for(challenge)
                        )
                    ]
                ),
            )
        ],
    )
    from _charge_node import HttpStatus

    failures = [HttpStatus(503)]

    def flaky(params: list[Any]) -> Any:
        if failures:
            raise failures.pop()
        return node.handle("eth_getTransactionReceipt", params)

    node.on("eth_getTransactionReceipt", flaky)
    receipt = await server.verify_credential(
        credential(challenge, {"hash": tx_hash, "type": "hash"})
    )
    assert receipt.status == "success"
    assert node.count("eth_getTransactionReceipt") == 3  # 503 + retry (validate) + broadcast


async def test_sync_broadcast_503_is_not_retried() -> None:
    from _charge_node import HttpStatus

    node = funded_node()
    sends: list[Any] = []

    def failing(params: list[Any]) -> Any:
        sends.append(params)
        raise HttpStatus(503)

    node.on("eth_sendRawTransactionSync", failing)
    node.on("eth_getTransactionReceipt", lambda params: None)
    server = make_server(node, confirmation_timeout_ms=60)
    challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    signature = sign(
        payer(),
        build_transaction(
            [
                transfer_call(
                    CURRENCY, challenge.request["recipient"], 1_000_000, memo_for(challenge)
                )
            ]
        ),
    )
    with pytest.raises(RpcTransportError):
        await server.verify_credential(
            credential(challenge, {"signature": signature, "type": "transaction"})
        )
    assert len(sends) == 1


# -- 2. ASCII, full-match validation ------------------------------------------------------------


def test_is_address_rejects_trailing_newline_and_unicode() -> None:
    assert is_address(ADDRESS)
    assert not is_address(ADDRESS + "\n")
    assert not is_address("0x" + "ab" * 19 + AR[1] + AR[2])


@pytest.mark.parametrize(
    "source",
    [
        f"did:pkh:eip155:4{AR[2]}{AR[1]}{AR[7]}:{ADDRESS}",
        f"did:pkh:eip155:4217:{ADDRESS}\n",
        f"did:pkh:eip155:4217\n:{ADDRESS}",
    ],
)
def test_parse_pkh_source_rejects_non_ascii_digits_and_trailing_newlines(source: str) -> None:
    assert parse_pkh_source(source) is None
    assert parse_pkh_source(f"did:pkh:eip155:4217:{ADDRESS}") is not None


def test_hosted_fee_token_with_trailing_newline_is_invalid() -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is invalid"):
        assert_allowed_fee_token(ADDRESS + "\n")
    assert_allowed_fee_token(ADDRESS)


@pytest.mark.parametrize("amount", ["1\n", AR[1], f"1.{AR[5]}"])
def test_amounts_are_ascii_and_full_match(amount: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        methods.ChargeRequest.model_validate(
            {"amount": amount, "currency": CURRENCY, "decimals": 6, "recipient": ADDRESS}
        )
    with pytest.raises(ValueError):  # noqa: PT011
        parse_units(amount, 6)


def test_hex_decoding_rejects_whitespace() -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        to_bytes("0xab cd")


async def test_hash_credential_with_unicode_digit_source_is_rejected() -> None:
    node = funded_node()
    server = make_server(node)
    handler = server.charge(amount="1", decimals=6)
    challenge = await challenge_of(handler)
    source = f"did:pkh:eip155:4{AR[2]}{AR[4]}{AR[3]}{AR[1]}:{payer().address}"
    response = await request(
        handler, credential(challenge, {"hash": "0x" + "ab" * 32, "type": "hash"}, source)
    )
    assert response.status == 402
    assert "Hash credential source is invalid." in (await problem(response))["detail"]


# -- 4. Malformed offers are not handleable -----------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        {
            "amount": "100",
            "currency": "0x" + "22" * 20,
            "recipient": "0x" + "11" * 20,
            "methodDetails": {"splits": ["bad"]},
        },
        {"amount": None, "currency": "0x" + "22" * 20, "recipient": "0x" + "11" * 20},
        {"amount": "x", "currency": "0x" + "22" * 20, "recipient": "0x" + "11" * 20},
        {"amount": "1", "currency": None, "recipient": "0x" + "11" * 20, "methodDetails": 5},
    ],
)
def test_can_handle_challenge_skips_malformed_offers(request_: dict[str, Any]) -> None:
    method = client_charge(expected_recipients=["0x" + "11" * 20])
    challenge = Challenge(
        id="c", realm="api.example.com", method="tempo", intent="charge", request=request_
    )
    assert method.can_handle_challenge is not None
    assert method.can_handle_challenge(challenge) is False
