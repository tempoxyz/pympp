"""Spent Tempo payments get a final 403, not a payable challenge."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import PaymentTransport
from mpp.methods.tempo import CHAIN_ID, ChargeIntent
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC
from mpp.server import pay
from mpp.store import MemoryStore
from tests import MockRequest, challenge_from_402

pytest.importorskip("starlette")
from starlette.responses import Response  # noqa: E402

REALM = "api.example.com"
SECRET = "test-secret"
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
PAYER = "0x1234567890123456789012345678901234567890"
TX_HASH = "0x" + "ab" * 32
REQUEST = {"amount": "1000", "currency": CURRENCY, "recipient": RECIPIENT}


class Route:
    """A paid route backed by a real ChargeIntent and a mocked Tempo RPC.

    ``receipt_case`` shapes the receipt: ``ok`` pays this challenge, ``memo``
    binds the transfer to another challenge, ``amount`` underpays, and
    ``reverted`` fails on chain.
    """

    def __init__(self, receipt_case: str) -> None:
        self.receipt_case = receipt_case
        self.challenge_id = ""
        self.lookups = 0
        self.hold_lookup: int | None = None
        self.lookup_held = asyncio.Event()
        self.release_lookup = asyncio.Event()
        self.store = MemoryStore()
        self.intent = ChargeIntent(
            rpc_url="https://rpc.test",
            store=self.store,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(self._rpc)),
        )

        @pay(intent=self.intent, request=REQUEST, realm=REALM, secret_key=SECRET)
        async def handler(request: Any, credential: Credential, receipt: Any) -> dict:
            return {"reference": receipt.reference}

        self.handler = handler

    async def credential(self) -> Credential:
        challenge = challenge_from_402(await self.handler(MockRequest()))
        self.challenge_id = challenge.id
        return Credential(challenge=challenge.to_echo(), payload={"type": "hash", "hash": TX_HASH})

    async def _rpc(self, request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content)["method"]
        if method == "eth_chainId":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(CHAIN_ID)})
        self.lookups += 1
        if self.lookups == self.hold_lookup:
            self.lookup_held.set()
            await self.release_lookup.wait()
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": self._receipt()})

    def _receipt(self) -> dict:
        bound_to = "another-challenge" if self.receipt_case == "memo" else self.challenge_id
        amount = 999 if self.receipt_case == "amount" else 1000
        return {
            "status": "0x0" if self.receipt_case == "reverted" else "0x1",
            "transactionHash": TX_HASH,
            "logs": [
                {
                    "address": CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + PAYER[2:].lower().zfill(64),
                        "0x" + RECIPIENT[2:].lower().zfill(64),
                        encode_attribution(challenge_id=bound_to, server_id=REALM),
                    ],
                    "data": "0x" + hex(amount)[2:].zfill(64),
                }
            ],
        }


def _response_parts(result: Any) -> tuple[int, Any, dict]:
    if isinstance(result, Response):
        return result.status_code, result.headers, json.loads(bytes(result.body))
    return result["status"], result["headers"], json.loads(result["body"])


async def _once(route: Route, authorization: str) -> Any:
    return await route.handler(MockRequest(authorization=authorization))


async def _replayed(route: Route, authorization: str) -> Any:
    assert await _once(route, authorization) == {"reference": TX_HASH}
    return await _once(route, authorization)


async def _in_flight(route: Route, authorization: str) -> Any:
    # Hold the first request in its settlement lookup, after validation has run
    # and the transaction hash is claimed.
    route.hold_lookup = 2
    first = asyncio.create_task(_once(route, authorization))
    await route.lookup_held.wait()
    duplicate = await _once(route, authorization)
    route.release_lookup.set()
    assert await first == {"reference": TX_HASH}
    return duplicate


Scenario = Callable[[Route, str], Awaitable[Any]]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("receipt_case", "scenario", "status", "challenged"),
    [
        ("ok", _replayed, 403, False),
        ("ok", _in_flight, 403, False),
        ("memo", _once, 403, False),
        ("amount", _once, 402, True),
        ("reverted", _once, 402, True),
    ],
    ids=["replay", "in-flight", "memo", "amount", "reverted"],
)
async def test_hash_credential_failure_response(
    receipt_case: str, scenario: Scenario, status: int, challenged: bool
) -> None:
    route = Route(receipt_case)
    credential = await route.credential()

    result = await scenario(route, credential.to_authorization())

    actual, headers, body = _response_parts(result)
    assert actual == status
    assert body["status"] == status
    assert body["type"] == "https://paymentauth.org/problems/verification-failed"
    assert headers["Cache-Control"] == "no-store"
    assert ("WWW-Authenticate" in headers) is challenged


class HashMethod:
    """Client method that answers every challenge with the same pushed transaction."""

    name = "tempo"
    intents = {"charge": True}

    def __init__(self, route: Route) -> None:
        self.route = route
        self.challenges: list[Challenge] = []

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.challenges.append(challenge)
        self.route.challenge_id = challenge.id
        return Credential(challenge=challenge.to_echo(), payload={"type": "hash", "hash": TX_HASH})


class RouteTransport(httpx.AsyncBaseTransport):
    def __init__(self, route: Route) -> None:
        self.route = route

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        result = await self.route.handler(
            MockRequest(authorization=request.headers.get("authorization"))
        )
        if isinstance(result, Response):
            return httpx.Response(
                result.status_code, headers=result.headers.raw, content=bytes(result.body)
            )
        return httpx.Response(200, json=result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("receipt_case", "consumed", "status", "payments"),
    [
        ("ok", True, 403, 1),
        ("memo", False, 403, 1),
        ("amount", False, 402, 3),
    ],
    ids=["replay", "memo", "amount"],
)
async def test_client_does_not_pay_again_for_spent_payment(
    receipt_case: str, consumed: bool, status: int, payments: int
) -> None:
    route = Route(receipt_case)
    if consumed:
        await route.store.put(route.intent._hash_store_key(TX_HASH), TX_HASH)
    method = HashMethod(route)
    transport = PaymentTransport(methods=[method], inner=RouteTransport(route))

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://api.example.com/paid")

    assert response.status_code == status
    assert len(method.challenges) == payments
