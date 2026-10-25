"""Shared setup for Tempo charge server/client tests (fake node + Mpp wiring)."""

from __future__ import annotations

from typing import Any

import httpx
from _charge_node import (
    CURRENCY,
    REALM,
    SECRET_KEY,
    FakeTempoNode,
    payer,
    recipient,
    serve,
    sponsor,
)

from mpp import store as _store
from mpp.challenge import Challenge
from mpp.client import Mpp as ClientMppx
from mpp.server import Mpp, Request, Response
from mpp.tempo import client as tempo_client
from mpp.tempo.assets import PATH_USD_ADDRESS
from mpp.tempo.server._charge import charge

URL = "https://api.example.com/paid"


def funded_node(**kwargs: Any) -> FakeTempoNode:
    node = FakeTempoNode(**kwargs)
    node.fund(CURRENCY, payer().address, 100_000_000)
    node.fund(PATH_USD_ADDRESS, sponsor().address, 100_000_000)
    node.fund(PATH_USD_ADDRESS, recipient().address, 100_000_000)
    return node


def server_method(node: FakeTempoNode, **parameters: Any) -> Any:
    rpc = node.client()
    defaults: dict[str, Any] = {
        "account": recipient().address,
        "currency": CURRENCY,
        "testnet": True,
        "get_client": lambda _: rpc,
        "store": _store.memory(),
    }
    return charge(**{**defaults, **parameters})


def make_server(node: FakeTempoNode, **parameters: Any) -> Mpp:
    return Mpp(methods=[server_method(node, **parameters)], realm=REALM, secret_key=SECRET_KEY)


def make_client(node: FakeTempoNode, handler: Any, **parameters: Any) -> ClientMppx:
    rpc = node.client()
    return ClientMppx(
        methods=[
            tempo_client.charge(**{"account": payer(), "get_client": lambda _: rpc, **parameters})
        ],
        inner=serve(handler),
    )


def charge_client(node: FakeTempoNode, **parameters: Any) -> Any:
    rpc = node.client()
    return tempo_client.charge(**{"account": payer(), "get_client": lambda _: rpc, **parameters})


async def request(handler: Any, authorization: str | None = None) -> Response:
    """Calls a route handler; returns the challenge or the receipt-bearing response."""
    headers = {"Authorization": authorization} if authorization else {}
    result = await handler(Request(method="GET", url=URL, headers=headers))
    if result.status == 402:
        return result.challenge
    return result.with_receipt(Response.text("OK"))


async def challenge_of(handler: Any) -> Challenge:
    response = await request(handler)
    assert response.status == 402, response.status
    return Challenge.deserialize(response.headers["www-authenticate"])


async def problem(response: Response) -> dict[str, Any]:
    import json

    return json.loads(await response.read())


async def create_credential(client_method: Any, challenge: Challenge, context: Any = None) -> str:
    from mpp.method import CredentialParams

    parsed = client_method.context.model_validate(context) if context is not None else None
    return await client_method.create_credential(
        CredentialParams(challenge=challenge, context=parsed)
    )


def hosted_transport(node: FakeTempoNode) -> httpx.AsyncClient:
    """An HTTP client whose requests are answered by ``node`` (a hosted fee payer)."""
    return httpx.AsyncClient(transport=node.transport())
