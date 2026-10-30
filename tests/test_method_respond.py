"""The ServerMethod respond hook: management responses that replace the route's."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mpp import Challenge, Credential, Receipt
from mpp.server import (
    Mpp,
    PaymentVerified,
    RespondContext,
    Response,
    ValidateContext,
    Validation,
    VerifyContext,
    pay,
)
from mpp.server.asgi import PaymentMiddleware
from tests import challenge, http_request, server_method


async def _paid(_context: VerifyContext) -> Receipt:
    return Receipt.success("0xabc")


def _management(context: RespondContext) -> Response | None:
    """Like mppx session: a body-less POST is a management action, answered with 204."""
    assert context.input is not None
    if context.input.method == "POST" and not context.input.body:
        return Response(204)
    return None


def _server(**hooks: Any) -> Mpp:
    hooks.setdefault("verify", _paid)
    return Mpp(methods=server_method(**hooks), realm="example.com", secret_key="secret")


def _authorization(issued: Challenge) -> str:
    return Credential(challenge=issued.to_echo(), payload={}).to_authorization()


async def test_respond_receives_verify_context_input_and_receipt() -> None:
    seen: list[RespondContext] = []
    verified: list[VerifyContext] = []

    async def verify(context: VerifyContext) -> Receipt:
        verified.append(context)
        return Receipt.success("0xabc")

    async def respond(context: RespondContext) -> None:
        seen.append(context)

    handler = _server(verify=verify, respond=respond).charge(amount="1")
    request = http_request(method="POST", body=b"{}", headers={"X-Test": "1"})
    issued = challenge(await handler(request))
    paid = await handler(
        http_request(_authorization(issued), method="POST", body=b"{}", headers={"X-Test": "1"})
    )
    assert isinstance(paid, PaymentVerified)
    assert paid.response is None
    [context] = seen
    assert context.receipt is paid.receipt
    assert context.challenge.id == issued.id
    assert context.request["amount"] == "1"
    assert context.input is not None
    assert context.input.method == "POST"
    assert context.input.body == b"{}"
    assert context.input.headers["x-test"] == "1"
    assert verified[0].input is context.input


async def test_validate_context_carries_input() -> None:
    seen: list[ValidateContext] = []

    async def validate(context: ValidateContext) -> Validation:
        seen.append(context)
        return Validation(
            credential=context.credential,
            details={},
            intent=context.challenge.intent,
            request=context.request,
        )

    handler = _server(verify=None, validate=validate, broadcast=_paid).charge(amount="1")
    issued = challenge(await handler(http_request(method="PUT")))
    paid = await handler(http_request(_authorization(issued), method="PUT"))
    assert isinstance(paid, PaymentVerified)
    assert seen[0].operation == "broadcast"
    assert seen[0].input is not None and seen[0].input.method == "PUT"


async def test_management_response_replaces_route_response_with_receipt() -> None:
    order: list[str] = []

    def respond(context: RespondContext) -> Response:
        order.append("respond")
        return Response(204, {"Cache-Control": "public, max-age=5", "X-Managed": "1"})

    server = _server(respond=respond)
    server.on_payment_success(lambda _payload: order.append("success"))
    handler = server.charge(amount="1")
    issued = challenge(await handler(http_request(method="POST")))
    paid = await handler(http_request(_authorization(issued), method="POST"))
    assert isinstance(paid, PaymentVerified)
    assert order == ["respond", "success"]
    assert paid.response is not None
    assert paid.response.status == 204
    assert paid.response.headers["x-managed"] == "1"
    assert paid.response.headers["payment-receipt"] == paid.receipt.to_payment_receipt()
    assert paid.response.headers["cache-control"] == "private, max-age=5"
    # with_receipt ignores the route's response, or works without one, like mppx.
    assert paid.with_receipt(Response.json({"content": True})) is paid.response
    assert paid.with_receipt() is paid.response


async def test_respond_must_return_a_response() -> None:
    handler = _server(respond=lambda _context: {"status": 204}).charge(amount="1")
    issued = challenge(await handler(http_request()))
    with pytest.raises(TypeError, match="respond must return a Response"):
        await handler(http_request(_authorization(issued)))


def test_respond_must_be_callable() -> None:
    with pytest.raises(ValueError, match="respond must be callable"):
        server_method(verify=_paid, respond="nope")


async def test_validate_and_broadcast_credential_have_no_input() -> None:
    seen: list[VerifyContext] = []

    async def verify(context: VerifyContext) -> Receipt:
        seen.append(context)
        return Receipt.success("0xabc")

    server = _server(verify=verify)
    issued = challenge(await server.charge(amount="1")(http_request()))
    await server.broadcast_credential(Credential(challenge=issued.to_echo(), payload={}))
    assert seen[0].input is None


def _starlette(calls: list[str], handler: Any) -> TestClient:
    @pay(handler)
    async def endpoint(request: StarletteRequest, credential: Any, receipt: Any) -> Any:
        calls.append(request.method)
        return JSONResponse({"content": True})

    return TestClient(Starlette(routes=[Route("/paid", endpoint, methods=["GET", "POST"])]))


def _paid_request(client: TestClient, method: str) -> Any:
    unpaid = client.request(method, "/paid")
    assert unpaid.status_code == 402
    issued = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
    return client.request(method, "/paid", headers={"Authorization": _authorization(issued)})


def test_pay_returns_management_response_without_calling_endpoint() -> None:
    calls: list[str] = []
    with _starlette(calls, _server(respond=_management).charge(amount="1")) as client:
        managed = _paid_request(client, "POST")
        content = _paid_request(client, "GET")
    assert managed.status_code == 204
    assert managed.headers["Payment-Receipt"]
    assert managed.headers["Cache-Control"] == "private"
    assert content.status_code == 200
    assert content.json() == {"content": True}
    assert content.headers["Payment-Receipt"]
    assert calls == ["GET"]


def test_asgi_middleware_returns_management_response_without_running_app() -> None:
    calls: list[str] = []

    async def app(request: StarletteRequest) -> JSONResponse:
        calls.append(request.method)
        return JSONResponse({"content": True})

    inner = Starlette(routes=[Route("/paid", app, methods=["GET", "POST"])])
    handler = _server(respond=_management).charge(amount="1")
    with TestClient(PaymentMiddleware(inner, handler)) as client:
        managed = _paid_request(client, "POST")
        content = _paid_request(client, "GET")
    assert managed.status_code == 204
    assert managed.headers["Payment-Receipt"]
    assert content.status_code == 200
    assert content.headers["Payment-Receipt"]
    assert calls == ["GET"]
