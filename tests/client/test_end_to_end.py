"""Client ↔ server round trips through ASGI (HTTP Payment auth)."""

from typing import Any

import httpx
from pydantic import BaseModel

from mpp import (
    ClientMethod,
    Credential,
    CredentialParams,
    Method,
    Receipt,
    ServerMethod,
    VerificationFailedError,
    VerifyContext,
    expires,
)
from mpp.client import Mpp as Client
from mpp.server import Mpp as Server
from mpp.server.starlette import paid

SECRET = "test-secret-key-test-secret-key-32"


class ChargeRequest(BaseModel):
    amount: str
    currency: str


class TokenPayload(BaseModel):
    token: str


charge = Method(
    name="demo", intent="charge", request_model=ChargeRequest, payload_model=TokenPayload
)


async def create(params: CredentialParams[Any]) -> str:
    return Credential(challenge=params.challenge, payload={"token": "secret"}).serialize()


def server_method(seen: list[str]) -> ServerMethod:
    async def verify(ctx: VerifyContext[Any]) -> Receipt:
        if ctx.credential.payload.token != "secret":
            raise VerificationFailedError(reason="bad token")
        seen.append(ctx.credential.challenge.id)
        return Receipt(method="demo", reference=f"ref-{len(seen)}", timestamp=expires.seconds(0))

    return ServerMethod(method=charge, verify=verify)


def paid_app(handler: Any) -> Any:
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    @paid(handler)
    async def premium(request: Any) -> PlainTextResponse:
        return PlainTextResponse("paid content")

    return Starlette(routes=[Route("/premium", premium)])


async def test_http_round_trip() -> None:
    seen: list[str] = []
    server = Server(methods=[server_method(seen)], realm="api.example.com", secret_key=SECRET)
    app = paid_app(server.charge(amount="100", currency="usd"))
    client = Client(
        methods=[ClientMethod(method=charge, create_credential=create)],
        inner=httpx.ASGITransport(app=app),
    )
    events: list[str] = []
    client.on("*", lambda env: events.append(env.name))
    response = await client.fetch("https://api.example.com/premium")
    assert response.status_code == 200
    assert response.text == "paid content"
    receipt = Receipt.from_headers(response.headers)
    assert receipt.reference == "ref-1"
    assert len(seen) == 1
    assert events == ["challenge.received", "credential.created", "payment.response"]
    await client.aclose()


async def test_http_round_trip_with_requires_auth() -> None:
    seen: list[str] = []
    server = Server(
        methods=[server_method(seen)],
        realm="api.example.com",
        secret_key=SECRET,
        requires_auth=True,
    )
    app = paid_app(server.charge(amount="100", currency="usd"))
    sent: list[httpx.Request] = []

    class Spy(httpx.AsyncBaseTransport):
        inner = httpx.ASGITransport(app=app)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return await self.inner.handle_async_request(request)

    client = Client(methods=[ClientMethod(method=charge, create_credential=create)], inner=Spy())
    response = await client.fetch(
        "https://api.example.com/premium", headers={"Authorization": "Bearer app"}
    )
    assert response.status_code == 200
    assert sent[1].headers["Authorization"] == "Bearer app"
    assert sent[1].headers["Payment-Authorization"].startswith("Payment ")
