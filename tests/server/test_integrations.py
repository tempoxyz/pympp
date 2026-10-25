"""Starlette / FastAPI integrations."""

from typing import Any

import httpx
import pytest

from mpp import Challenge, Receipt, payment_request
from mpp.server import Mpp, Response
from mpp.server._transport import HttpTransport

from ._fixtures import REALM, SECRET_KEY, credential_header, mock_server

OPTS = {"amount": "1", "currency": "0x1", "recipient": "0x2"}


def mppx(**hooks: Any) -> Mpp:
    return Mpp(methods=[mock_server(**hooks)], realm=REALM, secret_key=SECRET_KEY)


def client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.example.com"
    )


class TestStarlette:
    async def test_starlette_route(self) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        from mpp.server.starlette import paid

        handler = mppx().charge(**OPTS)

        @paid(handler)
        async def premium(request: Any) -> JSONResponse:
            return JSONResponse({"data": "paid", "item": request.path_params["item"]})

        app = Starlette(routes=[Route("/items/{item}", premium)])
        async with client(app) as c:
            first = await c.get("/items/1")
            assert first.status_code == 402
            challenge = Challenge.from_response(first)
            assert (
                payment_request.deserialize(challenge.opaque or "")["_mppx_scope"]
                == "GET /items/{item}"
            )
            # The route template (not the concrete path) is the scope: other items share it.
            paid_response = await c.get(
                "/items/2", headers={"Authorization": credential_header(challenge, {"token": "x"})}
            )
            assert paid_response.status_code == 200
            assert paid_response.json() == {"data": "paid", "item": "2"}
            assert paid_response.headers.get("payment-receipt")

    async def test_fastapi_route(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi import FastAPI

        from mpp.server.starlette import paid

        app = FastAPI()
        handler = mppx().charge(**OPTS)

        @app.get("/premium/{item}")
        @paid(handler)
        async def premium(item: int, q: str = "x") -> dict[str, Any]:
            return {"item": item, "q": q}

        async with client(app) as c:
            first = await c.get("/premium/7")
            assert first.status_code == 402
            challenge = Challenge.from_response(first)
            ok = await c.get(
                "/premium/7?q=y",
                headers={"Authorization": credential_header(challenge, {"token": "x"})},
            )
            assert ok.status_code == 200
            assert ok.json() == {"item": 7, "q": "y"}
            assert Receipt.from_headers(ok.headers).method == "mock"


class MeteredTransport(HttpTransport):
    """Minimal streaming-receipt transport: meters each yielded chunk (like Tempo session SSE)."""

    name = "metered"
    supports_streaming_receipts = True

    async def respond_receipt(self, **kwargs: Any) -> Response:  # type: ignore[override]
        response = kwargs["response"]
        if isinstance(response, Response):
            return super().respond_receipt(**kwargs)
        source = response() if callable(response) else response

        async def metered() -> Any:
            async for chunk in source:
                yield f"data: {chunk}\n\n".encode()
            yield b"event: payment-receipt\ndata: done\n\n"

        headers = {
            "Content-Type": "text/event-stream",
            "Payment-Receipt": kwargs["receipt"].serialize(),
        }
        return Response(200, headers, metered())


class TestStreamingReceipts:
    def mppx(self) -> Mpp:
        return Mpp(
            methods=[mock_server()],
            realm=REALM,
            secret_key=SECRET_KEY,
            transport=MeteredTransport(),
        )

    async def _paid(self, c: httpx.AsyncClient, path: str) -> httpx.Response:
        challenge = Challenge.from_response(await c.get(path))
        return await c.get(
            path, headers={"Authorization": credential_header(challenge, {"token": "x"})}
        )

    async def test_starlette_async_generator_endpoint(self) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.routing import Route

        from mpp.server.starlette import paid

        @paid(self.mppx().charge(**OPTS))
        async def stream(request: Any) -> Any:
            for token in ("hello", "world"):
                yield token

        async def factory_endpoint(request: Any) -> Any:
            async def generate() -> Any:
                yield "a"
                yield "b"

            return generate

        app = Starlette(
            routes=[
                Route("/stream", stream),
                Route("/factory", paid(self.mppx().charge(**OPTS))(factory_endpoint)),
            ]
        )
        async with client(app) as c:
            response = await self._paid(c, "/stream")
            assert response.status_code == 200
            assert response.headers["content-type"] == "text/event-stream"
            assert (
                response.text
                == "data: hello\n\ndata: world\n\nevent: payment-receipt\ndata: done\n\n"
            )
            assert response.headers.get("payment-receipt")
            factory = await self._paid(c, "/factory")
            assert factory.text.startswith("data: a\n\ndata: b\n\n")

    async def test_non_streaming_transport_streams_iterables(self) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.routing import Route

        from mpp.server.starlette import paid

        @paid(mppx().charge(**OPTS))
        async def stream(request: Any) -> Any:
            yield b"chunk-1 "
            yield b"chunk-2"

        async with client(Starlette(routes=[Route("/s", stream)])) as c:
            response = await self._paid(c, "/s")
            assert response.text == "chunk-1 chunk-2"
            assert Receipt.from_headers(response.headers).method == "mock"


class TestAuditRegressions:
    async def test_starlette_mount_prefix_is_part_of_route_scope(self) -> None:
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Mount, Route

        from mpp.server.starlette import paid

        handler = mppx().charge(**OPTS)

        @paid(handler)
        async def premium(request: Any) -> PlainTextResponse:
            return PlainTextResponse("ok")

        sub = [Route("/premium", premium)]
        app = Starlette(routes=[Mount("/a", routes=sub), Mount("/b", routes=sub)])
        async with client(app) as c:
            challenge = Challenge.from_response(await c.get("/a/premium"))
            assert (
                payment_request.deserialize(challenge.opaque or "")["_mppx_scope"]
                == "GET /a/premium"
            )
            header = {"Authorization": credential_header(challenge, {"token": "x"})}
            replay = await c.get("/b/premium", headers=header)
            assert replay.status_code == 402
            assert replay.json()["title"] == "Invalid Challenge"
            assert (await c.get("/a/premium", headers=header)).status_code == 200
