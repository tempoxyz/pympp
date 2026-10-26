"""ASGI middleware that gates every HTTP request of an app behind a route handler.

Works with any ASGI framework (Starlette, FastAPI, Litestar, Quart, Django ASGI)::

    from mpp.server import Mpp
    from mpp.server.asgi import PaymentMiddleware

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))
    app = PaymentMiddleware(app, mpp.charge(amount="0.01"))
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, TypeAlias

from mpp.server.compose import ComposedHandler
from mpp.server.http import PaymentRequired, Request, Response, make_headers

Scope: TypeAlias = MutableMapping[str, Any]
Message: TypeAlias = MutableMapping[str, Any]
Receive: TypeAlias = Callable[[], Awaitable[Message]]
Send: TypeAlias = Callable[[Message], Awaitable[None]]
ASGIApp: TypeAlias = Callable[[Scope, Receive, Send], Awaitable[None]]

DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024


class _BodyTooLarge(Exception):
    pass


def _decode(headers: Any) -> list[tuple[str, str]]:
    return [(name.decode("latin-1"), value.decode("latin-1")) for name, value in headers or ()]


def _url(scope: Scope, headers: list[tuple[str, str]]) -> str:
    scheme = scope.get("scheme", "http")
    host = next((value for name, value in headers if name.lower() == "host"), None)
    if host is None:
        server = scope.get("server")
        if server:
            name, port = server
            host = (
                name if port in (None, {"http": 80, "https": 443}.get(scheme)) else f"{name}:{port}"
            )
        else:
            host = "localhost"
    # raw_path keeps percent-encoding, so distinct paths keep distinct scopes.
    raw_path = scope.get("raw_path")
    if raw_path:
        path = raw_path.decode("latin-1").split("?", 1)[0]
    else:
        path = scope.get("root_path", "") + scope.get("path", "/")
    query = scope.get("query_string", b"").decode("latin-1")
    return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")


async def _read_body(receive: Receive, max_body_size: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > max_body_size:
            raise _BodyTooLarge
        chunks.append(chunk)
        more_body = message.get("more_body", False)
    return b"".join(chunks)


async def _send_response(send: Send, response: Response) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": response.status,
            "headers": [
                (name.encode("latin-1"), value.encode("latin-1"))
                for name, value in response.headers.multi_items()
            ],
        }
    )
    await send({"type": "http.response.body", "body": response.body or b""})


class PaymentMiddleware:
    """Require payment for every HTTP request of an ASGI app.

    Without a valid credential the app does not run and the client gets the handler's
    ``402`` challenge. Otherwise the app runs and its response carries ``Payment-Receipt``
    (and ``Cache-Control: private``); its body streams through unbuffered. Lifespan and
    WebSocket traffic pass through.

    Args:
        app: The ASGI app to protect.
        handler: A configured route handler, such as ``mpp.charge(amount="0.01")``.
        route: Route template bound into issued challenges, such as ``"/items/{id}"``.
        max_body_size: Largest request body read for an offer that binds it; larger
            bodies get ``413``.
    """

    def __init__(
        self,
        app: ASGIApp,
        handler: ComposedHandler,
        *,
        route: str | None = None,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> None:
        self.app = app
        self.handler = handler
        self.route = route
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = _decode(scope.get("headers"))
        body: bytes | None = None
        downstream = receive
        # Read the body only for an offer whose ``body`` option reads the request.
        if self.handler.needs_request_body:
            try:
                body = await _read_body(receive, self.max_body_size)
            except _BodyTooLarge:
                await _send_response(
                    send, Response(413, {"Content-Type": "text/plain"}, "Payload Too Large")
                )
                return
            replayed = False

            async def replay() -> Message:
                nonlocal replayed
                if replayed:
                    return await receive()
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            downstream = replay
        request = Request(
            scope.get("method", "GET"),
            _url(scope, headers),
            headers=headers,
            body=body or None,
            route=self.route,
        )
        result = await self.handler(request)
        if isinstance(result, PaymentRequired):
            await _send_response(send, result.challenge)
            return

        async def send_with_receipt(message: Message) -> None:
            if message["type"] == "http.response.start":
                response = result.with_receipt(
                    Response(message["status"], make_headers(_decode(message.get("headers"))))
                )
                message = {
                    **message,
                    "headers": [
                        (name.encode("latin-1"), value.encode("latin-1"))
                        for name, value in response.headers.multi_items()
                    ],
                }
            await send(message)

        await self.app(scope, downstream, send_with_receipt)


__all__ = ["DEFAULT_MAX_BODY_SIZE", "PaymentMiddleware"]
