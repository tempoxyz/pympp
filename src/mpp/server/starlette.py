"""Starlette / FastAPI integration (requires ``starlette``: ``pip install pympp[asgi]``).

Decorate an endpoint with :func:`paid`::

    from mpp.server.starlette import paid

    @app.get("/premium")              # FastAPI (any signature) or a Starlette route
    @paid(mppx.charge(amount="0.01"))
    async def premium(request: Request):
        return {"data": "paid content"}

Without a credential the route answers with the 402 challenge; otherwise the endpoint runs and
its response carries ``Payment-Receipt``. Challenges are bound to ``"METHOD /route/path"``
unless the handler configures ``scope``.
"""

from mpp._extras import require

require("asgi", "starlette")

import functools
import inspect
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

from mpp.method import resolve
from mpp.server import _binding
from mpp.server._http import Request, Response, make_headers

if TYPE_CHECKING:
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import Response as StarletteResponse

type PaymentHandler = Callable[[Request], Awaitable[Any]]

_REQUEST_PARAMETER = "mpp_request"
_RESPONSE_PARAMETER = "mpp_response"


async def to_request(request: "StarletteRequest", *, route_scope: str | None = None) -> Request:
    """Converts a Starlette request (reads its body) into a :class:`Request`."""
    body = await request.body()
    headers = make_headers(
        [
            (key.decode("latin-1"), value.decode("latin-1"))
            for key, value in request.scope.get("headers", [])
        ]
    )
    has_body = (
        bool(body)
        or headers.get("content-length") not in (None, "0")
        or "transfer-encoding" in headers
    )
    return Request(
        request.method,
        str(request.url),
        headers=headers,
        body=body if has_body else None,
        route_scope=route_scope,
    )


def to_starlette(response: Response) -> "StarletteResponse":
    """Converts a :class:`Response` into a Starlette response (streaming bodies stream)."""
    from starlette.responses import Response as StarletteResponse
    from starlette.responses import StreamingResponse

    raw_headers = [
        (k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers.multi_items()
    ]
    if response.body is None or isinstance(response.body, bytes):
        result = StarletteResponse(content=response.body or b"", status_code=response.status)
    else:
        result = StreamingResponse(response.body, status_code=response.status)
    result.raw_headers = raw_headers
    return result


def from_starlette(response: "StarletteResponse") -> Response:
    """Converts a Starlette response into a :class:`Response` (streaming bodies stay lazy)."""
    headers = make_headers(
        [(k.decode("latin-1"), v.decode("latin-1")) for k, v in response.raw_headers]
    )
    iterator = getattr(response, "body_iterator", None)
    if iterator is not None:

        async def body() -> AsyncIterator[bytes]:
            async for chunk in iterator:
                yield chunk if isinstance(chunk, bytes) else str(chunk).encode()

        return Response(status=response.status_code, headers=headers, body=body())
    return Response(status=response.status_code, headers=headers, body=bytes(response.body))


def _route_path(request: "StarletteRequest") -> str:
    """The matched route template including mount prefixes (mppx express ``baseUrl + path``)."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if not isinstance(path, str):
        return request.url.path
    return f"{request.scope.get('root_path', '')}{path}"


def paid[F: Callable[..., Any]](handler: PaymentHandler) -> Callable[[F], F]:
    """Requires payment before a Starlette/FastAPI endpoint runs.

    The endpoint may return a Starlette ``Response`` (the receipt is attached to it), an async
    iterable / async generator (factory) — streamed, and metered when the transport supports
    streaming receipts — or, under FastAPI, any value FastAPI serializes
    (the receipt headers are set on FastAPI's response).
    A ``Request`` parameter is injected when the endpoint does not declare one.
    """

    def decorate(fn: F) -> F:
        from starlette.requests import Request as StarletteRequest
        from starlette.responses import Response as StarletteResponse

        signature = inspect.signature(fn)
        request_name = next(
            (
                name
                for name, p in signature.parameters.items()
                if p.annotation is StarletteRequest or _is_fastapi_request(p.annotation)
            ),
            None,
        )
        positional_request = (
            request_name is None
            and len(signature.parameters) == 1
            and next(iter(signature.parameters.values())).annotation
            in (inspect.Parameter.empty, Any)
        )
        if positional_request:
            request_name = next(iter(signature.parameters))

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if request_name is not None:
                starlette_request = kwargs.get(request_name) or (args[0] if args else None)
            else:
                starlette_request = kwargs.pop(_REQUEST_PARAMETER)
            fastapi_response = kwargs.pop(_RESPONSE_PARAMETER, None)
            assert isinstance(starlette_request, StarletteRequest)
            request = await to_request(starlette_request)
            if not _has_configured_scope(handler):
                request = request.copy(
                    route_scope=f"{request.method} {_route_path(starlette_request)}"
                )
            result = await handler(request)
            if result.status == 402:
                return to_starlette(result.challenge)
            if result.has_management_response:
                return to_starlette(await resolve(result.with_receipt()))
            output = fn(*args, **kwargs)
            if inspect.isawaitable(output):
                output = await output
            if isinstance(output, StarletteResponse):
                return to_starlette(await resolve(result.with_receipt(from_starlette(output))))
            if result.supports_streaming_receipts and _is_stream(output):
                # Metered transports consume async iterables or
                # generator factories and return the streaming response (mppx withReceipt).
                return to_starlette(await resolve(result.with_receipt(output)))
            if _is_stream(output):
                streamed = Response(200, {"Content-Type": "text/event-stream"}, _iterate(output))
                return to_starlette(await resolve(result.with_receipt(streamed)))
            receipt_response: Response = await resolve(result.with_receipt(Response(204)))
            if not receipt_response.ok:
                return to_starlette(receipt_response)
            if fastapi_response is not None:
                for key, value in receipt_response.headers.multi_items():
                    fastapi_response.headers[key] = value
            return output

        parameters = list(signature.parameters.values())
        if request_name is None:
            parameters.append(
                inspect.Parameter(
                    _REQUEST_PARAMETER, inspect.Parameter.KEYWORD_ONLY, annotation=StarletteRequest
                )
            )
        parameters.append(
            inspect.Parameter(
                _RESPONSE_PARAMETER, inspect.Parameter.KEYWORD_ONLY, annotation=StarletteResponse
            )
        )
        wrapper.__signature__ = signature.replace(parameters=_sort_parameters(parameters))  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorate


def _is_stream(value: Any) -> bool:
    return callable(value) or isinstance(value, AsyncIterable)


async def _iterate(value: Any) -> AsyncIterator[bytes]:
    source = cast(AsyncIterable[Any], value() if callable(value) else value)
    async for chunk in source:
        yield chunk if isinstance(chunk, bytes) else str(chunk).encode()


def _is_fastapi_request(annotation: Any) -> bool:
    try:
        from starlette.requests import HTTPConnection
    except ImportError:  # pragma: no cover
        return False
    return inspect.isclass(annotation) and issubclass(annotation, HTTPConnection)


def _sort_parameters(parameters: list[inspect.Parameter]) -> list[inspect.Parameter]:
    order = [
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.VAR_POSITIONAL,
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.VAR_KEYWORD,
    ]
    return sorted(parameters, key=lambda p: order.index(p.kind))


__all__ = ["from_starlette", "paid", "to_request", "to_starlette"]


def _has_configured_scope(handler: Any) -> bool:
    """Whether a handler binds its own route scope (``scope=`` / ``meta["_mppx_scope"]``)."""
    offers = getattr(handler, "offers", ())
    return any(_binding.read_scope(offer.meta) is not None for offer in offers)
