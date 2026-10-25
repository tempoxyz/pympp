"""Framework-neutral HTTP request/response types used by the server engine."""

import json as _stdlib_json
from collections.abc import AsyncIterable, AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Self

import httpx

from mpp import _json

type HeadersInput = httpx.Headers | Mapping[str, str] | Sequence[tuple[str, str]] | None
type Body = bytes | AsyncIterable[bytes] | None


def make_headers(headers: HeadersInput = None) -> httpx.Headers:
    """Builds case-insensitive, multi-value headers (Latin-1 values, as on the wire)."""
    if isinstance(headers, httpx.Headers):
        items = headers.multi_items()
    elif isinstance(headers, Mapping):
        items = list(headers.items())
    else:
        items = list(headers or ())
    return httpx.Headers(items, encoding="latin-1")


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True, init=False)
class Request:
    """An incoming HTTP request as seen by the payment engine.

    Attributes:
        method: HTTP method (uppercase).
        url: Absolute request URL.
        headers: Case-insensitive request headers.
        body: Fully-read request body, or ``None`` when the request has no body.
        route_scope: Trusted adapter-derived route identity (e.g. ``"GET /premium"``) bound into
            challenges as reserved ``_mppx_scope`` metadata. Set by framework integrations;
            never derived from client input.
    """

    method: str
    url: str
    headers: httpx.Headers
    body: bytes | None
    route_scope: str | None

    def __init__(
        self,
        method: str,
        url: str,
        headers: HeadersInput = None,
        body: bytes | str | None = None,
        route_scope: str | None = None,
    ) -> None:
        object.__setattr__(self, "method", method.upper())
        object.__setattr__(self, "url", str(url))
        object.__setattr__(self, "headers", make_headers(headers))
        object.__setattr__(self, "body", body.encode() if isinstance(body, str) else body)
        object.__setattr__(self, "route_scope", route_scope)

    def copy(self, **changes: Any) -> Self:
        """Returns a copy with the given fields replaced."""
        return replace(self, **changes)

    def json(self) -> Any:
        """Parses the body as JSON."""
        return _stdlib_json.loads(self.body or b"")


@dataclass(frozen=True, slots=True, init=False)
class Response:
    """An outgoing HTTP response.

    ``body`` may be ``bytes`` or an async iterator of chunks (streaming / SSE).
    """

    status: int
    headers: httpx.Headers
    body: Body

    def __init__(
        self, status: int = 200, headers: HeadersInput = None, body: Body | str = None
    ) -> None:
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "headers", make_headers(headers))
        object.__setattr__(self, "body", body.encode() if isinstance(body, str) else body)

    @classmethod
    def json(cls, data: Any, *, status: int = 200, headers: HeadersInput = None) -> Self:
        """Creates a JSON response (``Content-Type: application/json``)."""
        result = make_headers(headers)
        if "content-type" not in result:
            result["Content-Type"] = "application/json"
        return cls(status=status, headers=result, body=_json.dumps(data).encode())

    @classmethod
    def text(cls, text: str, *, status: int = 200, headers: HeadersInput = None) -> Self:
        """Creates a ``text/plain`` response."""
        result = make_headers(headers)
        if "content-type" not in result:
            result["Content-Type"] = "text/plain;charset=UTF-8"
        return cls(status=status, headers=result, body=text.encode())

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_streaming(self) -> bool:
        return self.body is not None and not isinstance(self.body, bytes)

    async def read(self) -> bytes:
        """Returns the full body (consumes a streaming body)."""
        if self.body is None:
            return b""
        if isinstance(self.body, bytes):
            return self.body
        return b"".join([chunk async for chunk in self.body])

    async def text_body(self) -> str:
        """Returns the body decoded as UTF-8."""
        return (await self.read()).decode()

    def iter_body(self) -> AsyncIterator[bytes]:
        """Iterates the body as chunks."""

        async def iterate() -> AsyncIterator[bytes]:
            if self.body is None:
                return
            if isinstance(self.body, bytes):
                if self.body:
                    yield self.body
                return
            async for chunk in self.body:
                yield chunk

        return iterate()

    def copy(self, **changes: Any) -> Self:
        """Returns a copy with the given fields replaced."""
        return replace(self, **changes)
