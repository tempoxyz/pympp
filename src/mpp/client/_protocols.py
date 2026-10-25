"""Payment protocols carried over HTTP (MPP; x402 plugs in from ``mpp.x402``).

A protocol extracts its challenges from a response and attaches its credential to the retry
request. Protocols are composed by :func:`mpp.client.http_transport`.
"""

from collections.abc import AsyncIterator
from typing import Any, runtime_checkable
from typing import Protocol as _Protocol

import httpx

from mpp.challenge import Challenge
from mpp.constants import Header

PAYMENT_REQUIRED_STATUS = 402

MAX_INSPECTION_BYTES = 1024 * 1024
"""Bound on response bytes read while inspecting response bodies."""

_STALE_CREDENTIAL_HEADERS = (
    str(Header.AUTHORIZATION),
    "PAYMENT-REQUIRED",
    "PAYMENT-RESPONSE",
    "PAYMENT-SIGNATURE",
)


@runtime_checkable
class Protocol(_Protocol):
    """One payment protocol over the HTTP transport.

    Implementations must not consume the caller's response body; use :func:`peek_body` to
    inspect it (the stream is restored transparently).

    Attributes:
        name: Protocol name. Challenges whose ``protocol`` tag equals ``name`` are paid back
            through this protocol; untagged challenges go to the protocol named ``"mpp"``.
    """

    name: str

    async def get_challenges(
        self, response: httpx.Response, request: httpx.Request | None
    ) -> list[Challenge]:
        """Returns this protocol's challenges from ``response`` (``[]`` when not its concern)."""
        ...

    def set_credential(
        self, request: httpx.Request, credential: str, challenge: Challenge | None
    ) -> httpx.Request:
        """Returns a copy of ``request`` carrying ``credential``."""
        ...


def rebuild_request(
    request: httpx.Request,
    *,
    headers: httpx.Headers | None = None,
    content: bytes | None = None,
    url: httpx.URL | str | None = None,
    method: str | None = None,
) -> httpx.Request:
    """Copies a (buffered) request, optionally replacing headers, body, URL or method."""
    body = request.content if content is None else content
    new_headers = httpx.Headers(headers if headers is not None else request.headers)
    if content is not None:
        new_headers.pop("content-length", None)
        new_headers.pop("transfer-encoding", None)
    rebuilt = httpx.Request(
        method or request.method,
        url or request.url,
        headers=new_headers,
        content=body,
        extensions=request.extensions,
    )
    return rebuilt


def set_credential_header(request: httpx.Request, header: str, credential: str) -> httpx.Request:
    """Attaches ``credential`` under ``header``, clearing stale credential headers first.

    Ordinary application credentials in ``Authorization`` are preserved.
    """
    headers = httpx.Headers(request.headers)
    for stale in _STALE_CREDENTIAL_HEADERS:
        if stale == Header.AUTHORIZATION and not (headers.get(stale) or "").startswith("Payment "):
            continue
        headers.pop(stale, None)
    headers[header] = credential
    return rebuild_request(request, headers=headers)


class _ReplayStream(httpx.AsyncByteStream):
    def __init__(
        self, prefix: list[bytes], rest: AsyncIterator[bytes] | None, original: Any
    ) -> None:
        self._prefix = prefix
        self._rest = rest
        self._original = original

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._prefix:
            yield chunk
        if self._rest is not None:
            async for chunk in self._rest:
                yield chunk

    async def aclose(self) -> None:
        close = getattr(self._original, "aclose", None)
        if close is not None:
            await close()


async def peek_body(
    response: httpx.Response, *, until: Any = None, limit: int = MAX_INSPECTION_BYTES
) -> bytes | None:
    """Reads up to ``limit`` bytes of a streaming response without consuming it for the caller.

    ``until(buffer) -> bool`` stops early once enough has been read.
    Returns ``None`` when the limit is exceeded. The response stream is replaced with one that
    replays the bytes read so far followed by the remainder.
    """
    try:
        content = response.content
    except httpx.ResponseNotRead:
        pass
    else:
        return content if len(content) <= limit else None
    stream = response.stream
    iterator = stream.__aiter__()  # type: ignore[union-attr]
    chunks: list[bytes] = []
    received = 0
    exhausted = False
    exceeded = False
    try:
        while True:
            if until is not None and until(b"".join(chunks)):
                break
            try:
                chunk = await iterator.__anext__()
            except StopAsyncIteration:
                exhausted = True
                break
            chunks.append(chunk)
            received += len(chunk)
            if received > limit:
                exceeded = True
                break
    finally:
        response.stream = _ReplayStream(chunks, None if exhausted else iterator, stream)
    return None if exceeded else b"".join(chunks)


class MppProtocol:
    """MPP: native HTTP ``Payment`` authentication (402 + ``WWW-Authenticate``)."""

    name = "mpp"

    async def get_challenges(
        self, response: httpx.Response, request: httpx.Request | None
    ) -> list[Challenge]:
        if response.status_code != PAYMENT_REQUIRED_STATUS:
            return []
        header = response.headers.get(Header.WWW_AUTHENTICATE)
        if not header:
            return []
        return Challenge.deserialize_list(header)

    def set_credential(
        self, request: httpx.Request, credential: str, challenge: Challenge | None
    ) -> httpx.Request:
        header = challenge.credential_header if challenge is not None else Header.AUTHORIZATION
        return set_credential_header(request, header, credential)


def mpp() -> MppProtocol:
    """Creates the native ``Payment`` auth protocol."""
    return MppProtocol()
