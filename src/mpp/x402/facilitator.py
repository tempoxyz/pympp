"""x402 facilitator clients (mppx ``src/x402/server/Facilitator.ts``)."""

from __future__ import annotations

import inspect
import ipaddress
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import Any, Protocol, TypeAlias, runtime_checkable
from urllib.parse import urlsplit

import anyio
import httpx

from mpp.x402._types import (
    _ADDRESS_RE,
    X402_VERSION,
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    SupportedResponse,
    VerifyResponse,
    X402FormatError,
    parse_settle_response,
    parse_supported_response,
    parse_verify_response,
)

HeadersInput: TypeAlias = (
    Mapping[str, str] | Callable[[], Mapping[str, str] | Awaitable[Mapping[str, str]]] | None
)

PathHeaders: TypeAlias = Mapping[str, Mapping[str, str]]
"""Headers per facilitator endpoint, keyed by its path name (``verify``, ``settle``,
``supported``), the shape of x402's ``FacilitatorConfig.createAuthHeaders``."""

CreateAuthHeaders: TypeAlias = Callable[[], PathHeaders | Awaitable[PathHeaders]]

_ENDPOINTS = ("verify", "settle", "supported", "list")

_MAX_SUPPORTED_BYTES = 1024 * 1024
"""Largest decoded ``GET /supported`` body read; a list of kinds is a few KiB."""


class FacilitatorError(Exception):
    """A facilitator request failed or returned an unreadable response."""


@runtime_checkable
class Facilitator(Protocol):
    """An x402 facilitator that verifies and settles payments."""

    async def verify(
        self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> VerifyResponse: ...

    async def settle(
        self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> SettleResponse: ...


@runtime_checkable
class SupportsSupported(Protocol):
    """A facilitator that lists the payment kinds it supports (``GET /supported``).

    Optional for a :class:`Facilitator`, so existing custom clients keep working;
    it is needed only to read a ``payTo`` the facilitator publishes in
    ``kinds[].extra.payTo`` (:func:`mpp.methods.evm.server.facilitator_pay_to`).
    :class:`HttpFacilitator` implements it.
    """

    async def supported(self) -> SupportedResponse: ...


class HttpFacilitator:
    """Client for an x402 facilitator's HTTP API.

    Sends ``POST {url}/verify`` and ``POST {url}/settle`` with
    ``{"paymentPayload", "paymentRequirements", "x402Version": 2}``, and
    ``GET {url}/supported`` for :meth:`supported`.

    Example:
        facilitator = HttpFacilitator("https://x402.org/facilitator")

    Args:
        url: Facilitator base URL.
        headers: Extra request headers, or a sync or async callable returning
            them for each request (for example a short-lived bearer token).
        create_auth_headers: Sync or async callable returning headers per
            endpoint (``{"verify": {...}, "settle": {...}}``), called for each
            request, as x402's ``FacilitatorConfig.createAuthHeaders``. Use it
            when a token is bound to one endpoint, such as Coinbase's
            (:func:`mpp.x402.cdp.facilitator`).
        timeout: Request timeout in seconds.
        client: Optional ``httpx.AsyncClient`` to send requests with.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: HeadersInput = None,
        create_auth_headers: CreateAuthHeaders | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("facilitator url must be a non-empty string")
        self.url = url.rstrip("/")
        self._headers = headers
        if create_auth_headers is not None and not callable(create_auth_headers):
            raise ValueError("create_auth_headers must be callable")
        self._create_auth_headers = create_auth_headers
        self._timeout = timeout
        self._client = client

    async def _configured_headers(self) -> dict[str, str]:
        headers = self._headers
        if callable(headers):
            headers = headers()
            if inspect.isawaitable(headers):
                headers = await headers
        return dict(headers or {})

    async def _resolve_headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", **await self._configured_headers()}

    async def _auth_headers(self, endpoint: str) -> dict[str, str]:
        """The headers ``create_auth_headers`` returns for one endpoint, made per request
        because they may sign the request (Coinbase CDP's JWTs name method and path)."""
        if self._create_auth_headers is None:
            return {}
        result = self._create_auth_headers()
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, Mapping) or (
            result and not any(isinstance(result.get(name), Mapping) for name in _ENDPOINTS)
        ):
            raise ValueError(
                "create_auth_headers must return headers keyed by facilitator endpoint, "
                'e.g. {"verify": {"Authorization": "..."}, "settle": {...}}'
            )
        return dict(result.get(endpoint) or {})

    async def _post(
        self,
        path: str,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> Any:
        body = {
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
            "x402Version": X402_VERSION,
        }
        try:
            headers = {**await self._resolve_headers(), **await self._auth_headers(path.strip("/"))}
        except Exception as error:
            raise FacilitatorError(f"facilitator {path} auth headers failed: {error}") from error
        try:
            if self._client is not None:
                response = await self._client.post(
                    f"{self.url}{path}", json=body, headers=headers, timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.post(f"{self.url}{path}", json=body, headers=headers)
        except httpx.HTTPError as error:
            raise FacilitatorError(f"facilitator {path} request failed: {error}") from error
        try:
            return response.json()
        except ValueError as error:
            raise FacilitatorError(
                f"facilitator {path} returned HTTP {response.status_code} without a JSON body"
            ) from error

    async def verify(
        self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> VerifyResponse:
        """Ask the facilitator whether a payment is valid, without settling it."""
        data = await self._post("/verify", payment_payload, payment_requirements)
        try:
            return parse_verify_response(data)
        except X402FormatError as error:
            raise FacilitatorError(f"facilitator /verify returned {error}") from error

    async def settle(
        self,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> SettleResponse:
        """Ask the facilitator to settle a payment on-chain."""
        data = await self._post("/settle", payment_payload, payment_requirements)
        try:
            return parse_settle_response(data)
        except X402FormatError as error:
            raise FacilitatorError(f"facilitator /settle returned {error}") from error

    async def supported(self) -> SupportedResponse:
        """List the payment kinds the facilitator supports (``GET /supported``).

        The whole request, body included, must finish within ``timeout`` seconds,
        and the body may hold at most 1 MiB, sent uncompressed. Redirects are never followed. When
        this client opens its own connection to an ``http://`` URL, it ignores
        proxy environment variables, so loopback discovery stays on the machine;
        an injected ``client`` keeps its own proxy settings.
        """
        try:
            # A GET has no body, so only a Content-Type the caller configured is sent.
            # identity: the size cap counts the bytes on the wire, so refuse compression
            # rather than let a small gzip body inflate past it.
            headers = _merge_headers(
                await self._configured_headers(),
                await self._auth_headers("supported"),
                {"Accept-Encoding": "identity"},
            )
        except Exception as error:
            raise FacilitatorError(
                f"facilitator /supported auth headers failed: {error}"
            ) from error
        try:
            # httpx's timeout bounds each phase, so a body trickled a byte at a time
            # would never time out without one deadline for the whole exchange.
            # anyio, not asyncio.wait_for, so discovery also runs under trio.
            with anyio.fail_after(self._timeout):
                status, body = await self._get_supported(headers)
        except TimeoutError:
            raise FacilitatorError(
                f"facilitator /supported did not answer within {self._timeout} seconds"
            ) from None
        except httpx.HTTPError as error:
            # httpx's message can quote a header value it refused, such as a token.
            raise FacilitatorError(
                f"facilitator /supported request failed: {type(error).__name__}"
            ) from None
        if not 200 <= status < 300:
            raise FacilitatorError(f"facilitator /supported failed: {status}")
        try:
            return parse_supported_response(json.loads(body))
        # RecursionError: JSON nested deeper than the decoder allows.
        except (ValueError, RecursionError) as error:
            raise FacilitatorError(f"facilitator /supported returned {error}") from error

    async def _get_supported(self, headers: Mapping[str, str]) -> tuple[int, bytes]:
        url = f"{self.url}/supported"
        if self._client is not None:
            return await _read_capped(self._client, url, headers, self._timeout)
        # Cleartext is allowed only to a loopback host: don't let a proxy from the
        # environment carry it off the machine.
        trust_env = urlsplit(self.url).scheme == "https"
        async with httpx.AsyncClient(timeout=self._timeout, trust_env=trust_env) as client:
            return await _read_capped(client, url, headers, self._timeout)


def _merge_headers(*sources: Mapping[str, str]) -> dict[str, str]:
    """Merge header mappings; a later field replaces an earlier one of any case."""
    merged: dict[str, str] = {}
    for source in sources:
        for name, value in source.items():
            for existing in [key for key in merged if key.lower() == name.lower()]:
                del merged[existing]
            merged[name] = value
    return merged


async def _read_capped(
    client: httpx.AsyncClient, url: str, headers: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    """GET a URL without following redirects, reading at most ``_MAX_SUPPORTED_BYTES``."""
    # pay_to checks only the configured URL; a redirect could move discovery to cleartext.
    async with client.stream(
        "GET", url, headers=headers, timeout=timeout, follow_redirects=False
    ) as response:
        if not response.is_success:
            return response.status_code, b""
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding not in ("", "identity"):
            raise FacilitatorError("facilitator /supported returned a compressed body")
        body = bytearray()
        async for chunk in _wire_chunks(response):
            body += chunk
            if len(body) > _MAX_SUPPORTED_BYTES:
                raise FacilitatorError(
                    f"facilitator /supported returned more than {_MAX_SUPPORTED_BYTES} bytes"
                )
        return response.status_code, bytes(body)


async def _wire_chunks(response: httpx.Response) -> AsyncIterator[bytes]:
    """Yield a response's body as sent, without decoding any Content-Encoding."""
    if response.is_stream_consumed:
        # A transport that answers with an in-memory body (httpx.MockTransport) read it already.
        yield response.content
        return
    async for chunk in response.aiter_raw():
        yield chunk


async def pay_to(facilitator: str | Facilitator, *, network: str, scheme: str = "exact") -> str:
    """Read the ``payTo`` a facilitator publishes for a scheme and network in
    ``GET /supported`` (``kinds[].extra.payTo``), as an EIP-55 checksummed address.

    For facilitators that settle into an address of their own; call it once at
    startup and pass the result as the charge's ``recipient``.

    Raises:
        FacilitatorError: If the facilitator has no ``supported()``, or publishes
            no valid ``payTo`` for the x402 v2 kind of that scheme and network,
            or is an HTTP facilitator whose URL is not ``https://`` (loopback hosts
            excepted).
        ImportError: If the ``evm`` extra is not installed.
    """
    # Fail before the network request, naming the extra, rather than after discovery.
    try:
        from eth_utils.address import to_checksum_address
    except ImportError as error:
        raise ImportError('x402 pay_to needs the "evm" extra: pip install "pympp[evm]"') from error
    client = resolve_facilitator(facilitator)
    if isinstance(client, HttpFacilitator) and not _is_secure_url(client.url):
        # The answer becomes the payment recipient, so it must not be rewritable in transit.
        raise FacilitatorError("x402 pay_to needs an https:// facilitator URL (or a loopback host)")
    if not isinstance(client, SupportsSupported):
        raise FacilitatorError(
            "x402 facilitator does not implement supported(), so it cannot provide payTo"
        )
    try:
        # The protocol declares it async, but accept a custom client's plain method too.
        result: Any = client.supported()
        if inspect.isawaitable(result):
            result = await result
        response = parse_supported_response(result)
    except X402FormatError as error:
        raise FacilitatorError(f"facilitator /supported returned {error}") from error
    # Every matching kind that publishes a usable payTo counts; the zero address can't be paid.
    published = {
        pay_to.lower()
        for kind in response["kinds"]
        if kind.get("x402Version") == X402_VERSION
        and kind.get("scheme") == scheme
        and kind.get("network") == network
        for pay_to in [(kind.get("extra") or {}).get("payTo")]
        if isinstance(pay_to, str) and _ADDRESS_RE.fullmatch(pay_to) and int(pay_to, 16) != 0
    }
    if not published:
        raise FacilitatorError(f"x402 facilitator publishes no payTo for {scheme} on {network}")
    if len(published) > 1:
        # Don't let array order pick the recipient.
        raise FacilitatorError(
            f"x402 facilitator publishes {len(published)} different payTo addresses "
            f"for {scheme} on {network}"
        )
    return to_checksum_address(published.pop())


def _is_secure_url(url: str) -> bool:
    """Whether a URL is ``https`` to a host, or ``http`` to a loopback host."""
    parsed = urlsplit(url)
    # A hostless URL (``https:``, ``https:/path``) names no host for TLS to verify, and an
    # injected client resolves it against its own, possibly cleartext, base URL.
    if not parsed.hostname:
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    if parsed.hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def resolve_facilitator(facilitator: str | Facilitator) -> Facilitator:
    """Return a facilitator client for a base URL or an existing client."""
    if isinstance(facilitator, str):
        return HttpFacilitator(facilitator)
    if isinstance(facilitator, Facilitator):
        return facilitator
    raise TypeError("facilitator must be a URL or an object with verify() and settle()")
