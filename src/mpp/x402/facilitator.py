"""x402 facilitator clients (mppx ``src/x402/server/Facilitator.ts``)."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol, TypeAlias, runtime_checkable

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

    async def _resolve_headers(self) -> dict[str, str]:
        headers = self._headers
        if callable(headers):
            headers = headers()
            if inspect.isawaitable(headers):
                headers = await headers
        return {"Content-Type": "application/json", **dict(headers or {})}

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
        """List the payment kinds the facilitator supports (``GET /supported``)."""
        try:
            headers = {**await self._resolve_headers(), **await self._auth_headers("supported")}
        except Exception as error:
            raise FacilitatorError(
                f"facilitator /supported auth headers failed: {error}"
            ) from error
        headers.pop("Content-Type", None)
        try:
            if self._client is not None:
                response = await self._client.get(
                    f"{self.url}/supported", headers=headers, timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(f"{self.url}/supported", headers=headers)
        except httpx.HTTPError as error:
            raise FacilitatorError(f"facilitator /supported request failed: {error}") from error
        if not response.is_success:
            raise FacilitatorError(f"facilitator /supported failed: {response.status_code}")
        try:
            return parse_supported_response(response.json())
        # RecursionError: JSON nested deeper than the decoder allows.
        except (ValueError, RecursionError) as error:
            raise FacilitatorError(f"facilitator /supported returned {error}") from error


async def pay_to(facilitator: str | Facilitator, *, network: str, scheme: str = "exact") -> str:
    """Read the ``payTo`` a facilitator publishes for a scheme and network in
    ``GET /supported`` (``kinds[].extra.payTo``), as an EIP-55 checksummed address.

    For facilitators that settle into an address of their own; call it once at
    startup and pass the result as the charge's ``recipient``.

    Raises:
        FacilitatorError: If the facilitator has no ``supported()``, or publishes
            no valid ``payTo`` for the x402 v2 kind of that scheme and network.
    """
    client = resolve_facilitator(facilitator)
    if not isinstance(client, SupportsSupported):
        raise FacilitatorError(
            "x402 facilitator does not implement supported(), so it cannot provide payTo"
        )
    try:
        response = parse_supported_response(await client.supported())
    except X402FormatError as error:
        raise FacilitatorError(f"facilitator /supported returned {error}") from error
    # Take the first matching kind that publishes a valid payTo, not just the first match.
    value = next(
        (
            pay_to
            for kind in response["kinds"]
            if kind.get("x402Version") == X402_VERSION
            and kind.get("scheme") == scheme
            and kind.get("network") == network
            for pay_to in [(kind.get("extra") or {}).get("payTo")]
            if isinstance(pay_to, str) and _ADDRESS_RE.fullmatch(pay_to)
        ),
        None,
    )
    if value is None:
        raise FacilitatorError(f"x402 facilitator publishes no payTo for {scheme} on {network}")
    from eth_utils.address import to_checksum_address

    return to_checksum_address(value)


def resolve_facilitator(facilitator: str | Facilitator) -> Facilitator:
    """Return a facilitator client for a base URL or an existing client."""
    if isinstance(facilitator, str):
        return HttpFacilitator(facilitator)
    if isinstance(facilitator, Facilitator):
        return facilitator
    raise TypeError("facilitator must be a URL or an object with verify() and settle()")
