"""x402 facilitator clients (``POST /verify`` and ``POST /settle`` with v2 envelopes)."""

import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import httpx
from pydantic import ValidationError

from mpp import _json
from mpp.x402._types import (
    Facilitator,
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)

__all__ = [
    "FacilitatorError",
    "HeadersInput",
    "HttpFacilitator",
    "http",
    "resolve",
    "settle",
    "verify",
]


type HeadersInput = (
    Mapping[str, str] | Callable[[], Mapping[str, str] | Awaitable[Mapping[str, str]]] | None
)
"""Extra facilitator request headers, or a sync or async callable returning them per request."""


class FacilitatorError(Exception):
    """A facilitator request failed or returned an unreadable response."""


class HttpFacilitator:
    """Facilitator client for an HTTP base URL.

    Error responses with a JSON body are read like successful ones (facilitators report
    ``isValid: false`` or ``success: false`` with an error status).

    Args:
        url: Facilitator base URL (a trailing slash is ignored).
        client: Optional ``httpx.AsyncClient`` used for the RPCs (a fresh client per call
            otherwise). Pass a plain client, not a payment-aware one.
        headers: Extra request headers, or a sync or async callable returning them for each
            request (for example a short-lived bearer token).

    Raises:
        FacilitatorError: From ``verify`` and ``settle`` when the request fails or the response
            is not JSON of the expected shape.
    """

    def __init__(
        self, url: str, *, client: httpx.AsyncClient | None = None, headers: HeadersInput = None
    ) -> None:
        self.url = url.removesuffix("/")
        self._client = client
        self._headers = headers

    async def verify(
        self, payment_payload: PaymentPayload, payment_requirements: PaymentRequirements, /
    ) -> VerifyResponse:
        data = await self._post("verify", payment_payload, payment_requirements)
        return _as(VerifyResponse, data)

    async def settle(
        self, payment_payload: PaymentPayload, payment_requirements: PaymentRequirements, /
    ) -> SettleResponse:
        data = await self._post("settle", payment_payload, payment_requirements)
        return _as(SettleResponse, data)

    async def _post(
        self,
        path: str,
        payment_payload: PaymentPayload,
        payment_requirements: PaymentRequirements,
    ) -> Any:
        body = _json.dumps(
            {
                "paymentPayload": payment_payload.to_dict(),
                "paymentRequirements": payment_requirements.to_dict(),
                "x402Version": 2,
            }
        )
        headers = {"Content-Type": "application/json", **(await self._resolve_headers())}
        url = f"{self.url}/{path}"
        try:
            if self._client is not None:
                response = await self._client.post(url, content=body, headers=headers)
            else:
                async with httpx.AsyncClient() as client:
                    response = await client.post(url, content=body, headers=headers)
        except httpx.HTTPError as error:
            raise FacilitatorError(f"facilitator /{path} request failed: {error}") from error
        try:
            return response.json()
        except ValueError as error:
            raise FacilitatorError(
                f"facilitator /{path} returned HTTP {response.status_code} without a JSON body"
            ) from error

    async def _resolve_headers(self) -> dict[str, str]:
        headers = self._headers
        if callable(headers):
            headers = headers()
            if inspect.isawaitable(headers):
                headers = await headers
        return dict(headers or {})


def http(
    url: str, *, client: httpx.AsyncClient | None = None, headers: HeadersInput = None
) -> HttpFacilitator:
    """Creates an x402 facilitator client from an HTTP base URL."""
    return HttpFacilitator(url, client=client, headers=headers)


def resolve(
    facilitator: str | Facilitator,
    error_message: str = "x402 exact requires `facilitator`.",
    *,
    client: httpx.AsyncClient | None = None,
) -> Facilitator:
    """Resolves a facilitator URL or client into a facilitator client."""
    if isinstance(facilitator, str):
        if not facilitator:
            raise ValueError(error_message)
        return http(facilitator, client=client)
    if facilitator is None:
        raise ValueError(error_message)
    return facilitator


async def verify(
    facilitator: Facilitator,
    payment_payload: PaymentPayload,
    payment_requirements: PaymentRequirements,
) -> VerifyResponse:
    """Calls ``facilitator.verify`` and validates the (model or dict) result.

    Raises:
        FacilitatorError: When the result is not a verify response.
    """
    return _as(VerifyResponse, await facilitator.verify(payment_payload, payment_requirements))


async def settle(
    facilitator: Facilitator,
    payment_payload: PaymentPayload,
    payment_requirements: PaymentRequirements,
) -> SettleResponse:
    """Calls ``facilitator.settle`` and validates the (model or dict) result.

    Raises:
        FacilitatorError: When the result is not a settle response.
    """
    return _as(SettleResponse, await facilitator.settle(payment_payload, payment_requirements))


def _as[M: VerifyResponse | SettleResponse](model: type[M], value: Any) -> M:
    if isinstance(value, model):
        return value
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise FacilitatorError(f"facilitator returned an unreadable {model.__name__}") from error
