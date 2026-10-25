"""Stripe API access: the duck-typed client protocol and a built-in httpx implementation.

mppx accepts any object shaped like the Stripe Node SDK. The Python equivalent is the
:class:`StripeClient` protocol below; :class:`StripeHttpClient` implements it directly against
``api.stripe.com`` with the same endpoints, form parameters and headers mppx sends. Wrap any
other Stripe SDK in a small adapter implementing the protocol to reuse its retries/telemetry.
"""

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx

from mpp.stripe._internal.constants import STRIPE_API_URL

type HttpMethod = Literal["GET", "POST"]


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentIntent:
    """The subset of a Stripe PaymentIntent mpp relies on.

    Attributes:
        id: PaymentIntent id (``pi_...``).
        status: PaymentIntent status (e.g. ``"succeeded"``, ``"requires_action"``).
        replayed: Whether Stripe answered from its idempotency cache
            (``Idempotent-Replayed: true``).
    """

    id: str
    status: str
    replayed: bool = False


class StripeError(Exception):
    """A Stripe API request failed.

    Attributes:
        type: Stripe error type (e.g. ``"invalid_request_error"``), when known.
        code: Stripe (or JSON-RPC) error code, when known.
        status_code: HTTP status code, when known.
    """

    def __init__(
        self,
        message: str,
        *,
        type: str | None = None,
        code: str | int | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.type = type
        self.code = code
        self.status_code = status_code


class StripeClient(Protocol):
    """Duck-typed Stripe client used for server-side payment verification."""

    async def create_payment_intent(
        self,
        params: Mapping[str, Any],
        *,
        api_version: str,
        idempotency_key: str | None = None,
        stripe_account: str | None = None,
    ) -> PaymentIntent:
        """Creates a PaymentIntent (``POST /v1/payment_intents``)."""
        ...


class StripeRawClient(StripeClient, Protocol):
    """A :class:`StripeClient` that can also issue arbitrary API requests (mppx ``rawRequest``)."""

    async def raw_request(
        self,
        method: HttpMethod,
        path: str,
        params: Mapping[str, Any] | None = None,
        *,
        api_version: str,
        stripe_account: str | None = None,
    ) -> Any:
        """Issues an authenticated API request and returns the decoded JSON body."""
        ...


def encode_form(params: Mapping[str, Any], prefix: str | None = None) -> list[tuple[str, str]]:
    """Encodes nested params the way Stripe expects (``a[b][0]=c``); ``None`` values are omitted."""
    fields: list[tuple[str, str]] = []
    for name, value in params.items():
        key = f"{prefix}[{name}]" if prefix else str(name)
        fields.extend(_encode_value(key, value))
    return fields


def _encode_value(key: str, value: Any) -> list[tuple[str, str]]:
    match value:
        case None:
            return []
        case bool():
            return [(key, "true" if value else "false")]
        case Mapping():
            return encode_form(value, key)  # pyright: ignore[reportUnknownArgumentType]
        case list() | tuple():
            return [
                field
                for index, item in enumerate(value)  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
                for field in _encode_value(f"{key}[{index}]", item)
            ]
        case _:
            return [(key, str(value))]


def _error_from_response(response: httpx.Response) -> StripeError:
    body = response.text
    try:
        error = json.loads(body).get("error") or {}
    except (ValueError, AttributeError):
        error = {}
    if not isinstance(error, dict):
        error = {}
    message = error.get("message")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return StripeError(
        message if isinstance(message, str) else body,
        type=error.get("type"),  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        code=error.get("code"),  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        status_code=response.status_code,
    )


class StripeHttpClient:
    """Stripe client backed by ``httpx`` and a secret API key.

    Implements :class:`StripeRawClient`.

    Args:
        secret_key: Stripe secret API key (``sk_...``).
        http: Optional shared ``httpx.AsyncClient`` (a short-lived client is used per request
            otherwise).
        base_url: Stripe API base URL.
    """

    def __init__(
        self,
        secret_key: str,
        *,
        http: httpx.AsyncClient | None = None,
        base_url: str = STRIPE_API_URL,
    ) -> None:
        self._secret_key = secret_key
        self._http = http
        self._base_url = base_url.rstrip("/")

    async def _send(self, request: httpx.Request) -> httpx.Response:
        if self._http is not None:
            return await self._http.send(request)
        async with httpx.AsyncClient() as http:
            return await http.send(request)

    def _headers(
        self,
        *,
        api_version: str,
        idempotency_key: str | None = None,
        stripe_account: str | None = None,
    ) -> dict[str, str]:
        token = base64.b64encode(f"{self._secret_key}:".encode()).decode()
        headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        headers["Stripe-Version"] = api_version
        if stripe_account is not None:
            headers["Stripe-Account"] = stripe_account
        return headers

    async def create_payment_intent(
        self,
        params: Mapping[str, Any],
        *,
        api_version: str,
        idempotency_key: str | None = None,
        stripe_account: str | None = None,
    ) -> PaymentIntent:
        request = httpx.Request(
            "POST",
            f"{self._base_url}/v1/payment_intents",
            headers=self._headers(
                api_version=api_version,
                idempotency_key=idempotency_key,
                stripe_account=stripe_account,
            ),
            data=dict(encode_form(params)),
        )
        response = await self._send(request)
        if not response.is_success:
            raise _error_from_response(response)
        result = response.json()
        # https://docs.stripe.com/error-low-level#idempotency
        return PaymentIntent(
            id=result["id"],
            status=result["status"],
            replayed=response.headers.get("idempotent-replayed") == "true",
        )

    async def raw_request(
        self,
        method: HttpMethod,
        path: str,
        params: Mapping[str, Any] | None = None,
        *,
        api_version: str,
        stripe_account: str | None = None,
    ) -> Any:
        headers = self._headers(api_version=api_version, stripe_account=stripe_account)
        url = f"{self._base_url}{path}"
        fields = encode_form(params or {})
        if method == "GET":
            request = httpx.Request("GET", url, headers=headers, params=dict(fields) or None)
        else:
            request = httpx.Request("POST", url, headers=headers, data=dict(fields))
        response = await self._send(request)
        if not response.is_success:
            raise _error_from_response(response)
        return response.json()
