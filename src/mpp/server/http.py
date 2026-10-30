"""Framework-neutral HTTP request and response types used by the server engine."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal, Self, TypeAlias

import httpx

from mpp.x402._server import is_x402_credential, payment_response_header
from mpp.x402._types import PAYMENT_RESPONSE_HEADER

if TYPE_CHECKING:
    from mpp import Credential, Receipt

logger = logging.getLogger(__name__)

HeadersInput: TypeAlias = httpx.Headers | Mapping[str, str] | Sequence[tuple[str, str]] | None


def make_headers(headers: HeadersInput = None) -> httpx.Headers:
    """Build case-insensitive, multi-value headers.

    String values are latin-1 encoded, as HTTP servers decode header bytes, so any
    header a framework accepted round-trips.
    """
    if isinstance(headers, httpx.Headers):
        return httpx.Headers(headers.raw, encoding=headers.encoding)
    if isinstance(headers, Mapping):
        return httpx.Headers(list(headers.items()), encoding="latin-1")
    return httpx.Headers(list(headers or ()), encoding="latin-1")


@dataclass(frozen=True, slots=True, init=False)
class Request:
    """An incoming HTTP request as seen by the payment engine.

    Attributes:
        method: HTTP method (uppercase).
        url: Absolute request URL.
        headers: Case-insensitive request headers.
        body: The request body, or ``None`` when it has none.
        route: Route template matched by the framework, such as ``"/items/{id}"``. Set by
            framework integrations and bound into issued challenges.
    """

    method: str
    url: str
    headers: httpx.Headers
    body: bytes | None
    route: str | None

    def __init__(
        self,
        method: str,
        url: str,
        headers: HeadersInput = None,
        body: bytes | str | None = None,
        route: str | None = None,
    ) -> None:
        object.__setattr__(self, "method", method.upper())
        object.__setattr__(self, "url", str(url))
        object.__setattr__(self, "headers", make_headers(headers))
        object.__setattr__(self, "body", body.encode() if isinstance(body, str) else body)
        object.__setattr__(self, "route", route)

    def json(self) -> Any:
        """Parse the body as JSON."""
        return json.loads(self.body or b"")

    def scope(self) -> dict[str, str]:
        """The route identity bound into challenges: HTTP method, route, path and query."""
        url = httpx.URL(self.url)
        scope = {"http_method": self.method}
        if self.route:
            scope["route"] = self.route
        # The percent-encoded path: decoding would merge distinct paths, such as
        # /a%2Fb and /a/b, into one signed scope.
        resource = url.raw_path.split(b"?", 1)[0].decode("ascii")
        if resource:
            scope["resource"] = resource
        query = url.query.decode("latin-1")
        if query:
            scope["query"] = query
        return scope


@dataclass(frozen=True, slots=True, init=False)
class Response:
    """An outgoing HTTP response."""

    status: int
    headers: httpx.Headers
    body: bytes | None

    def __init__(
        self, status: int = 200, headers: HeadersInput = None, body: bytes | str | None = None
    ) -> None:
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "headers", make_headers(headers))
        object.__setattr__(self, "body", body.encode() if isinstance(body, str) else body)

    @classmethod
    def json(cls, data: Any, *, status: int = 200, headers: HeadersInput = None) -> Self:
        """Create a JSON response."""
        result = make_headers(headers)
        if "content-type" not in result:
            result["Content-Type"] = "application/json"
        return cls(status=status, headers=result, body=json.dumps(data).encode())

    def copy(self, **changes: Any) -> Self:
        """Return a copy with the given fields replaced."""
        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class PaymentRequired:
    """Payment is required, or the credential was rejected: return ``challenge`` as-is.

    ``challenge`` is a ``402`` response carrying ``WWW-Authenticate: Payment`` challenges,
    or a final ``403`` problem response when paying again cannot help.
    """

    challenge: Response

    @property
    def status(self) -> int:
        return self.challenge.status


@dataclass(frozen=True, slots=True)
class PaymentVerified:
    """Payment succeeded: run the route and wrap its response with :meth:`with_receipt`.

    ``response`` is set when the payment method fully handled the request (its
    ``respond`` hook returned a management response, such as for opening or closing a
    payment channel): it already carries the receipt headers, the route must not run, and
    :meth:`with_receipt` returns it in place of the route's response. ``status`` is
    200 either way (as in mppx), and nothing was charged for such a request, so check
    ``response`` before producing content::

        if result.response is not None:
            return result.response
        return result.with_receipt(Response.json(content()))
    """

    credential: Credential
    receipt: Receipt
    status: Literal[200] = 200
    response: Response | None = field(default=None, kw_only=True)

    def with_receipt(self, response: Any = None) -> Any:
        """Attach the receipt headers to ``response``.

        A :class:`Response` is copied; any other response object with mutable ``headers``,
        such as a Starlette response, is updated in place and returned. When the method
        returned a management response (:attr:`response`), that is returned instead and
        ``response`` is ignored.
        """
        if self.response is not None:
            return self.response
        headers = {"Payment-Receipt": self.receipt.to_payment_receipt()}
        if x402 := payment_response_header(self.credential, self.receipt):
            headers[PAYMENT_RESPONSE_HEADER] = x402
        if isinstance(response, Response):
            merged = httpx.Headers(response.headers)
            merged.update(headers)
            merged["Cache-Control"] = _private(merged.get("cache-control"))
            return response.copy(headers=merged)
        target = getattr(response, "headers", None)
        if target is None:
            if is_x402_credential(self.credential):
                _warn_plain_x402_response(response)
            return response
        try:
            for name, value in headers.items():
                if name not in target:
                    target[name] = value
            target["Cache-Control"] = _private(target.get("cache-control"))
        except (TypeError, AttributeError):
            pass
        return response


PaymentResult: TypeAlias = PaymentRequired | PaymentVerified


def _private(cache_control: str | None) -> str:
    """Keep a paid response out of shared caches, which could serve it to callers who never paid."""
    directives = [part.strip() for part in (cache_control or "").split(",") if part.strip()]
    lowered = [part.lower() for part in directives]
    if "private" in lowered or "no-store" in lowered:
        return ", ".join(directives)
    kept = [
        part
        for part in directives
        if part.lower() != "public" and not part.lower().startswith("s-maxage")
    ]
    return ", ".join(["private", *kept])


_warned_plain_x402_response = False


def _warn_plain_x402_response(response: Any) -> None:
    """Warn once when a paid x402 response can't carry its headers."""
    global _warned_plain_x402_response
    if _warned_plain_x402_response:
        return
    _warned_plain_x402_response = True
    logger.warning(
        "A handler paid with x402 returned %s instead of a response object, so "
        "PAYMENT-RESPONSE and Cache-Control: private could not be added. Return a "
        "response object from x402-paid handlers so shared caches can't serve the "
        "paid response to callers who didn't pay.",
        type(response).__name__,
    )
