"""Server-side transports: how challenges are issued and credentials received."""

import re
from abc import ABC, abstractmethod
from typing import Any

import httpx

from mpp import _json
from mpp.challenge import Challenge
from mpp.constants import Header
from mpp.credential import MAX_AUTHORIZATION_LENGTH, Credential, extract_payment_scheme
from mpp.errors import MalformedCredentialError, PaymentError
from mpp.method import CapturedRequest, VerifiedChallengeEnvelope
from mpp.receipt import Receipt
from mpp.server._http import Request, Response, make_headers

_PAYMENT_SCHEME = re.compile(r"(?:^|,)[ 	]*payment ", re.IGNORECASE)


class Transport[InputT, ChallengeT, ReceiptInT, ReceiptOutT](ABC):
    """Server-side transport adapter.

    Type parameters: the transport input (e.g. :class:`Request`), the challenge output, the
    response type accepted by ``with_receipt`` and the type it returns.

    Subclasses implement :meth:`get_credential`, :meth:`respond_challenge` and
    :meth:`respond_receipt`; the remaining hooks have sensible defaults.
    """

    name: str = "custom"
    supports_streaming_receipts: bool = False
    """Whether ``with_receipt`` accepts route-produced async iterables."""
    credential_headers: tuple[str, ...] = ()
    """HTTP header names from which this transport reads credentials."""

    async def capture_request(self, input: InputT) -> CapturedRequest:
        """Captures the input into an immutable snapshot (default: duck-typed attributes)."""
        headers = getattr(input, "headers", None)
        body = getattr(input, "body", None)
        return CapturedRequest(
            method=getattr(input, "method", None) or "POST",
            url=safe_url(getattr(input, "url", None)),
            headers=make_headers(headers if headers is not None else None),
            has_body=None if not hasattr(input, "body") else body is not None,
        )

    @abstractmethod
    def get_credential(self, input: InputT) -> Credential[Any] | None:
        """Extracts the credential; ``None`` when absent. Raises when malformed."""

    async def bind_credential(
        self, *, challenge: Challenge, credential: Credential[Any], input: InputT
    ) -> Credential[Any]:
        """Rebinds a transport-native credential to the route challenge (default: unchanged)."""
        return credential

    def route_scope(self, input: InputT) -> str | None:
        """Returns a trusted scope that binds challenges to this request's target (default: none).

        Applied to non-HTTP inputs only when the route configures no ``scope``; HTTP inputs use
        :attr:`Request.route_scope` set by framework integrations.
        """
        return None

    async def match_credential(self, *, input: InputT, request: dict[str, Any]) -> bool:
        """Returns whether a transport-native credential targets a configured request."""
        return False

    @property
    def has_native_credentials(self) -> bool:
        """Whether this transport overrides :meth:`match_credential` (e.g. x402)."""
        return type(self).match_credential is not Transport.match_credential

    @abstractmethod
    async def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: InputT,
        error: PaymentError | None = None,
    ) -> ChallengeT:
        """Creates the transport response for a payment challenge."""

    @abstractmethod
    def respond_receipt(
        self,
        *,
        challenge_id: str,
        credential: Credential[Any],
        input: InputT,
        receipt: Receipt,
        response: ReceiptInT,
        envelope: VerifiedChallengeEnvelope[Any] | None = None,
    ) -> ReceiptOutT:
        """Attaches a receipt to a successful response."""


def safe_url(url: Any) -> httpx.URL:
    """Parses ``url`` (``about:blank`` when missing or invalid)."""
    try:
        if url:
            parsed = httpx.URL(str(url))
            if parsed.scheme:
                return parsed
    except Exception:
        pass
    return httpx.URL("about:blank")


def problem_response(error: PaymentError, challenge_id: str | None = None) -> bytes:
    return _json.dumps(error.to_problem_details(challenge_id)).encode()


def with_private_cache_control(value: str | None) -> str:
    if not value:
        return "private"
    directives = [directive.strip().lower() for directive in value.split(",")]
    if "private" in directives:
        return value
    return f"{value}, private"


class HttpTransport(Transport[Request, Response, Response, Response]):
    """HTTP transport.

    Reads credentials from ``Authorization`` (``Payment-Authorization`` when the application
    needs ``Authorization`` for its own authentication), issues challenges via
    ``WWW-Authenticate`` with status 402 and attaches receipts via ``Payment-Receipt``.
    """

    name = "http"

    def __init__(self, *, requires_auth: bool = False) -> None:
        self.credential_header = (
            Header.PAYMENT_AUTHORIZATION if requires_auth else Header.AUTHORIZATION
        )
        self.credential_headers = (str(self.credential_header),)

    async def capture_request(self, input: Request) -> CapturedRequest:
        return CapturedRequest(
            method=input.method,
            url=safe_url(input.url),
            headers=make_headers(input.headers),
            has_body=input.body is not None,
        )

    def get_credential(self, input: Request) -> Credential[Any] | None:
        header = input.headers.get(self.credential_header)
        if not header:
            return None
        # An oversized value is a rejected credential only when it carries a Payment scheme; a
        # large non-payment value (e.g. a Bearer token) stays a silent challenge.
        if len(header) > MAX_AUTHORIZATION_LENGTH and _PAYMENT_SCHEME.search(header):
            raise MalformedCredentialError(reason="Authorization header exceeds maximum size")
        payment = extract_payment_scheme(header)
        if payment is None:
            return None
        return Credential.deserialize(payment)

    async def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: Request,
        error: PaymentError | None = None,
    ) -> Response:
        # A 403 means the payment was valid but cannot pay for this request. Omit the challenge
        # so clients do not pay again.
        if error is not None and error.status == 403:
            return Response(
                status=403,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Type": "application/problem+json",
                },
                body=problem_response(error),
            )
        headers: list[tuple[str, str]] = [
            (Header.WWW_AUTHENTICATE, challenge.serialize()),
            ("Cache-Control", "no-store"),
        ]
        body: bytes | None = None
        if error is not None:
            headers.append(("Content-Type", "application/problem+json"))
            body = problem_response(error, challenge.id)
        return Response(
            status=error.status if error is not None else 402, headers=headers, body=body
        )

    def respond_receipt(
        self,
        *,
        challenge_id: str,
        credential: Credential[Any],
        input: Request,
        receipt: Receipt,
        response: Response,
        envelope: VerifiedChallengeEnvelope[Any] | None = None,
    ) -> Response:
        headers = make_headers(response.headers)
        headers["Cache-Control"] = with_private_cache_control(headers.get("Cache-Control"))
        headers[Header.PAYMENT_RECEIPT] = receipt.serialize()
        return Response(status=response.status, headers=headers, body=response.body)


def http(*, requires_auth: bool = False) -> HttpTransport:
    """Creates the HTTP server transport."""
    return HttpTransport(requires_auth=requires_auth)


class McpTransport[InputT, ChallengeT, ReceiptInT, ReceiptOutT](
    Transport[InputT, ChallengeT, ReceiptInT, ReceiptOutT]
):
    """Base class of MCP transports.

    MCP ``compose()`` gathers the challenge lists of payment-required outputs through
    :meth:`payment_required_challenges` and :meth:`with_challenges`. The official ``mcp`` SDK
    integration lives in :mod:`mpp.mcp_sdk` (``mpp.mcp_sdk.server.mcp_sdk()``).
    """

    name = "mcp"

    @abstractmethod
    def payment_required_challenges(self, output: ChallengeT) -> list[Any] | None:
        """Returns the challenge objects of a payment-required (-32042) output, else ``None``."""

    @abstractmethod
    def with_challenges(self, output: ChallengeT, challenges: list[Any]) -> ChallengeT:
        """Returns ``output`` carrying the merged challenge list."""
