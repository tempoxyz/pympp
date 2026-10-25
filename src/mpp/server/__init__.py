"""Server-side payment engine: route handlers, transports and framework-neutral HTTP types.

The Starlette / FastAPI integration lives in :mod:`mpp.server.starlette`.
"""

from mpp.challenge import Challenge
from mpp.errors import PaymentError
from mpp.server._compose import compose
from mpp.server._events import (
    ChallengeCreated,
    EventEnvelope,
    MethodDescriptor,
    PaymentFailed,
    PaymentSucceeded,
)
from mpp.server._http import Request, Response, make_headers
from mpp.server._mpp import (
    ComposedHandler,
    ConfiguredHandler,
    HandlerFactory,
    MissingReceiptResponseError,
    Mpp,
    OfferInfo,
    PaymentRequired,
    PaymentResult,
    PaymentVerified,
    assert_secret_key,
)
from mpp.server._transport import (
    HttpTransport,
    McpTransport,
    Transport,
    http,
)


def require_payment(challenge: Challenge, error: PaymentError | None = None) -> Response:
    """Creates a 402 response with a ``WWW-Authenticate: Payment`` header.

    Includes RFC 9457 Problem Details in the body when ``error`` is given.
    """
    from mpp import _json
    from mpp.constants import Header

    headers = [(Header.WWW_AUTHENTICATE, challenge.serialize()), ("Cache-Control", "no-store")]
    body = None
    if error is not None:
        headers.append(("Content-Type", "application/problem+json"))
        body = _json.dumps(error.to_problem_details(challenge.id)).encode()
    return Response(status=402, headers=headers, body=body)


__all__ = [
    "ChallengeCreated",
    "ComposedHandler",
    "ConfiguredHandler",
    "EventEnvelope",
    "HandlerFactory",
    "HttpTransport",
    "McpTransport",
    "MethodDescriptor",
    "MissingReceiptResponseError",
    "Mpp",
    "OfferInfo",
    "PaymentFailed",
    "PaymentRequired",
    "PaymentResult",
    "PaymentSucceeded",
    "PaymentVerified",
    "Request",
    "Response",
    "Transport",
    "assert_secret_key",
    "compose",
    "http",
    "make_headers",
    "require_payment",
]
