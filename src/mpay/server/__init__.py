"""Server-side payment verification.

Example:
    from mpay.server import verify_or_challenge, Intent
    from mpay.methods.tempo import ChargeIntent

    result = await verify_or_challenge(
        authorization=request.headers.get("Authorization"),
        intent=ChargeIntent(client),
        request={"amount": "1000", "currency": "0x...", ...},
        realm="api.example.com",
    )

    if isinstance(result, Challenge):
        return Response(status=402, headers={"WWW-Authenticate": ...})
    else:
        return Response({"data": "..."}, headers={"Payment-Receipt": ...})
"""

from mpay.server.decorator import requires_payment
from mpay.server.intent import Intent, VerificationError, intent
from mpay.server.method import Method, transform_request
from mpay.server.mpay import Mpay
from mpay.server.verify import verify_or_challenge

__all__ = [
    "Intent",
    "Method",
    "Mpay",
    "VerificationError",
    "intent",
    "requires_payment",
    "transform_request",
    "verify_or_challenge",
]
