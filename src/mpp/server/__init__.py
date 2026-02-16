"""Server-side payment verification.

Example:
    from mpp.server import verify_or_challenge, Intent
    from mpp.methods.tempo import ChargeIntent

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

from mpp.server.decorator import requires_payment
from mpp.server.intent import Intent, VerificationError, intent
from mpp.server.method import Method, transform_request
from mpp.server.mpp import Mpp
from mpp.server.verify import verify_or_challenge
