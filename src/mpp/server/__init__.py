"""Server-side payment engine: route handlers and framework-neutral HTTP types.

Example:
    from mpp.server import Mpp, Request, Response
    from mpp.methods.tempo import server as tempo

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))

    async def handle(request: Request) -> Response:
        result = await mpp.charge(amount="0.50")(request)
        if result.status != 200:
            return result.challenge  # 402 with WWW-Authenticate
        return result.with_receipt(Response.json({"data": "paid content"}))
"""

from mpp import _expires as Expires
from mpp._validation import Validation
from mpp.errors import (
    BadRequestError,
    CredentialReplayedError,
    InternalPaymentError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentActionRequiredError,
    PaymentError,
    PaymentExpiredError,
    PaymentInsufficientError,
    PaymentMethodUnsupportedError,
    PaymentRequiredError,
    VerificationError,
    VerificationFailedError,
)
from mpp.events import (
    CHALLENGE_CREATED,
    PAYMENT_FAILED,
    PAYMENT_SUCCESS,
    WILDCARD_EVENT,
    EventDispatcher,
    PaymentEvent,
    PaymentEventName,
)
from mpp.methods import Method
from mpp.server.compose import (
    ComposedHandler,
    OfferSelectionContext,
    SelectOffers,
    ServerOffer,
    compose,
)
from mpp.server.decorator import pay
from mpp.server.http import (
    PaymentRequired,
    PaymentResult,
    PaymentVerified,
    Request,
    Response,
)
from mpp.server.method import (
    RequestContext,
    ServerMethod,
    ValidateContext,
    VerifyContext,
)
from mpp.server.mpp import HandlerFactory, Mpp
