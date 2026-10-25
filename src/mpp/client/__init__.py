"""Client-side payment engine: automatic 402 handling for ``httpx``.

``Mpp(methods=[...])`` exposes :attr:`Mpp.payment_transport` (an ``httpx`` transport) and
:meth:`Mpp.fetch`. Unlike mppx there is no global ``fetch`` polyfill: nothing is patched on
import or construction.

Payment protocols are pluggable: implement :class:`Protocol` (see :mod:`mpp.client._protocols`)
and pass it to :func:`http_transport`.
"""

from mpp._accept_payment import ChallengeCandidate
from mpp._accept_payment import Entry as AcceptPaymentEntry
from mpp.client._events import (
    ChallengeReceived,
    ClientEventEnvelope,
    ClientPaymentFailed,
    CredentialCreated,
    PaymentResponse,
)
from mpp.client._mpp import (
    BODY_TRUNCATED_HEADER,
    CONTEXT_EXTENSION,
    ORDER_CHALLENGES_EXTENSION,
    AcceptPaymentPolicy,
    Mpp,
    OnChallenge,
    OrderChallenges,
    PaymentTransport,
    PreparedPayment,
    PreparedRequest,
    PreparedRequestPayment,
    Redirect,
    validate_credential_header_value,
)
from mpp.client._protocols import (
    MppProtocol,
    Protocol,
    mpp,
    peek_body,
    rebuild_request,
    set_credential_header,
)
from mpp.client._transport import (
    ClientTransport,
    HttpTransport,
    default_protocols,
    http_transport,
)

__all__ = [
    "BODY_TRUNCATED_HEADER",
    "CONTEXT_EXTENSION",
    "ORDER_CHALLENGES_EXTENSION",
    "AcceptPaymentEntry",
    "AcceptPaymentPolicy",
    "ChallengeCandidate",
    "ChallengeReceived",
    "ClientEventEnvelope",
    "ClientPaymentFailed",
    "ClientTransport",
    "CredentialCreated",
    "HttpTransport",
    "Mpp",
    "MppProtocol",
    "OnChallenge",
    "OrderChallenges",
    "PaymentResponse",
    "PaymentTransport",
    "PreparedPayment",
    "PreparedRequest",
    "PreparedRequestPayment",
    "Protocol",
    "Redirect",
    "default_protocols",
    "http_transport",
    "mpp",
    "peek_body",
    "rebuild_request",
    "set_credential_header",
    "validate_credential_header_value",
]
