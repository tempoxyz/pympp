"""Client payment engine: automatic 402 payment handling for httpx.

Example:
    from mpp.client import Mpp
    from mpp.methods.tempo import client as tempo

    async with Mpp(methods=[tempo.charge(account=my_account)]) as mpp:
        response = await mpp.fetch("https://api.example.com/resource")

    # Or plug the transport into your own client:
    async with httpx.AsyncClient(transport=mpp.payment_transport) as client:
        response = await client.get("https://api.example.com/resource")
"""

from mpp import _expires as Expires
from mpp.client.transport import Mpp, PaymentTransport
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    PAYMENT_FAILED,
    PAYMENT_RESPONSE,
    WILDCARD_EVENT,
    EventDispatcher,
    PaymentEvent,
    PaymentEventName,
)
from mpp.methods import Method
from mpp.runtime import ClientMethod, CredentialParams, PaymentRuntime

__all__ = [
    "CHALLENGE_RECEIVED",
    "CREDENTIAL_CREATED",
    "ClientMethod",
    "CredentialParams",
    "EventDispatcher",
    "Expires",
    "Method",
    "Mpp",
    "PAYMENT_FAILED",
    "PAYMENT_RESPONSE",
    "PaymentEvent",
    "PaymentEventName",
    "PaymentRuntime",
    "PaymentTransport",
    "WILDCARD_EVENT",
]
