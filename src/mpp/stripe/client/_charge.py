"""Stripe charge for clients: obtains a Shared Payment Token (SPT) and builds the credential."""

import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mpp import expires
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.method import ClientMethod, CredentialParams
from mpp.stripe import charge as charge_method


class ChargeContext(BaseModel):
    """Per-request context accepted by the Stripe charge client method."""

    model_config = ConfigDict(populate_by_name=True)

    payment_method: str | None = Field(default=None, alias="paymentMethod")


@dataclass(frozen=True, slots=True, kw_only=True)
class TokenParams:
    """Arguments passed to the ``create_token`` callback.

    Attributes:
        amount: Payment amount in the currency's smallest unit.
        challenge: The Stripe charge challenge being paid.
        client: The ``client`` given to :func:`charge` (e.g. a Stripe SDK instance), if any.
        currency: Three-letter ISO currency code.
        expires_at: SPT expiration as a Unix timestamp (seconds).
        metadata: Optional metadata to associate with the SPT.
        network_id: Stripe Business Network profile id.
        payment_method: Stripe payment method id (e.g. ``pm_...``).
    """

    amount: str
    challenge: Challenge
    client: Any
    currency: str
    expires_at: int
    metadata: Mapping[str, str] | None
    network_id: str
    payment_method: str


type CreateToken = Callable[[TokenParams], Awaitable[str]]
"""Creates an SPT for a challenge (requires a Stripe secret key, so usually proxied through a
server endpoint) and returns its id."""


def charge(
    *,
    create_token: CreateToken,
    client: Any = None,
    external_id: str | None = None,
    payment_method: str | None = None,
) -> ClientMethod:
    """Creates a Stripe charge method for clients.

    Args:
        create_token: Called when a Stripe challenge is received; returns an SPT id.
        client: Optional Stripe client object forwarded to ``create_token``.
        external_id: Fallback external reference id; a request-bound ``externalId`` is echoed
            instead when the challenge carries one.
        payment_method: Default payment method id, overridden by ``context.payment_method``.
    """

    async def create_credential(params: CredentialParams[Any]) -> str:
        challenge = params.challenge
        context = params.context
        method = (
            context.payment_method if isinstance(context, ChargeContext) else None
        ) or payment_method
        if not method:
            raise ValueError("paymentMethod is required (pass via context or parameters)")

        request = challenge.request
        request_external_id = request.get("externalId")
        if not isinstance(request_external_id, str):
            request_external_id = None
        method_details = request.get("methodDetails") or {}
        network_id = method_details.get("networkId")
        if not network_id:
            raise ValueError("networkId is required in challenge.methodDetails")
        metadata = method_details.get("metadata")
        if metadata and metadata.get("externalId"):
            raise ValueError(
                "methodDetails.metadata.externalId is reserved; use credential externalId instead"
            )

        parsed = expires.parse(challenge.expires) if challenge.expires else None
        expires_at = math.floor(parsed.timestamp() if parsed else expires.now().timestamp() + 3600)

        spt = await create_token(
            TokenParams(
                amount=request["amount"],
                challenge=challenge,
                client=client,
                currency=request["currency"],
                expires_at=expires_at,
                metadata=metadata,
                network_id=network_id,
                payment_method=method,
            )
        )

        payload: dict[str, Any] = {"spt": spt}
        payload_external_id = (
            request_external_id if request_external_id is not None else external_id
        )
        if payload_external_id is not None:
            payload["externalId"] = payload_external_id
        return Credential(challenge=challenge, payload=payload).serialize()

    return ClientMethod(
        method=charge_method, create_credential=create_credential, context=ChargeContext
    )


def stripe(
    *,
    create_token: CreateToken,
    client: Any = None,
    external_id: str | None = None,
    payment_method: str | None = None,
) -> list[ClientMethod]:
    """Returns the Stripe client methods (``[charge(...)]``)."""
    return [
        charge(
            create_token=create_token,
            client=client,
            external_id=external_id,
            payment_method=payment_method,
        )
    ]
