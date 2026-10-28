"""Stripe charge for clients.

:func:`charge` returns the :class:`~mpp.runtime.ClientMethod` that pays Stripe
charge challenges with Shared Payment Tokens (SPTs); :class:`StripeMethod`
implements its credential creation.
"""

from __future__ import annotations

import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mpp import Challenge, Credential
from mpp._typing import is_dict, is_list
from mpp.runtime import ClientMethod, CredentialParams


@dataclass(frozen=True)
class OnChallengeParameters:
    """Parameters passed to the ``create_token`` callback.

    Attributes:
        amount: Payment amount in smallest currency unit (e.g. ``"150"`` for $1.50).
        challenge: The full payment challenge from the server.
        currency: Three-letter ISO currency code (e.g. ``"usd"``).
        external_id: Optional authenticated external identifier from the challenge.
        expires_at: SPT expiration as a Unix timestamp (seconds).
        metadata: Optional metadata from the challenge's methodDetails.
        network_id: Stripe Business Network profile ID.
        payment_method_types: Stripe payment method types allowed by the challenge.
        payment_method: Stripe payment method ID (e.g. ``"pm_card_visa"``).
    """

    amount: str
    challenge: Challenge
    currency: str
    external_id: str | None
    expires_at: int
    metadata: dict[str, str] | None
    network_id: str
    payment_method_types: list[str]
    payment_method: str


CreateTokenFn = Callable[[OnChallengeParameters], Awaitable[str]]


@dataclass
class StripeMethod:
    """Creates Stripe SPT credentials. Create it with :func:`charge`."""

    name: str = "stripe"
    create_token: CreateTokenFn | None = None
    payment_method: str | None = None
    external_id: str | None = None

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        Calls the user-supplied ``create_token`` callback to obtain an SPT,
        then wraps it in a credential for the Authorization header.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential with the SPT payload.

        Raises:
            ValueError: If no ``create_token`` callback or ``payment_method`` is configured.
        """
        if self.create_token is None:
            raise ValueError("No create_token callback configured")

        request = challenge.request
        method_details = request.get("methodDetails", {})

        payment_method = self.payment_method
        if not payment_method:
            raise ValueError("payment_method is required")

        amount = str(request.get("amount", ""))
        currency = str(request.get("currency", ""))
        raw_external_id = request.get("externalId")
        external_id = raw_external_id if isinstance(raw_external_id, str) else None
        network_id = method_details.get("networkId") if is_dict(method_details) else None
        if not network_id:
            raise ValueError("networkId is required in challenge.methodDetails")
        payment_method_types = (
            method_details.get("paymentMethodTypes") if is_dict(method_details) else None
        )
        if (
            not is_list(payment_method_types)
            or not payment_method_types
            or not all(isinstance(value, str) for value in payment_method_types)
        ):
            raise ValueError("paymentMethodTypes is required in challenge.methodDetails")
        metadata = method_details.get("metadata") if is_dict(method_details) else None
        if is_dict(metadata) and "externalId" in metadata:
            raise ValueError(
                "methodDetails.metadata.externalId is reserved; use request externalId instead"
            )

        if challenge.expires:
            expires_at = math.floor(_parse_iso_timestamp(challenge.expires))
        else:
            expires_at = math.floor(time.time()) + 3600

        spt = await self.create_token(
            OnChallengeParameters(
                amount=amount,
                challenge=challenge,
                currency=currency,
                external_id=external_id,
                expires_at=expires_at,
                metadata=metadata,
                network_id=network_id,
                payment_method_types=payment_method_types,
                payment_method=payment_method,
            )
        )

        # A request-bound externalId is echoed and takes precedence, as in mppx.
        payload_external_id = external_id if external_id is not None else self.external_id
        payload: dict[str, Any] = {"spt": spt}
        if payload_external_id is not None:
            payload["externalId"] = payload_external_id
        return Credential(challenge=challenge.to_echo(), payload=payload)


def _parse_iso_timestamp(iso_str: str) -> float:
    """Parse an ISO 8601 timestamp to a Unix timestamp (seconds)."""
    from datetime import datetime

    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return dt.timestamp()


def charge(
    *,
    create_token: CreateTokenFn,
    payment_method: str,
    external_id: str | None = None,
) -> ClientMethod:
    """Create the client method that pays Stripe charge challenges.

    Args:
        create_token: Callback that creates an SPT, usually through your
            backend. Receives :class:`OnChallengeParameters` and returns the SPT.
        payment_method: Stripe payment method ID (e.g. ``"pm_card_visa"``).
        external_id: External reference echoed in credentials for challenges
            that carry no ``externalId``.

    Example:
        from mpp.client import Mpp
        from mpp.methods.stripe import client as stripe

        async with Client(
            methods=[stripe.charge(create_token=create_spt, payment_method="pm_card_visa")]
        ) as client:
            response = await client.get("https://api.example.com/resource")
    """
    from mpp.methods.stripe.schemas import charge as definition

    method = StripeMethod(
        create_token=create_token, payment_method=payment_method, external_id=external_id
    )

    async def create_credential(params: CredentialParams) -> str:
        return (await method.create_credential(params.challenge)).to_authorization()

    return ClientMethod(method=definition, create_credential=create_credential)
