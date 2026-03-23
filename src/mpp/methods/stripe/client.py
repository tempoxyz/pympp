"""Stripe payment method for client-side credential creation.

Implements the charge client method using Stripe's Shared Payment Token (SPT) flow.
"""

from __future__ import annotations

import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential

if TYPE_CHECKING:
    from mpp.server.intent import Intent

    from mpp import Credential as CredentialType


@dataclass(frozen=True)
class OnChallengeParameters:
    """Parameters passed to the ``create_token`` callback.

    Attributes:
        amount: Payment amount in smallest currency unit (e.g. ``"150"`` for $1.50).
        challenge: The full payment challenge from the server.
        currency: Three-letter ISO currency code (e.g. ``"usd"``).
        expires_at: SPT expiration as a Unix timestamp (seconds).
        metadata: Optional metadata from the challenge's methodDetails.
        network_id: Stripe Business Network profile ID.
        payment_method: Stripe payment method ID (e.g. ``"pm_card_visa"``).
    """

    amount: str
    challenge: Challenge
    currency: str
    expires_at: int
    metadata: dict[str, str] | None
    network_id: str
    payment_method: str


CreateTokenFn = Callable[[OnChallengeParameters], Awaitable[str]]


@dataclass
class StripeMethod:
    """Stripe payment method implementation.

    Handles client-side credential creation for Stripe SPT payments.
    """

    name: str = "stripe"
    create_token: CreateTokenFn | None = None
    payment_method: str | None = None
    external_id: str | None = None
    currency: str | None = None
    decimals: int = 2
    recipient: str | None = None
    network_id: str | None = None
    payment_method_types: list[str] = field(default_factory=lambda: ["card"])
    _intents: dict[str, Intent] = field(default_factory=dict)

    @property
    def intents(self) -> dict[str, Intent]:
        """Available intents for this method."""
        return self._intents

    def transform_request(
        self, request: dict[str, Any], credential: CredentialType | None
    ) -> dict[str, Any]:
        """Inject Stripe-specific methodDetails into the challenge request.

        Called by ``Mpp`` before challenge creation to add ``networkId``
        and ``paymentMethodTypes`` to the request's ``methodDetails``.
        """
        method_details = dict(request.get("methodDetails", {}))
        if self.network_id and "networkId" not in method_details:
            method_details["networkId"] = self.network_id
        if self.payment_method_types and "paymentMethodTypes" not in method_details:
            method_details["paymentMethodTypes"] = self.payment_method_types
        request = {**request, "methodDetails": method_details}
        return request

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
            raise ValueError("payment_method is required (pass to stripe() or via context)")

        amount = str(request.get("amount", ""))
        currency = str(request.get("currency", ""))
        network_id = method_details.get("networkId") if isinstance(method_details, dict) else None
        if not network_id:
            raise ValueError("networkId is required in challenge.methodDetails")
        metadata = method_details.get("metadata") if isinstance(method_details, dict) else None
        if isinstance(metadata, dict) and "externalId" in metadata:
            raise ValueError(
                "methodDetails.metadata.externalId is reserved; "
                "use credential externalId instead"
            )

        if challenge.expires:
            expires_at = math.floor(
                _parse_iso_timestamp(challenge.expires)
            )
        else:
            expires_at = math.floor(time.time()) + 3600

        spt = await self.create_token(
            OnChallengeParameters(
                amount=amount,
                challenge=challenge,
                currency=currency,
                expires_at=expires_at,
                metadata=metadata,
                network_id=network_id,
                payment_method=payment_method,
            )
        )

        payload: dict[str, Any] = {"spt": spt}
        if self.external_id:
            payload["externalId"] = self.external_id

        return Credential(
            challenge=challenge.to_echo(),
            payload=payload,
        )


def _parse_iso_timestamp(iso_str: str) -> float:
    """Parse an ISO 8601 timestamp to a Unix timestamp (seconds)."""
    from datetime import datetime

    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return dt.timestamp()


# ──────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────


def stripe(
    intents: dict[str, Intent],
    create_token: CreateTokenFn | None = None,
    payment_method: str | None = None,
    external_id: str | None = None,
    currency: str | None = None,
    decimals: int = 2,
    recipient: str | None = None,
    network_id: str | None = None,
    payment_method_types: list[str] | None = None,
) -> StripeMethod:
    """Create a Stripe payment method.

    Args:
        intents: Intents to register (e.g. ``{"charge": ChargeIntent(...)}``)
        create_token: Callback to create an SPT (client-side).
            Receives :class:`OnChallengeParameters` and returns the SPT string.
        payment_method: Default Stripe payment method ID (e.g. ``"pm_card_visa"``).
        external_id: Optional client-side external reference ID.
        currency: Default ISO currency code (e.g. ``"usd"``).
        decimals: Decimal places for the currency (default: 2 for USD cents).
        recipient: Optional default recipient.
        network_id: Stripe Business Network profile ID. Included in
            challenge ``methodDetails.networkId``.
        payment_method_types: Stripe payment method types (default: ``["card"]``).
            Included in challenge ``methodDetails.paymentMethodTypes``.

    Returns:
        A configured :class:`StripeMethod` instance.

    Example:
        from mpp.methods.stripe import stripe, ChargeIntent

        # Server
        method = stripe(
            network_id="bn_...",
            payment_method_types=["card"],
            currency="usd",
            decimals=2,
            intents={"charge": ChargeIntent(secret_key="sk_...")},
        )

        # Client
        method = stripe(
            create_token=my_spt_proxy,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_...")},
        )
    """
    method = StripeMethod(
        create_token=create_token,
        payment_method=payment_method,
        external_id=external_id,
        currency=currency,
        decimals=decimals,
        recipient=recipient,
        network_id=network_id,
        payment_method_types=payment_method_types or ["card"],
    )
    method._intents = dict(intents)
    return method
