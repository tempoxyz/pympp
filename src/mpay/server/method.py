"""Method protocol for payment method implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mpay import Challenge, Credential
    from mpay.server.intent import Intent


@runtime_checkable
class Method(Protocol):
    """Payment method interface.

    A method represents a payment network (e.g., Tempo, Stripe) and provides:
    - Named intents for different payment operations
    - Client-side credential creation

    Example:
        class StripeMethod:
            name = "stripe"

            @property
            def intents(self) -> dict[str, Intent]:
                return {"charge": StripeChargeIntent(self.api_key)}

            async def create_credential(self, challenge: Challenge) -> Credential:
                # Create Stripe payment intent and return credential
                ...
    """

    name: str
    intents: dict[str, Intent]

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        This is called on the client side when a 402 response is received.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential that satisfies the challenge.
        """
        ...
