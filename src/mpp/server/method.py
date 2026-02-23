"""Method protocol for payment method implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mpp import Challenge, Credential
    from mpp.server.intent import Intent


@runtime_checkable
class Method(Protocol):
    """Payment method interface.

    A method represents a payment network (e.g., Tempo, Stripe) and provides:
    - Named intents for different payment operations
    - Client-side credential creation
    - Optional request transformation

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

    @property
    def intents(self) -> dict[str, Intent]:
        """Available intents for this method."""
        ...

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        This is called on the client side when a 402 response is received.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential that satisfies the challenge.
        """
        ...


def transform_request(
    method: Method,
    request: dict[str, Any],
    credential: Credential | None,
) -> dict[str, Any]:
    """Transform request using method's transform_request if available.

    This hook allows methods to modify the request before challenge creation,
    with access to the credential (if present) for conditional logic like
    feePayer sponsorship.

    Args:
        method: The payment method.
        request: The original request parameters.
        credential: The parsed credential, or None if not provided.

    Returns:
        The transformed request.
    """
    if hasattr(method, "transform_request"):
        return method.transform_request(request, credential)  # type: ignore[union-attr]
    return request
