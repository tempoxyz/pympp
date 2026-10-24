"""Method protocol for payment method implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mpp._units import _parse_decimal, parse_units
from mpp.methods import CanOfferFn, PaymentSuccessHandler

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mpp import Challenge, Credential
    from mpp.server.intent import Intent, VerifiableIntent


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
            def intents(self) -> Mapping[str, Intent | VerifiableIntent]:
                return {"charge": StripeChargeIntent(self.api_key)}

            async def create_credential(self, challenge: Challenge) -> Credential:
                # Create Stripe payment intent and return credential
                ...
    """

    name: str

    @property
    def intents(self) -> Mapping[str, Intent | VerifiableIntent]:
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


@runtime_checkable
class _SupportsCanOffer(Protocol):
    """A method that can decide whether to advertise a prepared offer."""

    can_offer: CanOfferFn | None


@runtime_checkable
class _SupportsPaymentSuccess(Protocol):
    """A method that handles its own successfully verified payments."""

    on_payment_success: PaymentSuccessHandler | None


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


def request_amount(method: Method, amount: str) -> str:
    """Convert a route's amount option to the method's wire ``amount``.

    A method that defines ``parse_amount(amount: str) -> str`` owns its wire
    representation, as a method's request schema does in mppx; a method whose
    wire format is a decimal string can return ``amount`` unchanged. The hook
    receives a stripped, finite, non-negative decimal string. Otherwise
    the amount is converted to base units with the method's ``decimals``
    (default 6).
    """
    hook = getattr(method, "parse_amount", None)
    if hook is None:
        return str(parse_units(amount, getattr(method, "decimals", 6)))
    _parse_decimal(amount)
    wire_amount = hook(amount.strip())
    if not isinstance(wire_amount, str) or not wire_amount:
        raise TypeError("parse_amount must return a non-empty string")
    return wire_amount


def prepare_intent(
    method: Method,
    intent: Intent | VerifiableIntent,
    input: Mapping[str, Any],
) -> tuple[Intent | VerifiableIntent, dict[str, Any]]:
    """Bind private method input to an isolated intent before request construction.

    Optional method hooks must only prepare input, never execute deferred work.
    Existing methods need not implement this hook. Neither the caller's mapping
    nor the shared method/intent may be mutated by a hook.
    """
    hook = getattr(method, "prepare_intent", None)
    if hook is None:
        return intent, dict(input)
    prepared = hook(intent, dict(input))
    if not isinstance(prepared, tuple) or len(prepared) != 2 or not isinstance(prepared[1], dict):
        raise TypeError("prepare_intent must return (intent, request_input)")
    return prepared
