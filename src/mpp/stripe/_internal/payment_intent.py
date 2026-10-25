"""Server-only Stripe PaymentIntent options and their lazy resolution."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import BaseModel, StringConstraints

from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.method import VerifiedChallengeEnvelope, resolve

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]


class TaxInputs(BaseModel):
    calculation: NonEmptyStr


class HookInputs(BaseModel):
    tax: TaxInputs


class PaymentIntentHooks(BaseModel):
    inputs: HookInputs


class PaymentIntentOptions(BaseModel):
    """Stripe PaymentIntent options accepted only by server-side route input.

    Unknown keys are ignored, so fields owned by mpp (``amount``, ``currency``, ``confirm``, …)
    can never be overridden.
    """

    customer: NonEmptyStr | None = None
    hooks: PaymentIntentHooks | None = None
    metadata: dict[str, str] | None = None
    receipt_email: NonEmptyStr | None = None

    def to_params(self) -> dict[str, Any]:
        """Returns the Stripe API params (``None`` fields omitted)."""
        return self.model_dump(exclude_none=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolveContext:
    """Context provided when resolving request-scoped Stripe options.

    Attributes:
        challenge: The verified challenge.
        credential: The credential being settled.
        envelope: The verified challenge envelope, when available.
        request: The canonical (wire) request.
    """

    challenge: Challenge
    credential: Credential[Any]
    request: Mapping[str, Any]
    envelope: VerifiedChallengeEnvelope[Any] | None = None


type OptionsValue = PaymentIntentOptions | Mapping[str, Any]
type ResolveOptions = Callable[
    [ResolveContext], OptionsValue | Awaitable[OptionsValue | None] | None
]
"""Lazily resolves PaymentIntent options right before the terminal payment operation."""
type OptionsInput = OptionsValue | ResolveOptions

OPTIONS_KEYS = ("payment_intent_options", "paymentIntentOptions")
"""Route-input keys carrying PaymentIntent options (Python name and mppx wire-style name)."""


def validate_input(value: Any) -> Any:
    """Validates a route-input value: resolvers are kept as-is (not invoked), options parsed."""
    if value is None or callable(value):
        return value
    return PaymentIntentOptions.model_validate(value)


def split_request(request: Mapping[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Separates the PaymentIntent options input from the rest of the route input."""
    options = next((request[key] for key in OPTIONS_KEYS if request.get(key) is not None), None)
    rest = {key: value for key, value in request.items() if key not in OPTIONS_KEYS}
    return options, rest


async def resolve_options(
    value: OptionsInput | None, context: ResolveContext
) -> PaymentIntentOptions | None:
    """Resolves (calling a resolver when given) and validates PaymentIntent options."""
    options = await resolve(value(context)) if callable(value) else value
    if options is None:
        return None
    return PaymentIntentOptions.model_validate(options)
