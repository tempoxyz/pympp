"""Stripe payment method: one-time charges paid with Shared Payment Tokens (SPTs).

Use :mod:`mpp.stripe.client` and :mod:`mpp.stripe.server` for the configured method factories::

    from mpp.server import Mpp
    from mpp.stripe import server as stripe

    mppx = Mpp(methods=[stripe.charge(secret_key="sk_...", network_id="internal",
                                       payment_method_types=["card"])])

See https://github.com/tempoxyz/payment-auth-spec/blob/main/specs/methods/stripe/draft-stripe-charge-00.md
"""

from typing import Annotated, Any, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_serializer,
)

from mpp.method import Method
from mpp.stripe._internal.api import (
    PaymentIntent,
    StripeClient,
    StripeError,
    StripeHttpClient,
    StripeRawClient,
)
from mpp.stripe._internal.constants import STRIPE_PREVIEW_VERSION
from mpp.stripe._internal.payment_intent import (
    PaymentIntentOptions,
    ResolveContext,
    validate_input,
)
from mpp.stripe._internal.units import parse_units

Amount = Annotated[str, StringConstraints(pattern=r"^[0-9]+(\.[0-9]+)?$")]
"""Decimal amount string (e.g. ``"1"``, ``"0.50"``)."""


class ChargeRequest(BaseModel):
    """Stripe charge route input; serializes to the wire request.

    ``amount`` is converted to the currency's smallest unit using ``decimals`` and the Stripe
    options move under ``methodDetails``. ``payment_intent_options`` is server-only and never
    part of the challenge.
    """

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    amount: Amount
    currency: str
    decimals: Annotated[int, Field(strict=True)]
    description: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    metadata: dict[str, str] | None = None
    network_id: str = Field(alias="networkId")
    payment_intent_options: Any = Field(default=None, alias="paymentIntentOptions")
    payment_method_types: Annotated[list[str], Field(min_length=1)] = Field(
        alias="paymentMethodTypes"
    )
    recipient: str | None = None

    @field_validator("payment_intent_options", mode="before")
    @classmethod
    def _check_options(cls, value: Any) -> Any:
        return validate_input(value)

    @field_validator("decimals")
    @classmethod
    def _check_decimals(cls, value: int) -> int:
        if value < 0:
            raise ValueError("Decimals must be a non-negative integer.")
        return value

    @model_serializer
    def _serialize(self) -> dict[str, Any]:
        method_details: dict[str, Any] = {
            "networkId": self.network_id,
            "paymentMethodTypes": self.payment_method_types,
        }
        if self.metadata is not None:
            method_details["metadata"] = self.metadata
        wire: dict[str, Any] = {"currency": self.currency}
        for key, value in (
            ("description", self.description),
            ("externalId", self.external_id),
            ("recipient", self.recipient),
        ):
            if value is not None:
                wire[key] = value
        wire["amount"] = str(parse_units(self.amount, self.decimals))
        wire["methodDetails"] = method_details
        return wire


class ChargePayload(BaseModel):
    """Stripe charge credential payload."""

    model_config = ConfigDict(populate_by_name=True)

    external_id: str | None = Field(default=None, alias="externalId")
    spt: str


charge: Final = Method(
    name="stripe", intent="charge", request_model=ChargeRequest, payload_model=ChargePayload
)
"""Stripe charge intent for one-time payments via Shared Payment Tokens (SPTs)."""

__all__ = [
    "STRIPE_PREVIEW_VERSION",
    "ChargePayload",
    "ChargeRequest",
    "PaymentIntent",
    "PaymentIntentOptions",
    "ResolveContext",
    "StripeClient",
    "StripeError",
    "StripeHttpClient",
    "StripeRawClient",
    "charge",
]
