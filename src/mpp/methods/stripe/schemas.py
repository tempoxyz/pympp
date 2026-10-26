"""Pydantic schemas for Stripe payment requests and credentials."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    model_serializer,
    model_validator,
)

from mpp._units import parse_units
from mpp.methods import Method


class StripeMethodDetails(BaseModel):
    """Method-specific details for Stripe charge requests."""

    metadata: dict[str, str] | None = None
    networkId: str
    paymentMethodTypes: list[str] = Field(min_length=1)


class ChargeRequest(BaseModel):
    """Request schema for the Stripe charge intent.

    ``amount`` is in the smallest currency unit (e.g. cents for USD).
    """

    amount: str
    currency: str
    description: str | None = None
    externalId: str | None = None
    methodDetails: StripeMethodDetails
    recipient: str | None = None


class StripeCredentialPayload(BaseModel):
    """Credential payload for Stripe SPT-based payments."""

    externalId: str | None = None
    """Echo of the challenge request's ``externalId``, required when it has one."""
    spt: str


def _prepare_options(options: Any) -> Any:
    from mpp.methods.stripe.payment_intent_options import prepare_options

    return prepare_options(options)


class ChargeInput(BaseModel):
    """Route input for a Stripe charge, serialized to its wire :class:`ChargeRequest`.

    ``amount`` is a decimal string converted to the smallest currency unit with
    ``decimals``. ``network_id``, ``payment_method_types`` and ``metadata``
    serialize under ``methodDetails``. ``payment_intent_options`` is private,
    request-scoped PaymentIntent input that never enters the challenge.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    amount: str
    currency: str
    decimals: int = 2
    network_id: str = Field(alias="networkId")
    payment_method_types: list[str] = Field(alias="paymentMethodTypes", min_length=1)
    metadata: dict[str, str] | None = None
    recipient: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    extra: dict[str, str] | None = None
    payment_intent_options: Annotated[Any, AfterValidator(_prepare_options)] = None

    @model_validator(mode="after")
    def _check(self) -> ChargeInput:
        parse_units(self.amount, self.decimals)
        return self

    @model_serializer
    def _wire(self) -> dict[str, Any]:
        details: dict[str, Any] = {
            "networkId": self.network_id,
            "paymentMethodTypes": list(self.payment_method_types),
        }
        if self.metadata is not None:
            details["metadata"] = dict(self.metadata)
        wire: dict[str, Any] = {
            "amount": str(parse_units(self.amount, self.decimals)),
            "currency": self.currency,
            "methodDetails": details,
        }
        if self.recipient is not None:
            wire["recipient"] = self.recipient
        if self.external_id is not None:
            wire["externalId"] = self.external_id
        if self.extra is not None:
            wire["extra"] = dict(self.extra)
        return wire


charge: Method[ChargeInput, StripeCredentialPayload] = Method(
    name="stripe", intent="charge", request_model=ChargeInput, payload_model=StripeCredentialPayload
)
"""The Stripe charge method: a one-time payment with a Shared Payment Token."""
