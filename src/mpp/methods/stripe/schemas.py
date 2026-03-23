"""Pydantic schemas for Stripe payment requests and credentials."""

from __future__ import annotations

from pydantic import BaseModel, Field


class StripeMethodDetails(BaseModel):
    """Method-specific details for Stripe charge requests."""

    metadata: dict[str, str] | None = None
    networkId: str
    paymentMethodTypes: list[str] = Field(min_length=1)


class ChargeRequest(BaseModel):
    """Request schema for the Stripe charge intent.

    After the transform in ``stripe()``, ``amount`` is in the smallest
    currency unit (e.g. cents for USD) and ``decimals`` is removed.
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
    spt: str
