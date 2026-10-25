"""A Tempo-like charge method (request transforms like mppx ``tempo`` ``Methods.charge``)."""

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from mpp import Method


class ChargeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    amount: str
    currency: str
    recipient: str
    decimals: int | None = Field(default=None, exclude=True)
    chain_id: int | None = Field(default=None, alias="chainId")
    fee_payer: bool | None = Field(default=None, alias="feePayer")

    @model_serializer(mode="plain")
    def _wire(self) -> dict[str, Any]:
        amount = self.amount
        if self.decimals is not None:
            amount = str(int(Decimal(amount) * (Decimal(10) ** self.decimals)))
        details = {
            key: value
            for key, value in {"chainId": self.chain_id, "feePayer": self.fee_payer}.items()
            if value is not None
        }
        wire: dict[str, Any] = {"amount": amount, "currency": self.currency}
        if details:
            wire["methodDetails"] = details
        wire["recipient"] = self.recipient
        return wire


class ChargePayload(BaseModel):
    type: str
    signature: str | None = None
    hash: str | None = None


charge_method = Method(
    name="tempo", intent="charge", request_model=ChargeRequest, payload_model=ChargePayload
)
