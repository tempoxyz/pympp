"""Pydantic schemas for Tempo payment requests and credentials."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

ALLOWED_FEE_PAYER_DOMAINS = frozenset(
    {
        "sponsor.moderato.tempo.xyz",
        "sponsor.tempo.xyz",
    }
)


class MethodDetails(BaseModel):
    """Method-specific details for Tempo charge requests."""

    chainId: int = 42431
    feePayer: bool = False
    feePayerUrl: str | None = None

    @field_validator("feePayerUrl")
    @classmethod
    def validate_fee_payer_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("feePayerUrl must use HTTPS")
        if parsed.hostname not in ALLOWED_FEE_PAYER_DOMAINS:
            raise ValueError(f"feePayerUrl domain not allowed: {parsed.hostname}")
        return v


class ChargeRequest(BaseModel):
    """Request schema for the charge intent.

    Follows the IETF Payment Authentication Scheme spec for Tempo method.
    """

    amount: str
    currency: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]
    recipient: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{40}$")]
    expires: str
    methodDetails: MethodDetails = Field(default_factory=MethodDetails)


class HashCredentialPayload(BaseModel):
    """Credential payload when paying with a transaction hash."""

    type: Literal["hash"]
    hash: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]{64}$")]


class TransactionCredentialPayload(BaseModel):
    """Credential payload when paying with a signed transaction."""

    type: Literal["transaction"]
    signature: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]


CredentialPayload = HashCredentialPayload | TransactionCredentialPayload
