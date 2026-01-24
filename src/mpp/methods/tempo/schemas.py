"""Pydantic schemas for Tempo payment requests and credentials."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field


class MethodDetails(BaseModel):
    """Method-specific details for Tempo charge requests."""

    chainId: int = 4217
    feePayer: bool = False
    feePayerUrl: str | None = None
    memo: str | None = None


class ChargeRequest(BaseModel):
    """Request schema for the charge intent.

    Follows the IETF Payment Authentication Scheme spec for Tempo method.
    Expiry is conveyed exclusively via the challenge-level ``expires``
    auth-param, not inside the request body.
    """

    amount: str
    currency: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    recipient: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    description: str | None = None
    externalId: str | None = None
    methodDetails: MethodDetails = Field(default_factory=MethodDetails)


class HashCredentialPayload(BaseModel):
    """Credential payload when paying with a transaction hash."""

    type: Literal["hash"]
    hash: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]


class TransactionCredentialPayload(BaseModel):
    """Credential payload when paying with a signed transaction."""

    type: Literal["transaction"]
    signature: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]


CredentialPayload = HashCredentialPayload | TransactionCredentialPayload
