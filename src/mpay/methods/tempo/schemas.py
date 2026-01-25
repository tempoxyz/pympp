"""Pydantic schemas for Tempo payment requests and credentials."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field


class ChargeRequest(BaseModel):
    """Request schema for the charge intent."""

    amount: str
    asset: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    destination: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    expires: str
    fee_payer: bool = False
    fee_payer_url: str | None = None


class HashCredentialPayload(BaseModel):
    """Credential payload when paying with a transaction hash."""

    type: Literal["hash"]
    hash: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]


class TransactionCredentialPayload(BaseModel):
    """Credential payload when paying with a signed transaction."""

    type: Literal["transaction"]
    signature: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]


CredentialPayload = HashCredentialPayload | TransactionCredentialPayload
