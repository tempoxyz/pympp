"""Pydantic schemas and internal state for Tempo session payments.

Wire types use pydantic BaseModel (matching ChargeRequest/CredentialPayload).
ChannelState uses a frozen dataclass (internal state, not a wire type).

Ported from mpp-rs session.rs + session_method.rs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from mpp.errors import VerificationError

# --- Credential Payloads (discriminated union on `action`) ---


class OpenPayload(BaseModel):
    """Credential payload for opening a new payment channel."""

    action: Literal["open"]
    type: Literal["transaction"]
    channel_id: str = Field(alias="channelId")
    transaction: str
    authorized_signer: str | None = Field(None, alias="authorizedSigner")
    cumulative_amount: str = Field(alias="cumulativeAmount")
    signature: str

    model_config = {"populate_by_name": True}


class TopUpPayload(BaseModel):
    """Credential payload for topping up an existing channel."""

    action: Literal["topUp"]
    type: Literal["transaction"]
    channel_id: str = Field(alias="channelId")
    transaction: str
    additional_deposit: str = Field(alias="additionalDeposit")

    model_config = {"populate_by_name": True}


class VoucherPayload(BaseModel):
    """Credential payload for an off-chain payment voucher."""

    action: Literal["voucher"]
    channel_id: str = Field(alias="channelId")
    cumulative_amount: str = Field(alias="cumulativeAmount")
    signature: str

    model_config = {"populate_by_name": True}


class ClosePayload(BaseModel):
    """Credential payload for closing a channel."""

    action: Literal["close"]
    channel_id: str = Field(alias="channelId")
    cumulative_amount: str = Field(alias="cumulativeAmount")
    signature: str

    model_config = {"populate_by_name": True}


SessionCredentialPayload = OpenPayload | TopUpPayload | VoucherPayload | ClosePayload


def parse_session_payload(data: dict) -> SessionCredentialPayload:
    """Parse credential payload, dispatching on ``action`` field."""
    action = data.get("action")
    match action:
        case "open":
            return OpenPayload.model_validate(data)
        case "topUp":
            return TopUpPayload.model_validate(data)
        case "voucher":
            return VoucherPayload.model_validate(data)
        case "close":
            return ClosePayload.model_validate(data)
        case _:
            raise VerificationError(f"Unknown session action: {action}")


# --- Method Details (embedded in challenge methodDetails) ---


class SessionMethodDetails(BaseModel):
    """Tempo session-specific method details for challenge construction."""

    escrow_contract: str | None = Field(None, alias="escrowContract")
    channel_id: str | None = Field(None, alias="channelId")
    min_voucher_delta: str | None = Field(None, alias="minVoucherDelta")
    chain_id: int | None = Field(None, alias="chainId")
    fee_payer: bool | None = Field(None, alias="feePayer")

    model_config = {"populate_by_name": True}


# --- Channel State (stored in ChannelStore, not a wire type) ---


@dataclass(frozen=True, slots=True)
class ChannelState:
    """Server-side state for a payment channel.

    Frozen to prevent accidental mutation outside ``update_channel``.
    Use ``dataclasses.replace()`` to create modified copies.
    Mirrors mpp-rs ``ChannelState``.
    """

    channel_id: str
    chain_id: int
    escrow_contract: str
    payer: str
    payee: str
    token: str
    authorized_signer: str
    deposit: int
    settled_on_chain: int
    highest_voucher_amount: int
    highest_voucher_signature: bytes | None
    spent: int = 0
    units: int = 0
    finalized: bool = False
    created_at: str = ""
