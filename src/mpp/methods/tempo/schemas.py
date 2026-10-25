"""Pydantic schemas for Tempo payment requests and credentials."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field


class Split(BaseModel):
    """A single split in a split payment."""

    amount: str
    recipient: str
    memo: str | None = None


FIXED_ATTRIBUTION_MEMO_ERROR = "Fixed split memos must not use MPP attribution; omit the memo"


def is_fixed_attribution_memo(memo: object) -> bool:
    """Return whether a fixed split ``memo`` uses the MPP attribution format."""
    from mpp.methods.tempo._attribution import is_mpp_memo

    if not isinstance(memo, str):
        return False
    try:
        raw = bytes.fromhex(memo.removeprefix("0x"))
    except ValueError:
        return False  # Calldata encoding reports malformed hex.
    return is_mpp_memo("0x" + raw.hex())


def reject_fixed_attribution_memos(request: Mapping[str, Any]) -> None:
    """Refuse a charge request whose fixed split memos use MPP attribution.

    Such a split transfer could also pay the challenge its memo names. Checked
    before a server issues a challenge and before a client pays one. Parsing
    stays permissive, so credentials for outstanding challenges fail
    verification with ``CredentialReplayedError``.
    """
    details = request.get("methodDetails")
    if not isinstance(details, Mapping):
        return
    splits = details.get("splits")
    if not isinstance(splits, list):
        return
    for split in splits:
        if isinstance(split, Mapping) and is_fixed_attribution_memo(split.get("memo")):
            raise ValueError(FIXED_ATTRIBUTION_MEMO_ERROR)


class MethodDetails(BaseModel):
    """Method-specific details for Tempo charge requests."""

    chainId: int = 4217
    feePayer: bool = False
    feePayerUrl: str | None = Field(
        default=None,
        description=(
            "External signing service. It must authorize, validate, simulate, and enforce "
            "gas and spending limits before returning a broadcastable signature; "
            "pympp does not enforce the external sponsor's policy."
        ),
    )
    splits: list[Split] | None = None


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
