"""Pydantic schemas for Tempo payment requests and credentials."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_serializer, model_validator

from mpp._units import parse_units
from mpp.methods import Method


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


class ChargeInput(BaseModel):
    """Route input for a Tempo charge, serialized to its wire :class:`ChargeRequest`.

    ``amount`` is a decimal string converted to base units with ``decimals``;
    ``splits`` are already in base units. ``chain_id``, ``fee_payer`` and
    ``splits`` serialize under ``methodDetails``; ``extra`` is string metadata
    embedded in the request.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    amount: str
    currency: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    recipient: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
    decimals: int = 6
    chain_id: int | None = Field(default=None, alias="chainId")
    fee_payer: bool = Field(default=False, alias="feePayer")
    splits: list[Split] | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    extra: dict[str, str] | None = None

    @model_validator(mode="after")
    def _check(self) -> ChargeInput:
        parse_units(self.amount, self.decimals)
        if self.splits and self.fee_payer:
            raise ValueError("splits and fee_payer cannot be used together")
        if any(is_fixed_attribution_memo(split.memo) for split in self.splits or ()):
            raise ValueError(FIXED_ATTRIBUTION_MEMO_ERROR)
        return self

    @model_serializer
    def _wire(self) -> dict[str, Any]:
        details: dict[str, Any] = {}
        if self.splits:
            details["splits"] = [split.model_dump(exclude_none=True) for split in self.splits]
        if self.fee_payer:
            details["feePayer"] = True
        if self.chain_id is not None:
            details["chainId"] = self.chain_id
        wire: dict[str, Any] = {
            "amount": str(parse_units(self.amount, self.decimals)),
            "currency": self.currency,
            "recipient": self.recipient,
        }
        if self.external_id is not None:
            wire["externalId"] = self.external_id
        if self.extra is not None:
            wire["extra"] = dict(self.extra)
        if details:
            wire["methodDetails"] = details
        return wire


class ChargePayload(RootModel[Annotated[CredentialPayload, Field(discriminator="type")]]):
    """Charge credential payload: a pushed transaction ``hash`` or a signed ``transaction``."""


charge: Method[ChargeInput, ChargePayload] = Method(
    name="tempo", intent="charge", request_model=ChargeInput, payload_model=ChargePayload
)
"""The Tempo charge method: a one-time TIP-20 transfer."""
