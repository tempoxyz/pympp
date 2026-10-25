"""Tempo method definitions: request and credential-payload schemas.

Each request model validates route input (decimal ``amount`` plus
``decimals``, Tempo options at the top level) and serializes to the wire
request (``amount`` in base units, Tempo options under ``methodDetails``),
exactly like the mppx zod schemas.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    RootModel,
    StrictInt,
    StringConstraints,
    field_validator,
    model_serializer,
    model_validator,
)

from mpp.method import Method
from mpp.tempo import attribution
from mpp.tempo._internal.units import parse_units

__all__ = [
    "CHARGE_MODES",
    "Amount",
    "ChargeMode",
    "ChargePayload",
    "ChargeRequest",
    "FeePayer",
    "Hash",
    "HashPayload",
    "HexAddress",
    "ProofPayload",
    "Signature",
    "Split",
    "TransactionPayload",
    "charge",
]


type ChargeMode = Literal["push", "pull"]
CHARGE_MODES: Final[tuple[ChargeMode, ...]] = ("push", "pull")

type SubscriptionPeriodUnit = Literal["dev_second", "day", "week"]

_UINT64_MAX: Final = (1 << 64) - 1
_PERIOD_UNIT_SECONDS: Final[dict[str, int]] = {"dev_second": 1, "day": 86_400, "week": 604_800}
_MAX_SAFE_INTEGER: Final = 2**53 - 1

Amount = Annotated[str, StringConstraints(pattern=r"^[0-9]+(\.[0-9]+)?$")]
"""Numeric string amount (e.g. ``"1"``, ``"1.5"``)."""
Hash = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]
HexAddress = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
Signature = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]+$")]


def _sponsor_flag(value: Any) -> Any:
    """``feePayer`` accepts a boolean or a fee-payer account (meaning ``true``)."""
    return value if isinstance(value, bool) or value is None else True


FeePayer = Annotated[bool, BeforeValidator(_sponsor_flag)]

_INPUT_CONFIG: Final = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


def _without_none(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


# -- charge ------------------------------------------------------------------------------------


FIXED_ATTRIBUTION_MEMO_ERROR: Final = (
    "Fixed split memos must not use MPP attribution; omit the memo"
)


class Split(BaseModel):
    model_config = _INPUT_CONFIG

    amount: Amount
    memo: Hash | None = None
    recipient: str

    @field_validator("memo")
    @classmethod
    def _reject_attribution_memo(cls, memo: str | None) -> str | None:
        # A fixed leg carrying an MPP attribution memo could also pay the challenge it names.
        # Omit the memo so the client binds the leg to the current challenge.
        if memo is not None and attribution.is_mpp_memo(memo):
            raise ValueError(FIXED_ATTRIBUTION_MEMO_ERROR)
        return memo


class ChargeRequest(BaseModel):
    """Tempo charge request (one-time TIP-20 transfer)."""

    model_config = _INPUT_CONFIG

    amount: Amount
    currency: str
    decimals: StrictInt
    chain_id: StrictInt | None = Field(default=None, alias="chainId")
    description: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    fee_payer: FeePayer | None = Field(default=None, alias="feePayer")
    memo: None = None
    recipient: str | None = None
    splits: Annotated[list[Split], Field(min_length=1, max_length=10)] | None = None
    supported_modes: Annotated[list[ChargeMode], Field(min_length=1)] | None = Field(
        default=None, alias="supportedModes"
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_memo(cls, data: Any) -> Any:
        if isinstance(data, dict) and "memo" in data:
            raise ValueError("Invalid input: expected never")
        return data

    @model_validator(mode="after")
    def _check_splits(self) -> ChargeRequest:
        if self.splits is None:
            return self
        total = parse_units(self.amount, self.decimals)
        amounts = [parse_units(split.amount, self.decimals) for split in self.splits]
        if not all(amount > 0 for amount in amounts) or sum(amounts) >= total:
            raise ValueError("Invalid splits")
        return self

    @model_serializer
    def _serialize(self) -> dict[str, Any]:
        method_details = _without_none(
            {
                "chainId": self.chain_id,
                "feePayer": self.fee_payer,
                "splits": None
                if self.splits is None
                else [
                    _without_none(
                        {
                            "amount": str(parse_units(split.amount, self.decimals)),
                            "memo": split.memo,
                            "recipient": split.recipient,
                        }
                    )
                    for split in self.splits
                ],
                "supportedModes": self.supported_modes,
            }
        )
        return _without_none(
            {
                "currency": self.currency,
                "description": self.description,
                "externalId": self.external_id,
                "recipient": self.recipient,
                "amount": str(parse_units(self.amount, self.decimals)),
                "methodDetails": method_details or None,
            }
        )


class HashPayload(BaseModel):
    type: Literal["hash"]
    hash: Hash


class TransactionPayload(BaseModel):
    type: Literal["transaction"]
    signature: Signature


class ProofPayload(BaseModel):
    type: Literal["proof"]
    signature: Signature


class ChargePayload(
    RootModel[
        Annotated[HashPayload | TransactionPayload | ProofPayload, Field(discriminator="type")]
    ]
):
    """Charge credential payload: a pushed tx ``hash``, a signed ``transaction``, or a ``proof``."""


charge: Final = Method(
    name="tempo", intent="charge", request_model=ChargeRequest, payload_model=ChargePayload
)
"""Tempo charge intent for one-time TIP-20 token transfers."""
