"""x402 v2 wire types (``PAYMENT-REQUIRED`` / ``PAYMENT-SIGNATURE`` / ``PAYMENT-RESPONSE``).

Fields are declared in the same (alphabetical) order as the mppx zod schemas so that encoded
headers are byte-for-byte identical. Unknown keys are dropped, like zod objects.
"""

from collections.abc import Awaitable, Mapping
from typing import Annotated, Any, Final, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

PAYMENT_METHOD: Final = "evm"
"""mppx method name used for EVM charge challenges backed by x402."""
EXACT_INTENT: Final = "charge"
"""mppx intent name used for EVM charge challenges backed by x402 exact."""
VERSIONS: Final = (2,)
SCHEMES: Final = ("exact",)
ASSET_TRANSFER_METHODS: Final = ("eip3009", "permit2")
EVM_NETWORK_PREFIX: Final = "eip155:"
SYNTHETIC_CHALLENGE_ID_PREFIX: Final = "x402:"
"""Prefix for synthetic challenge ids derived from x402 ``accepts`` entries."""

PAYMENT_REQUIRED_HEADER: Final = "PAYMENT-REQUIRED"
"""Header carrying a base64-encoded x402 payment-required response."""
PAYMENT_SIGNATURE_HEADER: Final = "PAYMENT-SIGNATURE"
"""Header carrying a base64-encoded x402 payment payload."""
LEGACY_PAYMENT_SIGNATURE_HEADER: Final = "X-PAYMENT"
"""Legacy header carrying an x402 v1 payment payload."""
PAYMENT_RESPONSE_HEADER: Final = "PAYMENT-RESPONSE"
"""Header carrying a base64-encoded x402 settlement response."""

type Scheme = Literal["exact"]
type AssetTransferMethod = Literal["eip3009", "permit2"]

NonEmptyString = Annotated[StrictStr, StringConstraints(min_length=1)]
AtomicAmount = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9]+$")]
Address = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
Hash = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]
Signature = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]+$")]
EvmNetwork = Annotated[StrictStr, StringConstraints(pattern=r"^eip155:[0-9]+$")]
"""CAIP-2 EVM network identifier (``eip155:<chainId>``)."""
PositiveNumber = Annotated[StrictInt | StrictFloat, Field(gt=0, allow_inf_nan=False)]

_CONFIG: Final = ConfigDict(populate_by_name=True, frozen=True)


class _Model(BaseModel):
    """Base x402 model: optional fields may be omitted but not ``null`` (zod ``z.optional``)."""

    model_config = _CONFIG

    @model_validator(mode="before")
    @classmethod
    def _reject_null(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            for name, field in cls.model_fields.items():
                for key in {name, field.alias}:
                    if key is not None and key in data and data[key] is None:
                        raise ValueError(f"`{field.alias or name}` must not be null")
        return data

    def to_dict(self) -> dict[str, Any]:
        """Returns the wire (camelCase) JSON object."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ResourceInfo(_Model):
    """Describes the protected resource in x402 v2 payment-required responses."""

    description: StrictStr | None = None
    icon_url: StrictStr | None = Field(default=None, alias="iconUrl")
    mime_type: StrictStr | None = Field(default=None, alias="mimeType")
    service_name: StrictStr | None = Field(default=None, alias="serviceName")
    tags: list[StrictStr] | None = None
    url: NonEmptyString


class PaymentRequirements(_Model):
    """x402 v2 payment requirements for the ``exact`` scheme."""

    amount: AtomicAmount
    asset: NonEmptyString
    extra: dict[str, Any] | None = None
    max_timeout_seconds: PositiveNumber = Field(alias="maxTimeoutSeconds")
    network: EvmNetwork
    pay_to: NonEmptyString = Field(alias="payTo")
    scheme: Scheme


class Extension(_Model):
    """x402 v2 protocol extension value."""

    info: dict[str, Any]
    schema_: dict[str, Any] = Field(alias="schema")


type Extensions = dict[str, Extension]
"""x402 v2 protocol extensions map."""


class PaymentRequired(_Model):
    """x402 v2 payment-required response (``PAYMENT-REQUIRED`` header body)."""

    accepts: Annotated[list[PaymentRequirements], Field(min_length=1)]
    error: StrictStr | None = None
    extensions: dict[str, Extension] | None = None
    resource: ResourceInfo
    x402_version: Literal[2] = Field(alias="x402Version")


class Eip3009Authorization(_Model):
    """EIP-3009 ``transferWithAuthorization`` parameters."""

    from_: Address = Field(alias="from")
    nonce: Hash
    to: Address
    valid_after: AtomicAmount = Field(alias="validAfter")
    valid_before: AtomicAmount = Field(alias="validBefore")
    value: AtomicAmount


class ExactEip3009Payload(_Model):
    """EIP-3009 transferWithAuthorization payload for exact EVM payments."""

    authorization: Eip3009Authorization
    signature: Signature


class Permit2Permitted(_Model):
    amount: AtomicAmount
    token: Address


class Permit2Witness(_Model):
    to: Address
    valid_after: AtomicAmount = Field(alias="validAfter")


class Permit2Authorization(_Model):
    deadline: AtomicAmount
    from_: Address = Field(alias="from")
    nonce: AtomicAmount
    permitted: Permit2Permitted
    spender: Address
    witness: Permit2Witness


class ExactPermit2Payload(_Model):
    """Permit2 payload for exact EVM payments."""

    permit2_authorization: Permit2Authorization = Field(alias="permit2Authorization")
    signature: Signature


type ExactPayload = ExactEip3009Payload | ExactPermit2Payload


class PaymentPayload(_Model):
    """x402 v2 payment payload (``PAYMENT-SIGNATURE`` header body)."""

    accepted: PaymentRequirements
    extensions: dict[str, Extension] | None = None
    payload: Annotated[ExactEip3009Payload | ExactPermit2Payload, Field(union_mode="left_to_right")]
    resource: ResourceInfo | None = None
    x402_version: Literal[2] = Field(alias="x402Version")


class VerifyResponse(_Model):
    """Facilitator verification response."""

    extensions: dict[str, Extension] | None = None
    extra: dict[str, Any] | None = None
    invalid_message: StrictStr | None = Field(default=None, alias="invalidMessage")
    invalid_reason: StrictStr | None = Field(default=None, alias="invalidReason")
    is_valid: StrictBool = Field(alias="isValid")
    payer: StrictStr | None = None


class SettleResponse(_Model):
    """Facilitator settlement response and ``PAYMENT-RESPONSE`` header body."""

    amount: AtomicAmount | None = None
    error_message: StrictStr | None = Field(default=None, alias="errorMessage")
    error_reason: StrictStr | None = Field(default=None, alias="errorReason")
    extensions: dict[str, Extension] | None = None
    extra: dict[str, Any] | None = None
    network: NonEmptyString
    payer: StrictStr | None = None
    success: StrictBool
    transaction: StrictStr


class Facilitator(Protocol):
    """x402 facilitator client used for verification and settlement.

    Implementations may return model instances or plain wire dicts; results are validated.
    """

    def verify(
        self, payment_payload: PaymentPayload, payment_requirements: PaymentRequirements, /
    ) -> Awaitable[VerifyResponse | Mapping[str, Any]]: ...

    def settle(
        self, payment_payload: PaymentPayload, payment_requirements: PaymentRequirements, /
    ) -> Awaitable[SettleResponse | Mapping[str, Any]]: ...


def to_payment_requirements(request: Mapping[str, Any]) -> PaymentRequirements:
    """Extracts x402 :class:`PaymentRequirements` from a canonical exact request.

    The exact request is the ``PaymentRequirements`` object plus optional ``extensions`` and
    ``resource`` (the shape of synthesized x402 challenge requests).
    """
    fields = {key: value for key, value in request.items() if key not in ("extensions", "resource")}
    return PaymentRequirements.model_validate(fields)


def chain_id_of(network: str) -> int:
    """Converts a CAIP-2 EVM network identifier to its chain id."""
    return int(network[len(EVM_NETWORK_PREFIX) :])
