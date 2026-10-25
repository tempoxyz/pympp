"""EVM charge wire types (``evm/charge``) and EIP-3009 helpers."""

from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_serializer,
)

from mpp import _json
from mpp.method import Method
from mpp.x402._evm import get_address, parse_units
from mpp.x402._exact import AUTHORIZATION_TYPES

PAYMENT_METHOD: Final = "evm"
"""Payment method name for Payment-auth EVM challenges."""
CHARGE_INTENT: Final = "charge"
"""Payment intent name for one-time EVM charges."""
EVM_NETWORK_PREFIX: Final = "eip155:"
"""CAIP-2 namespace prefix for EVM networks."""
EIP3009: Final = "eip3009"
"""EIP-3009 transfer authorization method identifier."""
CREDENTIAL_TYPES: Final = ("authorization",)
"""EVM charge credential types supported by this package."""

type CredentialType = Literal["authorization"]

Amount = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9]+(\.[0-9]+)?$")]
AtomicAmount = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9]+$")]
Address = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
Hash = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]
Signature = Annotated[StrictStr, StringConstraints(pattern=r"^0x[0-9a-fA-F]+$")]
CredentialTypes = Annotated[list[CredentialType], Field(min_length=1)]

_CONFIG: Final = ConfigDict(populate_by_name=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizationConfig:
    """EIP-3009 token domain metadata for ``transferWithAuthorization`` signatures."""

    name: str
    version: str

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("EVM authorization metadata requires a non-empty name and version.")


class Split(BaseModel):
    """A payment split (atomic amount to an additional recipient)."""

    model_config = _CONFIG

    amount: AtomicAmount
    recipient: Address


class MethodDetails(BaseModel):
    """EVM-specific charge method details (``request.methodDetails``)."""

    model_config = _CONFIG

    chain_id: StrictInt = Field(alias="chainId")
    credential_types: CredentialTypes | None = Field(default=None, alias="credentialTypes")
    decimals: StrictInt | None = None
    permit2_address: Address | None = Field(default=None, alias="permit2Address")
    splits: list[Split] | None = None


class ChargeRequest(BaseModel):
    """Canonical (wire) Payment-auth EVM charge request."""

    model_config = _CONFIG

    amount: AtomicAmount
    currency: Address
    description: StrictStr | None = None
    external_id: StrictStr | None = Field(default=None, alias="externalId")
    method_details: MethodDetails = Field(alias="methodDetails")
    recipient: Address


class ChargeRequestInput(BaseModel):
    """Route input: display-unit ``amount`` plus EVM options at the top level.

    Serializes to the wire :class:`ChargeRequest` (atomic amount, checksummed addresses, EVM
    options under ``methodDetails``, ``credentialTypes`` defaulting to ``["authorization"]``).
    """

    model_config = _CONFIG

    amount: Amount
    chain_id: StrictInt = Field(alias="chainId")
    currency: Address
    credential_types: CredentialTypes | None = Field(default=None, alias="credentialTypes")
    decimals: StrictInt
    description: StrictStr | None = None
    external_id: StrictStr | None = Field(default=None, alias="externalId")
    permit2_address: Address | None = Field(default=None, alias="permit2Address")
    recipient: Address
    splits: list[Split] | None = None

    @model_serializer
    def _serialize(self) -> dict[str, Any]:
        method_details: dict[str, Any] = {
            "chainId": self.chain_id,
            "credentialTypes": list(self.credential_types or CREDENTIAL_TYPES),
            "decimals": self.decimals,
        }
        if self.permit2_address:
            method_details["permit2Address"] = get_address(self.permit2_address)
        if self.splits:
            method_details["splits"] = [split.model_dump(by_alias=True) for split in self.splits]
        wire: dict[str, Any] = {}
        if self.description is not None:
            wire["description"] = self.description
        if self.external_id is not None:
            wire["externalId"] = self.external_id
        wire["amount"] = str(parse_units(self.amount, self.decimals))
        wire["currency"] = get_address(self.currency)
        wire["methodDetails"] = method_details
        wire["recipient"] = get_address(self.recipient)
        return wire


class AuthorizationPayload(BaseModel):
    """Payment-auth EVM ``authorization`` credential payload (EIP-3009)."""

    model_config = _CONFIG

    from_: Address = Field(alias="from")
    nonce: Hash
    signature: Signature
    to: Address
    type: Literal["authorization"]
    valid_after: AtomicAmount = Field(alias="validAfter")
    valid_before: AtomicAmount = Field(alias="validBefore")
    value: AtomicAmount

    def to_dict(self) -> dict[str, Any]:
        """Returns the wire (camelCase) JSON object."""
        return self.model_dump(mode="json", by_alias=True)


ChargePayload = AuthorizationPayload
"""Payment-auth EVM charge credential payload."""

charge: Final = Method(
    name=PAYMENT_METHOD,
    intent=CHARGE_INTENT,
    request_model=ChargeRequestInput,
    payload_model=AuthorizationPayload,
)
"""Native Payment-auth EVM charge method."""


def authorization_domain(
    *, authorization: AuthorizationConfig, chain_id: int, currency: str
) -> dict[str, Any]:
    """Returns the EIP-712 domain for an EIP-3009 authorization signature."""
    return {
        "chainId": chain_id,
        "name": authorization.name,
        "verifyingContract": currency,
        "version": authorization.version,
    }


def authorization_typed_data(
    *,
    authorization: AuthorizationConfig,
    chain_id: int,
    currency: str,
    from_: str,
    to: str,
    value: int | str,
    valid_after: int | str,
    valid_before: int | str,
    nonce: str,
) -> dict[str, Any]:
    """Returns the full EIP-712 ``TransferWithAuthorization`` typed-data message."""
    return {
        "domain": authorization_domain(
            authorization=authorization, chain_id=chain_id, currency=get_address(currency)
        ),
        "message": {
            "from": get_address(from_),
            "nonce": nonce,
            "to": get_address(to),
            "validAfter": int(valid_after),
            "validBefore": int(valid_before),
            "value": int(value),
        },
        "primaryType": "TransferWithAuthorization",
        "types": AUTHORIZATION_TYPES,
    }


def challenge_hash(*, id: str, realm: str) -> str:
    """Computes the challenge hash used as the EIP-3009 nonce.

    ``keccak256(JSON.stringify([id, realm]))`` so that id and realm are framed distinctly.
    """
    from eth_hash.auto import keccak

    return "0x" + keccak(_json.dumps([id, realm]).encode()).hex()


def network_of(chain_id: int) -> str:
    """Converts a chain id to the CAIP-2 EVM network identifier."""
    return f"{EVM_NETWORK_PREFIX}{chain_id}"


def to_source(*, address: str, chain_id: int) -> str:
    """Formats an EVM address as a ``did:pkh`` source identifier."""
    return f"did:pkh:eip155:{chain_id}:{address}"
