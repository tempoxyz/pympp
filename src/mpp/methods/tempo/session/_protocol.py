"""TIP-1034 session protocol types shared by servers and clients (mppx precompile/Protocol.ts).

Also holds the `tempo/session` method definition: its request transform and
credential payload models (mppx `Methods.session`).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_serializer, model_validator

from mpp._typing import is_dict
from mpp._units import parse_units
from mpp.methods import Method

ESCROW_ADDRESS = "0x4d50500000000000000000000000000000000000"
"""Canonical TIP20EscrowChannel precompile address (mppx `tip20ChannelEscrow`)."""

UINT96_MAX = (1 << 96) - 1
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

SESSION_PROTOCOL_V2 = "v2"
"""TIP-1034 precompile-backed Tempo session protocol."""

SESSION_CREDENTIAL_ACTIONS: frozenset[str] = frozenset({"open", "topUp", "voucher", "close"})

_UINT96_AMOUNT_RE = re.compile(r"^\d{1,29}$")


def is_uint96(value: int) -> bool:
    return 0 <= value <= UINT96_MAX


def uint96(value: int) -> int:
    """Return `value` after checking it fits a TIP-1034 `uint96` amount."""
    if not is_uint96(value):
        raise ValueError(f"Value {value} is outside uint96 bounds.")
    return value


def parse_uint96_amount(value: str) -> int | None:
    """Parse an unsigned decimal raw amount when it fits TIP-1034's `uint96` range."""
    if not _UINT96_AMOUNT_RE.fullmatch(value):
        return None
    amount = int(value)
    return amount if is_uint96(amount) else None


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelDescriptor:
    """Full TIP-1034 channel descriptor used to derive and verify a channel ID.

    Addresses and hashes are 0x-prefixed hex strings. `operator` and
    `authorized_signer` are the zero address when unset.
    """

    payer: str
    payee: str
    operator: str
    token: str
    salt: str
    authorized_signer: str
    expiring_nonce_hash: str

    def to_wire(self) -> dict[str, str]:
        """The camelCase JSON form mppx puts in credentials and snapshots."""
        return {
            "payer": self.payer,
            "payee": self.payee,
            "operator": self.operator,
            "token": self.token,
            "salt": self.salt,
            "authorizedSigner": self.authorized_signer,
            "expiringNonceHash": self.expiring_nonce_hash,
        }

    @classmethod
    def from_wire(cls, value: Any) -> ChannelDescriptor:
        """Parse the camelCase JSON form; raises ValueError when a field is missing."""
        if not isinstance(value, dict):
            raise ValueError("descriptor must be an object")
        try:
            return cls(
                payer=_str(value["payer"]),
                payee=_str(value["payee"]),
                operator=_str(value["operator"]),
                token=_str(value["token"]),
                salt=_str(value["salt"]),
                authorized_signer=_str(value["authorizedSigner"]),
                expiring_nonce_hash=_str(value["expiringNonceHash"]),
            )
        except KeyError as error:
            raise ValueError(f"descriptor is missing {error.args[0]}") from error


@dataclass(frozen=True, slots=True, kw_only=True)
class SignedVoucher:
    """A payer's signature over a cumulative amount for one channel."""

    channel_id: str
    cumulative_amount: int
    signature: str


def _str(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("descriptor fields must be strings")
    return value


# ──────────────────────────────────────────────────────────────────
# Credential payloads (mppx Methods.session credential schema)
# ──────────────────────────────────────────────────────────────────

_Hash = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{64}$")]
_Signature = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]+$")]
_Amount = Annotated[str, Field(pattern=r"^\d+(\.\d+)?$")]
_Address = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")]


class _PayloadBase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    channel_id: _Hash = Field(alias="channelId")
    descriptor: dict[str, Any] | None = None

    def channel_descriptor(self) -> ChannelDescriptor | None:
        """The payload's descriptor parsed into a :class:`ChannelDescriptor`, if present."""
        return None if self.descriptor is None else ChannelDescriptor.from_wire(self.descriptor)

    def to_wire(self) -> dict[str, Any]:
        """The camelCase JSON form sent in credentials."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class OpenPayload(_PayloadBase):
    """Opens a TIP-1034 channel with a signed transaction and authorizes initial spend."""

    action: Literal["open"] = "open"
    type: Literal["transaction"] = "transaction"
    transaction: _Signature
    signature: _Signature
    cumulative_amount: _Amount = Field(alias="cumulativeAmount")
    authorized_signer: str | None = Field(default=None, alias="authorizedSigner")


class TopUpPayload(_PayloadBase):
    """Adds deposit to an existing channel with a signed `topUp` transaction."""

    action: Literal["topUp"] = "topUp"
    type: Literal["transaction"] = "transaction"
    transaction: _Signature
    additional_deposit: _Amount = Field(alias="additionalDeposit")


class VoucherPayload(_PayloadBase):
    """Raises the channel's cumulative spend authorization."""

    action: Literal["voucher"] = "voucher"
    cumulative_amount: _Amount = Field(alias="cumulativeAmount")
    signature: _Signature


class ClosePayload(_PayloadBase):
    """Cooperatively closes the channel at a final cumulative amount."""

    action: Literal["close"] = "close"
    cumulative_amount: _Amount = Field(alias="cumulativeAmount")
    signature: _Signature
    close_signature: _Signature = Field(alias="closeSignature")


SessionCredentialPayload = OpenPayload | TopUpPayload | VoucherPayload | ClosePayload


class SessionPayload(RootModel[Annotated[SessionCredentialPayload, Field(discriminator="action")]]):
    """Session credential payload, discriminated on `action`."""


# ──────────────────────────────────────────────────────────────────
# Request (mppx Methods.session request transform)
# ──────────────────────────────────────────────────────────────────


class SessionRequest(BaseModel):
    """Route input for a Tempo session, serialized to its wire request.

    `amount`, `suggested_deposit` and `min_voucher_delta` are decimal strings converted
    to base units with `decimals`. Tempo-specific fields serialize under
    `methodDetails`, which is always present, as in mppx.
    """

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    amount: _Amount
    unit_type: str = Field(alias="unitType")
    currency: str
    decimals: int
    recipient: str | None = None
    chain_id: int | None = Field(default=None, alias="chainId")
    channel_id: _Hash | None = Field(default=None, alias="channelId")
    escrow_contract: str | None = Field(default=None, alias="escrowContract")
    fee_payer: Any = Field(default=None, alias="feePayer")
    fee_token: _Address | None = Field(default=None, alias="feeToken")
    min_voucher_delta: _Amount | None = Field(default=None, alias="minVoucherDelta")
    operator: _Address | None = None
    session_protocol: Literal["v2", "v1"] | None = Field(default=None, alias="sessionProtocol")
    session_snapshot: Any = Field(default=None, alias="sessionSnapshot")
    suggested_deposit: _Amount | None = Field(default=None, alias="suggestedDeposit")

    @model_validator(mode="after")
    def _check(self) -> SessionRequest:
        if parse_units(self.amount, self.decimals) <= 0:
            raise ValueError("Session amount must be greater than 0")
        if self.suggested_deposit is not None:
            parse_units(self.suggested_deposit, self.decimals)
        if self.min_voucher_delta is not None:
            parse_units(self.min_voucher_delta, self.decimals)
        return self

    @model_serializer
    def _wire(self) -> dict[str, Any]:
        details: dict[str, Any] = {}
        if self.escrow_contract is not None:
            details["escrowContract"] = self.escrow_contract
        if self.channel_id is not None:
            details["channelId"] = self.channel_id
        if self.min_voucher_delta is not None:
            details["minVoucherDelta"] = str(parse_units(self.min_voucher_delta, self.decimals))
        if self.chain_id is not None:
            details["chainId"] = self.chain_id
        if self.fee_payer is not None:
            # An account object means the server sponsors fees: advertise `true`.
            details["feePayer"] = self.fee_payer if isinstance(self.fee_payer, bool) else True
        if self.fee_token is not None:
            details["feeToken"] = self.fee_token
        if self.operator is not None:
            details["operator"] = self.operator
        if self.session_protocol is not None:
            details["sessionProtocol"] = self.session_protocol
        if self.session_snapshot is not None:
            details["sessionSnapshot"] = self.session_snapshot
        wire: dict[str, Any] = {
            "amount": str(parse_units(self.amount, self.decimals)),
            "currency": self.currency,
            "unitType": self.unit_type,
        }
        if self.recipient is not None:
            wire["recipient"] = self.recipient
        if self.suggested_deposit:
            wire["suggestedDeposit"] = str(parse_units(self.suggested_deposit, self.decimals))
        wire["methodDetails"] = details
        return wire


definition: Method[SessionRequest, SessionPayload] = Method(
    name="tempo", intent="session", request_model=SessionRequest, payload_model=SessionPayload
)
"""The Tempo session method: pay-as-you-go payments over a TIP-1034 channel."""


def is_session_credential_action(value: object) -> bool:
    """Return whether `value` is a supported session credential action."""
    return isinstance(value, str) and value in SESSION_CREDENTIAL_ACTIONS


# ──────────────────────────────────────────────────────────────────
# Receipts and need-voucher events
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class NeedVoucherEvent:
    """Sent when the session balance is exhausted; amounts are raw token units."""

    channel_id: str
    required_cumulative: int
    accepted_cumulative: int
    deposit: int

    def to_wire(self) -> dict[str, str]:
        return {
            "channelId": self.channel_id,
            "requiredCumulative": str(self.required_cumulative),
            "acceptedCumulative": str(self.accepted_cumulative),
            "deposit": str(self.deposit),
        }

    @classmethod
    def from_wire(cls, value: Any) -> NeedVoucherEvent:
        if not is_dict(value) or not all(
            isinstance(value.get(key), str)
            for key in ("channelId", "requiredCumulative", "acceptedCumulative", "deposit")
        ):
            raise ValueError("Invalid need-voucher event.")
        return cls(
            channel_id=value["channelId"],
            required_cumulative=int(value["requiredCumulative"]),
            accepted_cumulative=int(value["acceptedCumulative"]),
            deposit=int(value["deposit"]),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionReceipt:
    """Session receipt returned in the Payment-Receipt header (mppx `SessionReceipt`)."""

    timestamp: str
    reference: str
    challenge_id: str
    channel_id: str
    accepted_cumulative: str
    spent: str
    units: int | None = None
    tx_hash: str | None = None
    method: Literal["tempo"] = "tempo"
    intent: Literal["session"] = "session"
    status: Literal["success"] = "success"

    def to_wire(self) -> dict[str, Any]:
        """The JSON object mppx produces, in mppx's key order."""
        wire: dict[str, Any] = {
            "method": self.method,
            "intent": self.intent,
            "status": self.status,
            "timestamp": self.timestamp,
            "reference": self.reference,
            "challengeId": self.challenge_id,
            "channelId": self.channel_id,
            "acceptedCumulative": self.accepted_cumulative,
            "spent": self.spent,
        }
        if self.units is not None:
            wire["units"] = self.units
        if self.tx_hash is not None:
            wire["txHash"] = self.tx_hash
        return wire

    @classmethod
    def from_wire(cls, value: Any) -> SessionReceipt:
        if not is_session_receipt(value):
            raise ValueError("Invalid session receipt.")
        return cls(
            timestamp=value["timestamp"],
            reference=value["reference"],
            challenge_id=value["challengeId"],
            channel_id=value["channelId"],
            accepted_cumulative=value["acceptedCumulative"],
            spent=value["spent"],
            units=value.get("units"),
            tx_hash=value.get("txHash"),
        )


def is_session_receipt(value: object) -> bool:
    """Return whether `value` is a session receipt JSON object."""
    if not is_dict(value):
        return False
    units = value.get("units")
    tx_hash = value.get("txHash")
    return (
        value.get("method") == "tempo"
        and value.get("intent") == "session"
        and value.get("status") == "success"
        and all(
            isinstance(value.get(key), str)
            for key in (
                "timestamp",
                "reference",
                "challengeId",
                "channelId",
                "acceptedCumulative",
                "spent",
            )
        )
        and (units is None or (isinstance(units, (int, float)) and not isinstance(units, bool)))
        and (tx_hash is None or isinstance(tx_hash, str))
    )


def _iso_now() -> str:
    """The current time as JavaScript's `Date.toISOString()` formats it."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def create_session_receipt(
    *,
    challenge_id: str,
    channel_id: str,
    accepted_cumulative: int,
    spent: int,
    units: int | None = None,
    tx_hash: str | None = None,
) -> SessionReceipt:
    """Create a session receipt whose `reference` is the channel ID."""
    return SessionReceipt(
        timestamp=_iso_now(),
        reference=channel_id,
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=str(accepted_cumulative),
        spent=str(spent),
        units=units,
        tx_hash=tx_hash,
    )


def _json(value: Any) -> str:
    """Serialize like `JSON.stringify`: compact, non-ASCII kept as is."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def serialize_session_receipt(receipt: SessionReceipt) -> str:
    """Serialize a session receipt to the Payment-Receipt header (base64url, no padding)."""
    encoded = base64.urlsafe_b64encode(_json(receipt.to_wire()).encode())
    return encoded.decode().rstrip("=")


def deserialize_session_receipt(encoded: str) -> SessionReceipt:
    """Parse a Payment-Receipt header value into a session receipt."""
    try:
        normalized = encoded.replace("+", "-").replace("/", "_").rstrip("=")
        raw = base64.urlsafe_b64decode(normalized + "=" * (-len(normalized) % 4))
        value = json.loads(raw.decode())
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("Invalid session receipt.") from error
    return SessionReceipt.from_wire(value)
