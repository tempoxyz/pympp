"""Persistent models for Tempo TIP-1034 payment sessions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Literal

MAX_UINT96 = (1 << 96) - 1
MAX_UINT32 = (1 << 32) - 1
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
TIP20_CHANNEL_RESERVE = "0x4D50500000000000000000000000000000000000"


class SessionAction(StrEnum):
    """TIP-1034 client credential actions."""

    OPEN = "open"
    TOP_UP = "topUp"
    VOUCHER = "voucher"
    CLOSE = "close"


class SessionStatus(StrEnum):
    """Durable client-side channel lifecycle states."""

    OPENING = "opening"
    ACTIVE = "active"
    TOPPING_UP = "toppingUp"
    VOUCHER_PENDING = "voucherPending"
    CLOSING = "closing"
    CLOSED = "closed"


class PendingStatus(StrEnum):
    """Submission knowledge retained across process restarts."""

    PREPARED = "prepared"
    UNCERTAIN = "uncertain"


def _amount(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a decimal amount")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a decimal amount") from error
    if parsed < 0 or parsed > MAX_UINT96:
        raise ValueError(f"{field} is outside uint96 bounds")
    return parsed


def _uint32(value: Any, field: str) -> int:
    parsed = _amount(value, field)
    if parsed > MAX_UINT32:
        raise ValueError(f"{field} is outside uint32 bounds")
    return parsed


def _hex(value: Any, length: int, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{field} must be 0x-prefixed hex")
    body = value[2:]
    if len(body) != length * 2:
        raise ValueError(f"{field} must be {length} bytes")
    try:
        bytes.fromhex(body)
    except ValueError as error:
        raise ValueError(f"{field} must be hex") from error
    return "0x" + body.lower()


def normalize_address(value: Any, field: str) -> str:
    """Validate and lowercase an EVM address."""

    return _hex(value, 20, field)


def normalize_hash(value: Any, field: str) -> str:
    """Validate and lowercase a bytes32 value."""

    return _hex(value, 32, field)


@dataclass(frozen=True, slots=True)
class ChannelDescriptor:
    """TIP-1034 data that deterministically identifies a channel."""

    payer: str
    payee: str
    operator: str
    token: str
    salt: str
    authorized_signer: str
    expiring_nonce_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "payer", normalize_address(self.payer, "payer"))
        object.__setattr__(self, "payee", normalize_address(self.payee, "payee"))
        object.__setattr__(self, "operator", normalize_address(self.operator, "operator"))
        object.__setattr__(self, "token", normalize_address(self.token, "token"))
        object.__setattr__(
            self,
            "authorized_signer",
            normalize_address(self.authorized_signer, "authorizedSigner"),
        )
        object.__setattr__(self, "salt", normalize_hash(self.salt, "salt"))
        object.__setattr__(
            self,
            "expiring_nonce_hash",
            normalize_hash(self.expiring_nonce_hash, "expiringNonceHash"),
        )

    @property
    def effective_signer(self) -> str:
        """Resolve a zero signer to the payer, as TIP-1034 specifies."""

        return (
            self.payer if self.authorized_signer == ZERO_ADDRESS.lower() else self.authorized_signer
        )

    def to_wire(self) -> dict[str, str]:
        """Return the camelCase descriptor used on the wire."""

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
        """Validate a wire descriptor."""

        if not isinstance(value, dict):
            raise ValueError("session descriptor must be an object")
        return cls(
            payer=normalize_address(value.get("payer"), "payer"),
            payee=normalize_address(value.get("payee"), "payee"),
            operator=normalize_address(value.get("operator"), "operator"),
            token=normalize_address(value.get("token"), "token"),
            salt=normalize_hash(value.get("salt"), "salt"),
            authorized_signer=normalize_address(value.get("authorizedSigner"), "authorizedSigner"),
            expiring_nonce_hash=normalize_hash(value.get("expiringNonceHash"), "expiringNonceHash"),
        )


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    """Local authorization limits, all expressed in raw token units."""

    max_deposit: int
    max_top_up: int
    max_cumulative_spend: int
    opening_deposit: int | None = None
    top_up_amount: int | None = None

    def __post_init__(self) -> None:
        for field in ("max_deposit", "max_top_up", "max_cumulative_spend"):
            object.__setattr__(self, field, _amount(getattr(self, field), field))
        for field in ("opening_deposit", "top_up_amount"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _amount(value, field))
        if self.max_deposit == 0:
            raise ValueError("max_deposit must be positive")
        if self.max_top_up == 0:
            raise ValueError("max_top_up must be positive")
        if self.max_cumulative_spend == 0:
            raise ValueError("max_cumulative_spend must be positive")


@dataclass(slots=True)
class PendingOperation:
    """An exact signed operation that may already have reached the server."""

    action: SessionAction
    challenge_id: str
    payload: dict[str, Any]
    status: PendingStatus
    created_at: str
    expected_deposit: int | None = None
    expected_cumulative: int | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["action"] = self.action.value
        value["status"] = self.status.value
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PendingOperation:
        return cls(
            action=SessionAction(value["action"]),
            challenge_id=str(value["challenge_id"]),
            payload=dict(value["payload"]),
            status=PendingStatus(value["status"]),
            created_at=str(value["created_at"]),
            expected_deposit=(
                None
                if value.get("expected_deposit") is None
                else _amount(value["expected_deposit"], "expected_deposit")
            ),
            expected_cumulative=(
                None
                if value.get("expected_cumulative") is None
                else _amount(value["expected_cumulative"], "expected_cumulative")
            ),
        )


@dataclass(slots=True)
class SessionRecord:
    """Complete durable client knowledge for one reusable channel."""

    scope: str
    channel_id: str
    descriptor: ChannelDescriptor
    escrow: str
    chain_id: int
    deposit: int
    authorized_cumulative: int
    accepted_cumulative: int
    settled: int
    spent: int
    status: SessionStatus
    resource_url: str
    close_requested_at: int = 0
    pending: PendingOperation | None = None
    highest_voucher: dict[str, str] | None = None
    units: int = 0

    def __post_init__(self) -> None:
        self.channel_id = normalize_hash(self.channel_id, "channelId")
        self.escrow = normalize_address(self.escrow, "escrow")
        if self.chain_id <= 0:
            raise ValueError("chain_id must be positive")
        for field in (
            "deposit",
            "authorized_cumulative",
            "accepted_cumulative",
            "settled",
            "spent",
        ):
            setattr(self, field, _amount(getattr(self, field), field))
        if self.accepted_cumulative > self.authorized_cumulative:
            raise ValueError("accepted cumulative exceeds local authorization")
        if self.spent > self.accepted_cumulative:
            raise ValueError("spent exceeds accepted cumulative")
        if self.settled > self.deposit:
            raise ValueError("settled exceeds deposit")
        self.close_requested_at = _uint32(self.close_requested_at, "close_requested_at")
        if isinstance(self.units, bool) or not isinstance(self.units, int) or self.units < 0:
            raise ValueError("units must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "channel_id": self.channel_id,
            "descriptor": self.descriptor.to_wire(),
            "escrow": self.escrow,
            "chain_id": self.chain_id,
            "deposit": self.deposit,
            "authorized_cumulative": self.authorized_cumulative,
            "accepted_cumulative": self.accepted_cumulative,
            "settled": self.settled,
            "spent": self.spent,
            "status": self.status.value,
            "resource_url": self.resource_url,
            "close_requested_at": self.close_requested_at,
            "pending": None if self.pending is None else self.pending.to_dict(),
            "highest_voucher": self.highest_voucher,
            "units": self.units,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SessionRecord:
        pending = value.get("pending")
        return cls(
            scope=str(value["scope"]),
            channel_id=str(value["channel_id"]),
            descriptor=ChannelDescriptor.from_wire(value["descriptor"]),
            escrow=str(value["escrow"]),
            chain_id=int(value["chain_id"]),
            deposit=_amount(value["deposit"], "deposit"),
            authorized_cumulative=_amount(value["authorized_cumulative"], "authorized_cumulative"),
            accepted_cumulative=_amount(value["accepted_cumulative"], "accepted_cumulative"),
            settled=_amount(value["settled"], "settled"),
            spent=_amount(value["spent"], "spent"),
            status=SessionStatus(value["status"]),
            resource_url=str(value["resource_url"]),
            close_requested_at=_uint32(value.get("close_requested_at", 0), "close_requested_at"),
            pending=None if pending is None else PendingOperation.from_dict(pending),
            highest_voucher=(
                None if value.get("highest_voucher") is None else dict(value["highest_voucher"])
            ),
            units=int(value.get("units", 0)),
        )


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Validated server snapshot used only as a reconciliation hint."""

    accepted_cumulative: int
    chain_id: int
    channel_id: str
    deposit: int
    descriptor: ChannelDescriptor
    escrow: str
    required_cumulative: int
    settled: int
    spent: int
    close_requested_at: int | None = None
    highest_voucher: dict[str, str] | None = None
    units: int = 0

    @classmethod
    def from_wire(cls, value: Any) -> SessionSnapshot:
        if not isinstance(value, dict):
            raise ValueError("session snapshot must be an object")
        highest = value.get("highestVoucher")
        if highest is not None and not isinstance(highest, dict):
            raise ValueError("highestVoucher must be an object")
        chain_id = value.get("chainId")
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("session snapshot chainId must be a positive integer")
        units = value.get("units", 0)
        if isinstance(units, bool) or not isinstance(units, int) or units < 0:
            raise ValueError("session snapshot units must be a non-negative integer")
        snapshot = cls(
            accepted_cumulative=_amount(value.get("acceptedCumulative"), "acceptedCumulative"),
            chain_id=chain_id,
            channel_id=normalize_hash(value.get("channelId"), "channelId"),
            deposit=_amount(value.get("deposit"), "deposit"),
            descriptor=ChannelDescriptor.from_wire(value.get("descriptor")),
            escrow=normalize_address(value.get("escrow"), "escrow"),
            required_cumulative=_amount(value.get("requiredCumulative"), "requiredCumulative"),
            settled=_amount(value.get("settled"), "settled"),
            spent=_amount(value.get("spent"), "spent"),
            close_requested_at=(
                None
                if value.get("closeRequestedAt") is None
                else _uint32(value.get("closeRequestedAt"), "closeRequestedAt")
            ),
            highest_voucher=None if highest is None else dict(highest),
            units=units,
        )
        if snapshot.accepted_cumulative > snapshot.deposit:
            raise ValueError("session snapshot accepted cumulative exceeds deposit")
        if snapshot.settled > snapshot.deposit:
            raise ValueError("session snapshot settled exceeds deposit")
        if snapshot.spent > snapshot.accepted_cumulative:
            raise ValueError("session snapshot spent exceeds accepted cumulative")
        return snapshot


@dataclass(frozen=True, slots=True)
class SessionReceipt:
    """Successful tempo/session receipt."""

    method: Literal["tempo"]
    intent: Literal["session"]
    status: Literal["success"]
    timestamp: str
    reference: str
    challenge_id: str
    channel_id: str
    accepted_cumulative: int
    spent: int
    units: int | None = None
    tx_hash: str | None = None

    @classmethod
    def from_wire(cls, value: Any) -> SessionReceipt:
        if not isinstance(value, dict):
            raise ValueError("session receipt must be an object")
        if (value.get("method"), value.get("intent"), value.get("status")) != (
            "tempo",
            "session",
            "success",
        ):
            raise ValueError("invalid session receipt identity")
        units = value.get("units")
        if units is not None and (
            isinstance(units, bool) or not isinstance(units, int) or units < 0
        ):
            raise ValueError("session receipt units must be a non-negative integer")
        return cls(
            method="tempo",
            intent="session",
            status="success",
            timestamp=str(value["timestamp"]),
            reference=str(value["reference"]),
            challenge_id=str(value["challengeId"]),
            channel_id=normalize_hash(value["channelId"], "channelId"),
            accepted_cumulative=_amount(value["acceptedCumulative"], "acceptedCumulative"),
            spent=_amount(value["spent"], "spent"),
            units=units,
            tx_hash=(
                None if value.get("txHash") is None else normalize_hash(value["txHash"], "txHash")
            ),
        )
