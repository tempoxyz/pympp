"""Payment receipts carried in ``Payment-Receipt`` headers."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, Self

from mpp import _base64url, _json
from mpp.constants import Header
from mpp.expires import DATETIME_PATTERN

__all__ = [
    "Receipt",
]


_KNOWN_FIELDS = (
    "fundingCurrency",
    "method",
    "reference",
    "externalId",
    "subscriptionId",
    "status",
    "timestamp",
)


class _HeaderLookup(Protocol):
    def get(self, key: str, /) -> str | None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Receipt:
    """A payment receipt returned after successful verification.

    Failures never produce receipts; they use 402 + Problem Details.

    Attributes:
        method: Payment method used (e.g. ``"tempo"``).
        reference: Method-specific reference (e.g. a transaction hash).
        timestamp: RFC 3339 settlement timestamp.
        status: Always ``"success"``.
        external_id: Optional external reference ID echoed from the credential payload
            (wire ``externalId``).
        subscription_id: Optional server-issued subscription identifier (wire ``subscriptionId``).
        funding_currency: Currency actually debited to fund the payment, when known
            (wire ``fundingCurrency``).
        extra: Method-specific extension fields, preserved verbatim (wire keys).
    """

    method: str
    reference: str
    timestamp: str
    status: Literal["success"] = "success"
    external_id: str | None = None
    subscription_id: str | None = None
    funding_currency: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("method", "reference", "timestamp"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"Invalid receipt: `{name}` must be a string.")
        if self.status != "success":
            raise ValueError('Invalid receipt: `status` must be "success".')
        if not DATETIME_PATTERN.match(self.timestamp):
            raise ValueError("Invalid ISO 8601 datetime")
        for name in ("external_id", "subscription_id", "funding_currency"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"Invalid receipt: `{name}` must be a string.")
        overlap = set(self.extra) & set(_KNOWN_FIELDS)
        if overlap:
            raise ValueError(f"Invalid receipt: extra fields shadow base fields: {sorted(overlap)}")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Validates a receipt object in wire form (camelCase keys); unknown keys go to ``extra``.

        Raises:
            ValueError: When a base field is missing or invalid.
        """
        if not isinstance(data, Mapping):
            raise ValueError("Receipt must be an object.")
        for key in ("method", "reference", "status", "timestamp"):
            if key not in data:
                raise ValueError(f"Invalid receipt: missing `{key}`.")
        return cls(
            method=data["method"],
            reference=data["reference"],
            timestamp=data["timestamp"],
            status=data["status"],
            external_id=data.get("externalId"),
            subscription_id=data.get("subscriptionId"),
            funding_currency=data.get("fundingCurrency"),
            extra={key: value for key, value in data.items() if key not in _KNOWN_FIELDS},
        )

    def to_dict(self) -> dict[str, Any]:
        """Returns the wire object (camelCase keys) including extension fields."""
        result: dict[str, Any] = {}
        if self.funding_currency is not None:
            result["fundingCurrency"] = self.funding_currency
        result["method"] = self.method
        result["reference"] = self.reference
        if self.external_id is not None:
            result["externalId"] = self.external_id
        if self.subscription_id is not None:
            result["subscriptionId"] = self.subscription_id
        result["status"] = self.status
        result["timestamp"] = self.timestamp
        result.update(self.extra)
        return result

    def serialize(self) -> str:
        """Serializes to a base64url ``Payment-Receipt`` header value."""
        return _base64url.encode(_json.dumps(self.to_dict()))

    @classmethod
    def deserialize(cls, encoded: str) -> Self:
        """Parses a base64url ``Payment-Receipt`` header value.

        Raises:
            ValueError: On invalid encoding, JSON or receipt fields.
        """
        return cls.from_dict(_json.loads(_base64url.decode_text(encoded)))

    @classmethod
    def from_headers(cls, headers: _HeaderLookup) -> Self:
        """Extracts the receipt from response headers.

        Raises:
            ValueError: When the ``Payment-Receipt`` header is missing or invalid.
        """
        value = headers.get(Header.PAYMENT_RECEIPT)
        if not value:
            raise ValueError(f"Missing {Header.PAYMENT_RECEIPT} header.")
        return cls.deserialize(value)
