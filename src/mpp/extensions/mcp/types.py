"""MCP-specific payment types.

MCP types differ from core pympp types:
- MCPChallenge includes realm, expires, description (core Challenge lacks these)
- MCPCredential echoes the full challenge object (core Credential only has id)
- MCPReceipt includes challengeId, method, settlement (core Receipt lacks these)

The to_core()/from_core() methods are explicitly "information-reducing" when
mapping to core types, as MCP carries additional metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from mpp import Challenge, Credential, Receipt


@dataclass(frozen=True, slots=True)
class MCPChallenge:
    """Payment challenge for MCP transport.

    Per draft-payment-transport-mcp-00, challenges include additional fields
    not present in the core HTTP Challenge type.

    Example:
        challenge = MCPChallenge(
            id="ch_abc123",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "currency": "usd"},
            expires="2025-01-15T12:05:00Z",
            description="API call fee",
        )
    """

    id: str
    realm: str
    method: str
    intent: str
    request: dict[str, Any]
    expires: str | None = None
    description: str | None = None
    digest: str | None = None
    opaque: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for wire format."""
        result: dict[str, Any] = {
            "id": self.id,
            "realm": self.realm,
            "method": self.method,
            "intent": self.intent,
            "request": self.request,
        }
        if self.expires is not None:
            result["expires"] = self.expires
        if self.description is not None:
            result["description"] = self.description
        if self.digest is not None:
            result["digest"] = self.digest
        if self.opaque is not None:
            result["opaque"] = self.opaque
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPChallenge:
        """Parse from a JSON dict."""
        return cls(
            id=data["id"],
            realm=data["realm"],
            method=data["method"],
            intent=data["intent"],
            request=data["request"],
            expires=data.get("expires"),
            description=data.get("description"),
            digest=data.get("digest"),
            opaque=data.get("opaque"),
        )

    def to_core(self) -> Challenge:
        """Convert to core Challenge type (loses realm, expires, description)."""
        from mpp import Challenge

        return Challenge(
            id=self.id,
            method=self.method,
            intent=self.intent,
            request=self.request,
            digest=self.digest,
            opaque=self.opaque,
        )

    @classmethod
    def from_core(
        cls,
        challenge: Challenge,
        realm: str,
        expires: str | None = None,
        description: str | None = None,
    ) -> MCPChallenge:
        """Create from core Challenge type with additional MCP fields."""
        return cls(
            id=challenge.id,
            realm=realm,
            method=challenge.method,
            intent=challenge.intent,
            request=challenge.request,
            expires=expires,
            description=description,
            digest=challenge.digest,
            opaque=challenge.opaque,
        )


@dataclass(frozen=True, slots=True)
class MCPCredential:
    """Payment credential for MCP transport.

    Per draft-payment-transport-mcp-00, MCP credentials echo the full challenge
    object back to the server (not just the challenge ID as in HTTP transport).

    Example:
        credential = MCPCredential(
            challenge=MCPChallenge(...),
            payload={"signature": "0x..."},
            source="0x1234...",
        )
    """

    challenge: MCPChallenge
    payload: dict[str, Any]
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for wire format."""
        result: dict[str, Any] = {
            "challenge": self.challenge.to_dict(),
            "payload": self.payload,
        }
        if self.source is not None:
            result["source"] = self.source
        return result

    def to_meta(self) -> dict[str, Any]:
        """Serialize to the _meta dict format."""
        from mpp.extensions.mcp.constants import META_CREDENTIAL

        return {META_CREDENTIAL: self.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPCredential:
        """Parse from a JSON dict."""
        return cls(
            challenge=MCPChallenge.from_dict(data["challenge"]),
            payload=data["payload"],
            source=data.get("source"),
        )

    @classmethod
    def from_meta(cls, meta: dict[str, Any]) -> MCPCredential | None:
        """Extract credential from _meta dict, returns None if not present."""
        from mpp.extensions.mcp.constants import META_CREDENTIAL

        if META_CREDENTIAL not in meta:
            return None
        return cls.from_dict(meta[META_CREDENTIAL])

    def to_core(self) -> Credential:
        """Convert to core Credential type."""
        import base64
        import json

        from mpp import ChallengeEcho, Credential

        request_json = json.dumps(self.challenge.request, separators=(",", ":"), sort_keys=True)
        request_b64 = base64.urlsafe_b64encode(request_json.encode()).decode().rstrip("=")

        opaque_b64 = None
        if self.challenge.opaque is not None:
            opaque_json = json.dumps(self.challenge.opaque, separators=(",", ":"), sort_keys=True)
            opaque_b64 = base64.urlsafe_b64encode(opaque_json.encode()).decode().rstrip("=")

        echo = ChallengeEcho(
            id=self.challenge.id,
            realm=self.challenge.realm,
            method=self.challenge.method,
            intent=self.challenge.intent,
            request=request_b64,
            expires=self.challenge.expires,
            digest=self.challenge.digest,
            opaque=opaque_b64,
        )
        return Credential(
            challenge=echo,
            payload=self.payload,
            source=self.source,
        )

    @classmethod
    def from_core(
        cls,
        credential: Credential,
        challenge: MCPChallenge,
    ) -> MCPCredential:
        """Create from core Credential by attaching the full challenge."""
        return cls(
            challenge=challenge,
            payload=credential.payload,
            source=credential.source,
        )


@dataclass(frozen=True, slots=True)
class MCPReceipt:
    """Payment receipt for MCP transport.

    Per draft-payment-transport-mcp-00, MCP receipts include additional fields
    not present in the core HTTP Receipt type.

    Example:
        receipt = MCPReceipt(
            status="success",
            challenge_id="ch_abc123",
            method="tempo",
            timestamp="2025-01-15T12:00:30Z",
            reference="0xtx789...",
            settlement={"amount": "1000", "currency": "usd"},
        )
    """

    status: Literal["success"]
    challenge_id: str
    method: str
    timestamp: str
    reference: str | None = None
    settlement: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for wire format."""
        result: dict[str, Any] = {
            "status": self.status,
            "challengeId": self.challenge_id,
            "method": self.method,
            "timestamp": self.timestamp,
        }
        if self.reference is not None:
            result["reference"] = self.reference
        if self.settlement is not None:
            result["settlement"] = self.settlement
        return result

    def to_meta(self) -> dict[str, Any]:
        """Serialize to the _meta dict format."""
        from mpp.extensions.mcp.constants import META_RECEIPT

        return {META_RECEIPT: self.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPReceipt:
        """Parse from a JSON dict."""
        return cls(
            status=data["status"],
            challenge_id=data["challengeId"],
            method=data["method"],
            timestamp=data["timestamp"],
            reference=data.get("reference"),
            settlement=data.get("settlement"),
        )

    @classmethod
    def from_meta(cls, meta: dict[str, Any]) -> MCPReceipt | None:
        """Extract receipt from _meta dict, returns None if not present."""
        from mpp.extensions.mcp.constants import META_RECEIPT

        if META_RECEIPT not in meta:
            return None
        return cls.from_dict(meta[META_RECEIPT])

    def to_core(self) -> Receipt:
        """Convert to core Receipt type (loses challengeId, method, settlement)."""
        from mpp import Receipt

        return Receipt(
            status=self.status,
            timestamp=datetime.fromisoformat(self.timestamp.replace("Z", "+00:00")),
            reference=self.reference or "",
        )

    @classmethod
    def from_core(
        cls,
        receipt: Receipt,
        challenge_id: str,
        method: str,
        settlement: dict[str, Any] | None = None,
    ) -> MCPReceipt:
        """Create from core Receipt by adding MCP-specific fields."""
        timestamp = receipt.timestamp.isoformat()
        if timestamp.endswith("+00:00"):
            timestamp = timestamp[:-6] + "Z"
        return cls(
            status=receipt.status,
            challenge_id=challenge_id,
            method=method,
            timestamp=timestamp,
            reference=receipt.reference if receipt.reference else None,
            settlement=settlement,
        )
