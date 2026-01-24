"""Header parsing and formatting for HTTP Payment Authentication.

This module handles the critical path of parsing WWW-Authenticate, Authorization,
and Payment-Receipt headers according to the Payment HTTP Authentication Scheme.

Format:
    WWW-Authenticate: Payment realm="api.example.com", <base64-encoded-challenge>
    Authorization: Payment <base64-encoded-credential>
    Payment-Receipt: <base64-encoded-receipt>
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpay import Challenge, Credential, Receipt


MAX_HEADER_PAYLOAD_SIZE = 16 * 1024


class ParseError(Exception):
    """Failed to parse a payment header.

    Error messages are sanitized to avoid leaking sensitive credential data.
    """


def _b64_encode(data: dict[str, Any]) -> str:
    """Encode dict as URL-safe base64 JSON (compact, no padding)."""
    compact_json = json.dumps(data, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(compact_json.encode()).decode()
    return encoded.rstrip("=")


def _b64_decode(encoded: str) -> dict[str, Any]:
    """Decode URL-safe base64 JSON to dict.

    Raises:
        ParseError: If input exceeds size limit, is invalid base64/JSON, or not a dict.
    """
    if len(encoded) > MAX_HEADER_PAYLOAD_SIZE:
        raise ParseError("Header payload exceeds maximum size")

    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        obj = json.loads(decoded)
        if not isinstance(obj, dict):
            raise ParseError("Expected JSON object")
        return obj
    except (ValueError, json.JSONDecodeError):
        raise ParseError("Invalid base64 or JSON encoding") from None


_REALM_PATTERN = re.compile(r'realm="([^"]*)"')


def parse_www_authenticate(header: str) -> Challenge:
    """Parse a WWW-Authenticate header into a Challenge.

    Expected format:
        Payment realm="api.example.com", <base64-challenge>

    The challenge payload is a base64-encoded JSON object with:
        - id: Challenge identifier
        - method: Payment method name
        - intent: Intent name
        - request: Method-specific request data
    """
    from mpay import Challenge

    header = header.strip()

    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    content = header[8:].strip()

    parts = content.split(",", 1)
    if len(parts) != 2:
        raise ParseError("Missing realm or challenge in WWW-Authenticate header")

    realm_part = parts[0].strip()
    challenge_b64 = parts[1].strip()

    realm_match = _REALM_PATTERN.match(realm_part)
    if not realm_match:
        raise ParseError(f"Invalid realm format: {realm_part}")

    data = _b64_decode(challenge_b64)

    required = {"id", "method", "intent", "request"}
    missing = required - set(data.keys())
    if missing:
        raise ParseError(f"Challenge missing required fields: {missing}")

    return Challenge(
        id=str(data["id"]),
        method=str(data["method"]),
        intent=str(data["intent"]),
        request=data["request"],
    )


def format_www_authenticate(challenge: Challenge, realm: str) -> str:
    """Format a Challenge as a WWW-Authenticate header value.

    Output format:
        Payment realm="api.example.com", <base64-challenge>
    """
    payload = {
        "id": challenge.id,
        "method": challenge.method,
        "intent": challenge.intent,
        "request": challenge.request,
    }
    encoded = _b64_encode(payload)
    return f'Payment realm="{realm}", {encoded}'


def parse_authorization(header: str) -> Credential:
    """Parse an Authorization header into a Credential.

    Expected format:
        Payment <base64-credential>

    The credential payload is a base64-encoded JSON object with:
        - id: Challenge identifier (matches the original challenge)
        - payload: Method-specific credential data
        - source: Optional payer DID
    """
    from mpay import Credential

    header = header.strip()

    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    credential_b64 = header[8:].strip()
    data = _b64_decode(credential_b64)

    if "id" not in data:
        raise ParseError("Credential missing required field: id")
    if "payload" not in data:
        raise ParseError("Credential missing required field: payload")

    return Credential(
        id=str(data["id"]),
        payload=data["payload"],
        source=str(data["source"]) if data.get("source") else None,
    )


def format_authorization(credential: Credential) -> str:
    """Format a Credential as an Authorization header value.

    Output format:
        Payment <base64-credential>
    """
    payload: dict[str, Any] = {
        "id": credential.id,
        "payload": credential.payload,
    }
    if credential.source:
        payload["source"] = credential.source
    encoded = _b64_encode(payload)
    return f"Payment {encoded}"


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string to datetime."""
    try:
        ts_str = value.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        raise ParseError("Invalid timestamp format") from None


def parse_payment_receipt(header: str) -> Receipt:
    """Parse a Payment-Receipt header into a Receipt.

    Expected format:
        <base64-receipt>

    The receipt payload is a base64-encoded JSON object with:
        - status: "success" or "failed"
        - timestamp: ISO 8601 timestamp
        - reference: Method-specific reference
    """
    from mpay import Receipt

    header = header.strip()
    data = _b64_decode(header)

    required = {"status", "timestamp", "reference"}
    missing = required - set(data.keys())
    if missing:
        raise ParseError(f"Receipt missing required fields: {missing}")

    status = data["status"]
    if status not in ("success", "failed"):
        raise ParseError("Invalid receipt status")

    timestamp = _parse_timestamp(str(data["timestamp"]))

    return Receipt(
        status=status,
        timestamp=timestamp,
        reference=str(data["reference"]),
    )


def format_payment_receipt(receipt: Receipt) -> str:
    """Format a Receipt as a Payment-Receipt header value.

    Output format:
        <base64-receipt>
    """
    timestamp_str = receipt.timestamp.isoformat().replace("+00:00", "Z")

    payload = {
        "status": receipt.status,
        "timestamp": timestamp_str,
        "reference": receipt.reference,
    }
    return _b64_encode(payload)
