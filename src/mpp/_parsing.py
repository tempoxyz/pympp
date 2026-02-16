"""Header parsing and formatting for HTTP Payment Authentication.

This module handles the critical path of parsing WWW-Authenticate, Authorization,
and Payment-Receipt headers according to the Payment HTTP Authentication Scheme.

Format per IETF draft-ietf-httpauth-payment:
    WWW-Authenticate: Payment id="...", realm="...", method="...",
                      intent="...", request="<base64url>"
    Authorization: Payment <base64url-json>
    Payment-Receipt: <base64url-json>
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpp import Challenge, Credential, Receipt


MAX_HEADER_PAYLOAD_SIZE = 16 * 1024

# RFC 9110 auth-param: token BWS "=" BWS ( token / quoted-string )
# Matches: key="value" or key=token, handles escaped quotes in quoted strings
_AUTH_PARAM_RE = re.compile(r'([a-zA-Z_][\w-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))')


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


def _escape_quoted(s: str) -> str:
    """Escape a string for use in a quoted-string. Rejects CRLF."""
    if "\r" in s or "\n" in s:
        raise ParseError("Header value contains invalid CRLF characters")
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _unescape_quoted(s: str) -> str:
    """Unescape a quoted-string value (remove backslash escapes)."""
    return re.sub(r"\\(.)", r"\1", s)


def _parse_auth_params(params_str: str) -> dict[str, str]:
    """Parse RFC 9110 auth-params: key="value" or key=token pairs."""
    params: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(params_str):
        key = match.group(1)
        # Group 2 is quoted value, group 3 is unquoted token
        value = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = _unescape_quoted(value) if match.group(2) is not None else value
    return params


def parse_www_authenticate(header: str) -> Challenge:
    """Parse a WWW-Authenticate header into a Challenge.

    Expected format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"

    Optional parameters: digest, expires, description
    """
    from mpp import Challenge

    header = header.strip()

    # Case-insensitive scheme matching
    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    params_str = header[8:].strip()
    params = _parse_auth_params(params_str)

    # Extract required fields
    id_ = params.get("id")
    if not id_:
        raise ParseError("Missing 'id' field")

    realm = params.get("realm")
    if not realm:
        raise ParseError("Missing 'realm' field")

    method = params.get("method")
    if not method:
        raise ParseError("Missing 'method' field")

    intent = params.get("intent")
    if not intent:
        raise ParseError("Missing 'intent' field")

    request_b64 = params.get("request")
    if not request_b64:
        raise ParseError("Missing 'request' field")

    # Decode request JSON
    request = _b64_decode(request_b64)

    return Challenge(
        id=id_,
        method=method,
        intent=intent,
        request=request,
        realm=realm,
        request_b64=request_b64,
        digest=params.get("digest"),
        expires=params.get("expires"),
        description=params.get("description"),
    )


def format_www_authenticate(challenge: Challenge, realm: str) -> str:
    """Format a Challenge as a WWW-Authenticate header value.

    Output format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"
    """
    # Encode request as base64url JSON
    request_b64 = _b64_encode(challenge.request)

    # Build auth-params
    parts = [
        f'id="{_escape_quoted(challenge.id)}"',
        f'realm="{_escape_quoted(realm)}"',
        f'method="{_escape_quoted(challenge.method)}"',
        f'intent="{_escape_quoted(challenge.intent)}"',
        f'request="{request_b64}"',
    ]

    # Add optional parameters
    if challenge.digest:
        parts.append(f'digest="{_escape_quoted(challenge.digest)}"')
    if challenge.expires:
        parts.append(f'expires="{_escape_quoted(challenge.expires)}"')
    if challenge.description:
        parts.append(f'description="{_escape_quoted(challenge.description)}"')

    return "Payment " + ", ".join(parts)


def parse_authorization(header: str) -> Credential:
    """Parse an Authorization header into a Credential.

    Expected format:
        Payment <base64-credential>

    The credential payload is a base64-encoded JSON object with:
        - challenge: ChallengeEcho object containing id, realm, method, intent, request
        - payload: Method-specific credential data
        - source: Optional payer DID
    """
    from mpp import ChallengeEcho, Credential

    header = header.strip()

    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    credential_b64 = header[8:].strip()
    data = _b64_decode(credential_b64)

    if "challenge" not in data:
        raise ParseError("Credential missing required field: challenge")
    if "payload" not in data:
        raise ParseError("Credential missing required field: payload")

    challenge_data = data["challenge"]
    if not isinstance(challenge_data, dict):
        raise ParseError("Credential challenge must be an object")
    if "id" not in challenge_data:
        raise ParseError("Credential challenge missing required field: id")

    echo = ChallengeEcho(
        id=str(challenge_data["id"]),
        realm=str(challenge_data.get("realm", "")),
        method=str(challenge_data.get("method", "")),
        intent=str(challenge_data.get("intent", "")),
        request=str(challenge_data.get("request", "")),
        expires=str(challenge_data["expires"]) if challenge_data.get("expires") else None,
    )

    return Credential(
        challenge=echo,
        payload=data["payload"],
        source=str(data["source"]) if data.get("source") else None,
    )


def format_authorization(credential: Credential) -> str:
    """Format a Credential as an Authorization header value.

    Output format:
        Payment <base64-credential>

    The credential is a JSON object with:
        - challenge: ChallengeEcho with id, realm, method, intent, request, expires
        - payload: Method-specific credential data
        - source: Optional payer DID
    """
    challenge_dict: dict[str, Any] = {
        "id": credential.challenge.id,
        "realm": credential.challenge.realm,
        "method": credential.challenge.method,
        "intent": credential.challenge.intent,
        "request": credential.challenge.request,
    }
    if credential.challenge.expires:
        challenge_dict["expires"] = credential.challenge.expires

    payload: dict[str, Any] = {
        "challenge": challenge_dict,
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
    from mpp import Receipt

    header = header.strip()
    data = _b64_decode(header)

    required = {"status", "timestamp", "reference"}
    missing = required - set(data.keys())
    if missing:
        raise ParseError(f"Receipt missing required fields: {missing}")

    status = data["status"]
    if status != "success":
        raise ParseError("Invalid receipt status")

    timestamp = _parse_timestamp(str(data["timestamp"]))

    extra = data.get("extra")

    return Receipt(
        status=status,
        timestamp=timestamp,
        reference=str(data["reference"]),
        extra=extra if isinstance(extra, dict) else None,
    )


def format_payment_receipt(receipt: Receipt) -> str:
    """Format a Receipt as a Payment-Receipt header value.

    Output format:
        <base64-receipt>
    """
    timestamp_str = receipt.timestamp.isoformat().replace("+00:00", "Z")

    payload: dict[str, Any] = {
        "status": receipt.status,
        "timestamp": timestamp_str,
        "reference": receipt.reference,
    }
    if receipt.extra:
        payload["extra"] = receipt.extra
    return _b64_encode(payload)
