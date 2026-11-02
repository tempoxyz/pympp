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
import string
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpp._canonical import canonical_b64url
from mpp._typing import is_dict

if TYPE_CHECKING:
    from mpp import Challenge, Credential, Receipt


MAX_HEADER_PAYLOAD_SIZE = 16 * 1024
# A credential echoes its challenge, whose request alone may reach
# MAX_HEADER_PAYLOAD_SIZE, so Authorization values need room to expand during
# JSON and base64url encoding. Matches mppx.
MAX_AUTHORIZATION_SIZE = 64 * 1024

# Syntax-level Payment Auth grammar. Supported-method dispatch is handled after parsing.
# Matches mppx and mpp-rs: a lowercase letter, then lowercase letters, digits,
# colons, underscores, or hyphens (e.g. "tempo-v2", "vendor:method", "x402").
_PAYMENT_METHOD_ID_RE = re.compile(r"^[a-z][a-z0-9:_-]*$")
# Characters mppx accepts in an auth-param name.
_AUTH_PARAM_KEY_CHARS = frozenset(string.ascii_letters + string.digits + "_-")


class ParseError(Exception):
    """Failed to parse a payment header.

    Error messages are sanitized to avoid leaking sensitive credential data.
    """


# RFC 3339 date-time with a timezone, as mppx's `z.datetime()` accepts.
_DATETIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


def _validate_expires(expires: str) -> None:
    """Reject an ``expires`` the challenge parser would refuse, as mppx's Challenge schema does."""
    if not _DATETIME_RE.fullmatch(expires):
        raise ValueError(f"Invalid expires format: {expires!r}")


def _b64_encode(data: dict[str, Any]) -> str:
    """Encode dict as URL-safe base64 JSON (compact, no padding)."""
    compact_json = json.dumps(data, separators=(",", ":"), sort_keys=True)
    encoded = base64.urlsafe_b64encode(compact_json.encode()).decode()
    return encoded.rstrip("=")


_BASE64URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")


def _b64_decode(encoded: str, max_size: int = MAX_HEADER_PAYLOAD_SIZE) -> dict[str, Any]:
    """Decode URL-safe base64 JSON to dict.

    Raises:
        ParseError: If input exceeds size limit, is invalid base64/JSON, or not a dict.
    """
    if len(encoded) > max_size:
        raise ParseError("Header payload exceeds maximum size")

    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        obj = json.loads(decoded)
        if not is_dict(obj):
            raise ParseError("Expected JSON object")
        # JSON escapes can contain lone surrogates that fail later UTF-8/HMAC encoding.
        json.dumps(obj, ensure_ascii=False).encode("utf-8")
        return obj
    except (ValueError, json.JSONDecodeError):
        raise ParseError("Invalid base64 or JSON encoding") from None
    except RecursionError:
        # Deeply nested JSON exhausts json.loads' recursion limit.
        raise ParseError("Invalid base64 or JSON encoding") from None


def _escape_quoted(s: str) -> str:
    """Escape a string for use in a quoted-string. Rejects CRLF."""
    if "\r" in s or "\n" in s:
        raise ParseError("Header value contains invalid CRLF characters")
    escaped: list[str] = []
    for character in s:
        code = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif code <= 0xFF:
            escaped.append(character)
        elif code <= 0xFFFF:
            escaped.append(f"\\u{code:04x}")
        else:
            code -= 0x10000
            escaped.append(f"\\u{0xD800 + (code >> 10):04x}")
            escaped.append(f"\\u{0xDC00 + (code & 0x3FF):04x}")
    return "".join(escaped)


def _read_unicode_escape(s: str, index: int) -> int | None:
    """Return the UTF-16 code unit in a ``uXXXX`` escape body, if present."""
    if not s.startswith("u", index):
        return None
    digits = s[index + 1 : index + 5]
    if len(digits) != 4 or not all(character in string.hexdigits for character in digits):
        return None
    return int(digits, 16)


def _unescape_quoted(s: str) -> str:
    """Unescape quoted-pairs and the UTF-16 escapes emitted by mppx."""
    result: list[str] = []
    index = 0
    while index < len(s):
        if s[index] != "\\":
            result.append(s[index])
            index += 1
            continue

        index += 1
        if index >= len(s):
            break

        code = _read_unicode_escape(s, index)
        if code is None:
            result.append(s[index])
            index += 1
            continue
        index += 5

        if 0xD800 <= code <= 0xDBFF:
            low = _read_unicode_escape(s, index + 1) if s.startswith("\\", index) else None
            if low is not None and 0xDC00 <= low <= 0xDFFF:
                result.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                index += 6
                continue
            result.append("\ufffd")
        elif 0xDC00 <= code <= 0xDFFF:
            result.append("\ufffd")
        else:
            result.append(chr(code))
    return "".join(result)


def _validate_payment_method_id(method: str) -> None:
    """Validate a payment method id against the grammar mppx accepts."""
    if not _PAYMENT_METHOD_ID_RE.fullmatch(method):
        raise ParseError(f"Invalid payment method id: {method!r}")


def _parse_auth_params(params_str: str) -> dict[str, str]:
    """Parse RFC 9110 auth-params: key="value" or key=token pairs.

    Consumes the input sequentially like mppx's `parseAuthParams`: a position that
    cannot begin an auth-param is rejected rather than skipped, and parsing stops
    at a token without `=`, which begins another auth scheme.
    """
    params: dict[str, str] = {}
    length = len(params_str)
    index = 0
    while index < length:
        while index < length and (params_str[index].isspace() or params_str[index] == ","):
            index += 1
        if index >= length:
            break

        key_start = index
        while index < length and params_str[index] in _AUTH_PARAM_KEY_CHARS:
            index += 1
        # Auth-param names are case-insensitive (RFC 9110 §11.2).
        key = params_str[key_start:index].lower()
        if not key:
            raise ParseError("Malformed auth-param")

        while index < length and params_str[index].isspace():
            index += 1
        if index >= length or params_str[index] != "=":
            break
        index += 1
        while index < length and params_str[index].isspace():
            index += 1

        if index < length and params_str[index] == '"':
            value, index = _read_quoted_auth_param(params_str, index + 1)
        else:
            value_end = params_str.find(",", index)
            if value_end == -1:
                value_end = length
            value, index = params_str[index:value_end].strip(), value_end

        if key in params:
            raise ParseError(f"Duplicate parameter: {key}")
        params[key] = value
    return params


def _read_quoted_auth_param(params_str: str, start: int) -> tuple[str, int]:
    """Read a quoted-string value starting after its opening quote."""
    index = start
    escaped = False
    while index < len(params_str):
        character = params_str[index]
        index += 1
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            return _unescape_quoted(params_str[start : index - 1]), index
    raise ParseError("Unterminated quoted-string")


def parse_www_authenticate(header: str) -> Challenge:
    """Parse a WWW-Authenticate header into a Challenge.

    Expected format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"

    Optional parameters: digest, expires, description, header, opaque
    """
    from mpp import Challenge, advertised_credential_header

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
    _validate_payment_method_id(method)

    intent = params.get("intent")
    if not intent:
        raise ParseError("Missing 'intent' field")

    request_b64 = params.get("request")
    if not request_b64:
        raise ParseError("Missing 'request' field")

    # Decode request JSON
    request = _b64_decode(request_b64)

    opaque_b64 = params.get("opaque")
    opaque = None
    if opaque_b64:
        opaque = _b64_decode(opaque_b64)

    try:
        credential_header = advertised_credential_header(params.get("header"))
    except ValueError as error:
        raise ParseError(str(error)) from error

    # Match mppx's Challenge schema: `digest` is `sha-256=...` and `expires` is RFC 3339.
    digest = params.get("digest")
    if digest and not digest.startswith("sha-256="):
        raise ParseError("Invalid digest format")
    expires = params.get("expires")
    if expires:
        try:
            _validate_expires(expires)
        except ValueError:
            raise ParseError("Invalid expires format") from None

    return Challenge(
        id=id_,
        method=method,
        intent=intent,
        request=request,
        realm=realm,
        request_b64=request_b64,
        digest=digest,
        expires=expires,
        description=params.get("description"),
        opaque=opaque,
        header=credential_header,
        # Keep the issuer's string only when it is strict base64url, so that
        # echoing or re-formatting it cannot inject header parameters.
        _opaque_b64=opaque_b64 if opaque_b64 and _BASE64URL.fullmatch(opaque_b64) else None,
    )


def format_www_authenticate(challenge: Challenge, realm: str) -> str:
    """Format a Challenge as a WWW-Authenticate header value.

    Output format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"
    """
    # Encode request as base64url JSON
    request_b64 = canonical_b64url(challenge.request)

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
    if challenge.header:
        parts.append(f'header="{_escape_quoted(challenge.header)}"')
    opaque_b64 = challenge._encoded_opaque()
    if opaque_b64 is not None:
        parts.append(f'opaque="{opaque_b64}"')

    return "Payment " + ", ".join(parts)


def parse_authorization(header: str) -> Credential:
    """Parse an Authorization header into a Credential.

    Expected format:
        Payment <base64-credential>

    Values longer than 64 KiB are rejected before decoding.

    The credential payload is a base64-encoded JSON object with:
        - challenge: ChallengeEcho object containing id, realm, method, intent, request
        - payload: Method-specific credential data
        - source: Optional payer DID
    """
    from mpp import ChallengeEcho, Credential, advertised_credential_header

    if len(header) > MAX_AUTHORIZATION_SIZE:
        raise ParseError("Authorization header exceeds maximum size")

    header = header.strip()

    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    credential_b64 = header[8:].strip()
    data = _b64_decode(credential_b64, max_size=MAX_AUTHORIZATION_SIZE)

    if "challenge" not in data:
        raise ParseError("Credential missing required field: challenge")
    if "payload" not in data:
        raise ParseError("Credential missing required field: payload")

    challenge_data = data["challenge"]
    if not is_dict(challenge_data):
        raise ParseError("Credential challenge must be an object")
    if "id" not in challenge_data:
        raise ParseError("Credential challenge missing required field: id")

    method = str(challenge_data.get("method", ""))
    _validate_payment_method_id(method)

    try:
        credential_header = advertised_credential_header(
            str(challenge_data["header"]) if challenge_data.get("header") else None
        )
    except ValueError as error:
        raise ParseError(str(error)) from error

    description = (
        str(challenge_data["description"])
        if challenge_data.get("description") is not None
        else None
    )
    if description is not None:
        # A retry can reflect this unsigned display field into WWW-Authenticate.
        _escape_quoted(description)
        if any(
            (ord(character) < 0x20 and character != "\t") or ord(character) == 0x7F
            for character in description
        ):
            raise ParseError("Header value contains invalid control characters")

    echo = ChallengeEcho(
        id=str(challenge_data["id"]),
        realm=str(challenge_data.get("realm", "")),
        method=method,
        intent=str(challenge_data.get("intent", "")),
        request=str(challenge_data.get("request", "")),
        expires=str(challenge_data["expires"]) if challenge_data.get("expires") else None,
        digest=str(challenge_data["digest"]) if challenge_data.get("digest") else None,
        opaque=str(challenge_data["opaque"]) if challenge_data.get("opaque") else None,
        header=credential_header,
        description=description,
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
    if credential.challenge.digest:
        challenge_dict["digest"] = credential.challenge.digest
    if credential.challenge.header:
        challenge_dict["header"] = credential.challenge.header
    if credential.challenge.opaque is not None:
        challenge_dict["opaque"] = credential.challenge.opaque
    if credential.challenge.description is not None:
        challenge_dict["description"] = credential.challenge.description

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


_RECEIPT_BASE_FIELDS = {
    "status",
    "timestamp",
    "reference",
    "method",
    "externalId",
    "subscriptionId",
    "fundingCurrency",
    "extra",
}


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

    required = {"status", "timestamp", "reference", "method"}
    missing = required - set(data.keys())
    if missing:
        raise ParseError(f"Receipt missing required fields: {missing}")

    status = data["status"]
    if status != "success":
        raise ParseError("Invalid receipt status")

    # Base fields must be JSON strings and the timestamp RFC 3339 with a timezone,
    # as mppx's Receipt schema requires.
    timestamp_str = data["timestamp"]
    if not isinstance(timestamp_str, str) or not _DATETIME_RE.fullmatch(timestamp_str):
        raise ParseError("Invalid timestamp format")
    timestamp = _parse_timestamp(timestamp_str)
    for field in ("method", "reference", "externalId", "subscriptionId", "fundingCurrency"):
        if field in data and not isinstance(data[field], str):
            raise ParseError(f"Receipt field {field} must be a string")
    method = data["method"]
    _validate_payment_method_id(method)

    extra = data.get("extra")
    return Receipt(
        status=status,
        timestamp=timestamp,
        reference=data["reference"],
        method=method,
        external_id=data.get("externalId") or None,
        subscription_id=data.get("subscriptionId") or None,
        funding_currency=data.get("fundingCurrency") or None,
        extra=extra if is_dict(extra) else None,
        extensions={key: value for key, value in data.items() if key not in _RECEIPT_BASE_FIELDS}
        or None,
    )


def format_payment_receipt(receipt: Receipt) -> str:
    """Format a Receipt as a Payment-Receipt header value.

    Output format:
        <base64-receipt>
    """
    timestamp = receipt.timestamp
    # Always UTC with a Z suffix, as mppx's Date.toISOString writes it: other offsets
    # (such as ones with seconds) don't fit the receipt schema. A naive datetime is UTC.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    timestamp_str = timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")

    payload: dict[str, Any] = {
        "status": receipt.status,
        "timestamp": timestamp_str,
        "reference": receipt.reference,
    }
    payload["method"] = receipt.method
    if receipt.external_id:
        payload["externalId"] = receipt.external_id
    if receipt.subscription_id:
        payload["subscriptionId"] = receipt.subscription_id
    if receipt.funding_currency:
        payload["fundingCurrency"] = receipt.funding_currency
    elif receipt.extensions and receipt.extensions.get("fundingCurrency"):
        # Callers that set it through extensions before the field existed.
        payload["fundingCurrency"] = receipt.extensions["fundingCurrency"]
    if receipt.extra:
        payload["extra"] = receipt.extra
    if receipt.extensions:
        for key, value in receipt.extensions.items():
            if key not in _RECEIPT_BASE_FIELDS:
                payload[key] = value
    return _b64_encode(payload)
