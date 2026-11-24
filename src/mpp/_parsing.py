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
from collections.abc import Callable
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

# Syntax-level Payment Auth grammar: payment-method-id = 1*LOWERALPHA (a-z only).
# Supported-method dispatch is handled after parsing.
_PAYMENT_METHOD_ID_RE = re.compile(r"[a-z]+")
# Characters mppx accepts in an auth-param name.
_AUTH_PARAM_KEY_CHARS = frozenset(string.ascii_letters + string.digits + "_-")


class ParseError(Exception):
    """Failed to parse a payment header.

    Error messages are sanitized to avoid leaking sensitive credential data.
    """


_PAYMENT_AUTHORIZATION = "Payment-Authorization"


def is_payment_authorization_header(header: str | None) -> bool:
    """Whether ``header`` is ``Payment-Authorization``, compared ASCII case-insensitively."""
    return (
        header is not None and header.isascii() and header.lower() == _PAYMENT_AUTHORIZATION.lower()
    )


def _received_credential_header(header: object, *, present: bool) -> str | None:
    """Validate the raw ``header`` auth-param of a received challenge or its echo.

    Per https://paymentauth.org, omitting ``header`` selects ``Authorization``, and a
    present ``header`` must be ``Payment-Authorization``. Any other value, including
    ``Authorization`` and the empty string, makes the challenge unrecognized, so no
    credential is sent for it. The raw value is not echoed into the error.

    A valid value is returned in the spelling received: clients echo it unchanged, and
    the challenge ID may bind that exact spelling.
    """
    if not present:
        return None
    if isinstance(header, str) and is_payment_authorization_header(header):
        return header
    raise ParseError(
        "Unsupported credential header: challenges may only select Payment-Authorization"
    )


def with_received_credential_header(challenge: Challenge, header: str | None) -> Challenge:
    """Give a challenge built from received values the credential header as received.

    Constructing a ``Challenge`` canonicalizes ``header``. A received challenge keeps the
    issuer's spelling instead, so its credential echoes it unchanged and the challenge ID
    still verifies. ``header`` must already be absent or a ``Payment-Authorization``
    spelling.
    """
    if header is not None and challenge.header != header:
        object.__setattr__(challenge, "header", header)
    return challenge


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


# base64url (RFC 4648 §5). Trailing padding is still accepted, as mppx does. The
# possessive quantifier keeps rejection linear: no backtracking on a bad suffix.
_BASE64URL = re.compile(r"[A-Za-z0-9_-]++={0,2}")


def _b64_decode(encoded: str, max_size: int = MAX_HEADER_PAYLOAD_SIZE) -> dict[str, Any]:
    """Decode URL-safe base64 JSON to dict.

    Raises:
        ParseError: If input exceeds size limit, is invalid base64/JSON, or not a dict.
    """
    if len(encoded) > max_size:
        raise ParseError("Header payload exceeds maximum size")
    # urlsafe_b64decode discards characters outside the alphabet, so check it first.
    if not _BASE64URL.fullmatch(encoded):
        raise ParseError("Invalid base64 or JSON encoding")

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
    """Escape a string for use in a quoted-string.

    A quoted-pair can only carry Latin-1 (RFC 9110 qdtext and obs-text), so
    characters above U+00FF are rejected rather than encoded in a form the
    peer would parse back differently. Rejects CRLF.
    """
    if any(ord(character) > 0xFF for character in s):
        raise ParseError("Header value contains characters outside Latin-1")
    return _escape_quoted_text(s)


def _escape_quoted_text(s: str) -> str:
    """Escape display text, such as a description, for use in a quoted-string.

    Header values must be ByteStrings (code points up to U+00FF), so characters
    above Latin-1 are written as \\uXXXX UTF-16 escapes, as mppx does. Parsers
    follow quoted-pair semantics and read them back as ``uXXXX`` text, so use
    this only for unbound display fields. Rejects CRLF.
    """
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


def _unescape_quoted(s: str) -> str:
    """Unescape quoted-pairs (RFC 9110): a backslash yields the next character.

    A \\uXXXX escape is an ordinary quoted-pair, so it reads as ``uXXXX`` and
    is never decoded: the realm and other bound values must parse the same way
    in every SDK.
    """
    result: list[str] = []
    index = 0
    while index < len(s):
        if s[index] == "\\":
            index += 1
            if index >= len(s):
                break
        result.append(s[index])
        index += 1
    return "".join(result)


def is_valid_payment_method_id(method: object) -> bool:
    """Whether ``method`` is a string matching the spec grammar ``1*LOWERALPHA``."""
    return isinstance(method, str) and _PAYMENT_METHOD_ID_RE.fullmatch(method) is not None


def validate_payment_method_id(method: object) -> None:
    """Validate a payment method id against the spec grammar ``1*LOWERALPHA``."""
    if not is_valid_payment_method_id(method):
        raise ParseError(f"Invalid payment method id: {method!r}")


def _unescape_quoted_text(s: str) -> str:
    """Invert :func:`_escape_quoted_text`: decode its \\uXXXX escapes and quoted-pairs.

    A lone UTF-16 surrogate escape decodes to U+FFFD, so the result is always
    encodable and a Credential echoing it still parses.

    Only for display text this SDK formatted itself, such as re-reading a
    description from a header the server just built: that formatter always
    doubles a literal backslash, so a bare \\u only comes from an escape.
    Never use it for values from a peer, which follow quoted-pair semantics.
    """
    result: list[str] = []
    pending_high: int | None = None
    index = 0
    while index < len(s):
        character = s[index]
        unit: int | None = None
        if character == "\\" and index + 1 < len(s):
            digits = s[index + 2 : index + 6]
            if (
                s[index + 1] == "u"
                and len(digits) == 4
                and all(digit in string.hexdigits for digit in digits)
            ):
                unit = int(digits, 16)
                index += 6
            else:
                character = s[index + 1]
                index += 2
        elif character == "\\":
            break
        else:
            index += 1
        if pending_high is not None:
            if unit is not None and 0xDC00 <= unit <= 0xDFFF:
                result.append(chr(0x10000 + ((pending_high - 0xD800) << 10) + (unit - 0xDC00)))
                pending_high = None
                continue
            # A lone surrogate can't be encoded, so it reads as U+FFFD.
            result.append("\ufffd")
            pending_high = None
        if unit is None:
            result.append(character)
        elif 0xD800 <= unit <= 0xDBFF:
            pending_high = unit
        elif 0xDC00 <= unit <= 0xDFFF:
            result.append("\ufffd")
        else:
            result.append(chr(unit))
    if pending_high is not None:
        result.append("\ufffd")
    return "".join(result)


def parse_formatted_description(header: str) -> str | None:
    """Read the description of a WWW-Authenticate header this SDK formatted.

    :func:`format_www_authenticate` writes characters above Latin-1 in the
    description as \\uXXXX escapes, which :func:`parse_www_authenticate` reads
    as quoted-pairs (``uXXXX``). A server re-reading its own header, such as
    the MCP transport, uses this to recover the configured description.
    """
    header = header.strip()
    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")
    return _parse_auth_params(header[8:].strip(), _unescape_quoted_text).get("description")


# Auth-params the challenge ID binds (mppx); a \uXXXX escape in any of them is legacy.
_CHALLENGE_ID_BOUND_PARAMS = frozenset(
    ("realm", "method", "intent", "request", "expires", "digest", "opaque", "header")
)


def _has_unicode_escape(raw: str) -> bool:
    """Whether a raw quoted-string value holds a \\uXXXX escape.

    Walks the quoted-pairs, so an escaped backslash followed by ``uXXXX`` (a literal
    backslash in the value) is not one.
    """
    index = 0
    while index < len(raw):
        if raw[index] == "\\":
            digits = raw[index + 2 : index + 6]
            if (
                raw[index + 1 : index + 2] == "u"
                and len(digits) == 4
                and all(digit in string.hexdigits for digit in digits)
            ):
                return True
            index += 2
        else:
            index += 1
    return False


def _parse_auth_params(
    params_str: str,
    unescape: Callable[[str], str] = _unescape_quoted,
    quoted_raw: dict[str, str] | None = None,
) -> dict[str, str]:
    """Parse RFC 9110 auth-params: key="value" or key=token pairs.

    Consumes the input sequentially like mppx's `parseAuthParams`: a position that
    cannot begin an auth-param is rejected rather than skipped, and parsing stops
    at a token without `=`, which begins another auth scheme. When ``quoted_raw``
    is given, it receives each quoted value as written, before unescaping.
    """
    if len(params_str) > MAX_AUTHORIZATION_SIZE:
        raise ParseError("Authentication parameters exceed maximum size")
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
            start = index + 1
            value, index = _read_quoted_auth_param(params_str, start, unescape)
            if quoted_raw is not None:
                quoted_raw[key] = params_str[start : index - 1]
        else:
            # A token value ends at whitespace or the comma that separates auth-params.
            value_end = index
            while (
                value_end < length
                and params_str[value_end] != ","
                and not params_str[value_end].isspace()
            ):
                value_end += 1
            value, index = params_str[index:value_end], value_end

        # Auth-params are separated by OWS "," OWS: anything else after a value,
        # such as text after a closing quote or another auth-param, is malformed.
        while index < length and params_str[index].isspace():
            index += 1
        if index < length and params_str[index] != ",":
            raise ParseError("Malformed auth-param")

        if key in params:
            raise ParseError(f"Duplicate parameter: {key}")
        params[key] = value
    return params


def _read_quoted_auth_param(
    params_str: str, start: int, unescape: Callable[[str], str] = _unescape_quoted
) -> tuple[str, int]:
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
            return unescape(params_str[start : index - 1]), index
    raise ParseError("Unterminated quoted-string")


def is_legacy_unicode_escaped(challenge: object) -> bool:
    """Whether a parsed challenge escaped a bound parameter as \\uXXXX.

    Servers before quoted-pair parsing wrote characters above U+00FF that way. The value
    read differs from the one the challenge ID binds, so clients never pay such a
    challenge (mppx ``Challenge.isLegacyUnicodeEscaped``).
    """
    return getattr(challenge, "_legacy_unicode_escape", False) is True


def assert_not_legacy_unicode_escaped(challenge: object) -> None:
    """Raise :class:`~mpp.errors.LegacyUnicodeEscapedChallengeError` for a flagged challenge.

    Payment methods call this before signing anything, so a challenge whose bound value
    a pre-upgrade server escaped as \\uXXXX is never paid, even outside the client
    runtime (mppx ``Challenge.assertNotLegacyUnicodeEscaped``).
    """
    if is_legacy_unicode_escaped(challenge):
        from mpp.errors import LegacyUnicodeEscapedChallengeError

        raise LegacyUnicodeEscapedChallengeError([challenge])


def parse_www_authenticate(header: str) -> Challenge:
    """Parse a WWW-Authenticate header into a Challenge.

    Expected format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"

    Optional parameters: digest, expires, description, header, opaque
    """
    from mpp import Challenge

    if len(header) > MAX_AUTHORIZATION_SIZE:
        raise ParseError("WWW-Authenticate header exceeds maximum size")
    header = header.strip()

    # Case-insensitive scheme matching
    if not header.lower().startswith("payment "):
        raise ParseError("Expected 'Payment' authentication scheme")

    params_str = header[8:].strip()
    quoted_raw: dict[str, str] = {}
    params = _parse_auth_params(params_str, quoted_raw=quoted_raw)

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
    validate_payment_method_id(method)

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

    # Validate the raw value: an explicit Authorization or empty header is not the default.
    credential_header = _received_credential_header(
        params.get("header"), present="header" in params
    )

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

    challenge = Challenge(
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
        # Servers before quoted-pair parsing wrote characters above U+00FF as \uXXXX. Such
        # a bound value now reads as ``uXXXX``, which the challenge ID does not bind, so
        # clients refuse the challenge before paying. ``description`` is not bound.
        _legacy_unicode_escape=any(
            _has_unicode_escape(raw)
            for key, raw in quoted_raw.items()
            if key in _CHALLENGE_ID_BOUND_PARAMS
        ),
    )
    return with_received_credential_header(challenge, credential_header)


def format_www_authenticate(challenge: Challenge, realm: str) -> str:
    """Format a Challenge as a WWW-Authenticate header value.

    Output format (per IETF draft-ietf-httpauth-payment):
        Payment id="...", realm="...", method="...", intent="...", request="<base64url>"
    """
    from mpp import advertised_credential_header

    # Re-serializing a flagged challenge would hide that its bound values were misread.
    assert_not_legacy_unicode_escaped(challenge)

    # Encode request as base64url JSON
    request_b64 = canonical_b64url(challenge.request)

    validate_payment_method_id(challenge.method)

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
        parts.append(f'description="{_escape_quoted_text(challenge.description)}"')
    # Emit the challenge's own spelling: a received challenge keeps the issuer's.
    credential_header = advertised_credential_header(challenge.header)
    if credential_header:
        parts.append(f'header="{_escape_quoted(credential_header)}"')
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
    from mpp import ChallengeEcho, Credential

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
    # Match mppx's ChallengeEcho schema: these fields are required strings.
    for field in ("id", "realm", "method", "intent", "request"):
        if field not in challenge_data:
            raise ParseError(f"Credential challenge missing required field: {field}")
        if not isinstance(challenge_data[field], str):
            raise ParseError(f"Credential challenge field {field} must be a string")

    method = challenge_data["method"]
    validate_payment_method_id(method)

    credential_header = _received_credential_header(
        challenge_data.get("header"), present="header" in challenge_data
    )

    description = (
        str(challenge_data["description"])
        if challenge_data.get("description") is not None
        else None
    )
    if description is not None:
        # A retry can reflect this unsigned display field into WWW-Authenticate.
        _escape_quoted_text(description)
        if any(
            (ord(character) < 0x20 and character != "\t") or ord(character) == 0x7F
            for character in description
        ):
            raise ParseError("Header value contains invalid control characters")

    echo = ChallengeEcho(
        id=challenge_data["id"],
        realm=challenge_data["realm"],
        method=method,
        intent=challenge_data["intent"],
        request=challenge_data["request"],
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
    # Echo the challenge's spelling unchanged: the challenge ID binds it.
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
    validate_payment_method_id(method)

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


def receipt_with_valid_method(receipt: Receipt, method: str) -> Receipt:
    """Return ``receipt``, or a plain receipt with ``method`` if its method id is invalid.

    Runs once a payment has settled, so every receipt it returns must serialize. A
    receipt with a valid method (of any class) is returned as is. One whose method the
    grammar rejects is replaced by a plain :class:`~mpp.Receipt` built from its base
    fields, read as attributes, with ``method``: a subclass's constructor and copy
    behavior never run, and callers that serialize it themselves (such as
    ``verify_or_challenge`` users calling ``to_payment_receipt``) can't fail.
    """
    if is_valid_payment_method_id(receipt.method):
        return receipt
    from dataclasses import fields

    from mpp import Receipt

    values = {field.name: getattr(receipt, field.name) for field in fields(Receipt)}
    values["method"] = method
    return Receipt(**values)


def payment_receipt_header(receipt: Receipt, method: str) -> str:
    """Serialize ``receipt`` as a Payment-Receipt value, with ``method`` if its own is invalid.

    A receipt with a valid method serializes itself (keeping a subclass's override). One
    whose method the grammar rejects is written from its base fields with ``method``,
    reading them as attributes, so a settled payment always sends its receipt without
    copying or reconstructing the receipt object.
    """
    if is_valid_payment_method_id(receipt.method):
        return receipt.to_payment_receipt()
    validate_payment_method_id(method)
    from dataclasses import fields

    from mpp import Receipt

    values = {field.name: getattr(receipt, field.name) for field in fields(Receipt)}
    values["method"] = method
    return format_payment_receipt(Receipt(**values))


def format_payment_receipt(receipt: Receipt) -> str:
    """Format a Receipt as a Payment-Receipt header value.

    Output format:
        <base64-receipt>
    """
    validate_payment_method_id(receipt.method)

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
