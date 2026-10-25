"""Payment challenges carried in ``WWW-Authenticate: Payment ...`` headers."""

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, Self

from mpp import _base64url, payment_request
from mpp.constants import PAYMENT_SCHEME, Header
from mpp.expires import DATETIME_PATTERN, DatetimeInput, to_datetime_string

__all__ = [
    "MAX_REQUEST_PARAMETER_LENGTH",
    "Challenge",
    "compute_id",
]


if TYPE_CHECKING:
    from mpp.method import Method

MAX_REQUEST_PARAMETER_LENGTH = 16 * 1024
"""Maximum accepted length of the encoded ``request`` auth-param."""

_DIGEST_PATTERN = re.compile(r"^sha-256=")
_HEADER_TOKEN_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_METHOD_PATTERN = re.compile(r"^[a-z][a-z0-9:_-]*\Z")
_AUTH_PARAM_KEY_CHAR = re.compile(r"[A-Za-z0-9_-]")
_HEX4 = re.compile(r"^[0-9A-Fa-f]{4}\Z")
_KNOWN_PARAMS = frozenset(
    {"id", "realm", "method", "intent", "request", "description", "digest", "expires"}
    | {"header", "opaque"}
)


class _HeaderLookup(Protocol):
    def get(self, key: str, /) -> str | None: ...


class _ResponseLike(Protocol):
    @property
    def headers(self) -> Any: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Challenge:
    """A payment challenge.

    Construct directly when the ``id`` is known, or use :meth:`create` /
    :meth:`for_method` to compute an HMAC-bound id from a server secret.

    Attributes:
        id: Unique challenge identifier (HMAC-bound when issued by an mppx-style server).
        realm: Server realm (e.g. hostname).
        method: Payment method (e.g. ``"tempo"``).
        intent: Intent type (e.g. ``"charge"``).
        request: Method-specific request data (wire form, camelCase keys).
        description: Optional human-readable description (not HMAC-bound).
        digest: Optional request body digest (``sha-256=...``).
        expires: Optional ISO 8601 expiry.
        header: Optional HTTP field the client must use for the credential
            (``Authorization`` when omitted).
        meta: Optional parsed server correlation data (decoded ``opaque``).
        opaque: Optional raw base64url server correlation data; clients must echo it unchanged.
        protocol: Non-wire provenance tag set by client protocols (``None`` for native Payment
            auth, ``"mcp"`` for MCP-over-HTTP, ``"x402"`` for synthesized x402 challenges).
            Ignored by equality and serialization.
    """

    id: str
    realm: str
    method: str
    intent: str
    request: dict[str, Any]
    description: str | None = None
    digest: str | None = None
    expires: str | None = None
    header: str | None = None
    meta: dict[str, str] | None = None
    opaque: str | None = None
    protocol: str | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        _validate(self)

    # -- construction -------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        realm: str,
        method: str,
        intent: str,
        request: Mapping[str, Any],
        id: str | None = None,
        secret_key: str | None = None,
        description: str | None = None,
        digest: str | None = None,
        expires: DatetimeInput | None = None,
        header: str | None = None,
        meta: Mapping[str, str] | None = None,
        opaque: str | None = None,
    ) -> Self:
        """Creates a challenge, computing an HMAC-bound id when ``secret_key`` is given.

        The id is HMAC-SHA256 over ``realm|method|intent|request|expires|digest[|header]|opaque``
        (base64url, unpadded). The default ``Authorization`` credential header is never
        advertised. ``meta`` is serialized into ``opaque`` when ``opaque`` is not given.

        Raises:
            TypeError: When neither ``id`` nor ``secret_key`` is provided.
            ValueError: When a field is invalid.
        """
        if secret_key is None and id is None:
            raise TypeError("Challenge.create() requires either `id` or `secret_key`.")
        resolved_header = None if _is_default_credential_header(header) else header
        resolved_expires = to_datetime_string(expires) if expires else None
        resolved_meta = dict(meta) if meta is not None else None
        resolved_opaque = (
            opaque
            if opaque is not None
            else (payment_request.serialize(resolved_meta) if resolved_meta is not None else None)
        )
        resolved_request = dict(request)
        if secret_key is not None:
            id = _compute_id(
                secret_key,
                realm=realm,
                method=method,
                intent=intent,
                request=resolved_request,
                expires=resolved_expires,
                digest=digest,
                header=resolved_header,
                opaque=resolved_opaque,
            )
        assert id is not None
        return cls(
            id=id,
            realm=realm,
            method=method,
            intent=intent,
            request=resolved_request,
            description=description or None,
            digest=digest or None,
            expires=resolved_expires or None,
            header=resolved_header,
            meta=resolved_meta,
            opaque=resolved_opaque,
        )

    @classmethod
    def for_method(
        cls,
        method: "Method",
        *,
        realm: str,
        request: Mapping[str, Any],
        id: str | None = None,
        secret_key: str | None = None,
        description: str | None = None,
        digest: str | None = None,
        expires: DatetimeInput | None = None,
        header: str | None = None,
        meta: Mapping[str, str] | None = None,
    ) -> Self:
        """Creates a challenge whose request is validated/transformed by ``method``'s model."""
        return cls.create(
            realm=realm,
            method=method.name,
            intent=method.intent,
            request=method.normalize_request(request),
            id=id,
            secret_key=secret_key if id is None else None,
            description=description,
            digest=digest,
            expires=expires,
            header=header,
            meta=meta,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Validates a JSON challenge object (as carried in MCP errors); unknown keys are ignored.

        Raises:
            ValueError: When the object is not a valid challenge.
        """
        if not isinstance(data, Mapping):
            raise ValueError("Challenge must be an object.")
        for key in ("id", "realm", "method", "intent"):
            if not isinstance(data.get(key), str):
                raise ValueError(f"Invalid challenge: `{key}` must be a string.")
        return cls(
            id=data["id"],
            realm=data["realm"],
            method=data["method"],
            intent=data["intent"],
            request=data.get("request"),  # type: ignore[arg-type]  # validated in __post_init__
            description=data.get("description"),
            digest=data.get("digest"),
            expires=data.get("expires"),
            header=data.get("header"),
            meta=data.get("meta"),
            opaque=data.get("opaque"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Returns the JSON object form of the challenge (wire ``request`` stays an object)."""
        result: dict[str, Any] = {}
        if self.description is not None:
            result["description"] = self.description
        if self.digest is not None:
            result["digest"] = self.digest
        if self.expires is not None:
            result["expires"] = self.expires
        if self.header is not None:
            result["header"] = self.header
        result["id"] = self.id
        result["intent"] = self.intent
        result["method"] = self.method
        if self.meta is not None:
            result["meta"] = dict(self.meta)
        if self.opaque is not None:
            result["opaque"] = self.opaque
        result["realm"] = self.realm
        result["request"] = self.request
        return result

    # -- wire format --------------------------------------------------------------------------

    def serialize(self) -> str:
        """Serializes the challenge to a ``WWW-Authenticate`` header value.

        Raises:
            ValueError: When a value contains CR or LF (header injection).
        """
        parts = [
            _auth_param("id", self.id),
            _auth_param("realm", self.realm),
            _auth_param("method", self.method),
            _auth_param("intent", self.intent),
            _auth_param("request", payment_request.serialize(self.request)),
        ]
        if self.description is not None:
            parts.append(_auth_param("description", self.description))
        if self.digest is not None:
            parts.append(_auth_param("digest", self.digest))
        if self.expires is not None:
            parts.append(_auth_param("expires", self.expires))
        if self.header is not None and not _is_default_credential_header(self.header):
            parts.append(_auth_param("header", self.header))
        if self.opaque is not None:
            parts.append(_auth_param("opaque", self.opaque))
        elif self.meta is not None:
            parts.append(_auth_param("opaque", payment_request.serialize(self.meta)))
        return f"{PAYMENT_SCHEME} {', '.join(parts)}"

    @classmethod
    def deserialize(cls, value: str) -> Self:
        """Parses the ``Payment`` challenge from a ``WWW-Authenticate`` value.

        The value may contain other auth schemes; the first ``Payment`` scheme is used.

        Raises:
            ValueError: When no valid Payment challenge can be parsed.
        """
        params = _extract_payment_auth_params(value)
        if params is None:
            raise ValueError("Missing Payment scheme.")
        result = _parse_auth_params(params)
        request = result.pop("request", None)
        opaque = result.pop("opaque", None)
        if not request:
            raise ValueError("Missing request parameter.")
        if len(request) > MAX_REQUEST_PARAMETER_LENGTH:
            raise ValueError("Request parameter too large.")
        method = result.get("method")
        if method and not _METHOD_PATTERN.match(method):
            raise ValueError(f'Invalid method: "{method}". Must be lowercase per spec.')
        if "meta" in result:
            raise ValueError("Invalid challenge: `meta` must be an object.")
        for key in ("id", "realm", "method", "intent"):
            if key not in result:
                raise ValueError(f"Invalid challenge: missing `{key}`.")
        decoded = payment_request.deserialize(request)
        return cls.create(
            id=result["id"],
            realm=result["realm"],
            method=result["method"],
            intent=result["intent"],
            request=_require_record(decoded),
            description=result.get("description"),
            digest=result.get("digest"),
            expires=result.get("expires"),
            header=result.get("header"),
            opaque=opaque or None,
        )

    @classmethod
    def deserialize_list(cls, value: str) -> list[Self]:
        """Parses every ``Payment`` challenge in a (possibly merged) ``WWW-Authenticate`` value.

        Raises:
            ValueError: When no Payment scheme is present or one of them is invalid.
        """
        starts = _find_scheme_starts(value, PAYMENT_SCHEME)
        if not starts:
            raise ValueError("No Payment schemes found.")
        challenges: list[Self] = []
        for index, start in enumerate(starts):
            end = starts[index + 1] if index + 1 < len(starts) else len(value)
            chunk = re.sub(r",\s*$", "", value[start:end])
            challenges.append(cls.deserialize(chunk))
        return challenges

    @classmethod
    def from_headers(cls, headers: _HeaderLookup) -> Self:
        """Parses the ``Payment`` challenge from response headers.

        Raises:
            ValueError: When ``WWW-Authenticate`` is missing or invalid.
        """
        return cls.deserialize(_www_authenticate(headers))

    @classmethod
    def from_headers_list(cls, headers: _HeaderLookup) -> list[Self]:
        """Parses every ``Payment`` challenge from response headers."""
        return cls.deserialize_list(_www_authenticate(headers))

    @classmethod
    def from_response(cls, response: _ResponseLike) -> Self:
        """Parses the challenge from a 402 response (``httpx.Response`` or server ``Response``).

        Raises:
            ValueError: When the status is not 402 or the header is missing/invalid.
        """
        return cls.from_headers(_payment_required_headers(response))

    @classmethod
    def from_response_list(cls, response: _ResponseLike) -> list[Self]:
        """Parses every ``Payment`` challenge from a 402 response."""
        return cls.from_headers_list(_payment_required_headers(response))

    # -- verification -------------------------------------------------------------------------

    def verify(self, secret_key: str) -> bool:
        """Returns whether ``id`` is the HMAC this server would issue for these fields."""
        expected = _compute_id(
            secret_key,
            realm=self.realm,
            method=self.method,
            intent=self.intent,
            request=self.request,
            expires=self.expires,
            digest=self.digest,
            header=self.header,
            opaque=self._wire_opaque(),
        )
        return hmac.compare_digest(
            hashlib.sha256(self.id.encode()).digest(), hashlib.sha256(expected.encode()).digest()
        )

    @property
    def credential_header(self) -> str:
        """The HTTP field name a client must use for the payment credential."""
        return self.header or Header.AUTHORIZATION

    def _wire_opaque(self) -> str | None:
        if self.opaque is not None:
            return self.opaque
        return payment_request.serialize(self.meta) if self.meta is not None else None


def _www_authenticate(headers: _HeaderLookup) -> str:
    value = headers.get(Header.WWW_AUTHENTICATE)
    if not value:
        raise ValueError(f"Missing {Header.WWW_AUTHENTICATE} header.")
    return value


def _payment_required_headers(response: _ResponseLike) -> _HeaderLookup:
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(response, "status", None)
    if status != 402:
        raise ValueError("Response status is not 402.")
    return response.headers


def compute_id(
    secret_key: str,
    *,
    realm: str,
    method: str,
    intent: str,
    request: Mapping[str, Any],
    expires: str | None = None,
    digest: str | None = None,
    header: str | None = None,
    opaque: str | None = None,
) -> str:
    """Computes the HMAC-SHA256 challenge id over the canonical binding input."""
    return _compute_id(
        secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        digest=digest,
        header=None if _is_default_credential_header(header) else header,
        opaque=opaque,
    )


def _compute_id(
    secret_key: str,
    *,
    realm: str,
    method: str,
    intent: str,
    request: Mapping[str, Any],
    expires: str | None,
    digest: str | None,
    header: str | None,
    opaque: str | None,
) -> str:
    # Seven fixed positional slots joined by '|'; optional fields use '' so the slot count is
    # stable. A non-default credential header is inserted right before the final opaque slot.
    values = [
        realm,
        method,
        intent,
        payment_request.serialize(request),
        expires or "",
        digest or "",
    ]
    if header is not None and not _is_default_credential_header(header):
        values.append(header)
    values.append(opaque or "")
    mac = hmac.new(secret_key.encode(), "|".join(values).encode(), hashlib.sha256).digest()
    return _base64url.encode(mac)


def _is_default_credential_header(header: str | None) -> bool:
    return header is not None and header.lower() == Header.AUTHORIZATION.lower()


def _require_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Invalid challenge: `request` must be an object.")
    return value


def _validate(challenge: Challenge) -> None:
    for name in ("id", "realm", "method", "intent"):
        if not isinstance(getattr(challenge, name), str):
            raise ValueError(f"Invalid challenge: `{name}` must be a string.")
    if len(challenge.id) < 1:
        raise ValueError("Invalid challenge: `id` must not be empty.")
    if not isinstance(challenge.request, dict) or not all(
        isinstance(key, str) for key in challenge.request
    ):
        raise ValueError("Invalid challenge: `request` must be an object.")
    for name in ("description", "digest", "expires", "header", "opaque"):
        value = getattr(challenge, name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"Invalid challenge: `{name}` must be a string.")
    if challenge.digest is not None and not _DIGEST_PATTERN.match(challenge.digest):
        raise ValueError("Invalid digest format")
    if challenge.expires is not None and not DATETIME_PATTERN.match(challenge.expires):
        raise ValueError("Invalid ISO 8601 datetime")
    if challenge.header is not None and not _HEADER_TOKEN_PATTERN.match(challenge.header):
        raise ValueError("Invalid HTTP header name")
    if challenge.meta is not None and (
        not isinstance(challenge.meta, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in challenge.meta.items())
    ):
        raise ValueError("Invalid challenge: `meta` must be a string-to-string object.")


def _auth_param(name: str, value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError("Invalid quoted-string value.")
    out: list[str] = []
    for char in value:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif code > 0xFFFF:
            # JavaScript strings are UTF-16: astral characters escape as a surrogate pair.
            code -= 0x10000
            out.append(f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}")
        elif code >= 0x100:
            # Header values must be ByteStrings: escape anything above Latin-1.
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return f'{name}="{"".join(out)}"'


def _extract_payment_auth_params(header: str) -> str | None:
    starts = _find_scheme_starts(header, PAYMENT_SCHEME)
    if not starts:
        return None
    index = starts[0] + len(PAYMENT_SCHEME)
    while index < len(header) and header[index].isspace():
        index += 1
    return header[index:]


def _parse_auth_params(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    i = 0
    length = len(text)
    while i < length:
        while i < length and (text[i].isspace() or text[i] == ","):
            i += 1
        if i >= length:
            break
        key_start = i
        while i < length and _AUTH_PARAM_KEY_CHAR.match(text[i]):
            i += 1
        key = text[key_start:i].lower()
        if not key:
            raise ValueError("Malformed auth-param.")
        while i < length and text[i].isspace():
            i += 1
        # A token without '=' is most likely the start of another auth scheme.
        if i >= length or text[i] != "=":
            break
        i += 1
        while i < length and text[i].isspace():
            i += 1
        try:
            value, i = _read_auth_param_value(text, i)
        except ValueError:
            # An unterminated quoted value of an unknown extension parameter swallows the rest of
            # the header; ignore it (conformance `adversarial_unclosed_quoted_extension`). Known
            # parameters keep mppx's strict error.
            if key in _KNOWN_PARAMS:
                raise
            break
        if key in result:
            raise ValueError(f"Duplicate parameter: {key}")
        result[key] = value
    return result


def _read_auth_param_value(text: str, start: int) -> tuple[str, int]:
    if start < len(text) and text[start] == '"':
        return _read_quoted_value(text, start + 1)
    end = text.find(",", start)
    if end == -1:
        end = len(text)
    return text[start:end].strip(), end


def _read_quoted_value(text: str, start: int) -> tuple[str, int]:
    parts: list[str] = []
    i = start
    segment_start = start
    length = len(text)
    while i < length:
        char = text[i]
        i += 1
        if char == "\\":
            parts.append(text[segment_start : i - 1])
            if i >= length:
                break
            escaped = text[i]
            i += 1
            hex_digits = text[i : i + 4] if escaped == "u" else ""
            if escaped == "u" and _HEX4.match(hex_digits):
                parts.append(chr(int(hex_digits, 16)))
                i += 4
            else:
                parts.append(escaped)
            segment_start = i
            continue
        if char == '"':
            parts.append(text[segment_start : i - 1])
            joined = "".join(parts)
            # Recombine UTF-16 surrogate pairs produced by `\uXXXX` escapes.
            return _join_surrogates(joined), i
    raise ValueError("Unterminated quoted-string.")


def _starts_with_scheme_token(value: str, index: int, token: str) -> bool:
    end = index + len(token)
    if value[index:end].lower() != token.lower():
        return False
    return end < len(value) and value[end].isspace()


def _find_scheme_starts(value: str, token: str) -> list[int]:
    starts: list[int] = []
    in_quotes = False
    escaped = False
    first = token[0].lower()
    for i, char in enumerate(value):
        if in_quotes:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quotes = False
            continue
        if char == '"':
            in_quotes = True
            continue
        if char.lower() != first or not _starts_with_scheme_token(value, i, token):
            continue
        boundary = i - 1
        while boundary >= 0 and value[boundary].isspace():
            boundary -= 1
        if boundary >= 0 and value[boundary] != ",":
            continue
        starts.append(i)
    return starts


def _join_surrogates(value: str) -> str:
    if not any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        return value
    return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
