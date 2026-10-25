"""Payment credentials carried in ``Authorization: Payment <base64url-json>`` headers."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Protocol, Self

from mpp import _base64url, _json, payment_request
from mpp.challenge import Challenge
from mpp.constants import PAYMENT_SCHEME, Header

__all__ = [
    "MAX_AUTHORIZATION_LENGTH",
    "Credential",
    "InvalidCredentialEncodingError",
    "MissingAuthorizationHeaderError",
    "MissingPaymentSchemeError",
    "extract_payment_scheme",
]


MAX_AUTHORIZATION_LENGTH = 64 * 1024
"""Maximum accepted credential header length (checked before any decoding)."""

_PREFIX = re.compile(rf"^{PAYMENT_SCHEME}\s+(.+)\Z", re.IGNORECASE)
_SCHEME = re.compile(rf"^{PAYMENT_SCHEME}\s+", re.IGNORECASE)


class MissingAuthorizationHeaderError(ValueError):
    """The credential header is absent."""

    def __init__(self, header: str = Header.AUTHORIZATION) -> None:
        super().__init__(f"Missing {header} header.")


class MissingPaymentSchemeError(ValueError):
    """The header carries no ``Payment`` scheme."""

    def __init__(self) -> None:
        super().__init__("Missing Payment scheme.")


class InvalidCredentialEncodingError(ValueError):
    """The credential is not valid base64url JSON (or exceeds the size limit)."""

    def __init__(self) -> None:
        super().__init__("Invalid base64url or JSON.")


class _HeaderLookup(Protocol):
    def get(self, key: str, /) -> str | None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Credential[P]:
    """A payment credential: the echoed challenge plus a method-specific payment proof.

    Attributes:
        challenge: The challenge from the 402 response.
        payload: Method-specific payment proof (a JSON value, or the parsed pydantic payload
            model on the server after validation).
        source: Optional payer identifier as a DID (e.g. ``did:pkh:eip155:1:0x...``).
    """

    challenge: Challenge
    payload: P
    source: str | None = None

    def serialize(self) -> str:
        """Serializes to a ``Payment <base64url>`` credential header value.

        ``challenge.opaque`` is echoed unchanged (``meta`` is re-encoded when only it is set).
        """
        wire_challenge = {
            key: value
            for key, value in self.challenge.to_dict().items()
            if key not in ("meta", "opaque", "request")
        }
        wire_opaque = self.challenge._wire_opaque()
        if wire_opaque is not None:
            wire_challenge["opaque"] = wire_opaque
        wire_challenge["request"] = payment_request.serialize(self.challenge.request)
        wire: dict[str, Any] = {"challenge": wire_challenge, "payload": self.payload}
        if self.source:
            wire["source"] = self.source
        return f"{PAYMENT_SCHEME} {_base64url.encode(_json.dumps(wire))}"

    @classmethod
    def deserialize(cls, value: str) -> "Credential[Any]":
        """Parses a ``Payment <base64url>`` credential value.

        Accepts the spec base64url ``opaque`` string and the legacy object-shaped ``opaque``.

        Raises:
            MissingPaymentSchemeError: When the value is not a Payment credential.
            InvalidCredentialEncodingError: When oversized or not valid base64url JSON.
        """
        if len(value) > MAX_AUTHORIZATION_LENGTH:
            raise InvalidCredentialEncodingError()
        match = _PREFIX.match(value)
        if not match:
            raise MissingPaymentSchemeError()
        try:
            parsed = _json.loads(_base64url.decode_text(match.group(1)))
            raw_challenge = dict(parsed["challenge"])
            raw_opaque = raw_challenge.pop("opaque", None)
            raw_challenge.pop("meta", None)
            request = raw_challenge.pop("request")
            if not isinstance(request, str):
                raise ValueError("Invalid request.")
            meta, opaque = _normalize_opaque(raw_opaque)
            challenge = Challenge.from_dict(
                {
                    **raw_challenge,
                    "meta": meta,
                    "opaque": opaque,
                    "request": payment_request.deserialize(request),
                }
            )
            source = parsed.get("source")
            return Credential(
                challenge=challenge,
                payload=parsed.get("payload"),
                source=source if isinstance(source, str) and source else None,
            )
        except Exception as error:
            raise InvalidCredentialEncodingError() from error

    @classmethod
    def from_headers(
        cls, headers: _HeaderLookup, *, header: str = Header.AUTHORIZATION
    ) -> "Credential[Any]":
        """Extracts the credential from the given header of a request's headers.

        Raises:
            MissingAuthorizationHeaderError: When the header is absent.
            MissingPaymentSchemeError: When no Payment scheme is present.
            InvalidCredentialEncodingError: When the credential cannot be decoded.
        """
        value = headers.get(header)
        if not value:
            raise MissingAuthorizationHeaderError(header)
        payment = extract_payment_scheme(value)
        if payment is None:
            raise MissingPaymentSchemeError()
        return cls.deserialize(payment)

    def with_payload[Q](self, payload: Q) -> "Credential[Q]":
        """Returns a copy carrying a different (e.g. schema-parsed) payload."""
        return replace(self, payload=payload)  # type: ignore[return-value]

    def with_challenge(self, challenge: Challenge) -> Self:
        """Returns a copy bound to a different challenge."""
        return replace(self, challenge=challenge)


def extract_payment_scheme(header: str) -> str | None:
    """Returns the ``Payment ...`` scheme from a (comma-separated) authorization value.

    Values longer than 64 KiB are rejected (``None``) before splitting.
    """
    if len(header) > MAX_AUTHORIZATION_LENGTH:
        return None
    for scheme in (part.strip() for part in header.split(",")):
        if _SCHEME.match(scheme):
            return scheme
    return None


def _normalize_opaque(value: Any) -> tuple[dict[str, str] | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, str):
        return None, value
    if isinstance(value, Mapping) and all(isinstance(entry, str) for entry in value.values()):
        # Older mppx clients emitted `opaque` as an expanded object. Normalize it back to the
        # spec-required base64url string while keeping the parsed metadata.
        meta = {str(key): str(entry) for key, entry in value.items()}
        return meta, payment_request.serialize(meta)
    raise ValueError("Invalid opaque.")
