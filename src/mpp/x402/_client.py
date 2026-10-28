"""x402 client protocol: ``PAYMENT-REQUIRED`` offers as payment challenges.

Mirrors mppx's ``src/client/internal/protocols/X402.ts``: a ``402`` carrying a
``PAYMENT-REQUIRED`` header yields one synthetic ``evm/charge`` challenge per
supported ``accepts`` entry, paid back in ``PAYMENT-SIGNATURE``. The challenges
are :class:`X402Challenge` instances, which keeps them apart from native
``evm/charge`` challenges with the same method and intent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from mpp import Challenge, Credential
from mpp._canonical import canonical_b64url
from mpp._typing import is_list
from mpp.x402._header import _decode, decode_payment_response, decode_payment_signature
from mpp.x402._types import (
    EXACT_SCHEME,
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    SYNTHETIC_CHALLENGE_ID_PREFIX,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
    X402FormatError,
    _extensions,
    _object,
    _version,
    parse_payment_requirements,
    parse_resource,
)

X402_METHOD = "evm"
"""Method name of the challenges synthesized from x402 offers (mppx ``paymentMethod``)."""

X402_INTENT = "charge"
"""Intent of the challenges synthesized from x402 offers (mppx ``exactIntent``)."""

CREDENTIAL_HEADERS = (PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER)
"""x402 headers cleared before a fresh credential is attached (mppx ``credentialHeaders``)."""

_REQUIREMENT_KEYS = ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra")
_RESOURCE_KEYS = ("url", "description", "iconUrl", "mimeType", "serviceName", "tags")


@dataclass(frozen=True, slots=True)
class X402Challenge(Challenge):
    """An ``evm/charge`` challenge synthesized from an x402 ``accepts`` entry.

    ``request`` holds the entry's payment requirements plus the response's
    ``resource`` and ``extensions``.
    """


def is_x402_challenge(challenge: object) -> bool:
    """Return whether a challenge came from an x402 ``PAYMENT-REQUIRED`` offer."""
    if not isinstance(challenge, X402Challenge):
        return False
    request = challenge.request
    return request.get("scheme") == EXACT_SCHEME and isinstance(request.get("network"), str)


def _pick(record: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: record[key] for key in keys if key in record}


def _parse_envelope(value: Any) -> dict[str, Any]:
    """Validate the envelope only; ``accepts`` entries are checked one by one."""
    record = _object(value, "paymentRequired")
    _version(record, "paymentRequired")
    accepts = record.get("accepts")
    if not is_list(accepts):
        raise X402FormatError("paymentRequired.accepts must be an array")
    resource = parse_resource(record.get("resource"), "paymentRequired.resource")
    envelope: dict[str, Any] = {
        "accepts": list(accepts),
        "resource": _pick(dict(resource), _RESOURCE_KEYS),
    }
    if record.get("extensions") is not None:
        try:
            _extensions(record, "paymentRequired")
        except X402FormatError:
            pass
        else:
            envelope["extensions"] = record["extensions"]
    return envelope


def _realm(url: str) -> str:
    split = urlsplit(url)
    if not split.scheme or not split.hostname:
        raise X402FormatError("paymentRequired.resource.url must be an absolute URL")
    return split.netloc.rpartition("@")[2].lower()


def x402_challenges(header: str) -> list[Challenge]:
    """Return the challenges a ``PAYMENT-REQUIRED`` header value offers.

    Entries this package can't pay (other schemes, non-EVM networks, malformed
    requirements) are skipped, as mppx does.

    Raises:
        X402FormatError: The header is not a valid x402 v2 payment-required response.
    """
    envelope = _decode(header, _parse_envelope)
    resource: ResourceInfo = envelope["resource"]
    realm = _realm(resource["url"])
    challenges: list[Challenge] = []
    for index, entry in enumerate(envelope["accepts"]):
        try:
            accepted = parse_payment_requirements(entry)
        except X402FormatError:
            continue
        request: dict[str, Any] = _pick(dict(accepted), _REQUIREMENT_KEYS)
        if "extensions" in envelope:
            request["extensions"] = envelope["extensions"]
        request["resource"] = resource
        challenges.append(
            X402Challenge(
                id=f"{SYNTHETIC_CHALLENGE_ID_PREFIX}{index}",
                method=X402_METHOD,
                intent=X402_INTENT,
                request=request,
                realm=realm,
                request_b64=canonical_b64url(request),
            )
        )
    return challenges


def payment_requirements(challenge: Challenge) -> PaymentRequirements:
    """Return an x402 challenge's payment requirements (mppx ``toPaymentRequirements``)."""
    request = {
        key: value
        for key, value in challenge.request.items()
        if key not in ("extensions", "resource")
    }
    return parse_payment_requirements(request)


def x402_credential(challenge: Challenge, payment_signature: str) -> Credential:
    """Wrap a ``PAYMENT-SIGNATURE`` value as a credential for client events.

    The payload is the decoded x402 payment payload; the transport sends it
    back with :func:`mpp.x402.encode_payment_signature`.
    """
    return Credential(
        challenge=challenge.to_echo(),
        payload=dict(decode_payment_signature(payment_signature)),
    )


def payment_response(response: Any) -> SettleResponse | None:
    """Return the x402 settlement receipt (``PAYMENT-RESPONSE``) of a paid response.

    Accepts any response with a ``headers`` mapping, such as an
    ``httpx.Response``. Returns ``None`` when the header is absent.

    Raises:
        InvalidHeaderError: The header is present but malformed.
    """
    value = response.headers.get(PAYMENT_RESPONSE_HEADER)
    if value is None:
        return None
    return decode_payment_response(value)
