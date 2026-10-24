"""Server-side x402 compatibility for Payment-auth intents.

An intent that implements :class:`X402Intent` is offered to x402 clients
next to its native Payment challenge, the way mppx's EVM charge transport adds
an x402 path (``src/x402/server/EvmCharge.ts``):

- unpaid responses carry ``PAYMENT-REQUIRED`` next to ``WWW-Authenticate``,
- a ``PAYMENT-SIGNATURE`` credential is bound to the route by comparing its
  echoed ``accepted`` requirements and ``resource`` URL, converted to the
  intent's native credential payload, and verified like any other credential,
- paid responses to x402 requests carry ``PAYMENT-RESPONSE``.

x402 payloads carry no server-issued challenge, so the converted credential
gets a local challenge echo whose ID starts with ``x402:``. It is never
HMAC-verified; route binding comes from the requirements comparison above,
which is the binding x402 itself defines (mppx's ``routeBinding: 'resource'``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mpp import ChallengeEcho, Credential, canonical_b64url
from mpp._parsing import ParseError, _b64_decode
from mpp.errors import MalformedCredentialError, VerificationFailedError
from mpp.x402._header import (
    InvalidHeaderError,
    decode_payment_signature,
    encode_payment_required,
    encode_payment_response,
)
from mpp.x402._types import (
    PAYMENT_SIGNATURE_HEADER,
    SYNTHETIC_CHALLENGE_ID_PREFIX,
    X402_VERSION,
    PaymentPayload,
    PaymentRequirements,
    requirements_match,
)

if TYPE_CHECKING:
    from mpp import Receipt


@dataclass(frozen=True, slots=True)
class X402Input:
    """x402 request context for one paid route.

    Attributes:
        resource_url: Absolute URL of the protected resource. x402 responses
            advertise it, and x402 payloads that echo a resource must match it.
        payment_signature: The request's ``PAYMENT-SIGNATURE`` header value.
    """

    resource_url: str
    payment_signature: str | None = None


@runtime_checkable
class X402Intent(Protocol):
    """An intent that x402 ``exact`` clients can also pay."""

    name: str

    def x402_requirements(self, request: dict[str, Any]) -> PaymentRequirements:
        """Return the x402 requirements that pay this canonical request."""
        ...

    def x402_credential_payload(
        self, payment: PaymentPayload, request: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None]:
        """Convert a bound x402 payload to the native payload and its source DID."""
        ...


def x402_bindable(challenge: Any) -> bool:
    """Return whether x402 payments can pay a challenge without weakening it.

    x402 payloads can't carry a body digest or application metadata, so routes
    that bind either (``body=`` or ``meta=``) are not offered to x402 clients.
    """
    if getattr(challenge, "digest", None):
        return False
    opaque = getattr(challenge, "opaque", None)
    return not (isinstance(opaque, Mapping) and any(key != "_mpp_nonce" for key in opaque))


def is_x402_credential(credential: Credential) -> bool:
    """Return whether a credential was converted from an x402 payment payload."""
    return credential.challenge.id.startswith(SYNTHETIC_CHALLENGE_ID_PREFIX)


def x402_credential(
    payment_signature: str,
    intent: X402Intent,
    *,
    method: str,
    request: dict[str, Any],
    realm: str,
    resource_url: str,
) -> Credential:
    """Bind a ``PAYMENT-SIGNATURE`` value to a route and convert it.

    Raises:
        MalformedCredentialError: If the header is not a valid x402 v2 payload.
        VerificationFailedError: If the payload pays different requirements or
            a different resource than this route.
    """
    try:
        payment = decode_payment_signature(payment_signature)
    except InvalidHeaderError as error:
        raise MalformedCredentialError(
            f"invalid {PAYMENT_SIGNATURE_HEADER} header: {error}"
        ) from error

    requirements = intent.x402_requirements(request)
    if not requirements_match(payment["accepted"], requirements):
        raise VerificationFailedError("x402 payment payload does not match route requirements")

    # The resource sits outside the signed authorization, so this binds honest
    # clients to the route they were offered; requirements binding still
    # applies to every payload.
    resource = payment.get("resource")
    if resource is None or resource.get("url") != resource_url:
        raise VerificationFailedError("x402 payment payload resource does not match route resource")

    payload, source = intent.x402_credential_payload(payment, request)
    digest = hashlib.sha256(
        json.dumps(payment, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    echo = ChallengeEcho(
        id=f"{SYNTHETIC_CHALLENGE_ID_PREFIX}{digest}",
        realm=realm,
        method=method,
        intent=intent.name,
        request=canonical_b64url(request),
    )
    return Credential(challenge=echo, payload=payload, source=source)


def unique_requirements(
    accepts: Iterable[PaymentRequirements],
) -> list[PaymentRequirements]:
    """Drop duplicate requirements while keeping their order."""
    unique: list[PaymentRequirements] = []
    for accepted in accepts:
        if not any(requirements_match(accepted, existing) for existing in unique):
            unique.append(accepted)
    return unique


def payment_required_header(
    accepts: Iterable[PaymentRequirements],
    resource_url: str,
    error: str | None = None,
) -> str | None:
    """Build a ``PAYMENT-REQUIRED`` value, or ``None`` when nothing is offered."""
    unique = unique_requirements(accepts)
    if not unique:
        return None
    return encode_payment_required(
        {
            "x402Version": X402_VERSION,
            "accepts": unique,
            "resource": {"url": resource_url},
            "error": error or f"{PAYMENT_SIGNATURE_HEADER} header is required",
        }
    )


def payment_response_header(credential: Credential, receipt: Receipt) -> str | None:
    """Build the ``PAYMENT-RESPONSE`` value for a paid x402 request.

    Returns ``None`` for credentials that did not come from x402, which keep
    the native ``Payment-Receipt`` only.
    """
    if not is_x402_credential(credential):
        return None
    try:
        request = _b64_decode(credential.challenge.request) if credential.challenge.request else {}
    except ParseError:
        request = {}
    details = request.get("methodDetails") if isinstance(request, Mapping) else None
    chain_id = details.get("chainId") if isinstance(details, Mapping) else None
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        return None
    payer = receipt.payer or credential.payload.get("from")
    response: dict[str, Any] = {
        "success": True,
        "transaction": receipt.reference,
        "network": f"eip155:{chain_id}",
    }
    if isinstance(payer, str):
        response["payer"] = payer
    return encode_payment_response(response)  # type: ignore[arg-type]
