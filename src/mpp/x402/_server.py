"""Server-side x402 compatibility for Payment-auth methods.

A :class:`~mpp.server.method.ServerMethod` whose ``x402`` implements
:class:`X402Intent` is offered to x402 clients next to its native Payment
challenge:

- unpaid responses carry ``PAYMENT-REQUIRED`` next to ``WWW-Authenticate``,
- a ``PAYMENT-SIGNATURE`` credential is bound to the route by comparing its
  echoed ``accepted`` requirements and ``resource`` URL, converted to the
  intent's native credential payload, and verified like any other credential,
- paid responses to x402 requests carry ``PAYMENT-RESPONSE``.

x402 payloads carry no server-issued challenge, so the converted credential
gets a local challenge echo whose ID starts with ``x402:``. It is never
HMAC-verified. Route binding follows mppx: 402 responses advertise an
``extensions.mppx`` entry describing the route (HTTP method, framework scope,
body digest, application metadata), and a client that echoes it signs an
EIP-3009 nonce derived from it. With ``route_binding="required"`` (the default),
a route that has scope, a body digest or metadata only accepts such bound
payments; ``"resource"`` also accepts payments bound the way x402 itself binds
them, by the echoed ``accepted`` terms and ``resource`` URL.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from mpp import ChallengeEcho, Credential, canonical_b64url
from mpp._parsing import ParseError, _b64_decode
from mpp._typing import is_mapping
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
    _json_equal,
    requirements_match,
)

if TYPE_CHECKING:
    from mpp import Receipt


RouteBinding = Literal["required", "resource"]
"""How a route-scoped charge binds an x402 payment to its route (mppx ``routeBinding``)."""

ROUTE_BINDING_EXTENSION = "mppx"
"""x402 extension key carrying mppx's route binding."""

ROUTE_BINDING_SCHEMA: dict[str, Any] = {
    "additionalProperties": False,
    "properties": {
        "_mppx_scope": {"type": "string"},
        "digest": {"type": "string"},
        "method": {"type": "string"},
        "nonce": {"type": "string"},
        "opaque": {"type": "string"},
    },
    "required": ["method"],
    "type": "object",
}
"""JSON schema of the ``extensions.mppx.info`` object, identical to mppx's."""


@dataclass(frozen=True, slots=True)
class X402Input:
    """x402 request context for one paid route.

    Attributes:
        resource_url: Absolute URL of the protected resource. x402 responses
            advertise it, and x402 payloads that echo a resource must match it.
        payment_signature: The request's ``PAYMENT-SIGNATURE`` header value.
        http_method: The request's HTTP method, bound into the route binding.
    """

    resource_url: str
    payment_signature: str | None = None
    http_method: str = "GET"


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


def _application_meta(meta: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not is_mapping(meta):
        return None
    return {key: value for key, value in meta.items() if key != "_mpp_nonce"} or None


def route_requires_binding(
    *, scope: Any = None, digest: str | None = None, meta: Mapping[str, Any] | None = None
) -> bool:
    """Return whether a route is scoped: bound to a framework scope, body or metadata."""
    return scope is not None or bool(digest) or _application_meta(meta) is not None


def route_extensions(
    *,
    http_method: str,
    scope: Any = None,
    digest: str | None = None,
    meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the ``extensions`` object that describes a route (mppx ``routeExtensions``).

    pympp's framework scope is an object, so it is bound as its canonical
    base64url JSON, like application metadata in ``opaque``.
    """
    info: dict[str, Any] = {"method": http_method.upper()}
    if scope is not None:
        info["_mppx_scope"] = scope if isinstance(scope, str) else canonical_b64url(scope)
    if digest:
        info["digest"] = digest
    app_meta = _application_meta(meta)
    if app_meta is not None:
        info["opaque"] = canonical_b64url(app_meta)
    return {ROUTE_BINDING_EXTENSION: {"info": info, "schema": ROUTE_BINDING_SCHEMA}}


def challenge_route_extensions(challenge: Any, http_method: str) -> dict[str, Any]:
    """Return the route extensions of an issued challenge."""
    request = getattr(challenge, "request", None)
    scope = request.get("_mppx_scope") if is_mapping(request) else None
    return route_extensions(
        http_method=http_method,
        scope=scope,
        digest=getattr(challenge, "digest", None),
        meta=getattr(challenge, "opaque", None),
    )


def route_nonce(
    *, accepted: Mapping[str, Any], resource: Mapping[str, Any], extensions: Mapping[str, Any]
) -> str:
    """Return the route-bound EIP-3009 nonce (mppx ``RouteBinding.nonce``).

    ``sha256(jcs(accepted) | jcs(resource) | jcs(extensions))`` over unpadded
    base64url JCS encodings, hex encoded with a ``0x`` prefix.
    """
    joined = "|".join(canonical_b64url(value) for value in (accepted, resource, extensions))
    return "0x" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _contains_extensions(actual: Any, expected: Mapping[str, Any]) -> bool:
    """Return whether echoed extensions carry the route's, ignoring the client salt."""
    if not is_mapping(actual):
        return False
    for key, expected_extension in expected.items():
        extension = actual.get(key)
        if not is_mapping(extension):
            return False
        info = extension.get("info")
        if not is_mapping(info):
            return False
        nonce = info.get("nonce")
        stripped = (
            {k: v for k, v in info.items() if k != "nonce"} if isinstance(nonce, str) else info
        )
        if not _json_equal(extension.get("schema"), expected_extension["schema"]):
            return False
        if not _json_equal(stripped, expected_extension["info"]):
            return False
    return True


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
    http_method: str = "GET",
    digest: str | None = None,
    meta: Mapping[str, Any] | None = None,
) -> Credential:
    """Bind a ``PAYMENT-SIGNATURE`` value to a route and convert it.

    The intent's ``route_binding`` (default ``"required"``) decides whether
    scoped routes also accept payments without mppx's route binding.

    Raises:
        MalformedCredentialError: If the header is not a valid x402 v2 payload.
        VerificationFailedError: If the payload pays different requirements, a
            different resource or route, or lacks a binding the route requires.
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

    scope = request.get("_mppx_scope")
    mode: RouteBinding = getattr(intent, "route_binding", "required")
    expected_resource = {"url": resource_url}
    echoed_extensions = payment.get("extensions")
    binding = (
        echoed_extensions.get(ROUTE_BINDING_EXTENSION) if is_mapping(echoed_extensions) else None
    )
    client_nonce = binding.get("info", {}).get("nonce") if is_mapping(binding) else None
    is_route_bound = client_nonce is not None
    requires_binding = route_requires_binding(scope=scope, digest=digest, meta=meta)
    resource = payment.get("resource")

    # mppx's binding is not part of the x402 spec, so other clients can't
    # produce it; "resource" lets them pay scoped routes the way x402 binds.
    if requires_binding and not is_route_bound and mode == "required":
        raise VerificationFailedError("x402 payment payload does not bind required route metadata")
    if is_route_bound:
        if resource is None or not _json_equal(resource, expected_resource):
            raise VerificationFailedError(
                "x402 payment payload resource does not match route resource"
            )
        expected_extensions = route_extensions(
            http_method=http_method, scope=scope, digest=digest, meta=meta
        )
        if not _contains_extensions(echoed_extensions, expected_extensions):
            raise VerificationFailedError(
                "x402 payment payload extensions do not match route binding"
            )
    elif requires_binding:
        # The resource sits outside the signed authorization: this binds honest
        # clients to the route they were offered, not an active attacker.
        if resource is None or resource.get("url") != resource_url:
            raise VerificationFailedError(
                "x402 payment payload resource does not match route resource"
            )
    elif resource is not None and resource.get("url") != resource_url:
        raise VerificationFailedError("x402 payment payload resource does not match route resource")

    payload, source = intent.x402_credential_payload(payment, request)
    if is_route_bound:
        assert is_mapping(echoed_extensions)
        expected_nonce = route_nonce(
            accepted=requirements, resource=expected_resource, extensions=echoed_extensions
        )
        if str(payload.get("nonce", "")).lower() != expected_nonce:
            raise VerificationFailedError("x402 authorization nonce does not match route binding")

    payment_digest = hashlib.sha256(
        json.dumps(payment, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    echo = ChallengeEcho(
        id=f"{SYNTHETIC_CHALLENGE_ID_PREFIX}{payment_digest}",
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
    extensions: Mapping[str, Any] | None = None,
) -> str | None:
    """Build a ``PAYMENT-REQUIRED`` value, or ``None`` when nothing is offered.

    ``extensions`` carries the route binding (:func:`route_extensions`).
    """
    unique = unique_requirements(accepts)
    if not unique:
        return None
    value: dict[str, Any] = {
        "x402Version": X402_VERSION,
        "accepts": unique,
        "resource": {"url": resource_url},
        "error": error or f"{PAYMENT_SIGNATURE_HEADER} header is required",
    }
    if extensions is not None:
        value["extensions"] = dict(extensions)
    return encode_payment_required(value)  # type: ignore[arg-type]


def challenges_payment_required_header(
    challenges: Iterable[Any],
    accepts_for: Callable[[Any], PaymentRequirements | None],
    resource_url: str,
    http_method: str,
    error: str | None = None,
) -> str | None:
    """Build ``PAYMENT-REQUIRED`` for issued challenges, with their route binding.

    Offers whose route bindings differ can't share one header; like mppx, the
    first one is kept and the error says why the rest were dropped.
    """
    accepts: list[PaymentRequirements] = []
    extensions: dict[str, Any] | None = None
    mismatch = False
    for challenge in challenges:
        accepted = accepts_for(challenge)
        if accepted is None:
            continue
        challenge_extensions = challenge_route_extensions(challenge, http_method)
        if extensions is None:
            extensions = challenge_extensions
        elif not _json_equal(extensions, challenge_extensions):
            mismatch = True
            continue
        accepts.append(accepted)
    if mismatch:
        error = "; ".join(
            part
            for part in (error, "Cannot merge x402 payment requirements with different routes.")
            if part
        )
    return payment_required_header(accepts, resource_url, error, extensions)


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
    details = request.get("methodDetails") if is_mapping(request) else None
    chain_id = details.get("chainId") if is_mapping(details) else None
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
