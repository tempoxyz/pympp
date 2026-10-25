"""x402 wire path of the EVM charge server method.

Lets one ``evm/charge`` route also speak x402 v2: challenges carry a ``PAYMENT-REQUIRED``
header next to ``WWW-Authenticate``, ``PAYMENT-SIGNATURE`` credentials are bound to the route
challenge (optionally through the mppx route-binding extension) and converted to native
``authorization`` payloads, and receipts carry ``PAYMENT-RESPONSE``.
"""

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

import httpx
from pydantic import ValidationError

from mpp import _json, body_digest, payment_request
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import (
    InternalPaymentError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentError,
    VerificationFailedError,
)
from mpp.evm._types import (
    CHARGE_INTENT,
    EIP3009,
    PAYMENT_METHOD,
    AuthorizationConfig,
    AuthorizationPayload,
    network_of,
    to_source,
)
from mpp.receipt import Receipt
from mpp.x402 import _route_binding
from mpp.x402 import facilitator as _facilitator
from mpp.x402._evm import get_address
from mpp.x402._header import (
    InvalidJsonHeaderError,
    decode_payment_signature,
    encode_payment_required,
    encode_payment_response,
)
from mpp.x402._types import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    SYNTHETIC_CHALLENGE_ID_PREFIX,
    Eip3009Authorization,
    ExactEip3009Payload,
    Extension,
    Facilitator,
    PaymentPayload,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
)

if TYPE_CHECKING:
    from mpp.server import Request, Response

MPPX_EXTENSION_KEY: Final = "mppx"
SCOPE_KEY: Final = "_mppx_scope"
NONCE_KEY: Final = "_mppx_nonce"
MPPX_ROUTE_BINDING_SCHEMA: Final = {
    "additionalProperties": False,
    "properties": {
        SCOPE_KEY: {"type": "string"},
        "digest": {"type": "string"},
        "method": {"type": "string"},
        "nonce": {"type": "string"},
        "opaque": {"type": "string"},
    },
    "required": ["method"],
    "type": "object",
}

type RouteBindingMode = Literal["required", "resource"]
"""How a route-scoped charge binds an x402 credential to its route.

* ``"required"`` (default) — every credential for a scoped route must carry ``extensions.mppx``
  and the route-bound nonce; only clients implementing mppx's binding can pay.
* ``"resource"`` — a credential carrying ``extensions.mppx`` is verified in full; one without it
  is bound the way x402 binds, by comparing the echoed ``resource`` URL and ``accepted``. Any
  spec-compliant client can pay a scoped route, at the cost of weaker cross-route protection
  (``resource`` sits outside the EIP-3009 signature).
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class X402Options:
    """x402 compatibility options for an EVM charge.

    Attributes:
        facilitator: Facilitator client or base URL used for verification and settlement.
        client: ``httpx.AsyncClient`` used for facilitator RPCs when ``facilitator`` is a URL.
        max_timeout_seconds: Maximum time allowed for x402 payment completion.
        route_binding: See :data:`RouteBindingMode`.
    """

    facilitator: str | Facilitator | None = None
    client: httpx.AsyncClient | None = None
    max_timeout_seconds: int = 300
    route_binding: RouteBindingMode = "required"


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedOptions:
    authorization: AuthorizationConfig
    facilitator: Facilitator | None
    max_timeout_seconds: int
    route_binding: RouteBindingMode


@dataclass(frozen=True, slots=True, kw_only=True)
class SettleParams:
    """Arguments passed to an EVM authorization settler.

    Attributes:
        credential: The (verified) credential.
        payload: The parsed EIP-3009 authorization.
        request: The wire charge request (``credential.challenge.request``).
        source: The payer ``did:pkh`` identifier.
    """

    credential: Credential[Any]
    payload: AuthorizationPayload
    request: dict[str, Any]
    source: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SettleResult:
    """Settlement result: the on-chain ``reference`` and an optional ISO ``timestamp``."""

    reference: str
    timestamp: str | None = None


type SettleAuthorization = Callable[[SettleParams], Awaitable[SettleResult]]


@dataclass(frozen=True, slots=True, kw_only=True)
class PendingX402Credential(Credential[Any]):
    """A credential parsed from ``PAYMENT-SIGNATURE``; bound to the route challenge later."""


@dataclass(frozen=True, slots=True, kw_only=True)
class X402Credential(Credential[Any]):
    """A native authorization credential converted from an x402 payment payload."""


def is_pending_credential(credential: Credential[Any]) -> bool:
    """Returns whether a credential was parsed from the x402 payment header."""
    return isinstance(credential, PendingX402Credential)


def is_credential(credential: Credential[Any]) -> bool:
    """Returns whether a credential was converted from an x402 payment payload."""
    return isinstance(credential, X402Credential)


def resolve_options(
    *, authorization: AuthorizationConfig, options: X402Options | None
) -> ResolvedOptions:
    """Resolves optional x402 compatibility options for an EVM charge."""
    options = options or X402Options()
    return ResolvedOptions(
        authorization=authorization,
        facilitator=_facilitator.resolve(
            options.facilitator,
            "EVM authorization x402 requires `facilitator`.",
            client=options.client,
        )
        if options.facilitator
        else None,
        max_timeout_seconds=options.max_timeout_seconds,
        route_binding=options.route_binding,
    )


def to_payment_requirements(
    request: Mapping[str, Any], options: ResolvedOptions
) -> PaymentRequirements:
    """Converts a native EVM charge request to x402 exact payment requirements."""
    return PaymentRequirements.model_validate(
        {
            "amount": request["amount"],
            "asset": request["currency"],
            "extra": {
                "assetTransferMethod": EIP3009,
                "name": options.authorization.name,
                "version": options.authorization.version,
            },
            "maxTimeoutSeconds": options.max_timeout_seconds,
            "network": network_of(request["methodDetails"]["chainId"]),
            "payTo": request["recipient"],
            "scheme": "exact",
        }
    )


def payload_to_authorization(payment_payload: PaymentPayload) -> AuthorizationPayload:
    """Converts an x402 EIP-3009 payment payload to the native authorization payload."""
    payload = payment_payload.payload
    if not isinstance(payload, ExactEip3009Payload):
        raise VerificationFailedError(
            reason="EVM charge only supports x402 EIP-3009 authorization payloads"
        )
    try:
        return AuthorizationPayload.model_validate(
            {
                **payload.authorization.to_dict(),
                "signature": payload.signature,
                "type": "authorization",
            }
        )
    except ValidationError as error:
        raise InvalidPayloadError() from error


def requirements_match(actual: PaymentRequirements, expected: PaymentRequirements) -> bool:
    """Compares echoed requirements with a route's: addresses case-insensitively, the rest
    exactly (``true`` never equals ``1``)."""

    def comparable(requirements: PaymentRequirements) -> dict[str, Any]:
        wire = requirements.to_dict()
        return {**wire, "asset": wire["asset"].lower(), "payTo": wire["payTo"].lower()}

    return _strict_equal(comparable(actual), comparable(expected))


def _strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _strict_equal(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(map(_strict_equal, left, right))
    return left == right


# -- transport path ----------------------------------------------------------------------------


class X402Path:
    """The x402 half of the EVM charge HTTP transport."""

    credential_headers: Final = (PAYMENT_SIGNATURE_HEADER,)

    def __init__(self, options: ResolvedOptions) -> None:
        self.options = options

    def get_credential(self, input: "Request") -> Credential[Any] | None:
        header = input.headers.get(PAYMENT_SIGNATURE_HEADER)
        if not header:
            return None
        try:
            payment_payload = decode_payment_signature(header)
        except InvalidJsonHeaderError as error:
            raise MalformedCredentialError(
                reason=f"invalid {PAYMENT_SIGNATURE_HEADER} header: "
                + (error.reason or "not base64 JSON")
            ) from error
        return PendingX402Credential(
            challenge=_pending_challenge(payment_payload), payload=payment_payload.to_dict()
        )

    def match_credential(self, *, input: "Request", request: Mapping[str, Any]) -> bool:
        header = input.headers.get(PAYMENT_SIGNATURE_HEADER)
        if not header:
            return False
        try:
            payment_payload = decode_payment_signature(header)
            return requirements_match(
                payment_payload.accepted, to_payment_requirements(request, self.options)
            )
        except (ValueError, KeyError, TypeError):
            return False

    async def bind_credential(
        self, *, challenge: Challenge, credential: Credential[Any], input: "Request"
    ) -> Credential[Any]:
        payment_payload = _parse_payment_payload(credential.payload)
        if payment_payload is None or not is_pending_credential(credential):
            return credential
        _assert_body_digest(challenge, input)

        request = challenge.request
        requirements = to_payment_requirements(request, self.options)
        if not requirements_match(payment_payload.accepted, requirements):
            raise VerificationFailedError(
                reason="x402 payment payload does not match route requirements"
            )

        expected_resource = ResourceInfo(url=str(input.url))
        extensions = payment_payload.extensions or {}
        mppx = extensions.get(MPPX_EXTENSION_KEY)
        is_route_bound = mppx is not None and "nonce" in mppx.info
        route_requires_binding = challenge.digest is not None or (
            challenge.opaque is not None
            if challenge.meta is None
            else route_meta(challenge.meta) is not None
        )
        # `extensions.mppx` binding is not part of the x402 spec, so a client mppx did not write
        # cannot produce it. Under "resource" such a credential falls through to the binding x402
        # itself defines instead of being rejected outright.
        if (
            route_requires_binding
            and not is_route_bound
            and self.options.route_binding == "required"
        ):
            raise VerificationFailedError(
                reason="x402 payment payload does not bind required route metadata"
            )

        resource = payment_payload.resource
        if is_route_bound:
            if resource != expected_resource:
                raise VerificationFailedError(
                    reason="x402 payment payload resource does not match route resource"
                )
            if not _contains_extensions(extensions, route_extensions(challenge, input)):
                raise VerificationFailedError(
                    reason="x402 payment payload extensions do not match route binding"
                )
        elif route_requires_binding:
            # A scoped route still binds what x402 makes bindable: the resource must be echoed.
            # Only the URL is compared; descriptive ResourceInfo fields carry no binding.
            if resource is None or resource.url != expected_resource.url:
                raise VerificationFailedError(
                    reason="x402 payment payload resource does not match route resource"
                )
        elif resource is not None and resource.url != expected_resource.url:
            raise VerificationFailedError(
                reason="x402 payment payload resource does not match route resource"
            )

        payload = payload_to_authorization(payment_payload)
        if is_route_bound:
            expected_nonce = _route_binding.nonce(
                accepted=requirements, extensions=extensions, resource=expected_resource
            )
            if payload.nonce.lower() != expected_nonce.lower():
                raise VerificationFailedError(
                    reason="x402 authorization nonce does not match route binding"
                )

        return X402Credential(
            challenge=challenge,
            payload=payload.to_dict(),
            source=to_source(
                address=get_address(payload.from_), chain_id=request["methodDetails"]["chainId"]
            ),
        )

    def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: "Request",
        error: PaymentError | None,
        response: "Response",
    ) -> "Response":
        headers = httpx.Headers(response.headers)
        headers[PAYMENT_REQUIRED_HEADER] = encode_payment_required(
            PaymentRequired(
                accepts=[to_payment_requirements(challenge.request, self.options)],
                error=error.message
                if error is not None
                else f"{PAYMENT_SIGNATURE_HEADER} header is required",
                extensions=route_extensions(challenge, input),
                resource=ResourceInfo(url=str(input.url)),
                x402Version=2,
            )
        )
        return response.copy(headers=headers)

    def respond_receipt(
        self,
        *,
        credential: Credential[Any],
        input: "Request",
        receipt: Receipt,
        response: "Response",
    ) -> "Response":
        if PAYMENT_SIGNATURE_HEADER not in input.headers:
            return response
        payload = _authorization(credential.payload)
        headers = httpx.Headers(response.headers)
        headers[PAYMENT_RESPONSE_HEADER] = encode_payment_response(
            SettleResponse(
                network=network_of(credential.challenge.request["methodDetails"]["chainId"]),
                payer=payload.from_,
                success=True,
                transaction=receipt.reference,
            )
        )
        return response.copy(headers=headers)


# -- facilitator settlement --------------------------------------------------------------------


def settle_with_facilitator(options: ResolvedOptions) -> SettleAuthorization:
    """Settles a verified EVM authorization through an x402 facilitator."""
    facilitator = options.facilitator
    if facilitator is None:
        raise ValueError("EVM authorization x402 requires `facilitator`.")

    async def settle(params: SettleParams) -> SettleResult:
        payment_payload, requirements = _facilitator_payment(options, params)
        try:
            settled = await _facilitator.settle(facilitator, payment_payload, requirements)
        except _facilitator.FacilitatorError as error:
            # The facilitator may have broadcast the transfer before failing.
            raise InternalPaymentError(cause=error) from error
        if not settled.success:
            if settled.error_reason == "settlement_pending":
                # The transfer was broadcast and may still confirm: answer without a retry
                # challenge so the payer is not charged twice.
                error = _facilitator.FacilitatorError("facilitator settlement is pending")
                raise InternalPaymentError(cause=error) from error
            raise VerificationFailedError(
                reason=settled.error_message
                or settled.error_reason
                or "EVM facilitator settlement failed"
            )
        if not settled.transaction:
            error = _facilitator.FacilitatorError(
                "facilitator reported success without a transaction"
            )
            raise InternalPaymentError(cause=error) from error
        return SettleResult(reference=settled.transaction)

    return settle


async def verify_with_facilitator(options: ResolvedOptions, params: SettleParams) -> None:
    """Checks an EVM authorization with the facilitator without settling it."""
    facilitator = options.facilitator
    if facilitator is None:
        raise ValueError("EVM authorization x402 requires `facilitator`.")
    payment_payload, requirements = _facilitator_payment(options, params)
    try:
        verified = await _facilitator.verify(facilitator, payment_payload, requirements)
    except _facilitator.FacilitatorError as error:
        raise InternalPaymentError(cause=error) from error
    if not verified.is_valid:
        raise VerificationFailedError(
            reason=verified.invalid_message
            or verified.invalid_reason
            or "EVM facilitator verify failed"
        )


def _facilitator_payment(
    options: ResolvedOptions, params: SettleParams
) -> tuple[PaymentPayload, PaymentRequirements]:
    requirements = to_payment_requirements(params.request, options)
    payload = params.payload
    payment_payload = PaymentPayload(
        accepted=requirements,
        payload=ExactEip3009Payload(
            authorization=Eip3009Authorization.model_validate(
                {
                    key: value
                    for key, value in payload.to_dict().items()
                    if key not in ("signature", "type")
                }
            ),
            signature=payload.signature,
        ),
        x402Version=2,
    )
    return payment_payload, requirements


# -- helpers -----------------------------------------------------------------------------------


def route_meta(meta: Mapping[str, str] | None) -> dict[str, str] | None:
    """Removes issuance-only metadata (``_mppx_nonce``) from challenge metadata."""
    rest = {key: value for key, value in (meta or {}).items() if key != NONCE_KEY}
    return rest or None


def route_extensions(challenge: Challenge, input: "Request") -> dict[str, Extension]:
    """Builds the ``extensions.mppx`` route binding advertised for a challenge."""
    binding: dict[str, Any] = {"method": input.method}
    scope = (challenge.meta or {}).get(SCOPE_KEY)
    if scope is not None:
        binding[SCOPE_KEY] = scope
    if challenge.digest is not None:
        binding["digest"] = challenge.digest
    if challenge.meta is None:
        opaque = challenge.opaque
    else:
        meta = route_meta(challenge.meta)
        opaque = payment_request.serialize(meta) if meta else None
    if opaque is not None:
        binding["opaque"] = opaque
    return {MPPX_EXTENSION_KEY: Extension(info=binding, schema=MPPX_ROUTE_BINDING_SCHEMA)}


def _contains_extensions(
    actual: Mapping[str, Extension], expected: Mapping[str, Extension]
) -> bool:
    for key, expected_extension in expected.items():
        actual_extension = actual.get(key)
        if actual_extension is None:
            return False
        if actual_extension.schema_ != expected_extension.schema_:
            return False
        if _strip_client_nonce(actual_extension.info) != expected_extension.info:
            return False
    return True


def _strip_client_nonce(info: dict[str, Any]) -> dict[str, Any]:
    if "nonce" in info and not isinstance(info["nonce"], str):
        return info
    return {key: value for key, value in info.items() if key != "nonce"}


def _assert_body_digest(challenge: Challenge, input: "Request") -> None:
    if input.body is None or challenge.digest is None:
        return
    if not body_digest.verify(challenge.digest, input.body):
        raise VerificationFailedError(reason="x402 payment body digest mismatch")


def _parse_payment_payload(payload: Any) -> PaymentPayload | None:
    if isinstance(payload, PaymentPayload):
        return payload
    try:
        return PaymentPayload.model_validate(payload)
    except ValidationError:
        return None


def _authorization(payload: Any) -> AuthorizationPayload:
    if isinstance(payload, AuthorizationPayload):
        return payload
    return AuthorizationPayload.model_validate(payload)


def _pending_challenge(payment_payload: PaymentPayload) -> Challenge:
    # The route challenge is built after request normalization in bind_credential(). Until then
    # this deterministic local id only carries the payload through the credential pipeline; it
    # is never HMAC-verified.
    digest = hashlib.sha256(_json.dumps(payment_payload.to_dict()).encode()).hexdigest()
    return Challenge(
        id=f"{SYNTHETIC_CHALLENGE_ID_PREFIX}0x{digest}",
        realm="x402",
        method=PAYMENT_METHOD,
        intent=CHARGE_INTENT,
        request=payment_payload.accepted.to_dict(),
    )
