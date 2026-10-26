"""Core verification logic for server-side payment handling."""

from __future__ import annotations

import re
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import rfc8785

from mpp import (
    Challenge,
    Credential,
    Receipt,
    _body_digest,
    _constant_time_equal,
    generate_challenge_id,
)
from mpp._parsing import MAX_AUTHORIZATION_SIZE, ParseError, _b64_decode
from mpp._typing import is_dict
from mpp._units import transform_units
from mpp._validation import Validation
from mpp.errors import (
    InternalPaymentError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentError,
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    VerificationFailedError,
)
from mpp.events import CHALLENGE_CREATED, PAYMENT_FAILED, PAYMENT_SUCCESS, EventDispatcher
from mpp.x402._server import X402Input, X402Intent, x402_credential

DEFAULT_EXPIRES_MINUTES = 5


class Intent(Protocol):
    """Verification hooks for one intent: ``verify``, or ``validate`` and ``broadcast``."""

    name: str


async def _settle(intent: Any, credential: Credential, request: dict[str, Any]) -> Receipt:
    """Run ``validate`` then ``broadcast`` when the intent has them, else ``verify``.

    The validation's ``payer`` is copied to the receipt unless it already has one.
    """
    if hasattr(intent, "broadcast"):
        validation = await intent.validate(credential, request)
        if not isinstance(validation, Validation):
            raise VerificationFailedError("Intent returned an invalid validation result")
        receipt: Receipt = await intent.broadcast(credential, request)
        if validation.payer is not None and receipt.payer is None:
            receipt = replace(receipt, payer=validation.payer)
        return receipt
    return await intent.verify(credential, request)


async def verify_or_challenge(
    *,
    authorization: str | None,
    intent: Intent,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    method: str | None = None,
    description: str | None = None,
    meta: dict[str, str] | None = None,
    expires: str | None = None,
    body: str | bytes | dict[str, Any] | None = None,
    events: EventDispatcher | None = None,
    header: str | None = None,
    unique_challenges: bool = True,
    x402: X402Input | None = None,
) -> Challenge | tuple[Credential, Receipt]:
    """Verify a payment credential or generate a new challenge.

    Set ``unique_challenges=False`` only for a verifier-first rolling upgrade.

    This is the core server-side function for handling payment authentication.
    It checks for an Authorization header, verifies the credential if present,
    or generates a new challenge if not.

    When `secret_key` is provided, the challenge ID is computed as HMAC-SHA256
    over the challenge parameters (realm|method|intent|request|expires|digest),
    cryptographically binding the ID to its contents. This enables stateless
    verification - the server can verify a challenge was issued by it without
    storing state.

    Args:
        authorization: The Authorization header value (or None if missing).
        intent: The payment intent to verify against.
        request: The payment request parameters.
        realm: The realm for the WWW-Authenticate header.
        secret_key: Server secret for HMAC-bound challenge IDs. Required.
            Enables stateless challenge verification by computing challenge IDs
            as HMAC-SHA256 over the challenge parameters.
        method: The payment method name (defaults to "tempo").
        description: Optional human-readable description for newly issued challenges.
        meta: Optional opaque challenge metadata.
        expires: Challenge expiration (ISO 8601). Defaults to now + 5 minutes.
        body: Actual request body bytes, string, or JSON-like dict to bind with
            a SHA-256 digest. If provided, new challenges include a digest and
            submitted credentials must echo a matching digest.
        events: Optional dispatcher for challenge/payment lifecycle events.
        header: Optional HTTP field for the Payment credential. When set to
            ``Payment-Authorization``, issued challenges advertise that field
            so ``Authorization`` can carry application authentication.
        x402: Optional x402 request context. When the intent supports x402
            (:class:`~mpp.x402.X402Intent`) and the request carries no Payment
            credential, its ``PAYMENT-SIGNATURE`` value is bound to this route
            and verified instead.

    Returns:
        If no valid Authorization header:
            A Challenge that should be returned as a 402 response.
        If Authorization is valid:
            A tuple of (Credential, Receipt) for the successful payment.

    Example:
        result = await verify_or_challenge(
            authorization=request.headers.get("Authorization"),
            intent=ChargeIntent(client),
            request={"amount": "1000", ...},
            realm="api.example.com",
            secret_key="my-server-secret",  # Enables HMAC-bound IDs
        )

        if isinstance(result, Challenge):
            return Response(
                status=402,
                headers={"WWW-Authenticate": result.to_www_authenticate(realm)},
            )

        credential, receipt = result
        return Response(
            {"data": "..."},
            headers={"Payment-Receipt": receipt.to_payment_receipt()},
        )
    """
    method_name = method or "tempo"
    request = transform_units(request)

    async def new_challenge() -> Challenge:
        challenge = _create_challenge(
            method_name,
            intent.name,
            request,
            realm,
            secret_key,
            description,
            meta,
            expires,
            body,
            header,
            unique_challenges,
        )
        if events is not None:
            await events.emit(
                CHALLENGE_CREATED,
                {
                    "challenge": challenge,
                    "intent": intent.name,
                    "method": method_name,
                    "request": request,
                },
            )
        return challenge

    async def fail(error: Exception, credential: Credential | None = None) -> Challenge:
        # Preserve the existing challenge-on-failure flow while giving hooks a
        # typed reason for why the submitted credential was rejected.
        challenge = await new_challenge()
        await emit_failure(error, challenge, credential)
        return challenge

    async def emit_failure(
        error: Exception,
        challenge: Challenge,
        credential: Credential | None = None,
    ) -> None:
        if events is not None:
            await events.emit(
                PAYMENT_FAILED,
                {
                    "challenge": challenge,
                    "credential": credential,
                    "error": error,
                    "intent": intent.name,
                    "method": method_name,
                    "request": request,
                },
            )

    async def verify_x402(x402_input: X402Input) -> tuple[Credential, Receipt]:
        assert isinstance(intent, X402Intent)
        assert x402_input.payment_signature is not None
        try:
            credential = x402_credential(
                x402_input.payment_signature,
                intent,
                method=method_name,
                request=request,
                realm=realm,
                resource_url=x402_input.resource_url,
                http_method=x402_input.http_method,
                digest=_body_digest.compute(body) if body is not None else None,
                meta=meta,
            )
        except PaymentError as error:
            error.retry_challenge = await new_challenge()
            await emit_failure(error, error.retry_challenge)
            raise
        submitted_challenge = Challenge(
            id=credential.challenge.id,
            realm=realm,
            method=method_name,
            intent=intent.name,
            request=request,
            request_b64=credential.challenge.request,
        )
        try:
            receipt = await _settle(intent, credential, request)
        except (InternalPaymentError, PaymentOutcomeUnknownError) as error:
            # The payment may have landed; a retryable 402 would invite a second one.
            await emit_failure(error, submitted_challenge, credential)
            raise
        except PaymentError as error:
            if error.status != 403:
                error.retry_challenge = await new_challenge()
            await emit_failure(error, submitted_challenge, credential)
            raise
        except Exception as error:
            await emit_failure(error, submitted_challenge, credential)
            raise
        if events is not None:
            await events.emit(
                PAYMENT_SUCCESS,
                {
                    "challenge": submitted_challenge,
                    "credential": credential,
                    "intent": intent.name,
                    "method": method_name,
                    "receipt": receipt,
                    "request": request,
                },
            )
        return (credential, receipt)

    payment_scheme = None
    if authorization is not None:
        # Reject oversized values before extraction. Report them as a rejected
        # credential only when they carry a Payment scheme, so oversized
        # non-payment auth (e.g. a large Bearer token) stays a silent challenge.
        if len(authorization) > MAX_AUTHORIZATION_SIZE:
            if _PAYMENT_SCHEME_RE.search(authorization) is not None:
                return await fail(
                    MalformedCredentialError("Authorization header exceeds maximum size")
                )
        else:
            payment_scheme = _extract_payment_scheme(authorization)
    if payment_scheme is None:
        # A Payment credential takes precedence; otherwise accept an x402
        # payment for intents that support it, like mppx (MPP, then x402).
        if x402 is not None and x402.payment_signature and isinstance(intent, X402Intent):
            return await verify_x402(x402)
        return await new_challenge()

    try:
        credential = Credential.from_authorization(payment_scheme)
    except ParseError as error:
        return await fail(MalformedCredentialError(str(error)))

    # Stateless challenge verification: recompute expected challenge ID from
    # echoed parameters and compare to the credential's challenge ID.
    echo = credential.challenge
    try:
        echo_request, echo_opaque = _authenticate_echo(credential, secret_key=secret_key)
    except (MalformedCredentialError, InvalidChallengeError) as error:
        return await fail(error, credential)

    # Reject credentials minted for a different realm, method, or intent.
    # This still returns a new Challenge; the only new behavior is the
    # payment.failed hook emitted by fail().
    if echo.realm != realm or echo.method != method_name or echo.intent != intent.name:
        return await fail(
            InvalidChallengeError(echo.id, "credential does not match this route's requirements"),
            credential,
        )

    # Assert echoed request matches server's current request.
    # expires is a challenge-level auth-param, not in the request body.
    if echo_request != request:
        return await fail(
            InvalidChallengeError(echo.id, "credential request does not match this route"),
            credential,
        )

    if _application_meta(echo_opaque) != (meta or None):
        return await fail(
            InvalidChallengeError(echo.id, "credential opaque does not match this route"),
            credential,
        )

    if digest_error := _body_digest_error(echo.digest, body):
        return await fail(InvalidChallengeError(echo.id, digest_error), credential)

    # Enforce challenge expiry — fail closed.  Credentials without an
    # expires field or with an unparseable value are rejected outright.
    if not echo.expires:
        return await fail(InvalidChallengeError(echo.id, "missing expires"), credential)
    try:
        expires_dt = datetime.fromisoformat(echo.expires.replace("Z", "+00:00"))
    except ValueError:
        return await fail(InvalidChallengeError(echo.id, "invalid expires"), credential)
    if expires_dt.tzinfo is None:
        # A timestamp without an offset does not name an instant, and comparing
        # it to an aware "now" raises TypeError. Reject it like any other
        # unparseable value so the route still fails closed.
        return await fail(InvalidChallengeError(echo.id, "invalid expires"), credential)
    if expires_dt <= datetime.now(UTC):
        return await fail(PaymentExpiredError(echo.expires), credential)

    submitted_challenge = _challenge_from_echo(echo, echo_request, echo_opaque)
    try:
        receipt = await _settle(intent, credential, request)
    except (InternalPaymentError, PaymentOutcomeUnknownError) as error:
        # The payment may have landed; a retryable 402 would invite a second one.
        await emit_failure(error, submitted_challenge, credential)
        raise
    except PaymentError as error:
        # 403 means the payment was valid but cannot pay for this request, so a
        # fresh challenge would only invite the client to pay again.
        if error.status != 403:
            error.retry_challenge = (
                await new_challenge()
                if isinstance(error, (InvalidPayloadError, PaymentExpiredError))
                else submitted_challenge
            )
        await emit_failure(error, submitted_challenge, credential)
        raise
    except Exception as error:
        await emit_failure(error, submitted_challenge, credential)
        raise

    if events is not None:
        await events.emit(
            PAYMENT_SUCCESS,
            {
                "challenge": submitted_challenge,
                "credential": credential,
                "intent": intent.name,
                "method": method_name,
                "receipt": receipt,
                "request": request,
            },
        )

    return (credential, receipt)


def _authenticate_echo(
    credential: Credential,
    *,
    secret_key: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Authenticate a credential's echoed challenge against the server secret.

    Decodes the echoed request/opaque, recomputes the HMAC-bound challenge ID,
    and compares it in constant time.

    Returns:
        The decoded (request, opaque) echoed by the credential.

    Raises:
        MalformedCredentialError: If the echoed parameters cannot be decoded.
        InvalidChallengeError: If the challenge ID was not issued by this server.
    """
    echo = credential.challenge
    try:
        echo_request = _b64_decode(echo.request) if echo.request else {}
        echo_opaque = _b64_decode(echo.opaque) if echo.opaque else None
        if echo_opaque is not None and not isinstance(echo_opaque, dict):
            raise MalformedCredentialError("Challenge opaque must be an object")
    except ParseError as error:
        raise MalformedCredentialError(str(error)) from error

    try:
        expected_id = generate_challenge_id(
            secret_key=secret_key,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo_request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=echo_opaque,
            header=echo.header,
        )
    except rfc8785.CanonicalizationError as error:
        raise MalformedCredentialError("Challenge contains non-canonical JSON") from error
    if not _constant_time_equal(echo.id, expected_id):
        raise InvalidChallengeError(echo.id, "challenge was not issued by this server")
    return echo_request, echo_opaque


def _create_challenge(
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    description: str | None = None,
    meta: dict[str, str] | None = None,
    expires: str | None = None,
    body: str | bytes | dict[str, Any] | None = None,
    header: str | None = None,
    unique_challenges: bool = True,
) -> Challenge:
    """Create a new payment challenge with HMAC-bound ID.

    ``expires`` is a challenge-level auth-param (not part of the request body).
    If not provided, defaults to 5 minutes from now.
    """
    # Runtime guard: untyped callers may pass a non-string expires value.
    # Fall back to a generated default instead of raising during HMAC input join.
    if expires is not None and not isinstance(expires, str):
        expires = None

    if expires is None:
        expires_dt = datetime.now(UTC) + timedelta(minutes=DEFAULT_EXPIRES_MINUTES)
        expires = expires_dt.isoformat().replace("+00:00", "Z")

    if method == "tempo" and intent_name == "charge":
        from mpp.methods.tempo.schemas import reject_fixed_attribution_memos

        reject_fixed_attribution_memos(request)
        _assert_sponsored_challenge_lifetime(request, expires)

    digest = _body_digest.compute(body) if body is not None else None
    if meta is not None and "_mpp_nonce" in meta:
        raise ValueError("_mpp_nonce is reserved for challenge issuance")
    issued_meta = (
        {**(meta or {}), "_mpp_nonce": secrets.token_hex(32)} if unique_challenges else meta
    )

    return Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        expires=expires,
        digest=digest,
        description=description,
        meta=issued_meta,
        header=header,
    )


def _assert_sponsored_challenge_lifetime(request: dict[str, Any], expires: str) -> None:
    """Refuse to issue a sponsored Tempo charge that expires too soon to cosign.

    Clients cap the transaction's ``valid_before`` at the challenge expiry and
    the sponsoring server needs ``MIN_REMAINING_VALIDITY_SECONDS`` of remaining
    validity, so a shorter-lived sponsored challenge could never be paid.
    """
    from mpp.methods.tempo.fee_payer_policy import MIN_REMAINING_VALIDITY_SECONDS

    details = request.get("methodDetails")
    if not is_dict(details) or not details.get("feePayer"):
        return
    try:
        expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        return
    if expires_dt.tzinfo is None:
        return
    if expires_dt - datetime.now(UTC) < timedelta(seconds=MIN_REMAINING_VALIDITY_SECONDS):
        raise ValueError(
            "Sponsored (feePayer) charge challenges must expire at least "
            f"{MIN_REMAINING_VALIDITY_SECONDS} seconds after issuance; "
            "increase expires or expires_in"
        )


def _body_digest_error(
    digest: str | None,
    body: str | bytes | dict[str, Any] | None,
) -> str | None:
    if body is None:
        if digest is not None:
            return "body digest present but request body was not provided"
        return None
    if not digest:
        return "missing body digest"
    if not _body_digest.verify(digest, body):
        return "body digest mismatch"
    return None


def _challenge_from_echo(
    echo: Any,
    request: dict[str, Any],
    opaque: dict[str, str] | None,
) -> Challenge:
    return Challenge(
        id=echo.id,
        realm=echo.realm,
        method=echo.method,
        intent=echo.intent,
        request=request,
        request_b64=echo.request,
        expires=echo.expires,
        digest=echo.digest,
        opaque=opaque,
        header=echo.header,
        description=echo.description,
    )


_PAYMENT_SCHEME_RE = re.compile(r"(?:^|,)[ \t]*payment ", re.IGNORECASE)


def _extract_payment_scheme(header: str) -> str | None:
    """Extract the Payment scheme from an Authorization header.

    Supports comma-separated multiple schemes per RFC 9110.
    Returns the full ``Payment ...`` string, or None if not found.
    Headers longer than 64 KiB are rejected before splitting.
    """
    if len(header) > MAX_AUTHORIZATION_SIZE:
        return None
    for scheme in header.split(","):
        scheme = scheme.strip()
        if scheme.lower().startswith("payment "):
            return scheme
    return None


def _application_meta(meta: dict[str, str] | None) -> dict[str, str] | None:
    """Remove the HMAC-authenticated issuance nonce for route comparison."""
    if not isinstance(meta, dict):
        return None
    return {key: value for key, value in meta.items() if key != "_mpp_nonce"} or None
