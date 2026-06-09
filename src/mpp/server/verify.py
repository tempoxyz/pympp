"""Core verification logic for server-side payment handling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpp import (
    Challenge,
    Credential,
    Receipt,
    _body_digest,
    _constant_time_equal,
    generate_challenge_id,
)
from mpp._parsing import ParseError, _b64_decode
from mpp._units import transform_units
from mpp.errors import (
    InvalidChallengeError,
    MalformedCredentialError,
    PaymentExpiredError,
)
from mpp.events import CHALLENGE_CREATED, PAYMENT_FAILED, PAYMENT_SUCCESS, EventDispatcher

DEFAULT_EXPIRES_MINUTES = 5

if TYPE_CHECKING:
    from mpp.server.intent import Intent


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
) -> Challenge | tuple[Credential, Receipt]:
    """Verify a payment credential or generate a new challenge.

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
            method_name, intent.name, request, realm, secret_key, description, meta, expires, body
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
        return challenge

    if authorization is None:
        return await new_challenge()

    payment_scheme = _extract_payment_scheme(authorization)
    if payment_scheme is None:
        return await new_challenge()

    try:
        credential = Credential.from_authorization(payment_scheme)
    except ParseError as error:
        return await fail(MalformedCredentialError(str(error)))

    # Stateless challenge verification: recompute expected challenge ID from
    # echoed parameters and compare to the credential's challenge ID.
    echo = credential.challenge
    try:
        echo_request = _b64_decode(echo.request) if echo.request else {}
        echo_opaque = _b64_decode(echo.opaque) if echo.opaque else None
    except ParseError as error:
        return await fail(MalformedCredentialError(str(error)), credential)

    expected_id = generate_challenge_id(
        secret_key=secret_key,
        realm=echo.realm,
        method=echo.method,
        intent=echo.intent,
        request=echo_request,
        expires=echo.expires,
        digest=echo.digest,
        opaque=echo_opaque,
    )
    if not _constant_time_equal(echo.id, expected_id):
        return await fail(
            InvalidChallengeError(echo.id, "challenge was not issued by this server"),
            credential,
        )

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

    if echo_opaque != meta:
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
    if expires_dt < datetime.now(UTC):
        return await fail(PaymentExpiredError(echo.expires), credential)

    try:
        receipt: Receipt = await intent.verify(credential, request)
    except Exception as error:
        if events is not None:
            await events.emit(
                PAYMENT_FAILED,
                {
                    "challenge": _challenge_from_echo(echo, echo_request, echo_opaque),
                    "credential": credential,
                    "error": error,
                    "intent": intent.name,
                    "method": method_name,
                    "request": request,
                },
            )
        raise

    if events is not None:
        await events.emit(
            PAYMENT_SUCCESS,
            {
                "challenge": _challenge_from_echo(echo, echo_request, echo_opaque),
                "credential": credential,
                "intent": intent.name,
                "method": method_name,
                "receipt": receipt,
                "request": request,
            },
        )

    return (credential, receipt)


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

    digest = _body_digest.compute(body) if body is not None else None

    return Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        expires=expires,
        digest=digest,
        description=description,
        meta=meta,
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
    )


def _extract_payment_scheme(header: str) -> str | None:
    """Extract the Payment scheme from an Authorization header.

    Supports comma-separated multiple schemes per RFC 9110.
    Returns the full ``Payment ...`` string, or None if not found.
    """
    for scheme in header.split(","):
        scheme = scheme.strip()
        if scheme.lower().startswith("payment "):
            return scheme
    return None
