"""Core verification logic for server-side payment handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpay import Challenge, Credential, Receipt
from mpay._parsing import ParseError, _b64_encode
from mpay.server.intent import VerificationError

if TYPE_CHECKING:
    from mpay.server.intent import Intent

DEFAULT_CHALLENGE_TTL = timedelta(minutes=5)


def _compute_challenge_id(
    realm: str,
    method: str,
    intent: str,
    request: dict[str, Any],
    expires: datetime | None,
    digest: str | None,
    secret_key: str,
) -> str:
    """Compute HMAC-SHA256 challenge ID.

    Creates a deterministic challenge ID by HMACing the challenge parameters.
    This enables stateless verification - the server can recompute the expected
    ID from the echoed challenge without storing state.
    """
    request_b64 = _b64_encode(request)
    expires_str = expires.isoformat().replace("+00:00", "Z") if expires else ""
    input_str = "|".join([realm, method, intent, request_b64, expires_str, digest or ""])
    mac = hmac.new(secret_key.encode(), input_str.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def verify_challenge_id(
    credential: Credential,
    realm: str,
    secret_key: str,
) -> bool:
    """Verify that the credential's challenge ID matches the expected HMAC.

    Args:
        credential: The credential containing the echoed challenge.
        realm: The realm for this service.
        secret_key: The secret key used to compute HMAC-bound IDs.

    Returns:
        True if the challenge ID is valid, False otherwise.
    """
    expected_id = _compute_challenge_id(
        realm=realm,
        method=credential.challenge.method,
        intent=credential.challenge.intent,
        request=credential.challenge.request,
        expires=credential.challenge.expires,
        digest=credential.challenge.digest,
        secret_key=secret_key,
    )
    return _constant_time_compare(credential.challenge.id, expected_id)


async def verify_or_challenge(
    *,
    authorization: str | None,
    intent: Intent,
    request: dict[str, Any],
    realm: str,
    method: str | None = None,
    secret_key: str | None = None,
    expires_in: timedelta = DEFAULT_CHALLENGE_TTL,
    digest: str | None = None,
) -> Challenge | tuple[Credential, Receipt]:
    """Verify a payment credential or generate a new challenge.

    This is the core server-side function for handling payment authentication.
    It checks for an Authorization header, verifies the credential if present,
    or generates a new challenge if not.

    Args:
        authorization: The Authorization header value (or None if missing).
        intent: The payment intent to verify against.
        request: The payment request parameters.
        realm: The realm for the WWW-Authenticate header.
        method: The payment method name (defaults to "tempo").
        secret_key: Optional secret for HMAC-bound challenge IDs.
            If provided, challenge IDs are deterministic HMACs enabling
            stateless verification. If None, random IDs are used.
        expires_in: Challenge expiration time (defaults to 5 minutes).
        digest: Optional digest of the request body.

    Returns:
        If no valid Authorization header:
            A Challenge that should be returned as a 402 response.
        If Authorization is valid:
            A tuple of (Credential, Receipt) for the successful payment.

    Raises:
        ValueError: If realm is empty.

    Example:
        result = await verify_or_challenge(
            authorization=request.headers.get("Authorization"),
            intent=ChargeIntent(client),
            request={"amount": "1000", ...},
            realm="api.example.com",
            secret_key="your-secret-key",  # Enables stateless verification
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
    if not realm or not realm.strip():
        raise ValueError("realm must be a non-empty string")

    method_name = method or "tempo"
    expires = datetime.now(UTC) + expires_in

    if authorization is None:
        return _create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires=expires,
            digest=digest,
        )

    if not authorization.lower().startswith("payment "):
        return _create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires=expires,
            digest=digest,
        )

    try:
        credential = Credential.from_authorization(authorization)
    except ParseError:
        return _create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires=expires,
            digest=digest,
        )

    # Verify HMAC-bound challenge ID if secret_key is provided
    if secret_key is not None:
        if not verify_challenge_id(credential, realm, secret_key):
            return _create_challenge(
                method=method_name,
                intent_name=intent.name,
                request=request,
                realm=realm,
                secret_key=secret_key,
                expires=expires,
                digest=digest,
            )

    try:
        receipt: Receipt = await intent.verify(credential, request)
    except VerificationError:
        return _create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires=expires,
            digest=digest,
        )

    return (credential, receipt)


def _create_challenge(
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str | None = None,
    expires: str | None = None,
    digest: str | None = None,
) -> Challenge:
    """Create a new payment challenge.

    Args:
        method: The payment method name.
        intent_name: The intent name (e.g., "charge").
        request: The payment request parameters.
        realm: The realm for this service.
        secret_key: Optional secret for HMAC-bound IDs. If None, uses random ID.
        expires: Optional expiration timestamp.
        digest: Optional digest of the request body.
    """
    if secret_key is not None:
        challenge_id = _compute_challenge_id(
            realm=realm,
            method=method,
            intent=intent_name,
            request=request,
            expires=expires,
            digest=digest,
            secret_key=secret_key,
        )
    else:
        challenge_id = secrets.token_urlsafe(16)

    return Challenge(
        id=challenge_id,
        method=method,
        intent=intent_name,
        request=request,
        realm=realm,
        expires=expires,
        digest=digest,
    )
