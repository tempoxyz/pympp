"""Core verification logic for server-side payment handling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential, Receipt, generate_challenge_id, _constant_time_equal
from mpp._parsing import ParseError, _b64_decode
from mpp._units import transform_units
from mpp.errors import InvalidChallengeError, MalformedCredentialError, PaymentRequiredError

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

    if authorization is None:
        return _create_challenge(method_name, intent.name, request, realm, secret_key, description)

    payment_scheme = _extract_payment_scheme(authorization)
    if payment_scheme is None:
        return _create_challenge(method_name, intent.name, request, realm, secret_key, description)

    try:
        credential = Credential.from_authorization(payment_scheme)
    except ParseError:
        return _create_challenge(method_name, intent.name, request, realm, secret_key, description)

    # Stateless challenge verification: recompute expected challenge ID from
    # echoed parameters and compare to the credential's challenge ID.
    echo = credential.challenge
    echo_request = _b64_decode(echo.request) if echo.request else {}
    expected_id = generate_challenge_id(
        secret_key=secret_key,
        realm=echo.realm,
        method=echo.method,
        intent=echo.intent,
        request=echo_request,
        expires=echo.expires,
        digest=echo.digest,
    )
    if not _constant_time_equal(echo.id, expected_id):
        return _create_challenge(method_name, intent.name, request, realm, secret_key, description)

    receipt: Receipt = await intent.verify(credential, request)

    # Per spec, synchronous flows MUST NOT return 200 with a failed receipt.
    # If payment failed (e.g., tx reverted on-chain), return 402 with fresh expires.
    if receipt.status == "failed":
        fresh_request = {k: v for k, v in request.items() if k != "expires"}
        fail_desc = f"Payment failed (ref={receipt.reference})"
        return _create_challenge(
            method_name, intent.name, fresh_request, realm, secret_key, fail_desc
        )

    return (credential, receipt)


def _create_challenge(
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    description: str | None = None,
) -> Challenge:
    """Create a new payment challenge with HMAC-bound ID."""
    if "expires" not in request:
        expires = datetime.now(UTC) + timedelta(minutes=DEFAULT_EXPIRES_MINUTES)
        request = {**request, "expires": expires.isoformat().replace("+00:00", "Z")}

    return Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        description=description,
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
