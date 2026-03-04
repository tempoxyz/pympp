"""Core verification logic for server-side payment handling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential, Receipt, _constant_time_equal, generate_challenge_id
from mpp._parsing import ParseError, _b64_decode
from mpp._units import transform_units

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

    def new_challenge() -> Challenge:
        return _create_challenge(
            method_name, intent.name, request, realm, secret_key, description, meta
        )

    if authorization is None:
        return new_challenge()

    payment_scheme = _extract_payment_scheme(authorization)
    if payment_scheme is None:
        return new_challenge()

    try:
        credential = Credential.from_authorization(payment_scheme)
    except ParseError:
        return new_challenge()

    # Stateless challenge verification: recompute expected challenge ID from
    # echoed parameters and compare to the credential's challenge ID.
    echo = credential.challenge
    try:
        echo_request = _b64_decode(echo.request) if echo.request else {}
        echo_opaque = _b64_decode(echo.opaque) if echo.opaque else None
    except ParseError:
        return new_challenge()

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
        return new_challenge()

    # Assert echoed challenge fields match server's values
    if echo.realm != realm or echo.method != method_name or echo.intent != intent.name:
        return new_challenge()

    # Assert echoed request matches server's current request (exclude dynamic expires)
    echo_req_comparable = {k: v for k, v in echo_request.items() if k != "expires"}
    server_req_comparable = {k: v for k, v in request.items() if k != "expires"}
    if echo_req_comparable != server_req_comparable:
        return new_challenge()

    if echo_opaque != meta:
        return new_challenge()

    # Reject expired challenges at the transport layer as defense-in-depth
    if echo.expires:
        try:
            expires_dt = datetime.fromisoformat(echo.expires.replace("Z", "+00:00"))
            if expires_dt < datetime.now(UTC):
                return new_challenge()
        except (ValueError, TypeError):
            pass

    # Verify the echoed request parameters match this endpoint's expected
    # request to prevent cross-endpoint replay when two endpoints share
    # the same intent name but differ in amount, recipient, or currency.
    # Compare only the fields present in the server's expected request
    # (excluding "expires" which is generated per-challenge).
    for key, value in request.items():
        if key == "expires":
            continue
        echo_value = echo_request.get(key)
        if echo_value != value:
            return _create_challenge(
                method_name,
                intent.name,
                request,
                realm,
                secret_key,
                description,
                meta,
            )

    # Enforce challenge expiry — fail closed.  Credentials without an
    # expires field or with an unparseable value are rejected outright so
    # that attackers cannot bypass expiry by omitting or corrupting it.
    if not echo.expires:
        return _create_challenge(
            method_name,
            intent.name,
            request,
            realm,
            secret_key,
            description,
            meta,
        )
    try:
        expires_dt = datetime.fromisoformat(echo.expires.replace("Z", "+00:00"))
    except ValueError:
        return _create_challenge(
            method_name,
            intent.name,
            request,
            realm,
            secret_key,
            description,
            meta,
        )
    if expires_dt < datetime.now(UTC):
        return _create_challenge(
            method_name,
            intent.name,
            request,
            realm,
            secret_key,
            description,
            meta,
        )

    # Ensure request dict includes "expires" for intent.verify().
    # _create_challenge generates expires into a copy, but when
    # verification succeeds we skip that path.  Use the HMAC-bound
    # expires from the echoed challenge so the intent sees the same
    # value the client committed to.
    if "expires" not in request and echo.expires:
        request = {**request, "expires": echo.expires}

    receipt: Receipt = await intent.verify(credential, request)

    return (credential, receipt)


def _create_challenge(
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    description: str | None = None,
    meta: dict[str, str] | None = None,
) -> Challenge:
    """Create a new payment challenge with HMAC-bound ID."""
    if "expires" not in request:
        expires_dt = datetime.now(UTC) + timedelta(minutes=DEFAULT_EXPIRES_MINUTES)
        expires_str = expires_dt.isoformat().replace("+00:00", "Z")
        request = {**request, "expires": expires_str}

    # Guard against non-string values that would cause a TypeError in
    # generate_challenge_id().
    expires = request.get("expires")
    if not isinstance(expires, str):
        expires = None

    return Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        expires=expires,
        description=description,
        meta=meta,
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
