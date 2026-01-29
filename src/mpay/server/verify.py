"""Core verification logic for server-side payment handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mpay import Challenge, Credential, Receipt
from mpay._parsing import ParseError
from mpay.server.intent import VerificationError

if TYPE_CHECKING:
    from mpay.server.intent import Intent


async def verify_or_challenge(
    *,
    authorization: str | None,
    intent: Intent,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    method: str | None = None,
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

    if authorization is None:
        return _create_challenge(method_name, intent.name, request, realm, secret_key)

    if not authorization.lower().startswith("payment "):
        return _create_challenge(method_name, intent.name, request, realm, secret_key)

    try:
        credential = Credential.from_authorization(authorization)
    except ParseError:
        return _create_challenge(method_name, intent.name, request, realm, secret_key)

    receipt: Receipt = await intent.verify(credential, request)

    # Per IETF spec, synchronous flows MUST NOT return 200 with a failed receipt.
    # Convert failed receipts to VerificationError.
    if receipt.status == "failed":
        raise VerificationError(f"payment failed: {receipt.reference}")

    return (credential, receipt)


def _create_challenge(
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
) -> Challenge:
    """Create a new payment challenge with HMAC-bound ID."""
    return Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
    )
