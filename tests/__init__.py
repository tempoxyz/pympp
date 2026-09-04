"""mpp test suite."""

import os
from typing import Any

import pytest

from mpp import Challenge, ChallengeEcho, Credential, _b64url_encode

# Default secret used by tests when calling verify_or_challenge
TEST_SECRET = "test-secret"
TEST_REALM = "test.example.com"

INTEGRATION = pytest.mark.skipif(
    not os.environ.get("TEMPO_RPC_URL"),
    reason="TEMPO_RPC_URL not set (no local node)",
)


def make_credential(
    payload: dict[str, Any],
    challenge_id: str = "test",
    realm: str = TEST_REALM,
    method: str = "tempo",
    intent: str = "charge",
    request: str = "e30",
    source: str | None = None,
    expires: str | None = None,
) -> Credential:
    """Create a Credential with a ChallengeEcho for testing."""
    echo = ChallengeEcho(
        id=challenge_id,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
    )
    return Credential(challenge=echo, payload=payload, source=source)


def _default_expires() -> str:
    """Return an expires timestamp 1 hour in the future."""
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


def make_bound_credential(
    payload: dict[str, Any],
    request: dict[str, Any],
    secret_key: str = TEST_SECRET,
    realm: str = TEST_REALM,
    method: str = "tempo",
    intent: str = "charge",
    source: str | None = None,
    expires: str | None = None,
    digest: str | None = None,
    meta: dict[str, str] | None = None,
    header: str | None = None,
) -> Credential:
    """Create a Credential with an HMAC-bound challenge ID for testing.

    This produces credentials that will pass stateless challenge verification
    in verify_or_challenge().  If no ``expires`` is provided, a default 1-hour
    future timestamp is used so that credentials pass expiry enforcement.
    """
    if expires is None:
        expires = _default_expires()

    challenge = Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        digest=digest,
        meta=meta,
        header=header,
    )
    echo = challenge.to_echo()
    return Credential(challenge=echo, payload=payload, source=source)


class MockRequest:
    """Mock request object for testing."""

    def __init__(
        self,
        authorization: str | None = None,
        body: bytes | None = None,
        path: str | None = None,
        route: str | None = None,
        query_string: str | None = None,
        payment_authorization: str | None = None,
    ) -> None:
        self.headers: dict[str, str] = {}
        if authorization:
            self.headers["authorization"] = authorization
        if payment_authorization:
            self.headers["payment-authorization"] = payment_authorization
        self.body = body
        if path is not None:
            self.path = path
        if route is not None:
            self.route = route
        if query_string is not None:
            self.query_string = query_string


def challenge_from_402(result: Any) -> Challenge:
    """Extract the challenge from a 402 response (Starlette or plain-dict form)."""
    headers = result.headers if hasattr(result, "headers") else result["headers"]
    return Challenge.from_www_authenticate(headers["WWW-Authenticate"])
