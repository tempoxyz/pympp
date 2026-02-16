"""mpp test suite."""

from typing import Any

from mpp import Challenge, ChallengeEcho, Credential, _b64url_encode

# Default secret used by tests when calling verify_or_challenge
TEST_SECRET = "test-secret"
TEST_REALM = "test.example.com"


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
) -> Credential:
    """Create a Credential with an HMAC-bound challenge ID for testing.

    This produces credentials that will pass stateless challenge verification
    in verify_or_challenge().
    """
    import json

    challenge = Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        digest=digest,
    )
    echo = challenge.to_echo()
    return Credential(challenge=echo, payload=payload, source=source)
