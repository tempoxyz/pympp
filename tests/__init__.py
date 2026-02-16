"""mpp test suite."""

from typing import Any

from mpp import ChallengeEcho, Credential


def make_credential(
    payload: dict[str, Any],
    challenge_id: str = "test",
    realm: str = "test.example.com",
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
