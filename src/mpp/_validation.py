"""Dependency-neutral credential validation result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpp import ChallengeEcho, Credential


@dataclass(frozen=True, slots=True)
class Validation:
    """Result of non-mutating credential validation.

    Returned by ``VerifiableIntent.validate`` and exposed from
    ``Mpp.validate_credential()``. A validation confirms that a credential is
    currently acceptable to the payment method; it does not settle, reserve,
    or otherwise consume the payment, and a later broadcast may still fail.

    Attributes:
        credential: The exact credential the validation examined.
        details: Method-specific validation details (for Tempo charges, the
            settlement ``mode`` and, in pull mode, the serialized transaction).
        intent: Name of the intent that accepted the credential.
        request: The request parameters the credential was validated against.
    """

    credential: Credential
    details: Any
    intent: str
    request: dict[str, Any]

    @property
    def challenge(self) -> ChallengeEcho:
        """The challenge echoed by the validated credential."""
        return self.credential.challenge

    @property
    def method(self) -> str:
        """Name of the payment method that issued the challenge."""
        return self.credential.challenge.method

    @property
    def source(self) -> str | None:
        """Payer identity submitted with the credential, if any."""
        return self.credential.source
