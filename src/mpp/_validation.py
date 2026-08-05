"""Dependency-neutral credential validation result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpp import ChallengeEcho, Credential


@dataclass(frozen=True, slots=True)
class Validation:
    """Result of non-mutating credential validation."""

    credential: Credential
    details: Any
    intent: str
    request: dict[str, Any]

    @property
    def challenge(self) -> ChallengeEcho:
        return self.credential.challenge

    @property
    def method(self) -> str:
        return self.credential.challenge.method

    @property
    def source(self) -> str | None:
        return self.credential.source
