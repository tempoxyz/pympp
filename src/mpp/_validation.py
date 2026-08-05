"""Dependency-neutral credential validation result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpp import ChallengeEcho, Credential


@dataclass(frozen=True, slots=True)
class Validation:
    """Result of non-mutating credential validation."""

    challenge: ChallengeEcho
    credential: Credential
    details: Any
    intent: str
    method: str
    request: dict[str, Any]
    source: str | None = None
