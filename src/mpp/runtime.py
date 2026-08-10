"""Transport-neutral client payment handling."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from mpp import Challenge, Credential
from mpp.errors import InvalidChallengeError, PaymentExpiredError
from mpp.events import CHALLENGE_RECEIVED, CREDENTIAL_CREATED, EventDispatcher


@runtime_checkable
class Method(Protocol):
    """Client-side payment method."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential for a challenge."""
        ...


class PaymentRuntime:
    """Match challenges and create credentials on the caller's event loop."""

    def __init__(
        self,
        methods: Sequence[Method] = (),
        *,
        events: EventDispatcher | None = None,
    ) -> None:
        self.methods = tuple(methods)
        self._methods: dict[tuple[str, str], Method] = {}
        for method in self.methods:
            intents = getattr(method, "intents", ("charge",))
            for intent in intents:
                self._methods[(method.name, intent)] = method
        self.events = events if events is not None else EventDispatcher()

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, Method]:
        """Return the first challenge with a configured method and intent."""
        for challenge in challenges:
            method = self._methods.get((challenge.method, challenge.intent))
            if method is not None:
                return challenge, method

        offered = [challenge.method for challenge in challenges]
        raise ValueError(f"No compatible payment method for challenges: {offered}")

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Create a credential and emit its lifecycle events."""
        if not any(candidate is method for candidate in self.methods):
            raise ValueError("Method is not installed in this PaymentRuntime")
        if challenge.method != method.name:
            raise ValueError(f"Method {method.name!r} does not support {challenge.method!r}")
        if challenge.expires is not None:
            try:
                expires = datetime.fromisoformat(challenge.expires)
            except (TypeError, ValueError) as error:
                raise InvalidChallengeError(challenge.id, "invalid expires") from error
            if expires.tzinfo is None:
                raise InvalidChallengeError(challenge.id, "invalid expires")
            if expires < datetime.now(UTC):
                raise PaymentExpiredError(challenge.expires)

        payload = {
            **(event_payload or {}),
            "challenge": challenge,
            "method": method,
        }
        payload.setdefault("challenges", [challenge])
        supplied = await self.events.emit(
            CHALLENGE_RECEIVED,
            payload,
            first_result=True,
        )
        credential = (
            supplied
            if isinstance(supplied, Credential)
            else await method.create_credential(challenge)
        )
        await self.events.emit(
            CREDENTIAL_CREATED,
            {**payload, "credential": credential},
        )
        return credential
