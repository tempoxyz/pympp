"""Transport-neutral client payment handling."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from mpp import Challenge, Credential
from mpp.errors import InvalidChallengeError, PaymentExpiredError
from mpp.events import CHALLENGE_RECEIVED, CREDENTIAL_CREATED, EventDispatcher

_CONTEXT_UNSET = object()


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
        self.events = events if events is not None else EventDispatcher()

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, Method]:
        """Return the first challenge with a configured payment method."""
        for challenge in challenges:
            for method in reversed(self.methods):
                if _supports(method, challenge):
                    return challenge, method

        offered = [challenge.method for challenge in challenges]
        raise ValueError(f"No compatible payment method for challenges: {offered}")

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
        context: Any = _CONTEXT_UNSET,
    ) -> Credential:
        """Create a credential and emit its lifecycle events."""
        if not any(candidate is method for candidate in self.methods):
            raise ValueError("Method is not installed in this PaymentRuntime")
        if not _supports(method, challenge):
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
        if isinstance(supplied, Credential):
            credential = supplied
        elif context is _CONTEXT_UNSET:
            credential = await method.create_credential(challenge)
        else:
            credential = await method.create_credential(challenge, context=context)  # type: ignore[call-arg]
        await self.events.emit(
            CREDENTIAL_CREATED,
            {**payload, "credential": credential},
        )
        return credential


def _supports(method: Method, challenge: Challenge) -> bool:
    if challenge.method != method.name:
        return False
    intents = getattr(method, "intents", None)
    if isinstance(intents, Mapping) and challenge.intent not in (intents or {"charge": None}):
        return False
    can_handle = getattr(method, "can_handle_challenge", None)
    return can_handle is None or bool(can_handle(challenge))
