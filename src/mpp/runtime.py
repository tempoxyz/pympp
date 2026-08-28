"""Transport-neutral client payment handling."""

from __future__ import annotations

import asyncio
import inspect
import math
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


def _method_accepts_currency(method: Method, challenge: Challenge) -> bool:
    """Return whether a Challenge matches a method's optional currency constraint."""
    if getattr(method, "_currency_explicit", True) is False:
        return True
    configured_currency = getattr(method, "currency", None)
    if configured_currency is None:
        return True
    offered_currency = challenge.request.get("currency")
    return (
        isinstance(configured_currency, str)
        and isinstance(offered_currency, str)
        and offered_currency.lower() == configured_currency.lower()
    )


class PaymentRuntime:
    """Match challenges and create credentials on the caller's event loop."""

    def __init__(
        self,
        methods: Sequence[Method] = (),
        *,
        events: EventDispatcher | None = None,
    ) -> None:
        self.methods = tuple(methods)
        self._methods: dict[tuple[str, str], list[Method]] = {}
        for method in self.methods:
            intents = getattr(method, "intents", ("charge",))
            for intent in intents:
                self._methods.setdefault((method.name, intent), []).append(method)
        self.events = events if events is not None else EventDispatcher()

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, Method]:
        """Return the first challenge with a configured method and intent."""
        candidates = self._compatible_candidates(challenges)
        if candidates:
            return candidates[0]

        offered = [challenge.method for challenge in challenges]
        raise ValueError(f"No compatible payment method for challenges: {offered}")

    async def select_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, Method]:
        """Return the preferred compatible challenge, including async method priorities."""
        candidates = self._compatible_candidates(challenges)
        if not candidates:
            offered = [challenge.method for challenge in challenges]
            raise ValueError(f"No compatible payment method for challenges: {offered}")

        return (await self._prioritize_candidates(candidates))[0]

    async def _prioritize_candidates(
        self,
        candidates: Sequence[tuple[Challenge, Method]],
    ) -> list[tuple[Challenge, Method]]:
        """Apply async method priorities without changing cross-method order."""

        ordered = list(candidates)
        positions_by_method: dict[int, list[int]] = {}
        for index, (_challenge, method) in enumerate(candidates):
            if not callable(getattr(method, "get_challenge_priority", None)):
                continue
            positions_by_method.setdefault(id(method), []).append(index)

        for positions in positions_by_method.values():
            if len(positions) < 2:
                continue
            method = candidates[positions[0]][1]
            priority_fn = getattr(method, "get_challenge_priority")  # noqa: B009

            async def rank_candidate(
                original_index: int,
                position: int,
                priority_fn: Any,
            ) -> tuple[float, int, tuple[Challenge, Method]]:
                candidate = candidates[position]
                priority = priority_fn(candidate[0])
                if inspect.isawaitable(priority):
                    priority = await priority
                if not isinstance(priority, int | float) or not math.isfinite(priority):
                    raise ValueError("Challenge priority must be finite")
                return float(priority), original_index, candidate

            ranked = await asyncio.gather(
                *(
                    rank_candidate(index, position, priority_fn)
                    for index, position in enumerate(positions)
                )
            )
            ranked.sort(key=lambda item: (-item[0], item[1]))
            for ranked_index, position in enumerate(positions):
                ordered[position] = ranked[ranked_index][2]

        return ordered

    def _compatible_candidates(
        self,
        challenges: Sequence[Challenge],
    ) -> list[tuple[Challenge, Method]]:
        """Return compatible candidates in normal negotiation order."""
        candidates: list[tuple[Challenge, Method]] = []
        for challenge in challenges:
            methods = self._methods.get((challenge.method, challenge.intent), ())
            for method in methods:
                if _method_accepts_currency(method, challenge):
                    candidates.append((challenge, method))
                    break
        return candidates

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
        if not _method_accepts_currency(method, challenge):
            configured_currency = getattr(method, "currency", None)
            offered_currency = challenge.request.get("currency")
            raise ValueError(
                f"Method {method.name!r} currency {configured_currency!r} "
                f"does not support {offered_currency!r}"
            )
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
