"""Transport-neutral client payment handling."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from mpp import Challenge, Credential
from mpp.errors import InvalidChallengeError, NoMethodFoundError, PaymentExpiredError
from mpp.events import CHALLENGE_RECEIVED, CREDENTIAL_CREATED, EventDispatcher
from mpp.methods import Method as MethodDefinition
from mpp.x402._client import is_x402_challenge, x402_credential


@dataclass(frozen=True, slots=True, kw_only=True)
class AttemptOutcome:
    """What became of a credential a transport sent (mppx ``MethodResponse.AttemptOutcome``).

    ``status`` is ``accepted`` (a successful response), ``rejected`` (a failed response,
    an error, or a replacement challenge) or ``pending`` (an identical challenge again, or
    a redirect). ``response`` is the response, when there is one; ``challenges`` are the
    challenges it carried.
    """

    status: Literal["accepted", "pending", "rejected"]
    response: Any = None
    challenges: Sequence[Challenge] = ()


@dataclass(slots=True, kw_only=True, eq=False)
class PaymentAttempt:
    """Response lifecycle of one credential a transport sends (mppx ``MethodResponse.Attempt``).

    A method sets :attr:`settle` to keep state for the credential until the transport
    reports its :class:`AttemptOutcome`. While ``settle`` returns ``False`` for a
    ``pending`` outcome, the transport resends the same credential for an identical
    challenge instead of creating another.
    """

    settle: Callable[[AttemptOutcome], Awaitable[bool]] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialParams:
    """Arguments passed to :attr:`ClientMethod.create_credential`."""

    challenge: Challenge
    context: Any = None
    request: Any = None
    """The request that received the challenge (an ``httpx.Request`` over HTTP), when known."""
    fetch: Callable[[Any], Awaitable[Any]] | None = None
    """Sends an auxiliary request to the challenging server without payment handling.

    Over HTTP it takes an ``httpx.Request`` and returns the read ``httpx.Response``. Methods
    use it for management requests a credential depends on, such as a session top-up.
    """
    attempt: PaymentAttempt | None = None
    """The response lifecycle of this credential, when a transport sends it and reports back."""


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class ClientMethod:
    """A payment method configured for clients.

    Attributes:
        method: The method definition.
        create_credential: Returns the serialized credential (``"Payment ..."``) for a challenge,
            or the ``PAYMENT-SIGNATURE`` header value for an x402 challenge.
        can_handle_challenge: Optional predicate selecting the challenges this method pays,
            such as those in a configured currency.
        transaction_hash: Optional derivation of the on-chain hash a credential settles with,
            reported on :class:`~mpp.errors.PaymentOutcomeUnknownError`.
    """

    method: MethodDefinition[Any, Any]
    create_credential: Callable[[CredentialParams], Awaitable[str]]
    can_handle_challenge: Callable[[Challenge], bool] | None = None
    transaction_hash: Callable[[Credential], str | None] | None = None

    @property
    def name(self) -> str:
        return self.method.name

    @property
    def intent(self) -> str:
        return self.method.intent

    @property
    def key(self) -> str:
        """The ``name/intent`` key."""
        return self.method.key


@dataclass(frozen=True, slots=True, kw_only=True)
class ChallengeCandidate:
    """An offered challenge paired with a configured method that can pay it.

    mppx ``AcceptPayment.ChallengeCandidate``. ``index`` is the challenge's position
    among the offered challenges.
    """

    challenge: Challenge
    method: ClientMethod
    index: int


OrderChallenges = Callable[
    [Sequence[ChallengeCandidate]],
    Sequence[ChallengeCandidate] | Awaitable[Sequence[ChallengeCandidate]],
]
"""Filters and sorts supported challenges before credential creation (mppx ``orderChallenges``).

It receives the candidates in the default order and returns them in preference order; the
client pays the first one. Returning an empty sequence rejects every offered challenge.
"""


class PaymentRuntime:
    """Match challenges and create credentials on the caller's event loop."""

    def __init__(
        self,
        methods: Sequence[ClientMethod | Sequence[ClientMethod]] = (),
        *,
        events: EventDispatcher | None = None,
    ) -> None:
        self.methods = _flatten(methods)
        self._methods: dict[tuple[str, str], list[ClientMethod]] = {}
        for method in self.methods:
            self._methods.setdefault((method.name, method.intent), []).append(method)
        self.events = events if events is not None else EventDispatcher()

    def challenge_candidates(self, challenges: Sequence[Challenge]) -> list[ChallengeCandidate]:
        """Return every offered challenge a configured method can pay, in default order.

        Challenges keep the server's order, except that native Payment challenges come
        before x402 offers, as in mppx: a client pays x402 only when no native challenge
        suits it. A challenge several methods can pay appears once per method, in
        configured order.
        """
        candidates: list[ChallengeCandidate] = []
        for x402 in (False, True):
            for index, challenge in enumerate(challenges):
                if is_x402_challenge(challenge) != x402:
                    continue
                for method in self._methods.get((challenge.method, challenge.intent), ()):
                    if method.can_handle_challenge is None or method.can_handle_challenge(
                        challenge
                    ):
                        candidates.append(
                            ChallengeCandidate(challenge=challenge, method=method, index=index)
                        )
        return candidates

    async def order_challenges(
        self,
        challenges: Sequence[Challenge],
        order: OrderChallenges | None = None,
    ) -> list[ChallengeCandidate]:
        """Return the payable candidates in preference order, applying an ``order`` hook."""
        candidates = self.challenge_candidates(challenges)
        if order is None:
            return candidates
        ordered = order(candidates)
        if inspect.isawaitable(ordered):
            ordered = await ordered
        return list(ordered)

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, ClientMethod]:
        """Return the first challenge with a configured method and intent.

        Native Payment challenges come before x402 offers, as in mppx: a client
        pays x402 only when no native challenge suits it.

        Raises:
            NoMethodFoundError: If no configured method can pay any challenge.
        """
        candidates = self.challenge_candidates(challenges)
        if not candidates:
            raise NoMethodFoundError(challenges, self.methods)
        return candidates[0].challenge, candidates[0].method

    async def create_credential(
        self,
        challenge: Challenge,
        method: ClientMethod,
        *,
        event_payload: dict[str, Any] | None = None,
        request: Any = None,
        fetch: Callable[[Any], Awaitable[Any]] | None = None,
        attempt: PaymentAttempt | None = None,
    ) -> Credential:
        """Create a credential and emit its lifecycle events.

        ``request`` and ``fetch`` are passed to the method in :class:`CredentialParams`.
        """
        if not any(candidate is method for candidate in self.methods):
            raise ValueError("Method is not installed in this PaymentRuntime")
        if challenge.method != method.name or challenge.intent != method.intent:
            raise ValueError(
                f"Method {method.key!r} does not support {challenge.method}/{challenge.intent}"
            )
        if method.can_handle_challenge is not None and not method.can_handle_challenge(challenge):
            raise ValueError(f"Method {method.key!r} does not accept this challenge")
        if challenge.expires is not None:
            try:
                expires = datetime.fromisoformat(challenge.expires)
            except (TypeError, ValueError) as error:
                raise InvalidChallengeError(challenge.id, "invalid expires") from error
            if expires.tzinfo is None:
                raise InvalidChallengeError(challenge.id, "invalid expires")
            if expires <= datetime.now(UTC):
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
        else:
            serialized = await method.create_credential(
                CredentialParams(challenge=challenge, request=request, fetch=fetch, attempt=attempt)
            )
            if is_x402_challenge(challenge):
                # x402 methods return the PAYMENT-SIGNATURE header value.
                credential = x402_credential(challenge, serialized)
            else:
                credential = Credential.from_authorization(serialized)
        await self.events.emit(
            CREDENTIAL_CREATED,
            {**payload, "credential": credential},
        )
        return credential


def _flatten(methods: Sequence[Any]) -> tuple[ClientMethod, ...]:
    """Flatten (nested) sequences of client methods."""
    flat: list[ClientMethod] = []
    for entry in methods:
        if isinstance(entry, ClientMethod):
            flat.append(entry)
        elif isinstance(entry, Sequence) and not isinstance(entry, str):
            flat.extend(_flatten(cast("Sequence[Any]", entry)))
        else:
            raise TypeError(f"not a client payment method: {entry!r}")
    return tuple(flat)
