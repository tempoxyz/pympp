"""Transport-neutral client payment handling."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from mpp import Challenge, Credential
from mpp.errors import InvalidChallengeError, PaymentExpiredError
from mpp.events import CHALLENGE_RECEIVED, CREDENTIAL_CREATED, EventDispatcher
from mpp.methods import Method as MethodDefinition


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


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class ClientMethod:
    """A payment method configured for clients.

    Attributes:
        method: The method definition.
        create_credential: Returns the serialized credential (``"Payment ..."``) for a challenge.
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

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
    ) -> tuple[Challenge, ClientMethod]:
        """Return the first challenge with a configured method and intent."""
        for challenge in challenges:
            methods = self._methods.get((challenge.method, challenge.intent), ())
            for method in methods:
                if method.can_handle_challenge is None or method.can_handle_challenge(challenge):
                    return challenge, method

        offered = [challenge.method for challenge in challenges]
        raise ValueError(f"No compatible payment method for challenges: {offered}")

    async def create_credential(
        self,
        challenge: Challenge,
        method: ClientMethod,
        *,
        event_payload: dict[str, Any] | None = None,
        request: Any = None,
        fetch: Callable[[Any], Awaitable[Any]] | None = None,
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
                CredentialParams(challenge=challenge, request=request, fetch=fetch)
            )
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
