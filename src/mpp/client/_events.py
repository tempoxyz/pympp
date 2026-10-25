"""Client payment events."""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from mpp.challenge import Challenge
from mpp.method import ClientMethod, resolve

logger = logging.getLogger("mpp.client")

type ClientEventName = Literal[
    "challenge.received", "credential.created", "payment.failed", "payment.response"
]
_NAMES: tuple[ClientEventName, ...] = (
    "challenge.received",
    "credential.created",
    "payment.failed",
    "payment.response",
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ChallengeReceived:
    """A payment challenge was selected. Handlers may return a credential string to use."""

    challenge: Challenge
    challenges: tuple[Challenge, ...]
    create_credential: Callable[..., Awaitable[str]]
    method: ClientMethod
    response: Any
    request: Any = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialCreated:
    """A credential was created for the selected challenge."""

    challenge: Challenge
    credential: str
    method: ClientMethod
    response: Any = None
    request: Any = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentResponse:
    """The paid retry returned a successful response (a bodyless snapshot)."""

    challenge: Challenge
    credential: str
    method: ClientMethod
    response: Any
    request: Any = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientPaymentFailed:
    """Automatic payment handling failed (``error`` may be ``PaymentOutcomeUnknownError``)."""

    error: BaseException
    challenge: Challenge | None = None
    challenges: tuple[Challenge, ...] | None = None
    method: ClientMethod | None = None
    response: Any = None
    request: Any = None


type ClientEvent = ChallengeReceived | CredentialCreated | PaymentResponse | ClientPaymentFailed


@dataclass(frozen=True, slots=True)
class ClientEventEnvelope:
    """Payload delivered to ``"*"`` handlers."""

    name: ClientEventName
    payload: ClientEvent


type Unsubscribe = Callable[[], None]


class ClientEventDispatcher:
    """``challenge.received`` handlers run first; the first non-empty credential wins.

    Observation handlers are isolated: their errors never alter the payment flow.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, dict[Callable[[Any], Any], None]] = {
            "*": {},
            **{name: {} for name in _NAMES},
        }

    def on(self, name: str, handler: Callable[[Any], Any]) -> Unsubscribe:
        if name not in self._handlers:
            raise ValueError(f'Unknown client event "{name}".')
        handlers = self._handlers[name]
        # Set semantics (like mppx): re-registering is idempotent; one unsubscribe removes it.
        handlers[handler] = None

        def unsubscribe() -> None:
            handlers.pop(handler, None)

        return unsubscribe

    def has_observers(self, name: ClientEventName) -> bool:
        return bool(self._handlers[name]) or bool(self._handlers["*"])

    async def emit(self, name: ClientEventName, payload: ClientEvent) -> str | None:
        credential: str | None = None
        if name == "challenge.received":
            for handler in list(self._handlers[name]):
                try:
                    value = await resolve(handler(payload))
                except Exception:
                    logger.debug("challenge.received handler failed", exc_info=True)
                    continue
                if isinstance(value, str) and value:
                    credential = value
                    break
        else:
            for handler in list(self._handlers[name]):
                await _observe(handler, payload)
        envelope = ClientEventEnvelope(name, payload)
        for handler in list(self._handlers["*"]):
            await _observe(handler, envelope)
        return credential


async def _observe(handler: Callable[[Any], Any], payload: Any) -> None:
    try:
        await resolve(handler(payload))
    except Exception:
        logger.debug("client event handler failed", exc_info=True)
