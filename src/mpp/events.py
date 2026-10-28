"""Payment lifecycle event helpers."""

from __future__ import annotations

import copy
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Literal, TypedDict, overload

if TYPE_CHECKING:
    import httpx

    from mpp import Challenge, Credential, Receipt

logger = logging.getLogger(__name__)


class PaymentEventName(StrEnum):
    """Supported payment lifecycle event names."""

    CHALLENGE_RECEIVED = "challenge.received"
    CREDENTIAL_CREATED = "credential.created"
    PAYMENT_RESPONSE = "payment.response"
    CHALLENGE_CREATED = "challenge.created"
    PAYMENT_SUCCESS = "payment.success"
    PAYMENT_FAILED = "payment.failed"
    WILDCARD = "*"


# Public aliases preserve the string-like event API while avoiding duplicated
# literals throughout the client and server implementations.
CHALLENGE_RECEIVED: Final = PaymentEventName.CHALLENGE_RECEIVED
CREDENTIAL_CREATED: Final = PaymentEventName.CREDENTIAL_CREATED
PAYMENT_RESPONSE: Final = PaymentEventName.PAYMENT_RESPONSE
CHALLENGE_CREATED: Final = PaymentEventName.CHALLENGE_CREATED
PAYMENT_SUCCESS: Final = PaymentEventName.PAYMENT_SUCCESS
PAYMENT_FAILED: Final = PaymentEventName.PAYMENT_FAILED
WILDCARD_EVENT: Final = PaymentEventName.WILDCARD

ClientEventName = Literal[
    PaymentEventName.CHALLENGE_RECEIVED,
    PaymentEventName.CREDENTIAL_CREATED,
    PaymentEventName.PAYMENT_RESPONSE,
    PaymentEventName.PAYMENT_FAILED,
]
ServerEventName = Literal[
    PaymentEventName.CHALLENGE_CREATED,
    PaymentEventName.PAYMENT_SUCCESS,
    PaymentEventName.PAYMENT_FAILED,
]
KnownEventName = ClientEventName | ServerEventName
EventName = KnownEventName | Literal[PaymentEventName.WILDCARD]


class ClientChallengeReceivedPayload(TypedDict):
    challenge: Challenge
    challenges: list[Challenge]
    method: Any
    request: httpx.Request
    response: httpx.Response


class ClientCredentialCreatedPayload(ClientChallengeReceivedPayload):
    credential: Credential


class ClientPaymentResponsePayload(ClientCredentialCreatedPayload):
    response: httpx.Response


class ClientPaymentFailedPayload(TypedDict):
    challenge: Challenge | None
    challenges: list[Challenge]
    credential: Credential | None
    error: Exception
    method: Any | None
    request: httpx.Request
    response: httpx.Response


class ServerChallengeCreatedPayload(TypedDict):
    challenge: Challenge
    intent: str
    method: str
    request: dict[str, Any]


class ServerPaymentFailedPayload(ServerChallengeCreatedPayload):
    credential: Credential | None
    error: Exception


class ServerPaymentSuccessPayload(ServerChallengeCreatedPayload):
    credential: Credential
    receipt: Receipt


EventPayload = (
    ClientChallengeReceivedPayload
    | ClientCredentialCreatedPayload
    | ClientPaymentResponsePayload
    | ClientPaymentFailedPayload
    | ServerChallengeCreatedPayload
    | ServerPaymentFailedPayload
    | ServerPaymentSuccessPayload
    | dict[str, Any]
)
EventHandler = Callable[[Any], Any | Awaitable[Any]]
WildcardEventHandler = Callable[["PaymentEvent"], Any | Awaitable[Any]]
AnyEventHandler = Callable[[Any], Any | Awaitable[Any]]
Unsubscribe = Callable[[], None]


@dataclass(frozen=True, slots=True)
class PaymentEvent:
    """Wildcard event envelope."""

    name: str
    payload: EventPayload


def _identity(payload: Any) -> Any:
    return payload


def _snapshot(payload: Any) -> Any:
    """Copy a payload's protocol data so a listener's edits stay its own.

    mppx hands listeners frozen snapshots. Here each listener gets its own copy
    of the payload dict and of the challenge, credential, receipt and request
    data in it; other values (errors, methods, HTTP objects) are shared.
    """
    from mpp import Challenge, Credential, Receipt

    if not isinstance(payload, dict):
        return payload
    return {
        key: copy.deepcopy(value)
        if isinstance(value, (dict, list, Challenge, Credential, Receipt))
        else value
        for key, value in payload.items()
    }


class EventDispatcher:
    """Dispatches payment lifecycle events."""

    # Handlers receive _copy(payload); the identity unless a subclass snapshots.
    _copy: Callable[[Any], Any] = staticmethod(_identity)

    def __init__(self) -> None:
        self._handlers: dict[str, list[AnyEventHandler]] = {}

    @overload
    def on(
        self, name: Literal[PaymentEventName.WILDCARD], handler: WildcardEventHandler
    ) -> Unsubscribe: ...

    @overload
    def on(self, name: KnownEventName, handler: EventHandler) -> Unsubscribe: ...

    @overload
    def on(self, name: str, handler: AnyEventHandler) -> Unsubscribe: ...

    def on(self, name: str, handler: AnyEventHandler) -> Unsubscribe:
        """Register a handler and return an unsubscribe callback."""
        handlers = self._handlers.setdefault(name, [])
        handlers.append(handler)

        def unsubscribe() -> None:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

        return unsubscribe

    async def emit(
        self,
        name: str,
        payload: EventPayload,
        *,
        first_result: bool = False,
    ) -> Any:
        """Emit an event.

        Named handlers receive the payload. Wildcard handlers receive a
        ``PaymentEvent`` envelope. The first non-None value returned by a named
        handler is returned to the caller. When ``first_result`` is true,
        named handler dispatch stops after the first non-None return value.
        """
        result = None
        for handler in tuple(self._handlers.get(name, ())):
            try:
                value = handler(self._copy(payload))
                if inspect.isawaitable(value):
                    value = await value
                if result is None and value is not None:
                    result = value
                    if first_result:
                        break
            except Exception:
                logger.exception("Payment event handler failed for %s", name)

        for handler in tuple(self._handlers.get("*", ())):
            try:
                value = handler(PaymentEvent(name=name, payload=self._copy(payload)))
                if inspect.isawaitable(value):
                    await value
            except Exception:
                logger.exception("Payment wildcard event handler failed for %s", name)

        return result


class _SnapshotEventDispatcher(EventDispatcher):
    """Gives each handler its own copy of the payload's protocol data.

    One handler's edits then reach neither the next handler nor the caller,
    like mppx's frozen server event payloads.
    """

    _copy = staticmethod(_snapshot)
