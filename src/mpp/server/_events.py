"""Server lifecycle events (``challenge.created``, ``payment.failed``, ``payment.success``)."""

import copy
import functools
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, overload

from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import PaymentError
from mpp.method import (
    CapturedRequest,
    PaymentSuccessHookContext,
    ServerMethod,
    VerifiedChallengeEnvelope,
    resolve,
)
from mpp.receipt import Receipt
from mpp.server._http import Request, make_headers

logger = logging.getLogger("mpp.server")

type EventName = Literal["challenge.created", "payment.failed", "payment.success"]
EVENT_NAMES: tuple[EventName, ...] = ("challenge.created", "payment.failed", "payment.success")


@dataclass(frozen=True, slots=True)
class MethodDescriptor:
    """Inert method identity exposed to event handlers."""

    name: str
    intent: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ChallengeCreated:
    """A payment challenge was issued (only for responses that actually carry a challenge)."""

    challenge: Challenge
    method: MethodDescriptor
    request: Mapping[str, Any]
    captured_request: CapturedRequest | None = None
    credential: Credential[Any] | None = None
    error: PaymentError | None = None
    input: Any = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentFailed:
    """A submitted credential (or authorization attempt) failed.

    ``challenge`` is the fresh retry challenge when one was issued, otherwise the submitted one.
    """

    challenge: Challenge
    credential: Credential[Any] | None
    error: PaymentError
    method: MethodDescriptor
    request: Mapping[str, Any]
    captured_request: CapturedRequest | None = None
    input: Any = None
    retry_challenge: Challenge | None = None
    submitted_challenge: Challenge | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentSucceeded:
    """A payment was verified and settled."""

    challenge: Challenge
    method: MethodDescriptor
    receipt: Receipt
    request: Mapping[str, Any]
    captured_request: CapturedRequest | None = None
    credential: Credential[Any] | None = None
    envelope: VerifiedChallengeEnvelope[Any] | None = None
    input: Any = None
    payer: str | None = None
    request_input: Mapping[str, Any] | None = None


type ServerEvent = ChallengeCreated | PaymentFailed | PaymentSucceeded


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Payload delivered to ``"*"`` handlers."""

    name: EventName
    payload: ServerEvent


type EventHandler = Callable[[Any], Any]
type Unsubscribe = Callable[[], None]


class EventDispatcher:
    """Dispatches events inline and sequentially; handler errors are swallowed."""

    def __init__(self) -> None:
        self._handlers: dict[str, dict[EventHandler, None]] = {
            "*": {},
            **{name: {} for name in EVENT_NAMES},
        }

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        if name not in self._handlers:
            raise ValueError(f'Unknown server event "{name}".')
        handlers = self._handlers[name]
        # Set semantics (like mppx): re-registering is idempotent; one unsubscribe removes it.
        handlers[handler] = None

        def unsubscribe() -> None:
            handlers.pop(handler, None)

        return unsubscribe

    async def emit(
        self, name: EventName, payload: ServerEvent, method: ServerMethod | None = None
    ) -> None:
        if (
            name == "payment.success"
            and method is not None
            and method.on_payment_success is not None
            and isinstance(payload, PaymentSucceeded)
        ):
            try:
                await resolve(
                    method.on_payment_success(
                        PaymentSuccessHookContext(
                            challenge=payload.challenge,
                            input=payload.input,
                            payer=payload.payer,
                            receipt=payload.receipt,
                            request=payload.request,
                            request_input=payload.request_input,
                        )
                    )
                )
            except Exception:
                logger.debug("on_payment_success hook failed", exc_info=True)
        for handler in list(self._handlers[name]):
            await _call(handler, payload)
        envelope = EventEnvelope(name, payload)
        for handler in list(self._handlers["*"]):
            await _call(handler, envelope)


async def _call(handler: EventHandler, payload: Any) -> None:
    try:
        await resolve(handler(payload))
    except Exception:
        # Observers cannot change payment control flow.
        logger.debug("server event handler failed", exc_info=True)


def snapshot[T](value: T) -> T:
    """Deep-copies event data so listeners cannot mutate engine state."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


@overload
def snapshot_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]: ...
@overload
def snapshot_mapping(value: None) -> None: ...
@overload
def snapshot_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any] | None: ...
def snapshot_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """Detached, read-only (top-level) copy of request data for event listeners."""
    if value is None:
        return None
    return MappingProxyType(snapshot(dict(value)))


def snapshot_input(input: Any) -> Any:
    """Bodyless copy of an HTTP request, or a deep copy of other transport inputs."""
    if input is None:
        return None
    if isinstance(input, Request):
        return Request(input.method, input.url, make_headers(input.headers))
    try:
        return copy.deepcopy(input)
    except Exception:
        _warn_uncloneable_input()
        return None


@functools.cache
def _warn_uncloneable_input() -> None:
    # Logged once per process, like mppx `warnOnce`.
    logger.warning(
        "Could not clone server event input; omitting `input`. "
        "Use `captured_request` for request correlation."
    )


def snapshot_captured(captured: CapturedRequest | None) -> CapturedRequest | None:
    if captured is None:
        return None
    return CapturedRequest(
        method=captured.method,
        url=captured.url,
        headers=make_headers(captured.headers),
        has_body=captured.has_body,
    )


def descriptor(name: str, intent: str) -> MethodDescriptor:
    return MethodDescriptor(name, intent)
