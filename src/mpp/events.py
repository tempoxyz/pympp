"""Payment lifecycle event helpers."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

EventPayload = dict[str, Any]
EventHandler = Callable[[Any], Any | Awaitable[Any]]
Unsubscribe = Callable[[], None]


@dataclass(frozen=True, slots=True)
class PaymentEvent:
    """Wildcard event envelope."""

    name: str
    payload: EventPayload


class EventDispatcher:
    """Dispatches payment lifecycle events."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a handler and return an unsubscribe callback."""
        handlers = self._handlers.setdefault(name, [])
        handlers.append(handler)

        def unsubscribe() -> None:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

        return unsubscribe

    async def emit(self, name: str, payload: EventPayload) -> Any:
        """Emit an event.

        Named handlers receive the payload. Wildcard handlers receive a
        ``PaymentEvent`` envelope. The first non-None value returned by a named
        handler is returned to the caller.
        """
        result = None
        for handler in tuple(self._handlers.get(name, ())):
            try:
                value = handler(payload)
                if inspect.isawaitable(value):
                    value = await value
                if result is None and value is not None:
                    result = value
            except Exception:
                logger.exception("Payment event handler failed for %s", name)

        event = PaymentEvent(name=name, payload=payload)
        for handler in tuple(self._handlers.get("*", ())):
            try:
                value = handler(event)
                if inspect.isawaitable(value):
                    await value
            except Exception:
                logger.exception("Payment wildcard event handler failed for %s", name)

        return result
