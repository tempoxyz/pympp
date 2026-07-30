"""Shared client-side payment primitives."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Protocol, Self, runtime_checkable

import httpx

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    EventDispatcher,
    EventPayload,
)

if TYPE_CHECKING:
    from mpp.client import PaymentTransport
    from mpp.client._http import _HttpPaymentAttempt


@runtime_checkable
class Method(Protocol):
    """Client-side payment method."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential for a challenge."""
        ...


class PaymentRuntime:
    """Match methods and create credentials on the caller's event loop.

    Methods are borrowed: the runtime neither enters nor closes them.
    """

    def __init__(
        self,
        methods: Sequence[Method] = (),
        *,
        events: EventDispatcher | None = None,
        allowed_origins: Sequence[str] | None = None,
    ) -> None:
        from mpp.client._http import _AllowedOrigins, _HttpPaymentLedger

        self.methods = tuple(methods)
        for method in self.methods:
            if not _is_method(method):
                raise TypeError("methods must contain payment Methods")
            _method_intents(method)
        self.events = events or EventDispatcher()
        self._allowed_origins = _AllowedOrigins(allowed_origins)
        self._http = _HttpPaymentLedger()
        self._closed = False
        self._closing = False
        self._paid_operations = 0

    def start(self) -> Self:
        """Open the runtime, or return it if already open."""
        if self._closed or self._closing:
            raise RuntimeError("PaymentRuntime is closed")
        return self

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()

    async def astart(self) -> Self:
        """Asynchronously open the runtime."""
        return self.start()

    async def __aenter__(self) -> Self:
        return await self.astart()

    async def __aexit__(self, *_args: Any) -> None:
        await self.aclose()

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
        *,
        prefer_method_order: bool = True,
        allow_name_only: bool = False,
    ) -> tuple[Challenge, Method]:
        """Return the first compatible challenge and method."""
        self.start()
        pairs = (
            ((challenge, method) for method in self.methods for challenge in challenges)
            if prefer_method_order
            else ((challenge, method) for challenge in challenges for method in self.methods)
        )
        for challenge, method in pairs:
            if challenge.method == method.name and (
                allow_name_only or challenge.intent in _method_intents(method)
            ):
                return challenge, method

        offered = [challenge.method for challenge in challenges]
        installed = [method.name for method in self.methods]
        raise ValueError(
            f"No compatible payment method. Server offered: {offered}, client has: {installed}"
        )

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Create a credential and emit its lifecycle events."""
        self.start()
        return await self._create_credential(
            challenge,
            method,
            allow_name_only=allow_name_only,
            event_payload=event_payload,
        )

    async def _create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        if not any(candidate is method for candidate in self.methods):
            raise ValueError("Method is not installed in this PaymentRuntime")
        if challenge.method != method.name or (
            not allow_name_only and challenge.intent not in _method_intents(method)
        ):
            raise ValueError(
                f"Method {method.name!r} does not support {challenge.method!r}/{challenge.intent!r}"
            )
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

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        """Emit an event on the caller's event loop."""
        self.start()
        return await self._emit_event(name, payload)

    async def _emit_event(self, name: str, payload: EventPayload) -> Any:
        return await self.events.emit(name, payload)

    def payment_transport(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> PaymentTransport:
        """Create an asynchronous HTTPX transport backed by this runtime."""
        from mpp.client import PaymentTransport

        return PaymentTransport(inner=inner, runtime=self)

    def allows_http_payment(self, url: httpx.URL) -> bool:
        """Return whether credentials may be created for an HTTP origin."""
        return self._allowed_origins.allows(url)

    def reset_unknown_outcomes(self, *, reconciled: bool) -> None:
        """Allow new payments after retained uncertain outcomes were reconciled."""
        self._http.reset(reconciled=reconciled)

    def _begin_http_payment(
        self,
        challenge: Challenge,
        request: httpx.Request,
    ) -> _HttpPaymentAttempt:
        return self._http.begin(challenge, request)

    @contextmanager
    def _paid_operation(self):
        """Keep a committed payment flow alive if close is requested."""
        self.start()
        self._paid_operations += 1
        try:
            yield
        finally:
            self._paid_operations -= 1
            if self._closing and not self._paid_operations:
                self._closed = True

    def close(self) -> None:
        """Prevent new runtime operations."""
        self._closing = True
        if not self._paid_operations:
            self._closed = True

    async def aclose(self) -> None:
        """Asynchronously close the runtime."""
        self.close()


def _is_method(value: Any) -> bool:
    return isinstance(getattr(value, "name", None), str) and callable(
        getattr(value, "create_credential", None)
    )


def _method_intents(method: Method) -> Mapping[str, Any]:
    intents = getattr(method, "intents", None)
    if intents is None:
        intents = getattr(method, "_intents", None)
    if intents is None:
        return {"charge": None}
    if not isinstance(intents, Mapping):
        raise TypeError("Method intents must be a Mapping")
    return intents
