"""Shared client-side payment primitives."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import Future
from contextlib import (
    AbstractAsyncContextManager,
    ExitStack,
    contextmanager,
)
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, Self, TypeVar, runtime_checkable

import httpx
from anyio.from_thread import BlockingPortal, start_blocking_portal

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    EventDispatcher,
    EventPayload,
)

if TYPE_CHECKING:
    from mpp.client import PaymentTransport
    from mpp.client._http import _HttpPaymentAttempt as _Attempt


@dataclass(slots=True)
class _OwnedRuntimeScope:
    key: object
    active: bool = True


_OWNED_RUNTIME_SCOPES: ContextVar[tuple[_OwnedRuntimeScope, ...]] = ContextVar(
    "mpp_owned_runtime_scopes",
    default=(),
)
_ResultT = TypeVar("_ResultT")


@runtime_checkable
class Method(Protocol):
    """Client-side payment method."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential for a challenge."""
        ...


MethodFactory = Callable[[], AbstractAsyncContextManager[Method]]


class _PortalError(Exception):
    def __init__(self, error: BaseException) -> None:
        self.error = error


async def _portal_call(factory: Callable[[], Awaitable[_ResultT]]) -> _ResultT:
    try:
        return await factory()
    except BaseException as error:
        if isinstance(error, (Exception, asyncio.CancelledError)):
            raise
        raise _PortalError(error) from None


async def _settle_cancelled_task(task: asyncio.Task[Any]) -> None:
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    if not task.cancelled():
        task.exception()


@contextmanager
def _owned_scope(key: object):
    scope = _OwnedRuntimeScope(key)
    token = _OWNED_RUNTIME_SCOPES.set((*_OWNED_RUNTIME_SCOPES.get(), scope))
    try:
        yield
    finally:
        scope.active = False
        _OWNED_RUNTIME_SCOPES.reset(token)


def _owned_in_scope(key: object) -> bool:
    return any(scope.active and scope.key is key for scope in _OWNED_RUNTIME_SCOPES.get())


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
    ) -> _Attempt:
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


class OwnedPaymentRuntime:
    """Run borrowed and managed payment methods on one owned asyncio loop."""

    def __init__(
        self,
        methods: Sequence[Method] = (),
        *,
        method_factories: Sequence[MethodFactory] = (),
        events: EventDispatcher | None = None,
        allowed_origins: Sequence[str] | None = None,
    ) -> None:
        from mpp.client._http import _AllowedOrigins

        self._borrowed = tuple(methods)
        self._factories = tuple(method_factories)
        self.events = events or EventDispatcher()
        self._runtime_allowed_origins = allowed_origins
        self._allowed_origins = _AllowedOrigins(allowed_origins)
        self._changed = threading.Condition()
        self._scope_key = object()
        self._state = "new"
        self._start_claimed = False
        self._async_starters = 0
        self._leases = 0
        self._stack: ExitStack | None = None
        self._portal: BlockingPortal | None = None
        self._owner_thread_id: int | None = None
        self._runtime: PaymentRuntime | None = None

    def _start(self, *, claim: bool) -> None:
        with self._changed:
            if self._state == "starting" and threading.get_ident() == self._owner_thread_id:
                raise RuntimeError("Cannot start OwnedPaymentRuntime from its owned event loop")
            self._start_claimed |= claim
            while self._state == "starting":
                self._changed.wait()
            if self._state == "open":
                return
            if self._state != "new":
                raise RuntimeError(f"OwnedPaymentRuntime is {self._state}")
            self._state = "starting"

        stack = ExitStack()
        try:
            portal = stack.enter_context(start_blocking_portal(backend="asyncio"))
            owner_thread_id = portal.call(threading.get_ident)
            with self._changed:
                self._owner_thread_id = owner_thread_id
            managed = []
            for factory in self._factories:
                context = portal.call(factory)
                if not isinstance(context, AbstractAsyncContextManager):
                    raise TypeError("Expected an asynchronous context manager")
                managed.append(stack.enter_context(portal.wrap_async_context_manager(context)))
            runtime = PaymentRuntime(
                (*self._borrowed, *managed),
                events=self.events,
                allowed_origins=self._runtime_allowed_origins,
            )
            stack.callback(runtime.close)
        except BaseException:
            try:
                stack.close()
            finally:
                with self._changed:
                    self._owner_thread_id = None
                    self._state = "closed"
                    self._changed.notify_all()
            raise

        with self._changed:
            self._stack = stack.pop_all()
            self._portal = portal
            self._owner_thread_id = owner_thread_id
            self._runtime = runtime
            self._state = "open"
            self._changed.notify_all()

    def start(self) -> Self:
        """Start the owned event loop and initialize managed methods."""
        self._start(claim=True)
        return self

    __enter__ = start

    def __exit__(self, *_args: Any) -> None:
        self.close()

    async def astart(self) -> Self:
        """Start the runtime without blocking the caller's event loop."""
        with self._changed:
            if self._state == "starting" and threading.get_ident() == self._owner_thread_id:
                raise RuntimeError("Cannot start OwnedPaymentRuntime from its owned event loop")
            if self._state == "open":
                self._start_claimed = True
                return self
            self._async_starters += 1
        task = asyncio.create_task(asyncio.to_thread(self._start, claim=False))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await _settle_cancelled_task(task)
            with self._changed:
                self._async_starters -= 1
            cleanup = asyncio.create_task(asyncio.to_thread(self._close, unclaimed_only=True))
            await _settle_cancelled_task(cleanup)
            raise
        except BaseException:
            with self._changed:
                self._async_starters -= 1
            raise
        with self._changed:
            self._async_starters -= 1
            self._start_claimed = True
        return self

    __aenter__ = astart

    async def aclose(self) -> None:
        """Close the runtime without blocking the caller's event loop."""
        if _owned_in_scope(self._scope_key) or threading.get_ident() == self._owner_thread_id:
            self.close()
        await asyncio.to_thread(self.close)

    async def __aexit__(self, *_args: Any) -> None:
        await self.aclose()

    def _acquire(self, *, continuation: bool = False) -> None:
        if not continuation:
            self.start()
        with self._changed:
            if continuation:
                if not _owned_in_scope(self._scope_key) or self._state not in {
                    "open",
                    "closing",
                }:
                    raise RuntimeError("No active OwnedPaymentRuntime operation")
            elif self._state != "open":
                raise RuntimeError(f"OwnedPaymentRuntime is {self._state}")
            self._leases += 1

    def _release(self) -> None:
        with self._changed:
            self._leases -= 1
            self._changed.notify_all()

    @contextmanager
    def _lease(self, *, continuation: bool = False):
        self._acquire(continuation=continuation)
        try:
            with _owned_scope(self._scope_key):
                yield
        finally:
            self._release()

    @contextmanager
    def _paid_operation(self):
        """Keep the runtime open for one complete payment flow."""
        with self._lease():
            yield

    def _submit(
        self,
        factory: Callable[[], Awaitable[_ResultT]],
        *,
        continuation: bool = False,
    ) -> Future[_ResultT]:
        self._acquire(continuation=continuation)

        async def run() -> _ResultT:
            try:
                with _owned_scope(self._scope_key):
                    return await _portal_call(factory)
            finally:
                self._release()

        try:
            assert self._portal is not None
            return self._portal.start_task_soon(run)
        except BaseException:
            self._release()
            raise

    def _call(
        self,
        factory: Callable[[], Awaitable[_ResultT]],
        *,
        continuation: bool = False,
    ) -> _ResultT:
        if threading.get_ident() == self._owner_thread_id:
            raise RuntimeError("Cannot call a sync runtime API from its owned event loop")
        future = self._submit(factory, continuation=continuation)
        try:
            return future.result()
        except _PortalError as error:
            raise error.error from None
        except BaseException:
            future.cancel()
            raise

    async def _acall(
        self,
        factory: Callable[[], Awaitable[_ResultT]],
        *,
        continuation: bool = False,
    ) -> _ResultT:
        if threading.get_ident() == self._owner_thread_id:
            with self._lease(continuation=continuation):
                return await factory()
        if not continuation:
            await self.astart()
        future = self._submit(factory, continuation=continuation)
        try:
            return await asyncio.wrap_future(future)
        except _PortalError as error:
            raise error.error from None

    def _leased_core(self) -> PaymentRuntime:
        if not _owned_in_scope(self._scope_key):
            raise RuntimeError("No active OwnedPaymentRuntime operation")
        assert self._runtime is not None
        return self._runtime

    @property
    def methods(self) -> tuple[Method, ...]:
        with self._lease():
            return self._leased_core().methods

    def match_challenge(
        self,
        challenges: Sequence[Challenge],
        *,
        prefer_method_order: bool = True,
        allow_name_only: bool = False,
    ) -> tuple[Challenge, Method]:
        with self._lease():
            return self._leased_core().match_challenge(
                challenges,
                prefer_method_order=prefer_method_order,
                allow_name_only=allow_name_only,
            )

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        return await self._create_credential(
            challenge,
            method,
            allow_name_only=allow_name_only,
            event_payload=event_payload,
            _continuation=False,
        )

    async def _create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
        _continuation: bool = True,
    ) -> Credential:
        return await self._acall(
            lambda: self._leased_core()._create_credential(
                challenge,
                method,
                allow_name_only=allow_name_only,
                event_payload=event_payload,
            ),
            continuation=_continuation,
        )

    def create_credential_sync(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        return self._create_credential_sync(
            challenge,
            method,
            allow_name_only=allow_name_only,
            event_payload=event_payload,
            _continuation=False,
        )

    def _create_credential_sync(
        self,
        challenge: Challenge,
        method: Method,
        *,
        allow_name_only: bool = False,
        event_payload: dict[str, Any] | None = None,
        _continuation: bool = True,
    ) -> Credential:
        return self._call(
            lambda: self._leased_core()._create_credential(
                challenge,
                method,
                allow_name_only=allow_name_only,
                event_payload=event_payload,
            ),
            continuation=_continuation,
        )

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        return await self._emit_event(name, payload, _continuation=False)

    async def _emit_event(
        self,
        name: str,
        payload: EventPayload,
        *,
        _continuation: bool = True,
    ) -> Any:
        return await self._acall(
            lambda: self._leased_core()._emit_event(name, payload),
            continuation=_continuation,
        )

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        return self._emit_event_sync(name, payload, _continuation=False)

    def _emit_event_sync(
        self,
        name: str,
        payload: EventPayload,
        *,
        _continuation: bool = True,
    ) -> Any:
        return self._call(
            lambda: self._leased_core()._emit_event(name, payload),
            continuation=_continuation,
        )

    def allows_http_payment(self, url: httpx.URL) -> bool:
        return self._allowed_origins.allows(url)

    def reset_unknown_outcomes(self, *, reconciled: bool) -> None:
        with self._lease():
            self._leased_core().reset_unknown_outcomes(reconciled=reconciled)

    def _begin_http_payment(self, challenge: Challenge, request: httpx.Request) -> _Attempt:
        return self._leased_core()._begin_http_payment(challenge, request)

    def _close(self, *, unclaimed_only: bool = False) -> None:
        if _owned_in_scope(self._scope_key):
            raise RuntimeError("Cannot close OwnedPaymentRuntime from an active operation")
        if threading.get_ident() == self._owner_thread_id:
            raise RuntimeError("Cannot close OwnedPaymentRuntime from its owned event loop")

        with self._changed:
            while self._state == "starting":
                self._changed.wait()
            if unclaimed_only and (
                self._state != "open" or self._async_starters or self._start_claimed
            ):
                return
            while self._state == "closing":
                self._changed.wait()
            if self._state != "open":
                self._state = "closed"
                self._changed.notify_all()
                return
            self._state = "closing"
            while self._leases:
                self._changed.wait()
            stack = self._stack

        assert stack is not None
        try:
            stack.close()
        finally:
            with self._changed:
                self._stack = None
                self._portal = None
                self._owner_thread_id = None
                self._runtime = None
                self._state = "closed"
                self._changed.notify_all()

    def close(self) -> None:
        """Wait for active operations, close methods, and stop the owned loop."""
        self._close()


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
