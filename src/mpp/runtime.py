"""Shared lifecycle for client-side payment methods."""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack, contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
from typing import Any, Protocol, Self, TypeVar, runtime_checkable

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    EventDispatcher,
    EventPayload,
)

_T = TypeVar("_T")


@dataclass(slots=True)
class _Lifecycle:
    active: bool = True


@dataclass(slots=True)
class _RuntimeLease:
    owners: set[object]

    @property
    def active(self) -> bool:
        return bool(self.owners)


_RUNTIME_LEASES: ContextVar[dict[int, _RuntimeLease] | None] = ContextVar(
    "mpp_runtime_leases",
    default=None,
)
_LIFECYCLE: ContextVar[_Lifecycle | None] = ContextVar("mpp_runtime_lifecycle", default=None)


@contextmanager
def _lifecycle():
    lifecycle = _Lifecycle()
    token = _LIFECYCLE.set(lifecycle)
    try:
        yield
    finally:
        lifecycle.active = False
        _LIFECYCLE.reset(token)


def _lifecycle_active() -> bool:
    lifecycle = _LIFECYCLE.get()
    return lifecycle is not None and lifecycle.active


def _operation_owner() -> object:
    try:
        return asyncio.current_task() or threading.current_thread()
    except RuntimeError:
        return threading.current_thread()


async def _wait_for_task(task: asyncio.Task[_T]) -> _T:
    """Wait for completion while preserving an already-raised cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


@runtime_checkable
class Method(Protocol):
    """Client-side payment method."""

    name: str

    async def create_credential(self, challenge: Challenge, /) -> Credential:
        """Create a credential for a challenge."""
        ...


_MethodFactoryResult = Method | AbstractAsyncContextManager[Method]
MethodFactory = Callable[
    [],
    _MethodFactoryResult | Awaitable[_MethodFactoryResult],
]


class _AsyncBridge:
    """Own one lazy event loop for payment-method work."""

    def __init__(self) -> None:
        self._closed = False
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._start_error: BaseException | None = None
        self._stop_error: BaseException | None = None
        self._thread: threading.Thread | None = None

    def _record_stop_error(self, error: BaseException) -> None:
        if self._stop_error is None:
            self._stop_error = error

    @staticmethod
    def _drain_loop(loop: asyncio.AbstractEventLoop) -> BaseException | None:
        error: BaseException | None = None
        try:
            pending = asyncio.all_tasks(loop)
        except BaseException as cause:
            pending = set()
            error = cause
        for task in pending:
            try:
                task.cancel()
            except BaseException as cause:
                if error is None:
                    error = cause

        async def drain_pending() -> None:
            await asyncio.gather(*pending, return_exceptions=True)

        cleanup = (
            *((drain_pending,) if pending else ()),
            loop.shutdown_asyncgens,
            loop.shutdown_default_executor,
        )
        for action in cleanup:
            try:
                loop.run_until_complete(action())
            except BaseException as cause:
                if error is None:
                    error = cause
        return error

    def _submit(self, coroutine: Coroutine[Any, Any, _T]) -> Any:
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._thread is None:
                thread = threading.Thread(
                    target=self._run,
                    name="pympp-payment-runtime",
                    daemon=True,
                )
                self._thread = thread
                try:
                    thread.start()
                except BaseException as error:
                    self._start_error = error
                    self._ready.set()
                    self._stopped.set()
                    raise RuntimeError("PaymentRuntime background loop failed to start") from error
        self._ready.wait()
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._start_error is not None:
                raise RuntimeError("PaymentRuntime background loop failed to start") from (
                    self._start_error
                )
            if self._loop is None:
                raise RuntimeError("PaymentRuntime background loop failed to start")
            if threading.current_thread() is self._thread:
                raise RuntimeError("Cannot block the PaymentRuntime background loop")
            return copy_context().run(
                asyncio.run_coroutine_threadsafe,
                coroutine,
                self._loop,
            )

    def _run(self) -> None:
        initialized = False
        stop_error: BaseException | None = None
        try:
            with asyncio.Runner() as runner:
                self._loop = runner.get_loop()
                initialized = True
                self._ready.set()
                try:
                    self._loop.run_forever()
                except BaseException as error:
                    stop_error = error
                cleanup_error = self._drain_loop(self._loop)
                if stop_error is None:
                    stop_error = cleanup_error
        except BaseException as error:
            if not initialized:
                self._start_error = error
            elif stop_error is None:
                stop_error = error
        finally:
            if stop_error is not None:
                self._record_stop_error(stop_error)
            self._ready.set()
            self._stopped.set()

    def run(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run async work from synchronous code."""
        try:
            future = self._submit(coroutine)
        except BaseException:
            coroutine.close()
            raise
        try:
            return future.result()
        except BaseException:
            future.cancel()
            raise

    async def run_async(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run async work without blocking the caller's event loop."""
        if asyncio.get_running_loop() is self._loop:
            return await coroutine
        try:
            future = self._submit(coroutine)
        except BaseException:
            coroutine.close()
            raise
        try:
            return await asyncio.wrap_future(future)
        except BaseException:
            future.cancel()
            raise

    async def _cancel_pending(self) -> None:
        current = asyncio.current_task()
        pending = [task for task in asyncio.all_tasks() if task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def is_current_thread(self) -> bool:
        return threading.current_thread() is self._thread

    def cancel_pending(self) -> None:
        """Cancel and drain runtime-loop work without stopping the loop."""
        thread, loop = self._thread, self._loop
        if thread is None or loop is None or not thread.is_alive():
            return
        if self.is_current_thread():
            raise RuntimeError("Cannot synchronously cancel the PaymentRuntime loop")
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(self._cancel_pending(), loop).result()

    def close(self) -> None:
        """Stop the runtime loop, if it was started."""
        with self._lock:
            if self._closed:
                already_closed = True
                wait = threading.current_thread() is not self._thread
                thread = self._thread
            else:
                already_closed = False
                self._closed = True
                wait = False
                thread = self._thread
        if already_closed:
            if wait:
                self._stopped.wait()
                if self._stop_error is not None:
                    raise self._stop_error
            return
        if thread is None:
            self._stopped.set()
            return
        if self._loop is None:
            self._ready.wait()
        loop = self._loop
        if loop is None:
            if thread.ident is not None:
                thread.join()
            return
        if threading.current_thread() is thread:
            loop.stop()
            return
        error: BaseException | None = None
        if thread.is_alive() and loop.is_running():
            try:
                future = asyncio.run_coroutine_threadsafe(self._cancel_pending(), loop)
                future.result()
            except BaseException as cause:
                error = cause
        try:
            loop.call_soon_threadsafe(loop.stop)
        except BaseException as cause:
            if error is None:
                error = cause
        if thread.ident is not None:
            thread.join()
        if error is not None:
            raise error
        if self._stop_error is not None:
            raise self._stop_error


class PaymentRuntime:
    """Own one event loop and lifecycle for client-side payment methods.

    Direct ``methods`` are borrowed and must be loop-independent. Use
    ``method_factories`` for loop-bound methods: factories are called on the
    owned loop, and async context-manager results are exited there on close.
    """

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        *,
        method_factories: Sequence[MethodFactory] = (),
        events: EventDispatcher | None = None,
    ) -> None:
        if methods is not None and method_factories:
            raise ValueError("Pass either methods or method_factories, not both")
        self.methods = tuple(methods or ())
        if any(not _is_method(method) for method in self.methods):
            raise TypeError("methods must contain payment Methods")
        self._method_factories = tuple(method_factories)
        self._method_stack: AsyncExitStack | None = None
        self.events = events or EventDispatcher()
        self._bridge = _AsyncBridge()
        self._lifecycle = threading.Condition()
        self._active_operations = 0
        self._state = "new"
        self._start_error: BaseException | None = None
        self._finalizing = False
        self._deferred_close = False

    async def _initialize_methods(self) -> None:
        stack = AsyncExitStack()
        methods: list[Method] = []
        with _lifecycle():
            try:
                for factory in self._method_factories:
                    value: Any = factory()
                    if inspect.isawaitable(value):
                        value = await value
                    if hasattr(value, "__aenter__") and hasattr(value, "__aexit__"):
                        value = await stack.enter_async_context(value)
                    if not _is_method(value):
                        raise TypeError("Method factory must return a payment Method")
                    methods.append(value)
            except BaseException:
                try:
                    await stack.aclose()
                except BaseException:
                    pass
                raise
        if self._method_factories:
            self.methods = tuple(methods)
        self._method_stack = stack

    async def _teardown_methods(self) -> None:
        stack, self._method_stack = self._method_stack, None
        if stack is not None:
            with _lifecycle():
                await stack.aclose()

    def start(self) -> Self:
        """Start the owned loop and initialize method factories once."""
        with self._lifecycle:
            while self._state == "starting":
                if _lifecycle_active():
                    raise RuntimeError("Cannot use PaymentRuntime while method factories start")
                self._lifecycle.wait()
            if self._state == "open":
                return self
            if self._state in ("closing", "closed"):
                if self._start_error is not None:
                    raise RuntimeError("PaymentRuntime failed to start") from self._start_error
                raise RuntimeError("PaymentRuntime is closed")
            self._state = "starting"

        try:
            self._bridge.run(self._initialize_methods())
        except BaseException as error:
            try:
                self._bridge.close()
            except BaseException:
                pass
            with self._lifecycle:
                self._start_error = error
                self._state = "closed"
                self._lifecycle.notify_all()
            raise

        with self._lifecycle:
            self._state = "open"
            self._lifecycle.notify_all()
        return self

    async def astart(self) -> Self:
        """Asynchronously start the runtime without blocking the caller loop."""
        with self._lifecycle:
            if self._state == "open":
                return self
        start = asyncio.create_task(asyncio.to_thread(self.start))
        try:
            await asyncio.shield(start)
        except asyncio.CancelledError:
            await _wait_for_task(start)
            raise
        return self

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        try:
            return await self.astart()
        except BaseException:
            await self.aclose()
            raise

    async def __aexit__(self, *_args: Any) -> None:
        await self.aclose()

    @contextmanager
    def _runtime_operation(self, *, started: bool = False):
        key = id(self)
        leases = _RUNTIME_LEASES.get() or {}
        lease = leases.get(key)
        owner = _operation_owner()
        with self._lifecycle:
            inherited = lease is not None and lease.active
            joined = inherited and lease is not None and owner not in lease.owners
            if lease is not None and joined:
                lease.owners.add(owner)
        if inherited:
            assert lease is not None
            try:
                yield
            finally:
                if joined:
                    self._release_runtime_lease(lease, owner)
            return

        if not started:
            self.start()
        with self._lifecycle:
            if self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
            self._active_operations += 1
        lease = _RuntimeLease({owner})
        token = _RUNTIME_LEASES.set({**leases, key: lease})
        try:
            yield
        finally:
            _RUNTIME_LEASES.reset(token)
            self._release_runtime_lease(lease, owner)

    def _release_runtime_lease(self, lease: _RuntimeLease, owner: object) -> None:
        with self._lifecycle:
            lease.owners.discard(owner)
            if lease.active:
                return
            self._active_operations -= 1
            should_close = self._deferred_close and self._active_operations == 0
            if self._active_operations == 0:
                self._lifecycle.notify_all()
        if should_close:
            if self._bridge.is_current_thread():
                return
            self._finish_close()

    def _has_active_runtime_lease(self) -> bool:
        lease = (_RUNTIME_LEASES.get() or {}).get(id(self))
        return lease is not None and lease.active

    def _finish_close(self) -> None:
        with self._lifecycle:
            if self._state == "closed":
                return
            if self._finalizing:
                while self._state != "closed":
                    self._lifecycle.wait()
                return
            self._finalizing = True

        error: BaseException | None = None

        def cleanup(action: Callable[[], Any]) -> None:
            nonlocal error
            try:
                action()
            except BaseException as cause:
                if error is None:
                    error = cause

        try:
            cleanup(self._bridge.cancel_pending)
            if self._method_stack is not None:
                cleanup(lambda: self._bridge.run(self._teardown_methods()))
            cleanup(self._bridge.close)
        finally:
            with self._lifecycle:
                self._state = "closed"
                self._finalizing = False
                self._deferred_close = False
                self._lifecycle.notify_all()
        if error is not None:
            raise error

    async def _finish_close_async(self) -> None:
        with self._lifecycle:
            if (
                self._state != "closing"
                or not self._deferred_close
                or self._active_operations
                or self._finalizing
            ):
                return
            self._finalizing = True

        error: BaseException | None = None
        try:
            try:
                await self._bridge._cancel_pending()
            except BaseException as cause:
                error = cause
            if self._method_stack is not None:
                try:
                    await self._teardown_methods()
                except BaseException as cause:
                    if error is None:
                        error = cause
            try:
                self._bridge.close()
            except BaseException as cause:
                if error is None:
                    error = cause
        finally:
            with self._lifecycle:
                self._state = "closed"
                self._finalizing = False
                self._deferred_close = False
                self._lifecycle.notify_all()
        if error is not None:
            raise error

    def match_challenge(
        self,
        challenges: Sequence[Any],
        *,
        prefer_method_order: bool = True,
        allow_name_only: bool = False,
    ) -> tuple[Any, Method]:
        """Match payment challenges against configured methods."""
        pairs = (
            ((challenge, method) for method in self.methods for challenge in challenges)
            if prefer_method_order
            else ((challenge, method) for challenge in challenges for method in self.methods)
        )
        for challenge, method in pairs:
            if challenge.method != method.name:
                continue
            intents = _intent_names(method)
            if not allow_name_only and challenge.intent not in (
                intents if intents is not None else {"charge"}
            ):
                continue
            return challenge, method

        available = [challenge.method for challenge in challenges]
        installed = [method.name for method in self.methods]
        raise ValueError(
            f"No compatible payment method. Server offered: {available}, client has: {installed}"
        )

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Create a credential on the runtime-owned event loop."""
        return await self.run_async(
            self._create_credential(
                challenge,
                method,
                event_payload=event_payload,
            )
        )

    def create_credential_sync(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Synchronously create a credential on the runtime-owned event loop."""
        return self.run_sync(
            self._create_credential(
                challenge,
                method,
                event_payload=event_payload,
            )
        )

    def run_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run a coroutine on the owned loop and block for its result."""
        entered = False
        try:
            with self._runtime_operation():
                entered = True
                return self._bridge.run(coroutine)
        except BaseException:
            if not entered:
                coroutine.close()
            raise

    async def run_async(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run a coroutine on the owned loop without blocking."""
        entered = False
        try:
            if not self._has_active_runtime_lease():
                await self.astart()
            with self._runtime_operation(started=True):
                entered = True
                return await self._bridge.run_async(coroutine)
        except BaseException:
            if not entered:
                coroutine.close()
            raise
        finally:
            if entered and self._bridge.is_current_thread():
                await self._finish_close_async()

    async def _create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        payload = {
            **(event_payload or {}),
            "challenge": challenge,
            "challenges": [challenge],
            "method": method,
        }
        event_credential = await self._emit_event(
            CHALLENGE_RECEIVED,
            payload,
            first_result=True,
        )
        credential = (
            event_credential
            if isinstance(event_credential, Credential)
            else await method.create_credential(challenge)
        )
        await self._emit_event(
            CREDENTIAL_CREATED,
            {**payload, "credential": credential},
        )
        return credential

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        """Emit an event on the runtime-owned loop."""
        return await self.run_async(self._emit_event(name, payload))

    async def _emit_event(
        self,
        name: str,
        payload: EventPayload,
        *,
        first_result: bool = False,
    ) -> Any:
        return await self.events.emit(name, payload, first_result=first_result)

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        """Synchronously emit an event on the runtime-owned loop."""
        return self.run_sync(self._emit_event(name, payload))

    def close(self) -> None:
        """Close method resources and the owned event loop."""
        active_here = self._has_active_runtime_lease()
        on_runtime_thread = self._bridge.is_current_thread()
        wait_for_bridge = False
        with self._lifecycle:
            while self._state == "starting":
                if _lifecycle_active():
                    raise RuntimeError("Cannot close PaymentRuntime while method factories start")
                self._lifecycle.wait()
            if self._state == "closed":
                wait_for_bridge = not on_runtime_thread
            elif self._state == "closing":
                if active_here or on_runtime_thread or _lifecycle_active():
                    return
                while self._state != "closed":
                    self._lifecycle.wait()
                wait_for_bridge = True
            else:
                if on_runtime_thread and not active_here:
                    raise RuntimeError(
                        "Cannot close PaymentRuntime from unmanaged runtime-loop work"
                    )
                self._state = "closing"
                if active_here:
                    self._deferred_close = True
                    return
        if wait_for_bridge:
            self._bridge.close()
            return
        self._finish_close()

    async def aclose(self) -> None:
        """Asynchronously close method resources and the owned event loop."""
        if self._bridge.is_current_thread():
            self.close()
            return
        close = asyncio.create_task(asyncio.to_thread(self.close))
        try:
            await asyncio.shield(close)
        except asyncio.CancelledError:
            await _wait_for_task(close)
            raise


def _is_method(value: Any) -> bool:
    if not isinstance(getattr(value, "name", None), str):
        return False
    if not callable(getattr(value, "create_credential", None)):
        return False
    intents = getattr(value, "intents", None)
    return intents is None or isinstance(intents, Mapping)


def _intent_names(method: Method) -> set[str] | None:
    intents = getattr(method, "intents", None)
    if intents is not None:
        if not isinstance(intents, Mapping):
            raise TypeError("Method intents must be a Mapping")
        return set(intents)
    legacy_intents = getattr(method, "_intents", None)
    if isinstance(legacy_intents, Mapping):
        return set(legacy_intents)
    return None
