"""Shared lifecycle for client-side payment methods."""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from concurrent.futures import Future
from contextlib import (
    AbstractAsyncContextManager,
    AbstractContextManager,
    AsyncExitStack,
    contextmanager,
)
from contextvars import ContextVar
from typing import Any, Protocol, Self, TypeVar, cast

from anyio import TASK_STATUS_IGNORED
from anyio.abc import TaskStatus
from anyio.from_thread import BlockingPortal, start_blocking_portal

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    EventDispatcher,
    EventPayload,
)

_T = TypeVar("_T")


_RUNTIME_CONTEXT: ContextVar[tuple[object, str] | None] = ContextVar(
    "mpp_runtime_context",
    default=None,
)


@contextmanager
def _runtime_scope(key: object, kind: str):
    token = _RUNTIME_CONTEXT.set((key, kind))
    try:
        yield
    finally:
        _RUNTIME_CONTEXT.reset(token)


def _scope_active(key: object, kind: str) -> bool:
    current = _RUNTIME_CONTEXT.get()
    return current is not None and current[0] is key and current[1] == kind


async def _wait_for_task(task: asyncio.Task[_T]) -> _T:
    """Wait for completion while preserving an already-raised cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


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
    """Run payment work on one AnyIO-owned asyncio loop."""

    def __init__(self) -> None:
        self._closed = False
        self._lock = threading.Lock()
        self._context: AbstractContextManager[BlockingPortal] | None = None
        self._portal: BlockingPortal | None = None
        self._thread: threading.Thread | None = None
        self._tasks: set[asyncio.Task[Any]] = set()

    def start(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._portal is not None:
                return

            context = start_blocking_portal(
                backend="asyncio",
                name="pympp-payment-runtime",
            )
            portal: BlockingPortal | None = None
            try:
                portal = context.__enter__()
                self._portal = portal
                self._context = context
                self._thread = portal.call(threading.current_thread)
            except BaseException as error:
                self._closed = True
                if portal is not None:
                    context.__exit__(None, None, None)
                raise RuntimeError("PaymentRuntime background loop failed to start") from error

    async def _run_coroutine(
        self,
        coroutine: Coroutine[Any, Any, _T],
        *,
        task_status: TaskStatus[None] = TASK_STATUS_IGNORED,
    ) -> _T:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        task_status.started()
        try:
            return await coroutine
        finally:
            self._tasks.discard(task)

    def _submit(self, coroutine: Coroutine[Any, Any, _T]) -> Future[_T]:
        with self._lock:
            if self._closed or self._portal is None:
                raise RuntimeError("PaymentRuntime is closed")
            if self.is_current_thread():
                raise RuntimeError("Cannot block the PaymentRuntime background loop")
            future, _ = self._portal.start_task(self._run_coroutine, coroutine)
            return cast(Future[_T], future)

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
        if self.is_current_thread():
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

    async def _shutdown(
        self,
        finalizer: Callable[[], Awaitable[None]] | None,
    ) -> None:
        current = asyncio.current_task()
        pending = [task for task in self._tasks if task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if finalizer is not None:
            await finalizer()

    def is_current_thread(self) -> bool:
        return threading.current_thread() is self._thread

    def close(self, finalizer: Callable[[], Awaitable[None]] | None = None) -> None:
        """Stop the owned loop, if it was started."""
        if self.is_current_thread():
            raise RuntimeError("Cannot close the PaymentRuntime background loop from itself")

        with self._lock:
            if self._closed:
                return
            self._closed = True
            context, self._context = self._context, None
            portal, self._portal = self._portal, None

        if context is None or portal is None:
            return

        error: BaseException | None = None
        try:
            portal.call(self._shutdown, finalizer)
        except BaseException as cause:
            error = cause
        try:
            context.__exit__(None, None, None)
        except BaseException as cause:
            if error is None:
                error = cause
        if error is not None:
            raise error


class PaymentRuntime:
    """Own one event loop and lifecycle for client-side payment methods.

    Direct ``methods`` are borrowed and must be loop-independent. Use
    ``method_factories`` for loop-bound methods: factories are called on the
    owned loop, and async context-manager results are exited there on close.
    Factories and methods must finish any work they spawn before returning.
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
        self._state_changed = threading.Condition()
        self._active_operations = 0
        self._scope_key = object()
        self._state = "new"
        self._start_error: BaseException | None = None
        self._deferred_close = False

    def _in_method_lifecycle(self) -> bool:
        return _scope_active(self._scope_key, "lifecycle")

    def _in_operation(self) -> bool:
        return _scope_active(self._scope_key, "operation")

    async def _initialize_methods(self) -> None:
        with _runtime_scope(self._scope_key, "lifecycle"):
            async with AsyncExitStack() as stack:
                methods: list[Method] = []
                for factory in self._method_factories:
                    value: Any = factory()
                    if inspect.isawaitable(value):
                        value = await value
                    if hasattr(value, "__aenter__") and hasattr(value, "__aexit__"):
                        value = await stack.enter_async_context(value)
                    if not _is_method(value):
                        raise TypeError("Method factory must return a payment Method")
                    methods.append(value)
                if self._method_factories:
                    self.methods = tuple(methods)
                self._method_stack = stack.pop_all()

    async def _teardown_methods(self) -> None:
        stack, self._method_stack = self._method_stack, None
        if stack is not None:
            with _runtime_scope(self._scope_key, "lifecycle"):
                await stack.aclose()

    def start(self) -> Self:
        """Start the owned loop and initialize method factories once."""
        with self._state_changed:
            while self._state == "starting":
                if self._in_method_lifecycle():
                    raise RuntimeError("Cannot use PaymentRuntime while method factories start")
                self._state_changed.wait()
            if self._state == "open":
                return self
            if self._state in ("closing", "closed"):
                if self._start_error is not None:
                    raise RuntimeError("PaymentRuntime failed to start") from self._start_error
                raise RuntimeError("PaymentRuntime is closed")
            self._state = "starting"

        try:
            self._bridge.start()
            self._bridge.run(self._initialize_methods())
        except BaseException as error:
            try:
                self._bridge.close()
            except BaseException:
                pass
            with self._state_changed:
                self._start_error = error
                self._state = "closed"
                self._state_changed.notify_all()
            raise

        with self._state_changed:
            self._state = "open"
            self._state_changed.notify_all()
        return self

    async def astart(self) -> Self:
        """Asynchronously start the runtime without blocking the caller loop."""
        with self._state_changed:
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
    def _runtime_operation(self):
        if self._in_operation():
            yield
            return

        with self._state_changed:
            if self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
            self._active_operations += 1

        try:
            with _runtime_scope(self._scope_key, "operation"):
                yield
        finally:
            with self._state_changed:
                self._active_operations -= 1
                should_close = self._deferred_close and self._active_operations == 0
            if should_close:
                self._finish_close()

    def _finish_close(self) -> None:
        with self._state_changed:
            if self._state == "closed":
                return
        try:
            finalizer = self._teardown_methods if self._method_stack is not None else None
            self._bridge.close(finalizer)
        finally:
            with self._state_changed:
                self._state = "closed"
                self._deferred_close = False
                self._state_changed.notify_all()

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
        return await self._run_async(
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
        return self._run_sync(
            self._create_credential(
                challenge,
                method,
                event_payload=event_payload,
            )
        )

    def _run_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        entered = False
        try:
            if not self._in_operation():
                if self._bridge.is_current_thread():
                    raise RuntimeError("Cannot use PaymentRuntime from unmanaged runtime-loop work")
                self.start()
            with self._runtime_operation():
                entered = True
                return self._bridge.run(coroutine)
        except BaseException:
            if not entered:
                coroutine.close()
            raise

    async def _run_async(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        entered = False
        try:
            if not self._in_operation():
                if self._bridge.is_current_thread():
                    raise RuntimeError("Cannot use PaymentRuntime from unmanaged runtime-loop work")
                await self.astart()
            with self._runtime_operation():
                entered = True
                return await self._bridge.run_async(coroutine)
        except BaseException:
            if not entered:
                coroutine.close()
            raise

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
        event_credential = await self.events.emit(
            CHALLENGE_RECEIVED,
            payload,
            first_result=True,
        )
        credential = (
            event_credential
            if isinstance(event_credential, Credential)
            else await method.create_credential(challenge)
        )
        await self.events.emit(
            CREDENTIAL_CREATED,
            {**payload, "credential": credential},
        )
        return credential

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        """Emit an event on the runtime-owned loop."""
        return await self._run_async(self.events.emit(name, payload))

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        """Synchronously emit an event on the runtime-owned loop."""
        return self._run_sync(self.events.emit(name, payload))

    def close(self) -> None:
        """Close method resources and the owned event loop."""
        active_here = self._in_operation()
        on_runtime_thread = self._bridge.is_current_thread()
        with self._state_changed:
            while self._state == "starting":
                if self._in_method_lifecycle():
                    raise RuntimeError("Cannot close PaymentRuntime while method factories start")
                self._state_changed.wait()
            if self._state == "closed":
                return
            if self._state == "closing":
                if active_here or on_runtime_thread or self._in_method_lifecycle():
                    return
                while self._state != "closed":
                    self._state_changed.wait()
                return
            if on_runtime_thread and not active_here:
                raise RuntimeError("Cannot close PaymentRuntime from unmanaged runtime-loop work")
            self._state = "closing"
            if active_here:
                self._deferred_close = True
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
    intents = getattr(value, "intents", None)
    return (
        isinstance(getattr(value, "name", None), str)
        and callable(getattr(value, "create_credential", None))
        and (intents is None or isinstance(intents, Mapping))
    )


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
