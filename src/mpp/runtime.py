"""Shared payment runtime for asynchronous HTTP clients."""

from __future__ import annotations

import asyncio
import hashlib
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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, Self, TypeVar, cast

import httpx
from anyio import TASK_STATUS_IGNORED
from anyio.abc import TaskStatus
from anyio.from_thread import BlockingPortal, start_blocking_portal

from mpp import Challenge, Credential
from mpp._httpx import HTTPX_ADAPTER_VERSIONS as HTTPX_ADAPTER_VERSIONS
from mpp._httpx import HttpxCompatibilityError as HttpxCompatibilityError
from mpp._httpx import _validate_httpx_client
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    EventDispatcher,
    EventPayload,
)

if TYPE_CHECKING:
    from mpp.client import PaymentTransport, SyncPaymentTransport

_T = TypeVar("_T")


class _BridgeBaseException(Exception):
    def __init__(self, error: BaseException) -> None:
        self.error = error


@dataclass(slots=True)
class _PaymentFlow:
    active: bool = True


_RUNTIME_CONTEXT: ContextVar[tuple[tuple[object, str], ...]] = ContextVar(
    "mpp_runtime_context",
    default=(),
)
_PAYMENT_FLOW: ContextVar[_PaymentFlow | None] = ContextVar(
    "mpp_payment_flow",
    default=None,
)


@dataclass(frozen=True, slots=True)
class _HttpPaymentTombstone:
    challenge: Challenge
    credential: Credential | None
    cause: BaseException
    request: httpx.Request


@dataclass(eq=False, slots=True)
class _HttpPaymentAttempt:
    runtime: PaymentRuntime
    challenge_key: str
    operation_key: str
    challenge: Challenge
    request: httpx.Request
    credential: Credential | None = None
    cause: BaseException | None = None
    sent: bool = False
    body_complete: bool = False
    send_complete: bool = False
    operation: _HttpxOperation | None = None
    idempotent: bool = False
    retry_request: httpx.Request | None = None


@dataclass(slots=True)
class _HttpxOperation:
    attempts: list[_HttpPaymentAttempt] = field(default_factory=list)
    payment_sent: bool = False
    active: bool = True


_HTTPX_OPERATIONS: ContextVar[dict[int, _HttpxOperation] | None] = ContextVar(
    "mpp_httpx_operations",
    default=None,
)
_HTTPX_ADAPTER_RUNTIME: ContextVar[int | None] = ContextVar(
    "mpp_httpx_adapter_runtime",
    default=None,
)
_HTTP_PAYMENT_ATTEMPT_EXTENSION = "mpp.payment_attempt"
_DEFAULT_MAX_UNKNOWN_OUTCOMES = 1024


@contextmanager
def _runtime_scope(key: object, kind: str):
    token = _RUNTIME_CONTEXT.set((*_RUNTIME_CONTEXT.get(), (key, kind)))
    try:
        yield
    finally:
        _RUNTIME_CONTEXT.reset(token)


def _scope_active(key: object, kind: str) -> bool:
    return any(
        current_key is key and current_kind == kind
        for current_key, current_kind in _RUNTIME_CONTEXT.get()
    )


@contextmanager
def _payment_flow():
    flow = _PaymentFlow()
    token = _PAYMENT_FLOW.set(flow)
    try:
        yield
    finally:
        flow.active = False
        _PAYMENT_FLOW.reset(token)


def payment_flow_active() -> bool:
    """Return whether the current context is handling a payment flow."""
    flow = _PAYMENT_FLOW.get()
    return flow is not None and flow.active


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


class _BoundSendTransport(httpx.AsyncBaseTransport):
    def __init__(self, send: Any) -> None:
        self._send = send

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._send(request)


class _BoundSyncSendTransport(httpx.BaseTransport):
    def __init__(self, send: Any) -> None:
        self._send = send

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._send(request)


_MISSING_CLIENT_ATTRIBUTE = object()


def _set_client_attributes(client: Any, **updates: Any) -> None:
    namespace = vars(client)
    previous = {name: namespace.get(name, _MISSING_CLIENT_ATTRIBUTE) for name in updates}
    applied: list[str] = []
    try:
        for name, value in updates.items():
            setattr(client, name, value)
            applied.append(name)
    except BaseException as error:
        rollback_error: BaseException | None = None
        for name in reversed(applied):
            try:
                value = previous[name]
                if value is _MISSING_CLIENT_ATTRIBUTE:
                    delattr(client, name)
                else:
                    setattr(client, name, value)
            except BaseException as cause:
                rollback_error = rollback_error or cause
        if rollback_error is not None:
            raise RuntimeError("Failed to roll back HTTPX client adapter") from error
        raise


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
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            if isinstance(error, Exception):
                raise
            raise _BridgeBaseException(error) from None
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
        except _BridgeBaseException as error:
            raise error.error from None
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
        except _BridgeBaseException as error:
            raise error.error from None
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
        allowed_origins: Sequence[str] | None = None,
        max_unknown_outcomes: int = _DEFAULT_MAX_UNKNOWN_OUTCOMES,
    ) -> None:
        if methods is not None and method_factories:
            raise ValueError("Pass either methods or method_factories, not both")
        if (
            isinstance(max_unknown_outcomes, bool)
            or not isinstance(max_unknown_outcomes, int)
            or max_unknown_outcomes < 1
        ):
            raise ValueError("max_unknown_outcomes must be a positive integer")
        self.methods = tuple(methods or ())
        if any(not _is_method(method) for method in self.methods):
            raise TypeError("methods must contain payment Methods")
        self._method_factories = tuple(method_factories)
        self._method_stack: AsyncExitStack | None = None
        self.events = events or EventDispatcher()
        self._allowed = _AllowedOrigins(allowed_origins)
        self._bridge = _AsyncBridge()
        self._state_changed = threading.Condition()
        self._active_operations = 0
        self._active_paid_operations = 0
        self._scope_key = object()
        self._state = "new"
        self._start_error: BaseException | None = None
        self._deferred_close = False
        self._http_attempt_lock = threading.Lock()
        self._http_challenges: dict[str, _HttpPaymentAttempt] = {}
        self._http_unknown_challenges: dict[str, _HttpPaymentTombstone] = {}
        self._http_unknown_operations: dict[str, _HttpPaymentTombstone] = {}
        self._http_unknown_circuit: _HttpPaymentTombstone | None = None
        self._http_idempotent_operations: dict[str, _HttpPaymentAttempt] = {}
        self._http_active_idempotent_operations: dict[str, int] = {}
        self._max_unknown_outcomes = max_unknown_outcomes

    def _in_method_lifecycle(self) -> bool:
        return _scope_active(self._scope_key, "lifecycle")

    def _in_operation(self) -> bool:
        return _scope_active(self._scope_key, "operation")

    def _in_paid_operation(self) -> bool:
        return _scope_active(self._scope_key, "paid")

    async def _initialize_methods(self) -> None:
        with _runtime_scope(self._scope_key, "lifecycle"), _payment_flow():
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
            with _runtime_scope(self._scope_key, "lifecycle"), _payment_flow():
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
            if self._state != "open" and not self._in_paid_operation():
                raise RuntimeError("PaymentRuntime is closed")
            self._active_operations += 1

        try:
            with _runtime_scope(self._scope_key, "operation"):
                yield
        finally:
            with self._state_changed:
                self._active_operations -= 1
                should_close = (
                    self._deferred_close
                    and self._active_operations == 0
                    and self._active_paid_operations == 0
                )
            if should_close:
                self._finish_close()

    @contextmanager
    def _paid_operation(self):
        if self._in_paid_operation():
            yield
            return

        self.start()
        with self._state_changed:
            if self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
            self._active_paid_operations += 1

        try:
            with _runtime_scope(self._scope_key, "paid"):
                yield
        finally:
            with self._state_changed:
                self._active_paid_operations -= 1
                should_close = (
                    self._deferred_close
                    and self._active_operations == 0
                    and self._active_paid_operations == 0
                )
                self._state_changed.notify_all()
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
            self._clear_payment_state()
            with self._state_changed:
                self._state = "closed"
                self._deferred_close = False
                self._state_changed.notify_all()

    def _clear_payment_state(self) -> None:
        with self._http_attempt_lock:
            for attempt in set(self._http_challenges.values()):
                if attempt.sent:
                    self._mark_http_payment_unknown_locked(
                        attempt,
                        RuntimeError(
                            "PaymentRuntime closed before the paid response outcome was confirmed"
                        ),
                    )
                else:
                    self._remove_http_attempt_locked(attempt)
            self._http_challenges.clear()
            self._http_unknown_challenges.clear()
            self._http_unknown_operations.clear()
            self._http_unknown_circuit = None
            self._http_idempotent_operations.clear()
            self._http_active_idempotent_operations.clear()

    def reset_unknown_outcomes(self, *, reconciled: bool) -> None:
        """Reopen payments after every retained unknown outcome was reconciled.

        This clears runtime-level tombstones and any fail-closed circuits.
        Existing request objects keep their own tombstone markers and must not
        be reused.
        """
        if not reconciled:
            raise ValueError("Unknown payment outcomes must be externally reconciled before reset")
        with self._http_attempt_lock:
            self._http_unknown_challenges.clear()
            self._http_unknown_operations.clear()
            self._http_unknown_circuit = None

    def payment_transport(self, inner: httpx.AsyncBaseTransport | None = None) -> PaymentTransport:
        """Create an httpx transport using this runtime's payment methods."""
        from mpp.client import PaymentTransport

        return PaymentTransport(
            inner=inner,
            runtime=self,
        )

    def sync_payment_transport(
        self,
        inner: httpx.BaseTransport | None = None,
    ) -> SyncPaymentTransport:
        """Create a synchronous httpx transport using this runtime."""
        from mpp.client import SyncPaymentTransport

        return SyncPaymentTransport(inner=inner, runtime=self)

    def wrap_client(self, client: httpx.Client) -> httpx.Client:
        """Make one existing HTTPX client payment-aware."""
        if not isinstance(client, httpx.Client):
            raise TypeError("wrap_client requires an httpx.Client")
        if getattr(client, "_mpp_payment_wrapped", False):
            client._mpp_payment_runtime = self  # type: ignore[attr-defined]
            return client
        original_send_single, original_send = _validate_httpx_client(client)

        def send_single(request: httpx.Request) -> httpx.Response:
            runtime = client._mpp_payment_runtime  # type: ignore[attr-defined]
            return runtime.send_httpx_sync(original_send_single, request)

        def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = client._mpp_payment_runtime  # type: ignore[attr-defined]
            with runtime._httpx_operation_scope(request):
                return original_send(request, *args, **kwargs)

        _set_client_attributes(
            client,
            send=send,
            _send_single_request=send_single,
            _mpp_payment_runtime=self,
            _mpp_payment_wrapped=True,
        )
        return client

    def wrap_async_client(self, client: httpx.AsyncClient) -> httpx.AsyncClient:
        """Make one existing HTTPX async client payment-aware."""
        if not isinstance(client, httpx.AsyncClient):
            raise TypeError("wrap_async_client requires an httpx.AsyncClient")
        if getattr(client, "_mpp_payment_wrapped", False):
            client._mpp_payment_runtime = self  # type: ignore[attr-defined]
            return client
        original_send_single, original_send = _validate_httpx_client(client)

        async def send_single(request: httpx.Request) -> httpx.Response:
            runtime = client._mpp_payment_runtime  # type: ignore[attr-defined]
            return await runtime.send_httpx(original_send_single, request)

        async def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = client._mpp_payment_runtime  # type: ignore[attr-defined]
            with runtime._httpx_operation_scope(request):
                return await original_send(request, *args, **kwargs)

        _set_client_attributes(
            client,
            send=send,
            _send_single_request=send_single,
            _mpp_payment_runtime=self,
            _mpp_payment_wrapped=True,
        )
        return client

    async def send_httpx(
        self,
        send: Callable[[httpx.Request], Awaitable[httpx.Response]],
        request: httpx.Request,
    ) -> httpx.Response:
        """Send one HTTPX request with automatic 402 payment handling."""
        with self._httpx_operation_scope(request, reuse=True):
            token = _HTTPX_ADAPTER_RUNTIME.set(id(self))
            try:
                transport = _BoundSendTransport(send)
                response = await transport.handle_async_request(request)
                return await self.payment_transport(inner=transport)._handle_async_response(
                    request,
                    response,
                )
            finally:
                _HTTPX_ADAPTER_RUNTIME.reset(token)

    def send_httpx_sync(
        self,
        send: Callable[[httpx.Request], httpx.Response],
        request: httpx.Request,
    ) -> httpx.Response:
        """Send one synchronous HTTPX request with automatic 402 handling."""
        with self._httpx_operation_scope(request, reuse=True):
            token = _HTTPX_ADAPTER_RUNTIME.set(id(self))
            try:
                transport = _BoundSyncSendTransport(send)
                response = transport.handle_request(request)
                return self.sync_payment_transport(inner=transport)._handle_response(
                    request,
                    response,
                )
            finally:
                _HTTPX_ADAPTER_RUNTIME.reset(token)

    def allows_http_payment(self, url: httpx.URL) -> bool:
        """Return whether credentials may be created for an HTTP origin."""
        return self._allowed.http_url(url)

    def _allows_all_http_origins(self) -> bool:
        return self._allowed._allow_all

    def _httpx_adapter_active(self) -> bool:
        return _HTTPX_ADAPTER_RUNTIME.get() == id(self)

    @contextmanager
    def _httpx_operation_scope(
        self,
        request: httpx.Request,
        *,
        reuse: bool = False,
    ):
        operations = _HTTPX_OPERATIONS.get() or {}
        if reuse and (operation := operations.get(id(self))) is not None and operation.active:
            yield operation
            return

        operation_key = _http_idempotency_key(request)
        operation = _HttpxOperation()
        if operation_key is not None:
            with self._http_attempt_lock:
                self._http_active_idempotent_operations[operation_key] = (
                    self._http_active_idempotent_operations.get(operation_key, 0) + 1
                )
        token = _HTTPX_OPERATIONS.set({**operations, id(self): operation})
        try:
            yield operation
        except BaseException as cause:
            self._complete_httpx_operation(operation, cause)
            raise
        else:
            self._complete_httpx_operation(operation)
        finally:
            operation.active = False
            if operation_key is not None:
                with self._http_attempt_lock:
                    remaining = self._http_active_idempotent_operations.get(operation_key, 0) - 1
                    if remaining > 0:
                        self._http_active_idempotent_operations[operation_key] = remaining
                    else:
                        self._http_active_idempotent_operations.pop(operation_key, None)
                    if attempt := self._http_idempotent_operations.get(operation_key):
                        self._remove_completed_http_attempt_locked(attempt)
            _HTTPX_OPERATIONS.reset(token)

    def _complete_httpx_operation(
        self,
        operation: _HttpxOperation,
        cause: BaseException | None = None,
    ) -> None:
        for attempt in tuple(operation.attempts):
            if cause is not None:
                if attempt.sent:
                    self._mark_http_payment_unknown(attempt, cause)
                else:
                    self._discard_http_payment(attempt)
            else:
                self._mark_http_send_complete(attempt)

    def _begin_http_payment(
        self,
        challenge: Challenge,
        request: httpx.Request,
    ) -> _HttpPaymentAttempt:
        from mpp.errors import PaymentOutcomeUnknownError

        challenge_key, operation_key, idempotent = _http_attempt_keys(challenge, request)
        operation = (_HTTPX_OPERATIONS.get() or {}).get(id(self))
        marker = request.extensions.get(_HTTP_PAYMENT_ATTEMPT_EXTENSION)
        if isinstance(marker, _HttpPaymentTombstone):
            raise PaymentOutcomeUnknownError(
                marker.challenge,
                marker.cause,
                credential=marker.credential,
                request=marker.request,
            )
        if isinstance(marker, _HttpPaymentAttempt) and marker.runtime is not self:
            cause = marker.cause or RuntimeError(
                "A payment credential was already sent for this logical HTTPX request"
            )
            tombstone = marker.runtime._mark_http_payment_unknown(marker, cause)
            raise PaymentOutcomeUnknownError(
                tombstone.challenge,
                tombstone.cause,
                credential=tombstone.credential,
                request=tombstone.request,
            )
        with self._http_attempt_lock:
            if circuit := self._http_unknown_circuit:
                raise PaymentOutcomeUnknownError(
                    circuit.challenge,
                    circuit.cause,
                    credential=circuit.credential,
                    request=circuit.request,
                )
            existing: _HttpPaymentAttempt | _HttpPaymentTombstone | None = None
            if isinstance(marker, _HttpPaymentAttempt):
                cause = marker.cause or RuntimeError(
                    "A payment credential was already sent for this logical HTTPX request"
                )
                existing = self._mark_http_payment_unknown_locked(marker, cause)
            elif operation is not None and operation.payment_sent:
                sent = next(
                    (attempt for attempt in operation.attempts if attempt.sent),
                    None,
                )
                if sent is not None:
                    cause = sent.cause or RuntimeError(
                        "A payment credential was already sent for this logical HTTPX request"
                    )
                    existing = self._mark_http_payment_unknown_locked(sent, cause)
            if existing is None:
                existing = self._http_challenges.get(challenge_key)
            if existing is None:
                existing = self._http_unknown_challenges.get(challenge_key)
            if existing is None and idempotent:
                existing = self._http_idempotent_operations.get(operation_key)
            if existing is None:
                existing = self._http_unknown_operations.get(operation_key)
            if existing is not None:
                cause = existing.cause or RuntimeError(
                    "A matching payment attempt is already in progress"
                )
                raise PaymentOutcomeUnknownError(
                    existing.challenge,
                    cause,
                    credential=existing.credential,
                    request=existing.request,
                )
            attempt = _HttpPaymentAttempt(
                runtime=self,
                challenge_key=challenge_key,
                operation_key=operation_key,
                challenge=challenge,
                request=request,
                operation=operation,
                idempotent=idempotent,
            )
            self._http_challenges[challenge_key] = attempt
            if idempotent:
                self._http_idempotent_operations[operation_key] = attempt
            if operation is not None:
                operation.attempts.append(attempt)
            return attempt

    def _set_http_payment_credential(
        self,
        attempt: _HttpPaymentAttempt,
        credential: Credential,
    ) -> None:
        with self._http_attempt_lock:
            attempt.credential = credential

    def _mark_http_payment_sent(
        self,
        attempt: _HttpPaymentAttempt,
        retry_request: httpx.Request,
    ) -> None:
        from mpp.errors import PaymentOutcomeUnknownError

        with self._http_attempt_lock:
            if circuit := self._http_unknown_circuit:
                self._remove_http_attempt_locked(attempt)
                raise PaymentOutcomeUnknownError(
                    circuit.challenge,
                    circuit.cause,
                    credential=circuit.credential,
                    request=circuit.request,
                )
            existing = self._http_unknown_operations.get(attempt.operation_key)
            if existing is not None and existing is not attempt:
                self._remove_http_attempt_locked(attempt)
                raise PaymentOutcomeUnknownError(
                    existing.challenge,
                    existing.cause or RuntimeError("A matching payment outcome is already unknown"),
                    credential=existing.credential,
                    request=existing.request,
                )
            attempt.sent = True
            attempt.retry_request = retry_request
            if attempt.operation is not None:
                attempt.operation.payment_sent = True
            attempt.request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = attempt
            retry_request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = attempt

    def _mark_http_payment_unknown(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> _HttpPaymentTombstone:
        with self._http_attempt_lock:
            return self._mark_http_payment_unknown_locked(attempt, cause)

    def _mark_http_payment_unknown_locked(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> _HttpPaymentTombstone:
        compact_cause = _compact_cause(cause)
        attempt.cause = compact_cause
        tombstone = _HttpPaymentTombstone(
            challenge=attempt.challenge,
            credential=attempt.credential,
            cause=compact_cause,
            request=_compact_request(attempt.request),
        )
        self._remove_http_attempt_locked(attempt)
        self._set_http_request_markers(attempt, tombstone)
        if self._http_unknown_circuit is not None:
            return tombstone

        if attempt.operation_key in self._http_unknown_operations:
            if attempt.challenge_key not in self._http_unknown_challenges:
                if len(self._http_unknown_challenges) >= self._max_unknown_outcomes:
                    self._http_unknown_circuit = tombstone
                else:
                    self._http_unknown_challenges[attempt.challenge_key] = tombstone
            return tombstone

        if (
            len(self._http_unknown_challenges) >= self._max_unknown_outcomes
            or len(self._http_unknown_operations) >= self._max_unknown_outcomes
        ):
            self._http_unknown_circuit = tombstone
            return tombstone
        self._http_unknown_challenges[attempt.challenge_key] = tombstone
        self._http_unknown_operations[attempt.operation_key] = tombstone
        return tombstone

    def _mark_http_response_body_complete(self, attempt: _HttpPaymentAttempt) -> None:
        with self._http_attempt_lock:
            attempt.body_complete = True
            self._remove_completed_http_attempt_locked(attempt)

    def _mark_http_send_complete(self, attempt: _HttpPaymentAttempt) -> None:
        with self._http_attempt_lock:
            attempt.send_complete = True
            self._remove_completed_http_attempt_locked(attempt)

    def _discard_http_payment(self, attempt: _HttpPaymentAttempt) -> None:
        with self._http_attempt_lock:
            if not attempt.sent:
                self._remove_http_attempt_locked(attempt)

    def _remove_completed_http_attempt_locked(self, attempt: _HttpPaymentAttempt) -> None:
        if attempt.cause is not None or not attempt.body_complete or not attempt.send_complete:
            return
        active = self._http_active_idempotent_operations.get(attempt.operation_key, 0)
        if attempt.operation is not None and attempt.operation.active:
            active -= 1
        if not attempt.idempotent or active <= 0:
            self._remove_http_attempt_locked(attempt)

    def _remove_http_attempt_locked(self, attempt: _HttpPaymentAttempt) -> None:
        for request in (attempt.request, attempt.retry_request):
            if (
                request is not None
                and request.extensions.get(_HTTP_PAYMENT_ATTEMPT_EXTENSION) is attempt
            ):
                request.extensions.pop(_HTTP_PAYMENT_ATTEMPT_EXTENSION, None)
        if self._http_challenges.get(attempt.challenge_key) is attempt:
            self._http_challenges.pop(attempt.challenge_key, None)
        if (
            attempt.idempotent
            and self._http_idempotent_operations.get(attempt.operation_key) is attempt
        ):
            self._http_idempotent_operations.pop(attempt.operation_key, None)

    @staticmethod
    def _set_http_request_markers(
        attempt: _HttpPaymentAttempt,
        tombstone: _HttpPaymentTombstone,
    ) -> None:
        attempt.request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = tombstone
        if attempt.retry_request is not None:
            attempt.retry_request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = tombstone

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
            if not self._in_operation() and not self._in_paid_operation():
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
            if not self._in_operation() and not self._in_paid_operation():
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
        with _payment_flow():
            payload = {
                **(event_payload or {}),
                "challenge": challenge,
                "method": method,
            }
            payload.setdefault("challenges", [challenge])
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
        return await self._run_async(self._emit_event(name, payload))

    async def _emit_event(
        self,
        name: str,
        payload: EventPayload,
        *,
        first_result: bool = False,
    ) -> Any:
        with _payment_flow():
            return await self.events.emit(name, payload, first_result=first_result)

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        """Synchronously emit an event on the runtime-owned loop."""
        return self._run_sync(self._emit_event(name, payload))

    def close(self) -> None:
        """Close method resources and the owned event loop."""
        active_here = self._in_operation() or self._in_paid_operation()
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
            while self._active_paid_operations:
                self._state_changed.wait()
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


class _CallerLoopRuntime(PaymentRuntime):
    """Compatibility runtime for legacy async ``methods=`` entry points."""

    def start(self) -> Self:
        with self._state_changed:
            if self._state == "new":
                self._state = "open"
            elif self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
        return self

    async def astart(self) -> Self:
        return self.start()

    def _run_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        coroutine.close()
        raise RuntimeError("Caller-loop payment runtime cannot be used synchronously")

    async def _run_async(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        entered = False
        try:
            if not self._in_operation() and not self._in_paid_operation():
                self.start()
            with self._runtime_operation():
                entered = True
                return await coroutine
        except BaseException:
            if not entered:
                coroutine.close()
            raise


def _http_attempt_keys(
    challenge: Challenge,
    request: httpx.Request,
) -> tuple[str, str, bool]:
    origin = repr(_httpx_origin(request.url))
    challenge_key = _http_attempt_digest("challenge", origin, challenge.id)
    if operation_key := _http_idempotency_key(request):
        idempotent = True
    else:
        idempotent = False
        try:
            body = request.content
        except httpx.RequestNotRead:
            body = b""
        operation_key = _http_attempt_digest(
            "request",
            request.method,
            str(request.url).split("#", 1)[0],
            hashlib.sha256(body).hexdigest(),
        )
    return challenge_key, operation_key, idempotent


def _http_idempotency_key(request: httpx.Request) -> str | None:
    if not (idempotency_key := request.headers.get("idempotency-key")):
        return None
    return _http_attempt_digest(
        "idempotency",
        request.method,
        str(request.url).split("#", 1)[0],
        idempotency_key,
    )


def _http_attempt_digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _compact_cause(cause: BaseException) -> BaseException:
    try:
        compact = type(cause)(str(cause))
    except BaseException:
        compact = RuntimeError(f"{type(cause).__name__}: {cause}")
    compact.__traceback__ = None
    compact.__cause__ = None
    compact.__context__ = None
    return compact


def _compact_request(request: httpx.Request) -> httpx.Request:
    return httpx.Request(request.method, request.url)


def _challenge_is_expired(challenge: Any) -> bool:
    expires_value = getattr(challenge, "expires", None)
    if expires_value is None:
        return False
    if not isinstance(expires_value, str) or not expires_value:
        return True
    try:
        expires = datetime.fromisoformat(expires_value.replace("Z", "+00:00"))
        if expires.tzinfo is None or expires.utcoffset() is None:
            return True
        return expires < datetime.now(UTC)
    except (OverflowError, TypeError, ValueError):
        return True


class _AllowedOrigins:
    def __init__(self, allowed_origins: Sequence[str] | None) -> None:
        self._allow_all = allowed_origins is None
        self._origins = {
            origin for value in allowed_origins or () if (origin := _origin(str(value))) is not None
        }

    def http_url(self, url: httpx.URL) -> bool:
        return self._allow_all or _httpx_origin(url) in self._origins


def _origin(value: str) -> tuple[str, str, int | None] | None:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, TypeError, UnicodeError):
        return None
    if not url.scheme or not url.raw_host:
        return None
    return _httpx_origin(url)


def _httpx_origin(url: httpx.URL) -> tuple[str, str, int | None]:
    scheme = url.scheme.casefold()
    port = url.port
    if port == {"http": 80, "https": 443}.get(scheme):
        port = None
    return scheme, url.raw_host.decode("ascii").casefold(), port


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
