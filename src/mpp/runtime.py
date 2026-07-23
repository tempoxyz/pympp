"""Shared payment runtime for HTTP and MCP clients."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import threading
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack, contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, Self, TypeVar, runtime_checkable

import httpx

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    PAYMENT_FAILED,
    PAYMENT_RESPONSE,
    EventDispatcher,
    EventPayload,
)

if TYPE_CHECKING:
    from mpp.client import PaymentTransport, SyncPaymentTransport

_T = TypeVar("_T")
_PAYMENT_FLOW_ACTIVE: ContextVar[bool] = ContextVar("mpp_payment_flow_active", default=False)


@dataclass(slots=True)
class _PaidLease:
    active: bool = True


@dataclass(slots=True)
class _RuntimeLease:
    active: bool = True


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


@dataclass(slots=True)
class _HttpxOperation:
    attempts: list[_HttpPaymentAttempt] = field(default_factory=list)
    payment_sent: bool = False
    active: bool = True


@dataclass(eq=False, slots=True)
class _McpPaymentAttempt:
    challenge_key: str
    operation_key: str
    challenge: Any
    endpoint: Any
    credential: Credential | None = None
    cause: BaseException | None = None
    sent: bool = False


_PAID_LEASES: ContextVar[dict[int, _PaidLease] | None] = ContextVar("mpp_paid_leases", default=None)
_RUNTIME_LEASES: ContextVar[dict[int, _RuntimeLease] | None] = ContextVar(
    "mpp_runtime_leases",
    default=None,
)
_HTTPX_OPERATIONS: ContextVar[dict[int, _HttpxOperation] | None] = ContextVar(
    "mpp_httpx_operations",
    default=None,
)
_HTTPX_ADAPTER_RUNTIME: ContextVar[int | None] = ContextVar(
    "mpp_httpx_adapter_runtime",
    default=None,
)
_HTTP_PAYMENT_ATTEMPT_EXTENSION = "mpp.payment_attempt"


def payment_flow_active() -> bool:
    """Return whether the current context is handling a payment flow."""
    return _PAYMENT_FLOW_ACTIVE.get()


async def _wait_for_task(task: asyncio.Task[_T]) -> _T:
    """Wait for task completion while preserving an already-raised cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


@runtime_checkable
class Method(Protocol):
    """Payment method interface for client-side credential creation."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge."""
        ...


MethodFactory = Callable[
    [],
    Method | Awaitable[Method] | AbstractAsyncContextManager[Method],
]


class _BoundSendTransport(httpx.AsyncBaseTransport):
    def __init__(self, send: Any) -> None:
        self._send = send

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._send(request)

    async def aclose(self) -> None:
        return None


class _BoundSyncSendTransport(httpx.BaseTransport):
    def __init__(self, send: Any) -> None:
        self._send = send

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._send(request)

    def close(self) -> None:
        return None


class _AsyncBridge:
    """Own one lazy event loop for payment-method calls."""

    def __init__(self) -> None:
        self._closed = False
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._start_error: BaseException | None = None
        self._thread: threading.Thread | None = None

    def _submit(self, coroutine: Coroutine[Any, Any, _T]) -> Any:
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="pympp-payment-runtime",
                    daemon=True,
                )
                self._thread.start()
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
        vars(threading.current_thread())["_mpp_payment_internal_thread"] = True
        try:
            loop = asyncio.new_event_loop()
        except BaseException as error:
            self._start_error = error
            self._ready.set()
            self._stopped.set()
            return
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()
            self._stopped.set()

    def run(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run an async payment operation from synchronous code."""
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
        """Run an async payment operation on the runtime loop."""
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
            return
        if thread is None:
            self._stopped.set()
            return
        if self._loop is None:
            self._ready.wait()
        loop = self._loop
        if loop is None:
            thread.join()
            return
        if threading.current_thread() is thread:

            async def shutdown() -> None:
                await self._cancel_pending()
                loop.stop()

            loop.create_task(shutdown())
            return
        if thread.is_alive():
            future = asyncio.run_coroutine_threadsafe(self._cancel_pending(), loop)
            future.result()
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        thread.join()


class PaymentRuntime:
    """Payment runtime that owns one loop for method and lifecycle state.

    Direct ``methods`` are borrowed and must be safe to use on the owned loop.
    Use ``method_factories`` for loop-bound methods: factories are called on
    the owned loop, and async context-manager results are exited there when the
    runtime closes.
    """

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        *,
        method_factories: Sequence[MethodFactory] = (),
        events: EventDispatcher | None = None,
        allowed_origins: Sequence[str] | None = None,
    ) -> None:
        if methods is not None and method_factories:
            raise ValueError("Pass either methods or method_factories, not both")
        self.methods = tuple(methods or ())
        self._method_factories = tuple(method_factories)
        self._method_stack: AsyncExitStack | None = None
        self.events = events or EventDispatcher()
        self._allowed = _AllowedOrigins(allowed_origins)
        self._bridge = _AsyncBridge()
        self._lifecycle = threading.Condition()
        self._active_paid_operations = 0
        self._active_runtime_operations = 0
        self._state: str = "new"
        self._start_error: BaseException | None = None
        self._finalizing = False
        self._deferred_close = False
        self._http_attempt_lock = threading.Lock()
        self._http_challenges: dict[str, _HttpPaymentAttempt] = {}
        self._http_unknown_operations: dict[str, _HttpPaymentAttempt] = {}
        self._http_idempotent_operations: dict[str, _HttpPaymentAttempt] = {}
        self._mcp_attempt_lock = threading.Lock()
        self._mcp_challenges: dict[str, _McpPaymentAttempt] = {}
        self._mcp_unknown_operations: dict[str, _McpPaymentAttempt] = {}

    async def _initialize_methods(self) -> None:
        stack = AsyncExitStack()
        methods: list[Method] = []
        token = _PAYMENT_FLOW_ACTIVE.set(True)
        try:
            for factory in self._method_factories:
                value: Any = factory()
                if inspect.isawaitable(value):
                    value = await value
                if hasattr(value, "__aenter__") and hasattr(value, "__aexit__"):
                    value = await stack.enter_async_context(value)
                if not isinstance(value, Method):
                    raise TypeError("Method factory must return a payment Method")
                methods.append(value)
        except BaseException:
            await stack.aclose()
            raise
        finally:
            _PAYMENT_FLOW_ACTIVE.reset(token)
        if self._method_factories:
            self.methods = tuple(methods)
        self._method_stack = stack

    async def _teardown_methods(self) -> None:
        stack, self._method_stack = self._method_stack, None
        if stack is not None:
            token = _PAYMENT_FLOW_ACTIVE.set(True)
            try:
                await stack.aclose()
            finally:
                _PAYMENT_FLOW_ACTIVE.reset(token)

    def start(self) -> Self:
        """Start the owned loop and initialize method factories once."""
        with self._lifecycle:
            while self._state == "starting":
                if payment_flow_active():
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
            self._bridge.close()
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
            close = asyncio.create_task(self.aclose())
            await _wait_for_task(close)
            raise

    async def __aexit__(self, *_args: Any) -> None:
        close = asyncio.create_task(self.aclose())
        try:
            await asyncio.shield(close)
        except asyncio.CancelledError:
            await _wait_for_task(close)
            raise

    @contextmanager
    def _paid_operation(self):
        key = id(self)
        leases = _PAID_LEASES.get() or {}
        if (lease := leases.get(key)) is not None and lease.active:
            yield
            return

        self.start()
        with self._lifecycle:
            if self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
            self._active_paid_operations += 1
        lease = _PaidLease()
        token = _PAID_LEASES.set({**leases, key: lease})
        try:
            yield
        finally:
            lease.active = False
            _PAID_LEASES.reset(token)
            with self._lifecycle:
                self._active_paid_operations -= 1
                should_close = self._state == "closing" and self._active_paid_operations == 0
                if self._active_paid_operations == 0:
                    self._lifecycle.notify_all()
            if should_close:
                self._finish_close()

    @contextmanager
    def _runtime_operation(self):
        key = id(self)
        leases = _RUNTIME_LEASES.get() or {}
        if (lease := leases.get(key)) is not None and lease.active:
            yield
            return

        paid_here = self._has_active_paid_lease()
        if not paid_here:
            self.start()
        with self._lifecycle:
            if self._state != "open" and not paid_here:
                raise RuntimeError("PaymentRuntime is closed")
            self._active_runtime_operations += 1
        lease = _RuntimeLease()
        token = _RUNTIME_LEASES.set({**leases, key: lease})
        try:
            yield
        finally:
            lease.active = False
            _RUNTIME_LEASES.reset(token)
            with self._lifecycle:
                self._active_runtime_operations -= 1
                should_close = (
                    self._deferred_close
                    and self._active_runtime_operations == 0
                    and self._active_paid_operations == 0
                )
                if self._active_runtime_operations == 0:
                    self._lifecycle.notify_all()
            if should_close:
                self._finish_close()

    def _ensure_open(self) -> None:
        if self._has_active_runtime_lease() or self._has_active_paid_lease():
            return
        with self._lifecycle:
            if self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")

    def _has_active_paid_lease(self) -> bool:
        lease = (_PAID_LEASES.get() or {}).get(id(self))
        return lease is not None and lease.active

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
        try:
            self._bridge.cancel_pending()
            if self._method_stack is not None:
                self._bridge.run(self._teardown_methods())
        except BaseException as cause:
            error = cause
        finally:
            self._bridge.close()
            with self._lifecycle:
                self._state = "closed"
                self._finalizing = False
                self._lifecycle.notify_all()
        if error is not None:
            raise error

    def payment_transport(self, inner: httpx.AsyncBaseTransport | None = None) -> PaymentTransport:
        """Create an httpx transport using this runtime's payment methods."""
        from mpp.client import PaymentTransport

        return PaymentTransport(
            inner=inner,
            runtime=self,
        )

    def sync_payment_transport(
        self, inner: httpx.BaseTransport | None = None
    ) -> SyncPaymentTransport:
        """Create a synchronous httpx transport using this runtime."""
        from mpp.client import SyncPaymentTransport

        return SyncPaymentTransport(inner=inner, runtime=self)

    def wrap_client(self, client: httpx.Client) -> httpx.Client:
        """Make one existing Client payment-aware without global instrumentation."""
        from mpp.instrumentation import _validate_httpx_compatibility

        _validate_httpx_compatibility()
        client._mpp_payment_runtime = self  # type: ignore[attr-defined]
        if getattr(client, "_mpp_payment_wrapped", False):
            return client

        original_send_single = client._send_single_request
        original_send = client.send

        def send_single(request: httpx.Request) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            return runtime.send_httpx_sync(original_send_single, request)

        def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            with runtime._httpx_operation_scope(request):
                return original_send(request, *args, **kwargs)

        client._mpp_payment_wrapped = True  # type: ignore[attr-defined]
        client._send_single_request = send_single  # type: ignore[method-assign]
        client.send = send  # type: ignore[method-assign]
        return client

    def wrap_async_client(self, client: httpx.AsyncClient) -> httpx.AsyncClient:
        """Make one existing AsyncClient payment-aware without global instrumentation."""
        from mpp.instrumentation import _validate_httpx_compatibility

        _validate_httpx_compatibility()
        client._mpp_payment_runtime = self  # type: ignore[attr-defined]
        if getattr(client, "_mpp_payment_wrapped", False):
            return client

        original_send_single = client._send_single_request
        original_send = client.send

        async def send_single(request: httpx.Request) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            return await runtime.send_httpx(original_send_single, request)

        async def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            with runtime._httpx_operation_scope(request):
                return await original_send(request, *args, **kwargs)

        client._mpp_payment_wrapped = True  # type: ignore[attr-defined]
        client._send_single_request = send_single  # type: ignore[method-assign]
        client.send = send  # type: ignore[method-assign]
        return client

    async def send_httpx(
        self,
        send: Any,
        request: httpx.Request,
    ) -> httpx.Response:
        """Send one httpx request with automatic 402 payment handling."""
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
        send: Any,
        request: httpx.Request,
    ) -> httpx.Response:
        """Send one sync httpx request with automatic 402 payment handling."""
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

    async def call_mcp_tool(
        self,
        call_tool: Any,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call an MCP tool with automatic payment handling, preserving result type."""
        from mpp.errors import PaymentOutcomeUnknownError
        from mpp.extensions.mcp.client import (
            _extract_challenges,
            _extract_result_challenges,
            _is_payment_required_error,
            _is_payment_required_result,
        )
        from mpp.extensions.mcp.types import MCPCredential

        try:
            result = await call_tool(name, arguments, *args, **kwargs)
        except Exception as error:
            if not _is_payment_required_error(error):
                raise
            challenges = _extract_challenges(error)
            cause: Any = error
        else:
            challenges = _extract_result_challenges(result)
            if not challenges and not _is_payment_required_result(result):
                return result
            cause = result

        allowed_challenges = [
            challenge for challenge in challenges if self._allowed.mcp_realm(challenge.realm)
        ]
        if not allowed_challenges:
            error = ValueError(
                "Server returned malformed payment challenges or disallowed payment origins"
            )
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": None,
                    "challenges": [],
                    "credential": None,
                    "error": error,
                    "method": None,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            if isinstance(cause, Exception):
                raise error from cause
            raise error

        await self.astart()
        core_challenges = [item.to_core() for item in allowed_challenges]
        core_challenge = None
        method = None
        attempt = None
        try:
            challenge, method = self.match_challenge(allowed_challenges)
            core_challenge = challenge.to_core()
            if _challenge_is_expired(challenge):
                raise ValueError(f"Challenge expired at {challenge.expires}")
            attempt = self._begin_mcp_payment(challenge, call_tool, name, arguments)
            core_credential = await self.create_credential(
                core_challenge,
                method,
                event_payload={
                    "challenges": core_challenges,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            mcp_credential = MCPCredential.from_core(core_credential, challenge)
            self._set_mcp_payment_credential(attempt, core_credential)
        except BaseException as error:
            if attempt is not None:
                self._discard_mcp_payment(attempt)
            if not isinstance(error, Exception):
                raise
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": core_challenge,
                    "challenges": core_challenges,
                    "credential": getattr(error, "credential", None),
                    "error": error,
                    "method": method,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            raise

        assert attempt is not None
        try:
            retry_kwargs = dict(kwargs)
            retry_meta = dict(retry_kwargs.get("meta") or {})
            retry_meta.update(mcp_credential.to_meta())
            retry_kwargs["meta"] = retry_meta
        except BaseException as error:
            self._discard_mcp_payment(attempt)
            if not isinstance(error, Exception):
                raise
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": core_challenge,
                    "challenges": core_challenges,
                    "credential": core_credential,
                    "error": error,
                    "method": method,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            raise

        with self._mcp_paid_operation(attempt):
            self._mark_mcp_payment_sent(attempt)
            try:
                payment_response = await call_tool(name, arguments, *args, **retry_kwargs)
            except BaseException as error:
                self._mark_mcp_payment_unknown(attempt, error)
                outcome_error = PaymentOutcomeUnknownError(
                    challenge,
                    error,
                    credential=core_credential,
                )
                payload = {
                    "challenge": core_challenge,
                    "challenges": core_challenges,
                    "credential": core_credential,
                    "error": outcome_error,
                    "method": method,
                    "response": cause,
                    "protocol": "mcp",
                }
                if not isinstance(error, Exception):
                    try:
                        await self.emit_event(PAYMENT_FAILED, payload)
                    except BaseException:
                        pass
                    raise
                await self.emit_event(PAYMENT_FAILED, payload)
                raise outcome_error from error

            if _is_payment_required_result(payment_response):
                cause_error = RuntimeError(
                    "Server returned another payment challenge after receiving a credential"
                )
                self._mark_mcp_payment_unknown(attempt, cause_error)
                outcome_error = PaymentOutcomeUnknownError(
                    challenge,
                    cause_error,
                    credential=core_credential,
                )
                await self.emit_event(
                    PAYMENT_FAILED,
                    {
                        "challenge": core_challenge,
                        "challenges": core_challenges,
                        "credential": core_credential,
                        "error": outcome_error,
                        "method": method,
                        "response": payment_response,
                        "protocol": "mcp",
                    },
                )
                raise outcome_error from cause_error

            try:
                await self.emit_event(
                    PAYMENT_RESPONSE,
                    {
                        "challenge": core_challenge,
                        "challenges": core_challenges,
                        "credential": core_credential,
                        "method": method,
                        "response": payment_response,
                        "protocol": "mcp",
                    },
                )
            except BaseException as error:
                self._mark_mcp_payment_unknown(attempt, error)
                raise
            self._complete_mcp_payment(attempt)
            return payment_response

    @contextmanager
    def _mcp_paid_operation(self, attempt: _McpPaymentAttempt):
        try:
            with self._paid_operation():
                yield
        except BaseException:
            if not attempt.sent:
                self._discard_mcp_payment(attempt)
            raise

    def _begin_mcp_payment(
        self,
        challenge: Any,
        call_tool: Any,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> _McpPaymentAttempt:
        from mpp.errors import PaymentOutcomeUnknownError

        endpoint = getattr(call_tool, "__self__", None)
        if endpoint is None:
            endpoint = call_tool
        challenge_key, operation_key = _mcp_attempt_keys(
            challenge,
            endpoint,
            name,
            arguments,
        )
        with self._mcp_attempt_lock:
            existing = self._mcp_challenges.get(challenge_key)
            if existing is None:
                existing = self._mcp_unknown_operations.get(operation_key)
            if existing is not None:
                cause = existing.cause or RuntimeError(
                    "A matching MCP payment attempt is already in progress"
                )
                raise PaymentOutcomeUnknownError(
                    existing.challenge,
                    cause,
                    credential=existing.credential,
                )
            attempt = _McpPaymentAttempt(
                challenge_key=challenge_key,
                operation_key=operation_key,
                challenge=challenge,
                endpoint=endpoint,
            )
            self._mcp_challenges[challenge_key] = attempt
            return attempt

    def _set_mcp_payment_credential(
        self,
        attempt: _McpPaymentAttempt,
        credential: Credential,
    ) -> None:
        with self._mcp_attempt_lock:
            attempt.credential = credential

    def _mark_mcp_payment_sent(self, attempt: _McpPaymentAttempt) -> None:
        with self._mcp_attempt_lock:
            attempt.sent = True

    def _mark_mcp_payment_unknown(
        self,
        attempt: _McpPaymentAttempt,
        cause: BaseException,
    ) -> None:
        with self._mcp_attempt_lock:
            if attempt.cause is None:
                attempt.cause = cause
            self._mcp_challenges[attempt.challenge_key] = attempt
            self._mcp_unknown_operations[attempt.operation_key] = attempt

    def _discard_mcp_payment(self, attempt: _McpPaymentAttempt) -> None:
        with self._mcp_attempt_lock:
            if not attempt.sent and self._mcp_challenges.get(attempt.challenge_key) is attempt:
                self._mcp_challenges.pop(attempt.challenge_key, None)

    def _complete_mcp_payment(self, attempt: _McpPaymentAttempt) -> None:
        with self._mcp_attempt_lock:
            if attempt.cause is None and self._mcp_challenges.get(attempt.challenge_key) is attempt:
                self._mcp_challenges.pop(attempt.challenge_key, None)

    def match_challenge(
        self,
        challenges: list[Any],
        *,
        prefer_method_order: bool = True,
        allow_name_only: bool = False,
    ) -> tuple[Any, Method]:
        """Match payment challenges against configured methods."""
        if prefer_method_order:
            for method in self.methods:
                for challenge in challenges:
                    if challenge.method != method.name:
                        continue
                    if not allow_name_only and challenge.intent not in (
                        _intent_names(method) or {"charge"}
                    ):
                        continue
                    return challenge, method
        else:
            for challenge in challenges:
                for method in self.methods:
                    if challenge.method != method.name:
                        continue
                    if not allow_name_only and challenge.intent not in (
                        _intent_names(method) or {"charge"}
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
        """Create a credential with method state owned by the runtime loop."""
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
        """Run a coroutine on the runtime-owned loop and block for its result."""
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
        """Run a coroutine on the runtime-owned loop without blocking."""
        entered = False
        try:
            if not self._has_active_runtime_lease() and not self._has_active_paid_lease():
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
        token = _PAYMENT_FLOW_ACTIVE.set(True)
        try:
            payload = {
                "challenge": challenge,
                "challenges": [challenge],
                "method": method,
                **(event_payload or {}),
            }
            event_credential = await self._emit_event(
                CHALLENGE_RECEIVED,
                payload,
                first_result=True,
            )
            if isinstance(event_credential, Credential):
                credential = event_credential
            else:
                credential = await method.create_credential(challenge)
            await self._emit_event(
                CREDENTIAL_CREATED,
                {**payload, "credential": credential},
            )
            return credential
        finally:
            _PAYMENT_FLOW_ACTIVE.reset(token)

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        """Emit a lifecycle event on the runtime-owned loop."""
        return await self.run_async(self._emit_event(name, payload))

    async def _emit_event(
        self,
        name: str,
        payload: EventPayload,
        *,
        first_result: bool = False,
    ) -> Any:
        token = _PAYMENT_FLOW_ACTIVE.set(True)
        try:
            return await self.events.emit(name, payload, first_result=first_result)
        finally:
            _PAYMENT_FLOW_ACTIVE.reset(token)

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        """Synchronously emit a lifecycle event on the runtime-owned event loop."""
        return self.run_sync(self._emit_event(name, payload))

    def close(self) -> None:
        """Release the runtime background loop."""
        active_here = self._has_active_paid_lease() or self._has_active_runtime_lease()
        on_runtime_thread = self._bridge.is_current_thread()
        with self._lifecycle:
            while self._state == "starting":
                if payment_flow_active():
                    raise RuntimeError("Cannot close PaymentRuntime while method factories start")
                self._lifecycle.wait()
            if self._state == "closed":
                return
            if self._state == "closing":
                if active_here or self._bridge.is_current_thread():
                    return
                while self._state != "closed":
                    self._lifecycle.wait()
                return
            if on_runtime_thread and not active_here:
                raise RuntimeError("Cannot close PaymentRuntime from unmanaged runtime-loop work")
            self._state = "closing"
            if active_here:
                self._deferred_close = True
                return
            while self._active_paid_operations:
                self._lifecycle.wait()
        self._finish_close()

    async def aclose(self) -> None:
        """Asynchronously release the runtime background loop."""
        if self._bridge.is_current_thread():
            self.close()
            return
        await asyncio.to_thread(self.close)

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

        operation = _HttpxOperation()
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
        if isinstance(marker, _HttpPaymentAttempt) and marker.runtime is not self:
            cause = marker.cause or RuntimeError(
                "A payment credential was already sent for this logical HTTPX request"
            )
            marker.runtime._mark_http_payment_unknown(marker, cause)
            raise PaymentOutcomeUnknownError(
                marker.challenge,
                cause,
                credential=marker.credential,
                request=marker.request,
            )
        with self._http_attempt_lock:
            existing: _HttpPaymentAttempt | None = None
            if isinstance(marker, _HttpPaymentAttempt):
                existing = marker
                cause = marker.cause or RuntimeError(
                    "A payment credential was already sent for this logical HTTPX request"
                )
                self._mark_http_payment_unknown_locked(marker, cause)
            elif operation is not None and operation.payment_sent:
                existing = next(
                    (attempt for attempt in operation.attempts if attempt.sent),
                    None,
                )
                if existing is not None:
                    cause = existing.cause or RuntimeError(
                        "A payment credential was already sent for this logical HTTPX request"
                    )
                    self._mark_http_payment_unknown_locked(existing, cause)
            if existing is None:
                existing = self._http_challenges.get(challenge_key)
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
            if attempt.operation is not None:
                attempt.operation.payment_sent = True
            attempt.request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = attempt
            retry_request.extensions[_HTTP_PAYMENT_ATTEMPT_EXTENSION] = attempt

    def _mark_http_payment_unknown(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> None:
        with self._http_attempt_lock:
            self._mark_http_payment_unknown_locked(attempt, cause)

    def _mark_http_payment_unknown_locked(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> None:
        if attempt.cause is None:
            attempt.cause = cause
        self._http_challenges[attempt.challenge_key] = attempt
        self._http_unknown_operations[attempt.operation_key] = attempt

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
        if attempt.cause is None and attempt.body_complete and attempt.send_complete:
            self._remove_http_attempt_locked(attempt)

    def _remove_http_attempt_locked(self, attempt: _HttpPaymentAttempt) -> None:
        if self._http_challenges.get(attempt.challenge_key) is attempt:
            self._http_challenges.pop(attempt.challenge_key, None)
        if (
            attempt.idempotent
            and self._http_idempotent_operations.get(attempt.operation_key) is attempt
        ):
            self._http_idempotent_operations.pop(attempt.operation_key, None)


class _CallerLoopRuntime(PaymentRuntime):
    """Compatibility runtime for legacy async ``methods=`` entry points."""

    def start(self) -> Self:
        with self._lifecycle:
            if self._state == "new":
                self._state = "open"
            elif self._state != "open":
                raise RuntimeError("PaymentRuntime is closed")
        return self

    async def astart(self) -> Self:
        return self.start()

    def run_sync(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        coroutine.close()
        raise RuntimeError("Caller-loop payment runtime cannot be used synchronously")

    async def run_async(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        entered = False
        try:
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
    if idempotency_key := request.headers.get("idempotency-key"):
        idempotent = True
        operation_key = _http_attempt_digest(
            "idempotency",
            request.method,
            str(request.url).split("#", 1)[0],
            idempotency_key,
        )
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


def _mcp_attempt_keys(
    challenge: Any,
    endpoint: Any,
    name: str,
    arguments: dict[str, Any] | None,
) -> tuple[str, str]:
    realm = (
        repr(origin)
        if (origin := _origin(challenge.realm)) is not None
        else (_bare_host(challenge.realm) or challenge.realm.casefold())
    )
    challenge_key = _http_attempt_digest(
        "mcp-challenge",
        realm,
        challenge.id,
    )
    try:
        arguments_key = json.dumps(
            arguments or {},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        arguments_key = repr(arguments)
    operation_key = _http_attempt_digest(
        "mcp-operation",
        str(id(endpoint)),
        name,
        arguments_key,
    )
    return challenge_key, operation_key


def _http_attempt_digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _intent_names(method: Method) -> set[str] | None:
    intents = getattr(method, "intents", None) or getattr(method, "_intents", None)
    if isinstance(intents, dict):
        return set(intents.keys())
    return None


def _challenge_is_expired(challenge: Any) -> bool:
    if not challenge.expires:
        return False
    try:
        expires = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
        return expires < datetime.now(UTC)
    except (AttributeError, TypeError, ValueError):
        return False


class _AllowedOrigins:
    def __init__(self, allowed_origins: Sequence[str] | None) -> None:
        self._allow_all = allowed_origins is None
        self._origins = set[tuple[str, str, int | None]]()
        self._origin_hosts = set[str]()
        self._realms = set[str]()
        if allowed_origins is None:
            return
        for value in allowed_origins:
            origin = _origin(str(value))
            if origin is not None:
                self._origins.add(origin)
                self._origin_hosts.add(origin[1])
            else:
                realm = str(value)
                self._realms.add(realm.casefold())
                if host := _bare_host(realm):
                    self._realms.add(host)

    def http_url(self, url: httpx.URL) -> bool:
        if self._allow_all:
            return True
        return _httpx_origin(url) in self._origins

    def mcp_realm(self, realm: str) -> bool:
        if not isinstance(realm, str):
            return False
        origin = _origin(realm)
        if "://" in realm and origin is None:
            return False
        if self._allow_all:
            return True
        if origin is not None:
            return origin in self._origins or origin[1] in self._realms
        normalized = realm.casefold()
        host = _bare_host(realm)
        return (
            normalized in self._realms
            or normalized in self._origin_hosts
            or host is not None
            and (host in self._realms or host in self._origin_hosts)
        )


def _origin(value: str) -> tuple[str, str, int | None] | None:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, TypeError, UnicodeError):
        return None
    if not url.scheme or not url.raw_host:
        return None
    return _httpx_origin(url)


def _bare_host(value: str) -> str | None:
    if not value or any(character.isspace() or character in "/@?#%" for character in value):
        return None
    try:
        return httpx.URL(scheme="https", host=value).raw_host.decode("ascii").casefold()
    except (httpx.InvalidURL, TypeError, UnicodeError):
        return None


def _httpx_origin(url: httpx.URL) -> tuple[str, str, int | None]:
    scheme = url.scheme.casefold()
    port = url.port
    if port == {"http": 80, "https": 443}.get(scheme):
        port = None
    return scheme, url.raw_host.decode("ascii").casefold(), port
