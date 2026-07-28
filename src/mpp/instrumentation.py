"""Scoped HTTPX instrumentation for payment-aware Python harnesses."""

from __future__ import annotations

import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from types import MethodType
from typing import Any, Literal

import httpx

from mpp._httpx import (
    HTTPX_ADAPTER_VERSIONS,
    HttpxCompatibilityError,
    _validate_httpx_compatibility,
)
from mpp.runtime import PaymentRuntime, payment_flow_active

HTTPX_INSTRUMENTATION_VERSIONS = HTTPX_ADAPTER_VERSIONS
_PAYMENT_INTERNAL_THREAD = "_mpp_payment_internal_thread"


@dataclass(eq=False, slots=True)
class _Binding:
    runtime: PaymentRuntime
    scope: Literal["context", "process"]
    active: bool = True


@dataclass(frozen=True, slots=True)
class _Patch:
    owner: Any
    name: str
    original: Any
    replacement: Any


_bindings: ContextVar[tuple[_Binding, ...] | None] = ContextVar(
    "mpp_instrumentation_bindings",
    default=None,
)
_httpx_active: ContextVar[bool] = ContextVar("mpp_httpx_instrumentation_active", default=False)
_payment_internal_work: ContextVar[bool | None] = ContextVar(
    "mpp_payment_internal_work",
    default=None,
)


class _PaymentWorkerState(threading.local):
    internal: bool | None = None


_payment_worker_state = _PaymentWorkerState()


@dataclass(slots=True)
class InstrumentationHandle:
    """Handle returned by :func:`instrument`."""

    runtime: PaymentRuntime
    _binding: _Binding

    def disable(self) -> None:
        """Disable this binding and restore unused HTTPX patches."""
        binding = self._binding
        with _state.lock:
            if not binding.active:
                return
            binding.active = False
            _state.bindings = [item for item in _state.bindings if item is not binding]
            _restore_unused_patches()

        local = _bindings.get()
        if local is not None:
            _bindings.set(tuple(item for item in local if item is not binding))

    def __enter__(self) -> InstrumentationHandle:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.disable()


def instrument(
    runtime: PaymentRuntime,
    *,
    scope: Literal["context", "process"] = "context",
    allow_unrestricted: bool = False,
) -> InstrumentationHandle:
    """Make existing and future standard HTTPX clients payment-aware.

    Bindings are context-local by default. Process scope supports harnesses
    whose requests run on independent worker threads; ambiguous process
    bindings fail closed.
    """
    if scope not in ("context", "process"):
        raise ValueError('scope must be "context" or "process"')
    if runtime._allows_all_http_origins() and not allow_unrestricted:
        raise ValueError(
            "Global HTTPX instrumentation requires allowed_origins. "
            "Pass allow_unrestricted=True to explicitly allow payments to any origin."
        )
    binding = _Binding(runtime=runtime, scope=scope)

    with _state.lock:
        had_httpx_patches = bool(_state.httpx_patches)
        _install_httpx_patches()
        try:
            if scope == "process":
                _install_worker_patches()
            _state.bindings.append(binding)
        except BaseException:
            if not had_httpx_patches and not _state.bindings:
                _restore_patches(_state.httpx_patches)
                _state.httpx_patches = ()
            raise

    local = _bindings.get()
    _bindings.set((*(() if local is None else local), binding))
    return InstrumentationHandle(runtime=runtime, _binding=binding)


class _InstrumentationState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.bindings: list[_Binding] = []
        self.httpx_patches: tuple[_Patch, ...] = ()
        self.worker_patches: tuple[_Patch, ...] = ()


_state = _InstrumentationState()


def _internal_payment_work() -> bool:
    if _payment_worker_state.internal is not None:
        return _payment_worker_state.internal
    override = _payment_internal_work.get()
    if override is not None:
        return override
    return bool(getattr(threading.current_thread(), _PAYMENT_INTERNAL_THREAD, False))


def _select_runtime() -> PaymentRuntime | None:
    if _internal_payment_work():
        return None

    local = _bindings.get()
    if local is not None:
        for binding in reversed(local):
            if binding.active:
                if binding.scope == "context":
                    return binding.runtime
                break

    with _state.lock:
        runtimes: list[PaymentRuntime] = []
        for binding in _state.bindings:
            if not binding.active or binding.scope != "process":
                continue
            if all(runtime is not binding.runtime for runtime in runtimes):
                runtimes.append(binding.runtime)
        return runtimes[0] if len(runtimes) == 1 else None


def _runtime_for(client: httpx.Client | httpx.AsyncClient) -> PaymentRuntime | None:
    if (
        getattr(client, "_mpp_payment_wrapped", False)
        or payment_flow_active()
        or _httpx_active.get()
        or _internal_payment_work()
    ):
        return None
    return getattr(client, "_mpp_payment_runtime", None) or _select_runtime()


def _patch_is_installed(patch: _Patch) -> bool:
    try:
        return inspect.getattr_static(patch.owner, patch.name) is patch.replacement
    except AttributeError:
        return False


def _install_httpx_patches() -> None:
    if _state.httpx_patches:
        if not all(
            map(
                _patch_is_installed,
                (*_state.httpx_patches, *_state.worker_patches),
            )
        ):
            raise HttpxCompatibilityError(
                "Active pympp HTTPX instrumentation was replaced by another patch"
            )
        return

    (
        original_sync_send_single,
        original_async_send_single,
        original_sync_send,
        original_async_send,
    ) = _validate_httpx_compatibility()

    @wraps(original_sync_send_single)
    def sync_send_single(
        self: httpx.Client,
        request: httpx.Request,
    ) -> httpx.Response:
        runtime = _runtime_for(self)
        if runtime is None:
            return original_sync_send_single(self, request)
        token = _httpx_active.set(True)
        try:
            return runtime.send_httpx_sync(
                MethodType(original_sync_send_single, self),
                request,
            )
        finally:
            _httpx_active.reset(token)

    @wraps(original_async_send_single)
    async def async_send_single(
        self: httpx.AsyncClient,
        request: httpx.Request,
    ) -> httpx.Response:
        runtime = _runtime_for(self)
        if runtime is None:
            return await original_async_send_single(self, request)
        token = _httpx_active.set(True)
        try:
            return await runtime.send_httpx(
                MethodType(original_async_send_single, self),
                request,
            )
        finally:
            _httpx_active.reset(token)

    @wraps(original_sync_send)
    def sync_send(
        self: httpx.Client,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        runtime = _runtime_for(self)
        if runtime is None:
            return original_sync_send(self, request, *args, **kwargs)
        with runtime._httpx_operation_scope(request):
            return original_sync_send(self, request, *args, **kwargs)

    @wraps(original_async_send)
    async def async_send(
        self: httpx.AsyncClient,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        runtime = _runtime_for(self)
        if runtime is None:
            return await original_async_send(self, request, *args, **kwargs)
        with runtime._httpx_operation_scope(request):
            return await original_async_send(self, request, *args, **kwargs)

    patches = (
        _Patch(
            httpx.Client,
            "_send_single_request",
            original_sync_send_single,
            sync_send_single,
        ),
        _Patch(
            httpx.AsyncClient,
            "_send_single_request",
            original_async_send_single,
            async_send_single,
        ),
        _Patch(httpx.Client, "send", original_sync_send, sync_send),
        _Patch(httpx.AsyncClient, "send", original_async_send, async_send),
    )
    _install_patches(patches)
    _state.httpx_patches = patches


def _install_worker_patches() -> None:
    if _state.worker_patches:
        if not all(map(_patch_is_installed, _state.worker_patches)):
            raise HttpxCompatibilityError(
                "Active pympp worker instrumentation was replaced by another patch"
            )
        return

    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit

    @wraps(original_thread_start)
    def thread_start(self: threading.Thread, *args: Any, **kwargs: Any) -> Any:
        if payment_flow_active() or _internal_payment_work():
            setattr(self, _PAYMENT_INTERNAL_THREAD, True)
        return original_thread_start(self, *args, **kwargs)

    @wraps(original_executor_submit)
    def executor_submit(
        self: ThreadPoolExecutor,
        fn: Any,
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        internal = payment_flow_active() or _internal_payment_work()

        def run_with_payment_context() -> Any:
            previous = _payment_worker_state.internal
            _payment_worker_state.internal = internal
            token = _payment_internal_work.set(internal)
            try:
                return fn(*args, **kwargs)
            finally:
                _payment_internal_work.reset(token)
                _payment_worker_state.internal = previous

        return original_executor_submit(self, run_with_payment_context)

    patches = (
        _Patch(threading.Thread, "start", original_thread_start, thread_start),
        _Patch(
            ThreadPoolExecutor,
            "submit",
            original_executor_submit,
            executor_submit,
        ),
    )
    _install_patches(patches)
    _state.worker_patches = patches


def _install_patches(patches: tuple[_Patch, ...]) -> None:
    installed: list[_Patch] = []
    try:
        for patch in patches:
            setattr(patch.owner, patch.name, patch.replacement)
            installed.append(patch)
    except BaseException:
        _restore_patches(tuple(installed))
        raise


def _restore_patches(patches: tuple[_Patch, ...]) -> None:
    for patch in reversed(patches):
        if _patch_is_installed(patch):
            setattr(patch.owner, patch.name, patch.original)


def _restore_unused_patches() -> None:
    if not any(binding.active and binding.scope == "process" for binding in _state.bindings):
        _restore_patches(_state.worker_patches)
        _state.worker_patches = ()
    if not any(binding.active for binding in _state.bindings):
        _restore_patches(_state.httpx_patches)
        _state.httpx_patches = ()
