"""Scoped HTTPX instrumentation for payment-aware Python harnesses."""

from __future__ import annotations

import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from importlib.metadata import version
from types import MethodType
from typing import Any, Literal

import httpx

from mpp.runtime import PaymentRuntime, payment_flow_active

HTTPX_INSTRUMENTATION_VERSIONS = ">=0.27,<0.29"
_SUPPORTED_HTTPX_MINORS = {(0, 27), (0, 28)}
_PAYMENT_INTERNAL_THREAD = "_mpp_payment_internal_thread"


class HttpxCompatibilityError(RuntimeError):
    """The installed HTTPX version cannot be safely instrumented."""


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
# Executor workers may be marked when they are created during payment handling.
# Override that marker per submitted task so pooled threads remain reusable.
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
        """Disable this binding and safely restore unused HTTPX patches."""
        binding = self._binding
        with _state.lock:
            if not binding.active:
                return
            binding.active = False
            _state.bindings = [item for item in _state.bindings if item is not binding]
            _restore_httpx_patches()

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

    Bindings are context-local by default. Use ``scope="process"`` only for a
    single-wallet process whose calls run on independent worker threads;
    ambiguous process bindings fail closed.
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
        _install_httpx_patches()
        _state.bindings.append(binding)

    local = _bindings.get()
    _bindings.set((*(() if local is None else local), binding))
    return InstrumentationHandle(runtime=runtime, _binding=binding)


class _InstrumentationState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.bindings: list[_Binding] = []
        self.patches: tuple[_Patch, ...] = ()


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
                return binding.runtime

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


def _httpx_minor(installed: str) -> tuple[int, int]:
    try:
        major, minor, *_ = installed.split(".")
        return int(major), int(minor)
    except ValueError as error:
        raise HttpxCompatibilityError(
            f"Cannot determine HTTPX compatibility from version {installed!r}"
        ) from error


def _validate_method_shape(
    name: str,
    method: Any,
    *,
    parameters: tuple[tuple[str, Any], ...],
    asynchronous: bool,
) -> None:
    if not callable(method):
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not callable")
    try:
        actual = tuple(
            (parameter.name, parameter.kind)
            for parameter in inspect.signature(method).parameters.values()
        )
    except (TypeError, ValueError) as error:
        raise HttpxCompatibilityError(
            f"HTTPX adapter seam {name} has no inspectable signature"
        ) from error
    if actual != parameters:
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} has an unsupported signature")
    if inspect.iscoroutinefunction(method) is not asynchronous:
        shape = "async" if asynchronous else "sync"
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not {shape}")


def _validate_httpx_compatibility() -> tuple[Any, Any, Any, Any]:
    """Return compatible private/public HTTPX seams or fail before patching."""
    installed = version("httpx")
    if _httpx_minor(installed) not in _SUPPORTED_HTTPX_MINORS:
        raise HttpxCompatibilityError(
            f"HTTPX {installed} is unsupported by pympp HTTPX instrumentation "
            f"(supported: {HTTPX_INSTRUMENTATION_VERSIONS}). "
            "Use PaymentTransport explicitly or upgrade pympp."
        )
    seams = []
    for owner, name in (
        (httpx.Client, "_send_single_request"),
        (httpx.AsyncClient, "_send_single_request"),
        (httpx.Client, "send"),
        (httpx.AsyncClient, "send"),
    ):
        try:
            seams.append(inspect.getattr_static(owner, name))
        except AttributeError as error:
            raise HttpxCompatibilityError(
                f"HTTPX adapter seam {owner.__name__}.{name} is missing"
            ) from error
    sync_send_single, async_send_single, sync_send, async_send = seams

    positional = inspect.Parameter.POSITIONAL_OR_KEYWORD
    keyword_only = inspect.Parameter.KEYWORD_ONLY
    private_parameters = (("self", positional), ("request", positional))
    public_parameters = (
        ("self", positional),
        ("request", positional),
        ("stream", keyword_only),
        ("auth", keyword_only),
        ("follow_redirects", keyword_only),
    )
    for name, method, parameters, asynchronous in (
        ("Client._send_single_request", sync_send_single, private_parameters, False),
        ("AsyncClient._send_single_request", async_send_single, private_parameters, True),
        ("Client.send", sync_send, public_parameters, False),
        ("AsyncClient.send", async_send, public_parameters, True),
    ):
        _validate_method_shape(
            name,
            method,
            parameters=parameters,
            asynchronous=asynchronous,
        )
    return sync_send_single, async_send_single, sync_send, async_send


def _patch_is_installed(patch: _Patch) -> bool:
    try:
        return inspect.getattr_static(patch.owner, patch.name) is patch.replacement
    except AttributeError:
        return False


def _install_httpx_patches() -> None:
    if _state.patches:
        if not all(map(_patch_is_installed, _state.patches)):
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
    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit

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
        _Patch(threading.Thread, "start", original_thread_start, thread_start),
        _Patch(
            ThreadPoolExecutor,
            "submit",
            original_executor_submit,
            executor_submit,
        ),
    )
    installed: list[_Patch] = []
    try:
        for patch in patches:
            setattr(patch.owner, patch.name, patch.replacement)
            installed.append(patch)
    except BaseException:
        for patch in reversed(installed):
            if _patch_is_installed(patch):
                setattr(patch.owner, patch.name, patch.original)
        raise

    _state.patches = patches


def _restore_httpx_patches() -> None:
    if any(binding.active for binding in _state.bindings):
        return
    for patch in reversed(_state.patches):
        if _patch_is_installed(patch):
            setattr(patch.owner, patch.name, patch.original)
    _state.patches = ()
