"""Scoped instrumentation for payment-aware HTTP and MCP calls."""

from __future__ import annotations

import asyncio
import threading
from contextvars import ContextVar
from dataclasses import dataclass
from types import MethodType
from typing import Any, Literal

import httpx

from mpp.runtime import (
    PaymentRuntime,
    mcp_payment_flow_active,
    payment_flow_active,
)


@dataclass(eq=False, slots=True)
class _Binding:
    runtime: PaymentRuntime
    httpx: bool
    mcp: bool
    install_thread: int
    active: bool = True


_bindings: ContextVar[tuple[_Binding, ...] | None] = ContextVar(
    "mpp_instrumentation_bindings",
    default=None,
)
_httpx_active: ContextVar[bool] = ContextVar("mpp_httpx_instrumentation_active", default=False)
_mcp_active: ContextVar[bool] = ContextVar("mpp_mcp_instrumentation_active", default=False)
_PAYMENT_INTERNAL_THREAD = "_mpp_payment_internal_thread"


@dataclass(slots=True)
class InstrumentationHandle:
    """Handle returned by :func:`instrument`."""

    runtime: PaymentRuntime
    _binding: _Binding

    def disable(self) -> None:
        """Disable this binding and restore unused process patches safely."""
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
    httpx: bool = True,
    mcp: Literal["auto"] | bool = "auto",
) -> InstrumentationHandle:
    """Make common Python HTTP and MCP client boundaries payment-aware.

    Selection is context-local when instrumentation is installed in an async
    task or request context. A bare thread uses the process fallback only when
    exactly one runtime is active, which supports harness worker threads without
    choosing between multiple wallets.
    """
    client_session = _resolve_mcp_client(required=mcp is True) if mcp is not False else None
    binding = _Binding(
        runtime=runtime,
        httpx=httpx,
        mcp=client_session is not None,
        install_thread=threading.get_ident(),
    )

    with _state.lock:
        try:
            if httpx:
                _install_httpx_patches()
            if client_session is not None:
                _install_mcp_patch(client_session)
        except BaseException:
            _restore_unused_patches()
            raise
        _state.bindings.append(binding)

    local = _bindings.get()
    _bindings.set((*(() if local is None else local), binding))
    return InstrumentationHandle(runtime=runtime, _binding=binding)


class _InstrumentationState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.bindings: list[_Binding] = []
        self.original_sync_send: Any | None = None
        self.sync_send_patch: Any | None = None
        self.original_async_send: Any | None = None
        self.async_send_patch: Any | None = None
        self.original_thread_start: Any | None = None
        self.thread_start_patch: Any | None = None
        self.original_mcp_call_tool: Any | None = None
        self.mcp_call_tool_patch: Any | None = None
        self.mcp_client_session: Any | None = None


_state = _InstrumentationState()


def _select_runtime(protocol: Literal["httpx", "mcp"]) -> PaymentRuntime | None:
    local = _bindings.get()
    if local is not None:
        for binding in reversed(local):
            if binding.active and getattr(binding, protocol):
                return binding.runtime
        return None

    if getattr(threading.current_thread(), _PAYMENT_INTERNAL_THREAD, False):
        return None

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        running_loop = False
    else:
        running_loop = True

    with _state.lock:
        candidates = [
            binding for binding in _state.bindings if binding.active and getattr(binding, protocol)
        ]
        # A task that predates a context-local install on the same event-loop
        # thread must not inherit that task's wallet. An independently-owned
        # worker loop (such as Hermes' MCP loop) may use an unambiguous process
        # runtime.
        if running_loop and any(
            binding.install_thread == threading.get_ident() for binding in candidates
        ):
            return None
        runtimes: list[PaymentRuntime] = []
        for binding in candidates:
            if all(runtime is not binding.runtime for runtime in runtimes):
                runtimes.append(binding.runtime)
        return runtimes[0] if len(runtimes) == 1 else None


def _install_httpx_patches() -> None:
    if _state.original_thread_start is None:
        original_thread_start = threading.Thread.start

        def thread_start(self: threading.Thread, *args: Any, **kwargs: Any) -> Any:
            if payment_flow_active() or getattr(
                threading.current_thread(),
                _PAYMENT_INTERNAL_THREAD,
                False,
            ):
                setattr(self, _PAYMENT_INTERNAL_THREAD, True)
            return original_thread_start(self, *args, **kwargs)

        _state.original_thread_start = original_thread_start
        _state.thread_start_patch = thread_start
        threading.Thread.start = thread_start  # type: ignore[method-assign]

    if _state.original_sync_send is None:
        original_sync_send = httpx.Client.send

        def sync_send(
            self: httpx.Client,
            request: httpx.Request,
            *args: Any,
            **kwargs: Any,
        ) -> httpx.Response:
            if (
                getattr(self, "_mpp_payment_wrapped", False)
                or payment_flow_active()
                or _httpx_active.get()
            ):
                return original_sync_send(self, request, *args, **kwargs)
            runtime = getattr(self, "_mpp_payment_runtime", None) or _select_runtime("httpx")
            if runtime is None:
                return original_sync_send(self, request, *args, **kwargs)
            token = _httpx_active.set(True)
            try:
                return runtime.send_httpx_sync(
                    MethodType(original_sync_send, self),
                    request,
                    *args,
                    **kwargs,
                )
            finally:
                _httpx_active.reset(token)

        _state.original_sync_send = original_sync_send
        _state.sync_send_patch = sync_send
        httpx.Client.send = sync_send  # type: ignore[method-assign]

    if _state.original_async_send is None:
        original_async_send = httpx.AsyncClient.send

        async def async_send(
            self: httpx.AsyncClient,
            request: httpx.Request,
            *args: Any,
            **kwargs: Any,
        ) -> httpx.Response:
            if (
                getattr(self, "_mpp_payment_wrapped", False)
                or payment_flow_active()
                or _httpx_active.get()
            ):
                return await original_async_send(self, request, *args, **kwargs)
            runtime = getattr(self, "_mpp_payment_runtime", None) or _select_runtime("httpx")
            if runtime is None:
                return await original_async_send(self, request, *args, **kwargs)
            token = _httpx_active.set(True)
            try:
                return await runtime.send_httpx(
                    MethodType(original_async_send, self),
                    request,
                    *args,
                    **kwargs,
                )
            finally:
                _httpx_active.reset(token)

        _state.original_async_send = original_async_send
        _state.async_send_patch = async_send
        httpx.AsyncClient.send = async_send  # type: ignore[method-assign]


def _resolve_mcp_client(*, required: bool) -> Any | None:
    try:
        from mcp import ClientSession
    except ImportError as error:
        if required:
            raise ImportError(
                'Cannot instrument MCP calls. Install the "mcp" extra: pip install "pympp[mcp]"'
            ) from error
        return None
    _ = ClientSession.call_tool
    return ClientSession


def _install_mcp_patch(client_session: Any) -> None:
    if _state.original_mcp_call_tool is not None:
        return
    original_call_tool = client_session.call_tool

    async def call_tool(
        self: Any,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        if mcp_payment_flow_active() or _mcp_active.get():
            return await original_call_tool(self, name, arguments, *args, **kwargs)
        runtime = _select_runtime("mcp")
        if runtime is None:
            return await original_call_tool(self, name, arguments, *args, **kwargs)
        token = _mcp_active.set(True)
        try:
            return await runtime.call_mcp_tool(
                MethodType(original_call_tool, self),
                name,
                arguments,
                *args,
                **kwargs,
            )
        finally:
            _mcp_active.reset(token)

    client_session.call_tool = call_tool
    _state.original_mcp_call_tool = original_call_tool
    _state.mcp_call_tool_patch = call_tool
    _state.mcp_client_session = client_session


def _restore_unused_patches() -> None:
    if not any(binding.active and binding.httpx for binding in _state.bindings):
        if (
            _state.sync_send_patch is not None
            and httpx.Client.send is _state.sync_send_patch
            and _state.original_sync_send is not None
        ):
            httpx.Client.send = _state.original_sync_send  # type: ignore[method-assign]
        if (
            _state.async_send_patch is not None
            and httpx.AsyncClient.send is _state.async_send_patch
            and _state.original_async_send is not None
        ):
            httpx.AsyncClient.send = _state.original_async_send  # type: ignore[method-assign]
        _state.original_sync_send = None
        _state.sync_send_patch = None
        _state.original_async_send = None
        _state.async_send_patch = None
        if (
            _state.thread_start_patch is not None
            and threading.Thread.start is _state.thread_start_patch
            and _state.original_thread_start is not None
        ):
            threading.Thread.start = _state.original_thread_start  # type: ignore[method-assign]
        _state.original_thread_start = None
        _state.thread_start_patch = None

    if not any(binding.active and binding.mcp for binding in _state.bindings):
        if (
            _state.mcp_client_session is not None
            and _state.mcp_call_tool_patch is not None
            and _state.mcp_client_session.call_tool is _state.mcp_call_tool_patch
            and _state.original_mcp_call_tool is not None
        ):
            _state.mcp_client_session.call_tool = _state.original_mcp_call_tool
        _state.original_mcp_call_tool = None
        _state.mcp_call_tool_patch = None
        _state.mcp_client_session = None
