"""Explicit process-global HTTPX payment instrumentation."""

from __future__ import annotations

import inspect
import threading
from dataclasses import dataclass
from functools import partial, wraps
from typing import Any

import httpx

from mpp._httpx import (
    _client_adapter_active,
    _payment_budget,
    _send_async,
    _send_operation,
    _send_sync,
    _validate_httpx_classes,
)
from mpp.runtime import OwnedPaymentRuntime, _owned_in_scope


@dataclass(frozen=True, slots=True)
class _Patch:
    owner: type[Any]
    name: str
    original: Any
    wrapper: Any


@dataclass(slots=True)
class _Binding:
    runtime: OwnedPaymentRuntime
    patches: tuple[_Patch, ...] = ()
    references: int = 1


_LOCK = threading.RLock()
_binding: _Binding | None = None


class Instrumentation:
    """A reference-counted handle for global HTTPX instrumentation."""

    def __init__(self, binding: _Binding) -> None:
        self._binding: _Binding | None = binding

    def disable(self) -> None:
        """Release this handle and restore pympp-owned patches."""
        global _binding

        with _LOCK:
            binding = self._binding
            if binding is None:
                return
            if _binding is not binding:
                self._binding = None
                return
            if binding.references > 1:
                binding.references -= 1
            else:
                owned = tuple(
                    patch
                    for patch in binding.patches
                    if inspect.getattr_static(patch.owner, patch.name) is patch.wrapper
                )
                _replace(owned, enable=False)
                _binding = None
            self._binding = None

    def __enter__(self) -> Instrumentation:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.disable()


def instrument(
    runtime: OwnedPaymentRuntime,
    *,
    allow_unrestricted: bool = False,
) -> Instrumentation:
    """Make otherwise-unadapted HTTPX clients payment-aware."""
    global _binding

    if not isinstance(runtime, OwnedPaymentRuntime):
        raise TypeError("instrument requires an OwnedPaymentRuntime")
    if runtime._allowed_origins._allow_all and not allow_unrestricted:
        raise ValueError(
            "Global instrumentation requires allowed_origins or allow_unrestricted=True"
        )

    with _LOCK:
        if _binding is not None:
            if _binding.runtime is not runtime:
                raise RuntimeError("Another payment runtime is already globally instrumented")
            if not all(
                inspect.getattr_static(patch.owner, patch.name) is patch.wrapper
                for patch in _binding.patches
            ):
                raise RuntimeError("Global HTTPX instrumentation was modified while active")
            _binding.references += 1
            return Instrumentation(_binding)

        binding = _Binding(runtime)
        binding.patches = _make_patches(binding, _validate_httpx_classes())
        _replace(binding.patches, enable=True)
        _binding = binding
        return Instrumentation(binding)


def _make_patches(binding: _Binding, seams: tuple[Any, Any, Any, Any]) -> tuple[_Patch, ...]:
    sync_private, sync_auth, async_private, async_auth = seams

    @wraps(sync_private)
    def patched_sync_private(client: httpx.Client, request: httpx.Request) -> httpx.Response:
        if _bypass(binding, client):
            return sync_private(client, request)
        with _payment_budget(request):
            return _send_sync(binding.runtime, partial(sync_private, client), request)

    @wraps(sync_auth)
    def patched_sync_auth(
        client: httpx.Client,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        if _bypass(binding, client):
            return sync_auth(client, request, *args, **kwargs)
        with _send_operation():
            return sync_auth(client, request, *args, **kwargs)

    @wraps(async_private)
    async def patched_async_private(
        client: httpx.AsyncClient,
        request: httpx.Request,
    ) -> httpx.Response:
        if _bypass(binding, client):
            return await async_private(client, request)
        with _payment_budget(request):
            return await _send_async(
                binding.runtime,
                partial(async_private, client),
                request,
            )

    @wraps(async_auth)
    async def patched_async_auth(
        client: httpx.AsyncClient,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        if _bypass(binding, client):
            return await async_auth(client, request, *args, **kwargs)
        with _send_operation():
            return await async_auth(client, request, *args, **kwargs)

    return (
        _Patch(httpx.Client, "_send_single_request", sync_private, patched_sync_private),
        _Patch(httpx.Client, "_send_handling_auth", sync_auth, patched_sync_auth),
        _Patch(httpx.AsyncClient, "_send_single_request", async_private, patched_async_private),
        _Patch(httpx.AsyncClient, "_send_handling_auth", async_auth, patched_async_auth),
    )


def _bypass(binding: _Binding, client: Any) -> bool:
    return (
        _binding is not binding
        or _client_adapter_active(client)
        or threading.get_ident() == binding.runtime._owner_thread_id
        or _owned_in_scope(binding.runtime._scope_key)
    )


def _replace(patches: tuple[_Patch, ...], *, enable: bool) -> None:
    changed: list[_Patch] = []
    try:
        for patch in patches:
            expected = patch.original if enable else patch.wrapper
            replacement = patch.wrapper if enable else patch.original
            if inspect.getattr_static(patch.owner, patch.name) is not expected:
                raise RuntimeError("HTTPX changed while instrumentation was being updated")
            changed.append(patch)
            _assign(patch.owner, patch.name, replacement)
    except BaseException as error:
        rollback_error: BaseException | None = None
        for patch in reversed(changed):
            expected = patch.original if enable else patch.wrapper
            replacement = patch.wrapper if enable else patch.original
            try:
                if inspect.getattr_static(patch.owner, patch.name) is replacement:
                    _assign(patch.owner, patch.name, expected)
            except BaseException as cause:
                rollback_error = rollback_error or cause
        if rollback_error is not None:
            raise RuntimeError("Failed to roll back HTTPX instrumentation") from error
        raise


def _assign(owner: type[Any], name: str, value: Any) -> None:
    setattr(owner, name, value)
