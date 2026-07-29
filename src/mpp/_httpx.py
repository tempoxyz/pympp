"""Fail-fast adapters for existing HTTPX clients."""

from __future__ import annotations

import inspect
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mpp.runtime import OwnedPaymentRuntime

HTTPX_ADAPTER_VERSIONS = ">=0.27,<0.29"
_SUPPORTED_HTTPX_MINORS = {(0, 27), (0, 28)}
_MARKER = "_mpp_httpx_adapter"
_MISSING = object()
_LOCK = threading.RLock()
_POSITIONAL = inspect.Parameter.POSITIONAL_OR_KEYWORD
_PRIVATE = (("self", _POSITIONAL), ("request", _POSITIONAL))
_BOUND_PRIVATE = _PRIVATE[1:]
_AUTH = (
    ("self", _POSITIONAL),
    ("request", _POSITIONAL),
    ("auth", _POSITIONAL),
    ("follow_redirects", _POSITIONAL),
    ("history", _POSITIONAL),
)
_BOUND_AUTH = _AUTH[1:]


class HttpxCompatibilityError(RuntimeError):
    """The installed HTTPX client cannot be safely adapted."""


@dataclass(frozen=True, slots=True)
class _Adapter:
    runtime: OwnedPaymentRuntime
    private: Any
    auth: Any


@dataclass(slots=True)
class _SendOperation:
    paid: bool = False


_SEND_OPERATION: ContextVar[_SendOperation | None] = ContextVar(
    "mpp_httpx_send_operation",
    default=None,
)


@contextmanager
def _send_operation():
    token = _SEND_OPERATION.set(_SendOperation())
    try:
        yield
    finally:
        _SEND_OPERATION.reset(token)


@contextmanager
def _payment_budget(request: httpx.Request):
    from mpp.client._http import _PAYMENT_SENT

    operation = _SEND_OPERATION.get()
    if operation is not None:
        source = request.extensions.get(_PAYMENT_SENT)
        if operation.paid:
            request.extensions[_PAYMENT_SENT] = 0
        elif isinstance(source, int):
            request.extensions.pop(_PAYMENT_SENT, None)
    try:
        yield
    finally:
        if operation is not None and isinstance(request.extensions.get(_PAYMENT_SENT), int):
            operation.paid = True


class _SyncSend(httpx.BaseTransport):
    def __init__(self, send: Callable[[httpx.Request], httpx.Response]) -> None:
        self._send = send

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._send(request)


class _AsyncSend(httpx.AsyncBaseTransport):
    def __init__(
        self,
        send: Callable[[httpx.Request], Awaitable[httpx.Response]],
    ) -> None:
        self._send = send

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._send(request)


def _send_sync(
    runtime: OwnedPaymentRuntime,
    send: Callable[[httpx.Request], httpx.Response],
    request: httpx.Request,
) -> httpx.Response:
    from mpp.client import SyncPaymentTransport

    return SyncPaymentTransport(inner=_SyncSend(send), runtime=runtime).handle_request(request)


async def _send_async(
    runtime: OwnedPaymentRuntime,
    send: Callable[[httpx.Request], Awaitable[httpx.Response]],
    request: httpx.Request,
) -> httpx.Response:
    from mpp.client import PaymentTransport

    return await PaymentTransport(
        inner=_AsyncSend(send),
        runtime=runtime,
    ).handle_async_request(request)


def wrap_client(client: httpx.Client, runtime: OwnedPaymentRuntime) -> httpx.Client:
    """Make one synchronous HTTPX client payment-aware."""
    if not isinstance(client, httpx.Client):
        raise TypeError("wrap_client requires an httpx.Client")
    return _wrap(client, runtime, asynchronous=False)


def wrap_async_client(
    client: httpx.AsyncClient,
    runtime: OwnedPaymentRuntime,
) -> httpx.AsyncClient:
    """Make one asynchronous HTTPX client payment-aware."""
    if not isinstance(client, httpx.AsyncClient):
        raise TypeError("wrap_async_client requires an httpx.AsyncClient")
    return _wrap(client, runtime, asynchronous=True)


def _wrap(client: Any, runtime: OwnedPaymentRuntime, *, asynchronous: bool) -> Any:
    with _LOCK:
        existing = client.__dict__.get(_MARKER, _MISSING)
        if existing is not _MISSING:
            if (
                not isinstance(existing, _Adapter)
                or inspect.getattr_static(client, "_send_single_request") is not existing.private
                or inspect.getattr_static(client, "_send_handling_auth") is not existing.auth
            ):
                raise HttpxCompatibilityError("HTTPX client adapter was replaced or corrupted")
            if existing.runtime is not runtime:
                raise RuntimeError("HTTPX client is already bound to another payment runtime")
            return client

        original_private, original_auth = _validate_client(
            client,
            asynchronous=asynchronous,
        )
        if asynchronous:
            from mpp.client import PaymentTransport

            transport = PaymentTransport(inner=_AsyncSend(original_private), runtime=runtime)

            @wraps(original_private)
            async def async_private(request: httpx.Request) -> httpx.Response:
                with _payment_budget(request):
                    return await transport.handle_async_request(request)

            @wraps(original_auth)
            async def async_auth(
                request: httpx.Request,
                *args: Any,
                **kwargs: Any,
            ) -> httpx.Response:
                with _send_operation():
                    return await original_auth(request, *args, **kwargs)

            private, auth = async_private, async_auth
        else:
            from mpp.client import SyncPaymentTransport

            transport = SyncPaymentTransport(inner=_SyncSend(original_private), runtime=runtime)

            @wraps(original_private)
            def sync_private(request: httpx.Request) -> httpx.Response:
                with _payment_budget(request):
                    return transport.handle_request(request)

            @wraps(original_auth)
            def sync_auth(
                request: httpx.Request,
                *args: Any,
                **kwargs: Any,
            ) -> httpx.Response:
                with _send_operation():
                    return original_auth(request, *args, **kwargs)

            private, auth = sync_private, sync_auth

        _set_attributes(
            client,
            _send_single_request=private,
            _send_handling_auth=auth,
            **{_MARKER: _Adapter(runtime, private, auth)},
        )
        return client


def _validate_client(client: Any, *, asynchronous: bool) -> tuple[Any, Any]:
    _validate_version()
    owner = type(client)
    _validate_class(owner, asynchronous=asynchronous)
    bound = []
    for name, expected in (
        ("_send_single_request", _BOUND_PRIVATE),
        ("_send_handling_auth", _BOUND_AUTH),
    ):
        value = getattr(client, name)
        _validate_seam(
            f"{owner.__name__} instance.{name}",
            value,
            expected,
            asynchronous,
        )
        bound.append(value)
    return bound[0], bound[1]


def _validate_httpx_classes() -> tuple[Any, Any, Any, Any]:
    _validate_version()
    return (
        *_validate_class(httpx.Client, asynchronous=False),
        *_validate_class(httpx.AsyncClient, asynchronous=True),
    )


def _validate_class(owner: Any, *, asynchronous: bool) -> tuple[Any, Any]:
    seams = []
    for name, expected in (("_send_single_request", _PRIVATE), ("_send_handling_auth", _AUTH)):
        try:
            seam = inspect.getattr_static(owner, name)
        except AttributeError as error:
            raise HttpxCompatibilityError(
                f"HTTPX adapter seam {owner.__name__}.{name} is missing"
            ) from error
        _validate_seam(f"{owner.__name__}.{name}", seam, expected, asynchronous)
        seams.append(seam)
    return seams[0], seams[1]


def _client_adapter_active(client: Any) -> bool:
    adapter = client.__dict__.get(_MARKER)
    return isinstance(adapter, _Adapter) and (
        inspect.getattr_static(client, "_send_single_request") is adapter.private
        and inspect.getattr_static(client, "_send_handling_auth") is adapter.auth
    )


def _validate_version() -> None:
    installed = version("httpx")
    try:
        supported = tuple(map(int, installed.split(".")[:2])) in _SUPPORTED_HTTPX_MINORS
    except ValueError as error:
        raise HttpxCompatibilityError(
            f"Cannot determine HTTPX compatibility from version {installed!r}"
        ) from error
    if not supported:
        raise HttpxCompatibilityError(
            f"HTTPX {installed} is unsupported by pympp HTTPX adapters "
            f"(supported: {HTTPX_ADAPTER_VERSIONS}). "
            "Use PaymentTransport or SyncPaymentTransport explicitly, or upgrade pympp."
        )


def _validate_seam(
    name: str,
    seam: Any,
    expected: tuple[tuple[str, inspect._ParameterKind], ...],
    asynchronous: bool,
) -> None:
    try:
        shape = tuple(
            (parameter.name, parameter.kind)
            for parameter in inspect.signature(seam).parameters.values()
        )
    except (TypeError, ValueError) as error:
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not inspectable") from error
    if not callable(seam) or shape != expected:
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} has an unsupported signature")
    if inspect.iscoroutinefunction(seam) is not asynchronous:
        kind = "async" if asynchronous else "sync"
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not {kind}")


def _set_attributes(client: Any, **values: Any) -> None:
    previous = {name: client.__dict__.get(name, _MISSING) for name in values}
    changed: list[str] = []
    try:
        for name, value in values.items():
            changed.append(name)
            setattr(client, name, value)
    except BaseException as error:
        rollback_error: BaseException | None = None
        for name in reversed(changed):
            try:
                if previous[name] is _MISSING:
                    if name in client.__dict__:
                        delattr(client, name)
                else:
                    setattr(client, name, previous[name])
            except BaseException as cause:
                rollback_error = rollback_error or cause
        if rollback_error is not None:
            raise RuntimeError("Failed to roll back HTTPX client adapter") from error
        raise
