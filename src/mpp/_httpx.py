"""Compatibility checks for HTTPX client adapters."""

from __future__ import annotations

import inspect
from importlib.metadata import version
from typing import Any

import httpx

HTTPX_ADAPTER_VERSIONS = ">=0.27,<0.29"
_SUPPORTED_HTTPX_MINORS = {(0, 27), (0, 28)}


class HttpxCompatibilityError(RuntimeError):
    """The installed HTTPX version cannot be safely adapted."""


_POSITIONAL = inspect.Parameter.POSITIONAL_OR_KEYWORD
_KEYWORD_ONLY = inspect.Parameter.KEYWORD_ONLY
_PRIVATE_PARAMETERS = (("self", _POSITIONAL), ("request", _POSITIONAL))
_BOUND_PRIVATE_PARAMETERS = (("request", _POSITIONAL),)
_PUBLIC_PARAMETERS = (
    ("self", _POSITIONAL),
    ("request", _POSITIONAL),
    ("stream", _KEYWORD_ONLY),
    ("auth", _KEYWORD_ONLY),
    ("follow_redirects", _KEYWORD_ONLY),
)
_BOUND_PUBLIC_PARAMETERS = _PUBLIC_PARAMETERS[1:]


def _method_shape(method: Any) -> tuple[tuple[str, Any], ...]:
    try:
        return tuple(
            (parameter.name, parameter.kind)
            for parameter in inspect.signature(method).parameters.values()
        )
    except (TypeError, ValueError) as error:
        raise HttpxCompatibilityError("HTTPX adapter seam has no inspectable signature") from error


def _validate_method(
    name: str,
    method: Any,
    expected: tuple[tuple[str, Any], ...],
    *,
    asynchronous: bool,
) -> None:
    if not callable(method):
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not callable")
    if _method_shape(method) != expected:
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} has an unsupported signature")
    if inspect.iscoroutinefunction(method) is not asynchronous:
        kind = "async" if asynchronous else "sync"
        raise HttpxCompatibilityError(f"HTTPX adapter seam {name} is not {kind}")


def _validate_httpx_version() -> None:
    installed = version("httpx")
    try:
        major, minor, *_ = installed.split(".")
        supported = (int(major), int(minor)) in _SUPPORTED_HTTPX_MINORS
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


def _validate_httpx_seams(owner: Any, *, asynchronous: bool) -> tuple[Any, Any]:
    seams: list[Any] = []
    for name, parameters in (
        ("_send_single_request", _PRIVATE_PARAMETERS),
        ("send", _PUBLIC_PARAMETERS),
    ):
        seam_name = f"{owner.__name__}.{name}"
        try:
            method = inspect.getattr_static(owner, name)
        except AttributeError as error:
            raise HttpxCompatibilityError(f"HTTPX adapter seam {seam_name} is missing") from error
        _validate_method(
            seam_name,
            method,
            parameters,
            asynchronous=asynchronous,
        )
        seams.append(method)
    return seams[0], seams[1]


def _validate_httpx_compatibility() -> tuple[Any, Any, Any, Any]:
    """Return all compatible class-level HTTPX seams, without mutation."""
    _validate_httpx_version()
    sync_private, sync_public = _validate_httpx_seams(httpx.Client, asynchronous=False)
    async_private, async_public = _validate_httpx_seams(httpx.AsyncClient, asynchronous=True)
    return sync_private, async_private, sync_public, async_public


def _validate_httpx_client(
    client: httpx.Client | httpx.AsyncClient,
) -> tuple[Any, Any]:
    """Return compatible bound send seams, without mutating the client."""
    _validate_httpx_version()
    asynchronous = isinstance(client, httpx.AsyncClient)
    _validate_httpx_seams(
        type(client),
        asynchronous=asynchronous,
    )
    private, public = client._send_single_request, client.send
    owner = type(client).__name__
    _validate_method(
        f"{owner} instance._send_single_request",
        private,
        _BOUND_PRIVATE_PARAMETERS,
        asynchronous=asynchronous,
    )
    _validate_method(
        f"{owner} instance.send",
        public,
        _BOUND_PUBLIC_PARAMETERS,
        asynchronous=asynchronous,
    )
    return private, public
