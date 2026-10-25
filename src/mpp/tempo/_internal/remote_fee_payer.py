"""Configuration for a remote (hosted) Tempo fee-payer service."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

import httpx


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteFeePayer:
    url: str
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    http: httpx.AsyncClient | None = None
    """Custom HTTP client used only for fee-payer JSON-RPC transport."""


def from_value(value: object) -> RemoteFeePayer | None:
    """Normalizes a URL string or :class:`RemoteFeePayer`; anything else is ``None``."""
    if isinstance(value, str):
        return RemoteFeePayer(url=value)
    if isinstance(value, RemoteFeePayer):
        return value
    return None


def resolve_headers(config: RemoteFeePayer) -> dict[str, str]:
    """Copies the configured headers, reserving ``content-type`` for JSON-RPC."""
    return {name: value for name, value in config.headers.items() if name.lower() != "content-type"}
