"""Configuration for a hosted (remote) Tempo fee-payer service.

A server passes one as ``tempo.charge(fee_payer=...)``, in any of these forms::

    fee_payer="https://sponsor.example/rpc"
    fee_payer={"url": "https://sponsor.example/rpc", "headers": {"Authorization": "Bearer ..."}}
    fee_payer=RemoteFeePayer(url="https://sponsor.example/rpc", headers=get_auth_headers)

The service co-signs sponsored transactions over JSON-RPC
``eth_fillTransaction``; the server simulates and broadcasts them itself.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

HeadersProvider = Callable[[], Mapping[str, str] | Awaitable[Mapping[str, str]]]
"""Returns the headers for one fee-payer request, such as a fresh bearer token."""


@dataclass(frozen=True, slots=True)
class RemoteFeePayer:
    """A hosted fee-payer service.

    Attributes:
        url: The service's JSON-RPC endpoint.
        headers: Headers sent with every request, or a sync or async callable
            returning them per request. ``Content-Type`` is always JSON.
    """

    url: str
    headers: Mapping[str, str] | HeadersProvider | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError("RemoteFeePayer url must be a non-empty string")

    @classmethod
    def from_value(cls, value: object) -> RemoteFeePayer | None:
        """Return the remote fee payer a ``fee_payer`` value names, if any.

        A string is shorthand for its URL; a mapping needs a string ``url``
        and may set ``headers``.
        """
        if isinstance(value, RemoteFeePayer):
            return value
        if isinstance(value, str):
            return cls(url=value)
        if isinstance(value, Mapping):
            config: Mapping[Any, Any] = value  # pyright: ignore[reportUnknownVariableType]
            url = config.get("url")
            if not isinstance(url, str):
                return None
            unknown = set(config) - {"url", "headers"}
            if unknown:
                raise ValueError(f"Unknown remote fee payer options: {sorted(unknown)}")
            return cls(url=url, headers=config.get("headers"))
        return None

    async def resolve_headers(self) -> dict[str, str]:
        """Return this request's headers, without ``Content-Type``, which stays JSON."""
        headers: Any = self.headers
        if callable(headers):
            headers = headers()
            if inspect.isawaitable(headers):
                headers = await headers
        if headers is None:
            return {}
        if not isinstance(headers, Mapping):
            raise TypeError("RemoteFeePayer headers must be a mapping of strings")
        resolved: Mapping[Any, Any] = headers  # pyright: ignore[reportUnknownVariableType]
        return {
            str(name): str(value)
            for name, value in resolved.items()
            if str(name).lower() != "content-type"
        }
