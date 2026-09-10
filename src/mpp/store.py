"""Pluggable key-value store for replay protection.

Modeled after Cloudflare KV's API (get/put/delete).
"""

from __future__ import annotations

from typing import Any, Protocol


class Store(Protocol):
    """Async key-value store interface."""

    async def get(self, key: str) -> Any | None: ...
    async def put(self, key: str, value: Any) -> None: ...
    async def delete(self, key: str) -> None: ...

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Store *value* under *key* only if *key* does not already exist.

        Returns ``True`` if the key was new and the write succeeded,
        ``False`` if the key already existed (duplicate).

        Maps to ``SETNX`` in Redis, conditional put in DynamoDB, etc.
        """
        ...


class MemoryStore:
    """In-memory store for development/testing.

    ``max_entries`` caps retained keys without evicting replay protection.
    New writes fail at capacity; existing keys can still be read or updated.
    Use persistent storage for long-running or multi-replica deployments.
    """

    def __init__(self, *, max_entries: int | None = None) -> None:
        if max_entries is not None and max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._data: dict[str, Any] = {}

    def _check_capacity(self, key: str) -> None:
        if (
            key not in self._data
            and self._max_entries is not None
            and len(self._data) >= self._max_entries
        ):
            raise RuntimeError("Replay store capacity reached; configure a persistent store")

    async def get(self, key: str) -> Any | None:
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        self._check_capacity(key)
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        if key in self._data:
            return False
        self._check_capacity(key)
        self._data[key] = value
        return True
