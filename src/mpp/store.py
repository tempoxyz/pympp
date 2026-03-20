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
    """In-memory store backed by a dict. For development/testing."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    async def get(self, key: str) -> Any | None:
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        if key in self._data:
            return False
        self._data[key] = value
        return True
