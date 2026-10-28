"""Pluggable key-value store for replay protection.

Modeled after Cloudflare KV's API (get/put/delete).
"""

from __future__ import annotations

import math
import time
from typing import Any, Protocol, runtime_checkable


class Store(Protocol):
    """Async key-value store interface."""

    async def get(self, key: str) -> Any | None: ...
    async def put(self, key: str, value: Any) -> None: ...
    async def delete(self, key: str) -> None: ...

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Store *value* under *key* only if *key* does not already exist.

        Returns ``True`` if the key was new and the write succeeded,
        ``False`` if the key already existed (duplicate).

        Replay claims must not expire according to a general key-value TTL.
        A successful claim must remain protected until explicitly deleted.

        Maps to ``SETNX`` in Redis, conditional put in DynamoDB, etc.
        """
        ...


@runtime_checkable
class ExpiringStore(Store, Protocol):
    """Optional atomic absolute-expiry support for temporary recovery records."""

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        """Insert without replacing a live key, expiring at this Unix timestamp.

        An existing key's value and expiry must remain unchanged. This deadline
        overrides a store-wide TTL and must be finite and in the future.
        """
        ...


@runtime_checkable
class CompareAndSetStore(Store, Protocol):
    """Optional atomic compare-and-set support for state shared across processes."""

    async def compare_and_set(self, key: str, expected: Any | None, value: Any | None) -> bool:
        """Write *value* under *key* only while its current value equals *expected*.

        ``expected=None`` requires *key* to be absent and ``value=None`` deletes it.
        Returns whether the write happened. An existing key keeps its expiry.
        """
        ...


def _validate_expiry(expires_at: float) -> None:
    if not math.isfinite(expires_at) or expires_at <= time.time():
        raise ValueError("expires_at must be a finite future Unix timestamp")


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
        self._expiry_deadlines: dict[str, float] = {}

    def _prune_expired(self) -> None:
        now = time.time()
        for key, expires_at in list(self._expiry_deadlines.items()):
            if expires_at <= now:
                self._data.pop(key, None)
                del self._expiry_deadlines[key]

    def _check_capacity(self, key: str) -> None:
        self._prune_expired()
        if (
            key not in self._data
            and self._max_entries is not None
            and len(self._data) >= self._max_entries
        ):
            raise RuntimeError("Replay store capacity reached; configure a persistent store")

    async def get(self, key: str) -> Any | None:
        self._prune_expired()
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        self._check_capacity(key)
        self._data[key] = value
        self._expiry_deadlines.pop(key, None)

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._expiry_deadlines.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        self._prune_expired()
        if key in self._data:
            return False
        self._check_capacity(key)
        self._data[key] = value
        return True

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        _validate_expiry(expires_at)
        if not await self.put_if_absent(key, value):
            return False
        self._expiry_deadlines[key] = expires_at
        return True

    async def compare_and_set(self, key: str, expected: Any | None, value: Any | None) -> bool:
        self._prune_expired()
        if self._data.get(key) != expected:
            return False
        if value is None:
            await self.delete(key)
        else:
            self._check_capacity(key)
            self._data[key] = value
        return True
