"""Redis-backed store for multi-instance deployments.

Uses ``redis-py`` (``redis.asyncio``) as the async driver. Install with::

    pip install pympp[redis]

Example::

    from redis.asyncio import from_url
    from mpp.stores import RedisStore

    store = RedisStore(await from_url("redis://localhost:6379"))
"""

from __future__ import annotations

from typing import Any


class RedisStore:
    """Async key-value store backed by Redis.

    Each key is prefixed with ``key_prefix`` (default ``"mpp:"``) and
    automatically expires after ``ttl_seconds`` (default 300 — 5 minutes).

    ``put_if_absent`` maps to ``SET key value NX EX ttl`` — a single atomic
    Redis command with no TOCTOU race.
    """

    def __init__(
        self,
        client: Any,
        *,
        key_prefix: str = "mpp:",
        ttl_seconds: int = 300,
    ) -> None:
        self._redis = client
        self._prefix = key_prefix
        self._ttl = ttl_seconds

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Any | None:
        return await self._redis.get(self._key(key))

    async def put(self, key: str, value: Any) -> None:
        await self._redis.set(self._key(key), value, ex=self._ttl)

    async def delete(self, key: str) -> None:
        await self._redis.delete(self._key(key))

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomic ``SETNX`` with TTL.

        Returns ``True`` when the key was new and the write succeeded,
        ``False`` when the key already existed (duplicate).
        """
        result = await self._redis.set(
            self._key(key), value, nx=True, ex=self._ttl
        )
        return result is not None
