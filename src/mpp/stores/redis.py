"""Redis-backed store for MPP challenge replay protection."""
from __future__ import annotations

from typing import Any

_SETNX_SCRIPT = """
local set = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
if set then return 1 else return 0 end
"""


class RedisStore:
    """Production-ready Redis store with atomic SETNX and automatic TTL.

    Suitable for multi-instance deployments where MemoryStore would allow
    replay attacks across processes.

    Example::

        from redis.asyncio import from_url
        from mpp.stores.redis import RedisStore

        store = RedisStore(await from_url("redis://localhost:6379"))

    Args:
        client: An async Redis client (e.g. ``redis.asyncio.Redis``).
        ttl_seconds: How long challenges remain valid. Defaults to 300 (5 min).
        key_prefix: Namespace prefix for all keys. Defaults to ``"mpp:"``.
    """

    def __init__(
        self,
        client: Any,
        *,
        ttl_seconds: int = 300,
        key_prefix: str = "mpp:",
    ) -> None:
        self._redis = client
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Any | None:
        value = await self._redis.get(self._key(key))
        return value  # bytes or str depending on decode_responses

    async def put(self, key: str, value: Any) -> None:
        await self._redis.set(self._key(key), value, ex=self._ttl)

    async def delete(self, key: str) -> None:
        await self._redis.delete(self._key(key))

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomic SETNX with TTL — maps to Redis SET NX EX."""
        result = await self._redis.set(
            self._key(key), value, nx=True, ex=self._ttl
        )
        return result is not None
