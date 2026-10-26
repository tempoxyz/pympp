"""Redis-backed store for multi-instance deployments.

Uses ``redis-py`` (``redis.asyncio``) as the async driver. Install with::

    pip install pympp[redis]

Example::

    from redis.asyncio import from_url
    from mpp.stores import RedisStore

    store = RedisStore(await from_url("redis://localhost:6379"))
"""

from __future__ import annotations

import math
from typing import Any

from mpp.store import _validate_expiry

# KEYS[1]; ARGV: has_expected, expected, has_value, value.
_COMPARE_AND_SET = """
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '0' then
  if current then return 0 end
elseif current ~= ARGV[2] then
  return 0
end
if ARGV[3] == '0' then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], ARGV[4], 'KEEPTTL')
end
return 1
"""


class RedisStore:
    """Async key-value store backed by Redis.

    Each key is prefixed with ``key_prefix`` (default ``"mpp:"``).
    Keys written by ``put`` do not expire by default; set ``ttl_seconds``
    to opt into expiry for those writes.

    ``put_if_absent`` always creates persistent replay claims using
    ``SET key value NX``, regardless of ``ttl_seconds``. Existing keys
    retain their previous expiry.
    """

    def __init__(
        self,
        client: Any,
        *,
        key_prefix: str = "mpp:",
        ttl_seconds: int | None = None,
    ) -> None:
        self._redis = client
        self._prefix = key_prefix
        self._ttl = ttl_seconds

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Any | None:
        return await self._redis.get(self._key(key))

    async def put(self, key: str, value: Any) -> None:
        if self._ttl is None:
            await self._redis.set(self._key(key), value)
            return
        await self._redis.set(self._key(key), value, ex=self._ttl)

    async def delete(self, key: str) -> None:
        await self._redis.delete(self._key(key))

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomic ``SETNX`` without expiry, preserving replay protection.

        Returns ``True`` when the key was new and the write succeeded,
        ``False`` when the key already existed (duplicate).
        """
        result = await self._redis.set(self._key(key), value, nx=True)
        return result is not None

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        """Atomically insert with absolute expiry; requires Redis server >= 6.2.

        Overrides the default TTL using ``SET NX PXAT``.
        """
        _validate_expiry(expires_at)
        result = await self._redis.set(
            self._key(key), value, nx=True, pxat=math.ceil(expires_at * 1000)
        )
        return result is not None

    async def compare_and_set(self, key: str, expected: Any | None, value: Any | None) -> bool:
        """Atomic conditional write in a Lua script; requires Redis server >= 6.0."""
        result = await self._redis.eval(
            _COMPARE_AND_SET,
            1,
            self._key(key),
            "0" if expected is None else "1",
            "" if expected is None else expected,
            "0" if value is None else "1",
            "" if value is None else value,
        )
        return bool(result)
