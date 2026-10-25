"""Async key-value stores used for replay protection and method state.

A :class:`Store` exposes ``get`` / ``put`` / ``delete``; an :class:`AtomicStore` additionally
provides an atomic read-modify-write :meth:`~AtomicStore.update` and may provide an optimized
``try_claim``. Values are JSON round-tripped by every built-in implementation so that behavior in
tests matches production backends.

Built-ins: :func:`memory`, :func:`redis` (``redis.asyncio`` client, ``pympp[redis]``) and
:func:`kv` (wraps any async string KV such as a Cloudflare Workers KV binding). mppx's Upstash
adapter has no separate Python analog: Upstash speaks the Redis protocol, so use :func:`redis`.
"""

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable

__all__ = [
    "REPLAY_MARKER_TYPE",
    "AtomicStore",
    "Change",
    "Delete",
    "KvStore",
    "MemoryStore",
    "Noop",
    "PrefixedStore",
    "RedisStore",
    "Set",
    "Store",
    "StringKv",
    "UpdateFn",
    "is_replay_marker",
    "kv",
    "memory",
    "prefixed",
    "redis",
    "try_claim",
]


@dataclass(frozen=True, slots=True)
class Noop[R]:
    """Leave the stored value unchanged and return ``result``."""

    result: R


@dataclass(frozen=True, slots=True)
class Set[R]:
    """Write ``value`` for the key and return ``result``."""

    value: Any
    result: R


@dataclass(frozen=True, slots=True)
class Delete[R]:
    """Remove the key and return ``result``."""

    result: R


type Change[R] = Noop[R] | Set[R] | Delete[R]
"""Outcome of an atomic :meth:`AtomicStore.update` callback."""

type UpdateFn[R] = Callable[[Any | None], Change[R]]
"""Update callback: receives the current value (or ``None``). Must be pure and synchronous;
implementations may retry it."""


@runtime_checkable
class Store(Protocol):
    """Async key-value store."""

    async def get(self, key: str) -> Any | None: ...

    async def put(self, key: str, value: Any) -> None: ...

    async def delete(self, key: str) -> None: ...


@runtime_checkable
class AtomicStore(Store, Protocol):
    """A store with an atomic read-modify-write ``update`` (required for replay protection)."""

    async def update[R](self, key: str, fn: UpdateFn[R]) -> R: ...


REPLAY_MARKER_TYPE = "mppx:replay"


def _now_ms() -> int:
    return int(time.time() * 1000)


def is_replay_marker(value: Any) -> bool:
    """Returns whether ``value`` is a persisted ``{"expires": ms, "type": "mppx:replay"}``."""
    return (
        isinstance(value, dict)
        and isinstance(value.get("expires"), int | float)
        and not isinstance(value.get("expires"), bool)
        and value.get("type") == REPLAY_MARKER_TYPE
    )


def _claim(current: Any | None, expires: int) -> Change[bool]:
    if current is not None and (not is_replay_marker(current) or current["expires"] > _now_ms()):
        return Noop(False)
    return Set({"expires": expires, "type": REPLAY_MARKER_TYPE}, True)


async def try_claim(store: AtomicStore, key: str, expires: int) -> bool:
    """Atomically records first use of a replay key through ``expires`` (Unix ms).

    Returns ``True`` when this call recorded the key and ``False`` when it was already recorded
    and unexpired. Uses the store's ``try_claim`` fast path when available, otherwise
    :meth:`AtomicStore.update`.
    """
    fast: Any = getattr(store, "try_claim", None)
    if callable(fast):
        return bool(await cast(Any, fast)(key, expires))
    return await store.update(key, lambda current: _claim(current, expires))


class MemoryStore:
    """In-memory atomic store; JSON round-trips values to match production behavior."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    async def get(self, key: str) -> Any | None:
        raw = self._data.get(key)
        return None if raw is None else json.loads(raw)

    async def put(self, key: str, value: Any) -> None:
        self._data[key] = json.dumps(value)

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def update[R](self, key: str, fn: UpdateFn[R]) -> R:
        raw = self._data.get(key)
        change = fn(None if raw is None else json.loads(raw))
        _apply(self._data, key, change)
        return change.result

    async def try_claim(self, key: str, expires: int) -> bool:
        raw = self._data.get(key)
        change = _claim(None if raw is None else json.loads(raw), expires)
        _apply(self._data, key, change)
        return change.result


def _apply(data: dict[str, str], key: str, change: Change[Any]) -> None:
    match change:
        case Set(value=value):
            data[key] = json.dumps(value)
        case Delete():
            data.pop(key, None)
        case Noop():
            pass


class PrefixedStore:
    """Prefixes every backing key; forwards ``update`` / ``try_claim`` when the backing has them."""

    def __init__(self, store: Store, prefix: str) -> None:
        self._store = store
        self._prefix = prefix
        if callable(getattr(store, "update", None)):
            self.update = self._update
        if callable(getattr(store, "try_claim", None)):
            self.try_claim = self._try_claim

    async def get(self, key: str) -> Any | None:
        return await self._store.get(self._prefix + key)

    async def put(self, key: str, value: Any) -> None:
        await self._store.put(self._prefix + key, value)

    async def delete(self, key: str) -> None:
        await self._store.delete(self._prefix + key)

    async def _update[R](self, key: str, fn: UpdateFn[R]) -> R:
        return await cast(AtomicStore, self._store).update(self._prefix + key, fn)

    async def _try_claim(self, key: str, expires: int) -> bool:
        return bool(await cast(Any, self._store).try_claim(self._prefix + key, expires))


def prefixed[S: Store](store: S, key_prefix: str | None) -> S:
    """Returns ``store`` with ``key_prefix`` prepended to every key (``store`` when empty)."""
    if not key_prefix:
        return store
    return cast(S, PrefixedStore(store, key_prefix))


def memory(*, key_prefix: str | None = None) -> AtomicStore:
    """Creates an in-memory atomic store."""
    return prefixed(cast(AtomicStore, MemoryStore()), key_prefix)


class StringKv(Protocol):
    """Minimal async string KV (e.g. a Cloudflare Workers KV binding)."""

    async def get(self, key: str) -> str | None: ...

    async def put(self, key: str, value: str) -> None: ...

    async def delete(self, key: str) -> None: ...


class KvStore:
    """Wraps an async string KV with JSON serialization.

    The KV may also provide ``update(key, fn)`` operating on raw strings to make the store
    atomic.
    """

    def __init__(self, kv: StringKv) -> None:
        self._kv = kv
        if callable(getattr(kv, "update", None)):
            self.update = self._update

    async def get(self, key: str) -> Any | None:
        raw = await self._kv.get(key)
        return None if raw is None else json.loads(raw)

    async def put(self, key: str, value: Any) -> None:
        await self._kv.put(key, json.dumps(value))

    async def delete(self, key: str) -> None:
        await self._kv.delete(key)

    async def _update[R](self, key: str, fn: UpdateFn[R]) -> R:
        def wrapped(current: str | None) -> Change[R]:
            change = fn(None if current is None else json.loads(current))
            if isinstance(change, Set):
                return Set(json.dumps(change.value), change.result)
            return change

        return await cast(Any, self._kv).update(key, wrapped)


def kv(kv: StringKv, *, key_prefix: str | None = None) -> Store:
    """Wraps an async string KV (``get``/``put``/``delete``, optional ``update``) as a store."""
    return prefixed(cast(Store, KvStore(kv)), key_prefix)


class RedisStore:
    """Atomic store backed by a ``redis.asyncio`` client (optimistic ``WATCH``/``MULTI``)."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def get(self, key: str) -> Any | None:
        raw = await self._client.get(key)
        return None if raw is None else json.loads(raw)

    async def put(self, key: str, value: Any) -> None:
        await self._client.set(key, json.dumps(value))

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def update[R](self, key: str, fn: UpdateFn[R]) -> R:
        from redis.exceptions import WatchError

        async with self._client.pipeline(transaction=True) as pipe:
            while True:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    change = fn(None if raw is None else json.loads(raw))
                    if isinstance(change, Noop):
                        await pipe.unwatch()
                        return change.result
                    pipe.multi()
                    if isinstance(change, Set):
                        pipe.set(key, json.dumps(change.value))
                    else:
                        pipe.delete(key)
                    await pipe.execute()
                    return change.result
                except WatchError:
                    continue

    async def try_claim(self, key: str, expires: int) -> bool:
        if expires <= _now_ms():
            return await self.update(key, lambda current: _claim(current, expires))
        marker = json.dumps({"expires": expires, "type": REPLAY_MARKER_TYPE})
        # Redis expires the key itself, so an absent key covers "never claimed or expired".
        return bool(await self._client.set(key, marker, nx=True, pxat=expires))


def redis(client: Any, *, key_prefix: str | None = None) -> AtomicStore:
    """Wraps a ``redis.asyncio.Redis`` (or Valkey/Upstash over the Redis protocol) client.

    Requires the ``redis`` extra for atomic updates (``pip install pympp[redis]``).
    """
    return prefixed(cast(AtomicStore, RedisStore(client)), key_prefix)
