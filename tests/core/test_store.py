"""Ported from mppx src/Store.test.ts."""

import time
from typing import Any

import pytest

from mpp import store
from mpp.store import Change, Delete, Noop, Set

NESTED = {"name": "alice", "scores": [1, 2, 3], "meta": {"active": True, "tags": ["a", "b"]}}


class FakeStringKv:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def put(self, key: str, value: str) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)


class AtomicFakeStringKv(FakeStringKv):
    def __init__(self) -> None:
        super().__init__()
        self.updates = 0

    async def update(self, key: str, fn: Any) -> Any:
        self.updates += 1
        change = fn(self.data.get(key))
        if isinstance(change, Set):
            self.data[key] = change.value
        elif isinstance(change, Delete):
            self.data.pop(key, None)
        return change.result


class FakeRedis:
    """Implements the subset of redis.asyncio used by RedisStore (no WATCH contention)."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(
        self, key: str, value: str, nx: bool = False, pxat: int | None = None
    ) -> bool | None:
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)

    def pipeline(self, transaction: bool = True) -> "FakePipeline":
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis = redis
        self.ops: list[tuple[str, tuple[Any, ...]]] = []

    async def __aenter__(self) -> "FakePipeline":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def watch(self, key: str) -> None:
        return None

    async def unwatch(self) -> None:
        return None

    async def get(self, key: str) -> str | None:
        return await self.redis.get(key)

    def multi(self) -> None:
        self.ops.clear()

    def set(self, key: str, value: str) -> None:
        self.ops.append(("set", (key, value)))

    def delete(self, key: str) -> None:
        self.ops.append(("delete", (key,)))

    async def execute(self) -> None:
        for op, args in self.ops:
            await getattr(self.redis, op)(*args)


FACTORIES = {
    "memory": lambda: store.memory(),
    "kv": lambda: store.kv(FakeStringKv()),
    "redis": lambda: store.redis(FakeRedis()),
}


@pytest.mark.parametrize("factory", FACTORIES.values(), ids=FACTORIES.keys())
async def test_basic_operations(factory: Any) -> None:
    s = factory()
    await s.put("k", NESTED)
    assert await s.get("k") == NESTED
    assert await s.get("missing") is None
    await s.put("k", {"v": 2})
    assert await s.get("k") == {"v": 2}
    await s.delete("k")
    assert await s.get("k") is None
    big = 69420694206942069420694206942069420694206942069420
    await s.put("big", {"n": big})
    assert await s.get("big") == {"n": big}


async def test_key_prefix() -> None:
    backing = store.memory()
    prefixed = store.prefixed(backing, "p:")
    await prefixed.put("k", 1)
    assert await backing.get("p:k") == 1
    assert await prefixed.get("k") == 1
    assert await prefixed.update("k", lambda current: Set(current + 1, "ok")) == "ok"
    assert await backing.get("p:k") == 2
    assert await store.try_claim(prefixed, "claim", int(time.time() * 1000) + 60_000)
    assert await backing.get("p:claim") is not None
    await prefixed.delete("k")
    assert await backing.get("p:k") is None
    assert store.prefixed(backing, "") is backing
    assert store.prefixed(backing, None) is backing


async def test_memory_key_prefix_constructor() -> None:
    s = store.memory(key_prefix="x:")
    await s.put("a", 1)
    assert await s.get("a") == 1


async def test_try_claim_fast_path() -> None:
    s = store.memory()
    expires = int(time.time() * 1000) + 60_000
    assert await store.try_claim(s, "k", expires) is True
    assert await store.try_claim(s, "k", expires) is False
    assert await s.get("k") == {"expires": expires, "type": "mppx:replay"}


async def test_try_claim_update_fallback_replaces_expired() -> None:
    kv = AtomicFakeStringKv()
    s: Any = store.kv(kv)
    assert not hasattr(s, "try_claim")
    now = int(time.time() * 1000)
    assert await store.try_claim(s, "k", now - 1) is True
    assert await store.try_claim(s, "k", now + 60_000) is True
    assert await store.try_claim(s, "k", now + 60_000) is False
    assert await s.get("k") == {"expires": now + 60_000, "type": "mppx:replay"}
    assert kv.updates == 3


async def test_legacy_markers_are_consumed() -> None:
    s = store.memory()
    await s.put("k", int(time.time() * 1000) - 60_000)
    assert await store.try_claim(s, "k", int(time.time() * 1000) + 60_000) is False


async def test_redis_native_claim() -> None:
    s = store.redis(FakeRedis())
    expires = int(time.time() * 1000) + 60_000
    assert await store.try_claim(s, "k", expires) is True
    assert await store.try_claim(s, "k", expires) is False


@pytest.mark.parametrize(
    "factory", [FACTORIES["memory"], FACTORIES["redis"], lambda: store.kv(AtomicFakeStringKv())]
)
async def test_update_noop_set_delete(factory: Any) -> None:
    s = factory()

    def increment(current: Any) -> Change[int]:
        value = (current or 0) + 1
        return Set(value, value)

    assert await s.update("n", increment) == 1
    assert await s.update("n", increment) == 2
    assert await s.update("n", lambda current: Noop(current)) == 2
    assert await s.update("n", lambda current: Delete("gone")) == "gone"
    assert await s.get("n") is None
