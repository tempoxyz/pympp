"""Shared behaviour contract for every replay store backend.

Modeled on mppx src/Store.test.ts (describe.each over backends). Backend-specific
details, such as SQLite schema upgrades or Redis TTL commands, live in each
backend's own test file; this file pins what every backend must agree on.

Redis runs only when REDIS_URL is set (see tests/test_stores_redis_integration.py).
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from mpp.store import ExpiringStore, MemoryStore, Store
from mpp.stores.sqlite import SQLiteStore

REDIS_URL = os.environ.get("REDIS_URL")

# Expiry windows are wall-clock time on Redis: keep them wide enough that a slow
# round trip or scheduler pause can't expire a key before the "still live" checks.
TTL_SECONDS = 2
LIVE_SECONDS = 2.0
EXPIRE_AFTER = LIVE_SECONDS + 0.5


@dataclass
class Backend:
    """A store factory plus a clock the backend honours."""

    name: str
    make: Callable[..., Awaitable[Any]]
    now: Callable[[], float]
    advance: Callable[[float], Awaitable[None]]
    supports_ttl: bool
    cleanups: list[Callable[[], Awaitable[None]]] = field(default_factory=list)


class FakeClock:
    """Shifts time.time for backends that read the local clock."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.offset = 0.0
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + self.offset)

    def now(self) -> float:
        return time.time()

    async def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param(
            "redis",
            marks=[
                pytest.mark.redis,
                pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
            ],
        ),
    ]
)
async def backend(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path):
    name: str = request.param
    if name == "redis":
        from redis.asyncio import from_url

        from mpp.stores.redis import RedisStore

        assert REDIS_URL is not None
        client = from_url(REDIS_URL, decode_responses=True)
        prefix = f"contract:{uuid.uuid4().hex[:8]}:"

        async def make_redis(ttl_seconds: int | None = None, key_prefix: str = prefix) -> Any:
            return RedisStore(client, key_prefix=key_prefix, ttl_seconds=ttl_seconds)

        async def delete_keys() -> None:
            async for key in client.scan_iter(match=f"{prefix}*"):
                await client.delete(key)

        result = Backend(name, make_redis, time.time, asyncio.sleep, supports_ttl=True)
        result.cleanups.append(client.aclose)
        result.cleanups.append(delete_keys)
    else:
        clock = FakeClock(monkeypatch)
        if name == "memory":

            async def make_memory(ttl_seconds: int | None = None) -> Any:
                assert ttl_seconds is None, "MemoryStore has no TTL"
                return MemoryStore()

            result = Backend(name, make_memory, clock.now, clock.advance, supports_ttl=False)
        else:
            path = str(tmp_path / "contract.db")

            async def make_sqlite(ttl_seconds: int | None = None) -> Any:
                store = await SQLiteStore.create(path, ttl_seconds=ttl_seconds)
                result.cleanups.append(store.close)
                return store

            result = Backend(name, make_sqlite, clock.now, clock.advance, supports_ttl=True)
    yield result
    for cleanup in reversed(result.cleanups):
        await cleanup()


@pytest.fixture
async def store(backend: Backend) -> AsyncIterator[Any]:
    yield await backend.make()


@pytest.fixture
def ttl_backend(backend: Backend) -> Backend:
    if not backend.supports_ttl:
        pytest.skip(f"{backend.name} has no store-wide TTL")
    return backend


class TestProtocol:
    async def test_implements_store_and_expiring_store(self, store: Any) -> None:
        typed: Store = store
        assert isinstance(typed, ExpiringStore)


class TestKeyValue:
    async def test_missing_key_reads_none(self, store: Any) -> None:
        assert await store.get("missing") is None

    @pytest.mark.parametrize("value", ["value", "", "ünïcødé ✓", '{"json": [1, 2]}'])
    async def test_put_then_get_roundtrips(self, store: Any, value: str) -> None:
        await store.put("k", value)
        assert await store.get("k") == value

    async def test_put_overwrites(self, store: Any) -> None:
        await store.put("k", "first")
        await store.put("k", "second")
        assert await store.get("k") == "second"

    async def test_delete_removes_only_its_key(self, store: Any) -> None:
        await store.put("a", "1")
        await store.put("b", "2")
        await store.delete("a")
        assert await store.get("a") is None
        assert await store.get("b") == "2"

    async def test_delete_missing_key_is_a_noop(self, store: Any) -> None:
        await store.delete("missing")
        assert await store.get("missing") is None

    async def test_keys_are_case_sensitive_and_opaque(self, store: Any) -> None:
        await store.put("Key", "upper")
        await store.put("key", "lower")
        await store.put("a:b/c d", "punctuated")
        assert await store.get("Key") == "upper"
        assert await store.get("key") == "lower"
        assert await store.get("a:b/c d") == "punctuated"

    async def test_values_persist_without_ttl(self, backend: Backend, store: Any) -> None:
        await store.put("k", "v")
        assert await store.put_if_absent("claim", "v")
        await backend.advance(0.05 if backend.name == "redis" else 10 * 365 * 86400)
        assert await store.get("k") == "v"
        assert await store.get("claim") == "v"


class TestPutIfAbsent:
    async def test_claims_new_key(self, store: Any) -> None:
        assert await store.put_if_absent("k", "first") is True
        assert await store.get("k") == "first"

    @pytest.mark.parametrize("writer", ["put", "put_if_absent"])
    async def test_rejects_existing_key_without_overwriting(self, store: Any, writer: str) -> None:
        await getattr(store, writer)("k", "first")
        assert await store.put_if_absent("k", "second") is False
        assert await store.get("k") == "first"

    async def test_claims_again_after_delete(self, store: Any) -> None:
        assert await store.put_if_absent("k", "first")
        await store.delete("k")
        assert await store.put_if_absent("k", "second") is True
        assert await store.get("k") == "second"

    async def test_concurrent_claims_have_exactly_one_winner(self, store: Any) -> None:
        values = [f"claimant-{index}" for index in range(25)]

        results = await asyncio.gather(*(store.put_if_absent("k", value) for value in values))

        winners = [value for value, won in zip(values, results, strict=True) if won]
        assert len(winners) == 1
        assert await store.get("k") == winners[0]

    async def test_concurrent_claims_on_distinct_keys_all_win(self, store: Any) -> None:
        keys = [f"k{index}" for index in range(10)]

        results = await asyncio.gather(*(store.put_if_absent(key, key) for key in keys))

        assert results == [True] * len(keys)
        assert [await store.get(key) for key in keys] == keys


class TestTtl:
    async def test_put_expires_after_ttl(self, ttl_backend: Backend) -> None:
        store = await ttl_backend.make(ttl_seconds=TTL_SECONDS)
        await store.put("k", "v")
        assert await store.get("k") == "v"
        await ttl_backend.advance(TTL_SECONDS + 0.5)
        assert await store.get("k") is None

    async def test_expired_put_can_be_claimed(self, ttl_backend: Backend) -> None:
        store = await ttl_backend.make(ttl_seconds=TTL_SECONDS)
        await store.put("k", "stale")
        await ttl_backend.advance(TTL_SECONDS + 0.5)
        assert await store.put_if_absent("k", "fresh") is True
        assert await store.get("k") == "fresh"

    async def test_replay_claims_ignore_ttl(self, ttl_backend: Backend) -> None:
        store = await ttl_backend.make(ttl_seconds=TTL_SECONDS)
        assert await store.put_if_absent("paid", "receipt")
        await ttl_backend.advance(TTL_SECONDS + 0.5)
        assert await store.get("paid") == "receipt"
        assert await store.put_if_absent("paid", "replay") is False


class TestAbsoluteExpiry:
    async def test_expires_at_deadline_then_reclaims(self, backend: Backend, store: Any) -> None:
        assert await store.put_if_absent_until("k", "first", backend.now() + LIVE_SECONDS) is True
        assert await store.get("k") == "first"
        await backend.advance(EXPIRE_AFTER)
        assert await store.get("k") is None
        assert await store.put_if_absent_until("k", "second", backend.now() + LIVE_SECONDS) is True
        assert await store.get("k") == "second"

    async def test_live_key_keeps_value_and_deadline(self, backend: Backend, store: Any) -> None:
        assert await store.put_if_absent_until("k", "first", backend.now() + LIVE_SECONDS)
        assert await store.put_if_absent_until("k", "second", backend.now() + 3600) is False
        assert await store.put_if_absent("k", "third") is False
        assert await store.get("k") == "first"
        await backend.advance(EXPIRE_AFTER)
        assert await store.get("k") is None

    async def test_does_not_replace_a_persistent_key(self, backend: Backend, store: Any) -> None:
        await store.put("k", "persistent")
        assert await store.put_if_absent_until("k", "temp", backend.now() + LIVE_SECONDS) is False
        await backend.advance(EXPIRE_AFTER)
        assert await store.get("k") == "persistent"

    async def test_put_clears_the_deadline(self, backend: Backend, store: Any) -> None:
        assert await store.put_if_absent_until("k", "temp", backend.now() + LIVE_SECONDS)
        await store.put("k", "kept")
        await backend.advance(EXPIRE_AFTER)
        assert await store.get("k") == "kept"

    @pytest.mark.parametrize("deadline", ["now", "past", "nan", "inf"])
    async def test_rejects_invalid_deadlines(
        self, backend: Backend, store: Any, deadline: str
    ) -> None:
        now = backend.now()
        value = {"now": now - 0.001, "past": now - 60, "nan": float("nan"), "inf": float("inf")}
        with pytest.raises(ValueError, match="finite future"):
            await store.put_if_absent_until("k", "v", value[deadline])
        assert await store.get("k") is None


class TestScoping:
    async def test_instances_on_one_backend_share_state(self, backend: Backend) -> None:
        if backend.name == "memory":
            pytest.skip("each MemoryStore owns its data")
        first, second = await backend.make(), await backend.make()
        assert await first.put_if_absent("k", "v")
        assert await second.put_if_absent("k", "other") is False
        assert await second.get("k") == "v"

    async def test_memory_instances_are_isolated(self, backend: Backend) -> None:
        if backend.name != "memory":
            pytest.skip("only MemoryStore keeps per-instance data")
        first, second = await backend.make(), await backend.make()
        await first.put("k", "v")
        assert await second.get("k") is None

    async def test_key_prefix_scopes_every_operation(self, backend: Backend) -> None:
        if backend.name != "redis":
            pytest.skip("only RedisStore takes a key_prefix")
        tenant = f"tenant:{uuid.uuid4().hex[:8]}:"
        other = f"other:{uuid.uuid4().hex[:8]}:"
        a = await backend.make(key_prefix=tenant)
        b = await backend.make(key_prefix=other)
        raw = await backend.make(key_prefix="")

        await a.put("k", "a")
        assert await a.put_if_absent("claim", "a")
        assert await b.get("k") is None
        assert await b.put_if_absent("claim", "b") is True
        assert await raw.get(f"{tenant}k") == "a"
        assert await raw.get("k") is None

        await b.delete("k")
        assert await a.get("k") == "a"
        await a.delete("k")
        assert await raw.get(f"{tenant}k") is None
        for prefix in (tenant, other):
            await raw.delete(f"{prefix}claim")
