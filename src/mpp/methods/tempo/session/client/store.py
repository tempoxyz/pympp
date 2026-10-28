"""Client channel store for TIP-1034 sessions (mppx session/client/ChannelStore.ts).

Payer channels are cached per payment scope (payee, token, escrow, chain), so a
client reuses one channel and its deposit across requests. The default store is
in memory; :func:`create_json_channel_store` persists entries in any string
key-value backend.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import weakref
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol, TypeVar, cast

from mpp.methods.tempo.session.protocol import ChannelDescriptor

T = TypeVar("T")

_CHANNEL_PREFIX = "chan:"


@dataclass(slots=True, kw_only=True)
class ChannelEntry:
    """Client-side cached channel metadata used for automatic voucher management.

    Attributes:
        channel_id: TIP-1034 channel ID derived from descriptor, escrow and chain ID.
        cumulative_amount: Highest cumulative amount this client has authorized, in raw units.
        deposit: Latest channel deposit the client knows, in raw units.
        descriptor: Descriptor required for vouchers, top-ups and close credentials.
        escrow: Escrow address used to derive ``channel_id``.
        chain_id: Chain ID used for channel ID and voucher domain separation.
        opened: Whether the client considers the channel reusable for new vouchers.
        uncertain_top_up: Blocks new deposits until an uncertain top-up is reconciled.
    """

    channel_id: str
    cumulative_amount: int
    deposit: int
    descriptor: ChannelDescriptor
    escrow: str
    chain_id: int
    opened: bool
    uncertain_top_up: bool = False

    def copy(self, **changes: Any) -> ChannelEntry:
        """A copy with ``changes`` applied."""
        return replace(self, **changes)


class ChannelStore(Protocol):
    """Store of reusable payer session channels keyed by payment scope.

    Methods may be sync or async. Callers sharing a backend across processes
    must coordinate funding and writes externally.
    """

    def get(self, key: str) -> ChannelEntry | None | Awaitable[ChannelEntry | None]:
        """Return the channel cached for ``key``, when present."""
        ...

    def set(self, entry: ChannelEntry) -> None | Awaitable[None]:
        """Insert or replace a channel entry."""
        ...

    def delete(self, key: str) -> None | Awaitable[None]:
        """Remove the channel cached for ``key``."""
        ...


class JsonChannelKv(Protocol):
    """Plain string key-value backend a :func:`create_json_channel_store` persists into."""

    def get(self, key: str) -> str | None | Awaitable[str | None]: ...

    def set(self, key: str, value: str) -> None | Awaitable[None]: ...

    def delete(self, key: str) -> None | Awaitable[None]: ...


async def maybe_await(value: T | Awaitable[T]) -> T:
    """Await ``value`` when it is awaitable."""
    if inspect.isawaitable(value):
        return await cast("Awaitable[T]", value)
    return value


def channel_key(*, payee: str, token: str, escrow: str, chain_id: int) -> str:
    """The scope key for a reusable payer session channel."""
    return f"{payee.lower()}:{token.lower()}:{escrow.lower()}:{chain_id}"


def entry_key(entry: ChannelEntry) -> str:
    """The scope key for a stored channel entry."""
    return channel_key(
        payee=entry.descriptor.payee,
        token=entry.descriptor.token,
        escrow=entry.escrow,
        chain_id=entry.chain_id,
    )


class MemoryChannelStore:
    """The default in-memory :class:`ChannelStore`."""

    def __init__(self) -> None:
        self._channels: dict[str, ChannelEntry] = {}

    def get(self, key: str) -> ChannelEntry | None:
        return self._channels.get(key)

    def set(self, entry: ChannelEntry) -> None:
        self._channels[entry_key(entry)] = entry

    def delete(self, key: str) -> None:
        self._channels.pop(key, None)


def create_channel_store() -> MemoryChannelStore:
    """Create the default in-memory :class:`ChannelStore`."""
    return MemoryChannelStore()


def serialize_entry(entry: ChannelEntry) -> dict[str, Any]:
    """The JSON-safe form of an entry, amounts as decimal strings (mppx ``StoredChannel``)."""
    stored: dict[str, Any] = {
        "channelId": entry.channel_id,
        "cumulativeAmount": str(entry.cumulative_amount),
        "deposit": str(entry.deposit),
        "descriptor": entry.descriptor.to_wire(),
        "escrow": entry.escrow,
        "chainId": entry.chain_id,
        "opened": entry.opened,
    }
    if entry.uncertain_top_up:
        stored["uncertainTopUp"] = True
    return stored


def deserialize_entry(stored: dict[str, Any]) -> ChannelEntry:
    """Restore a channel entry from :func:`serialize_entry`'s form."""
    return ChannelEntry(
        channel_id=str(stored["channelId"]),
        cumulative_amount=int(stored["cumulativeAmount"]),
        deposit=int(stored["deposit"]),
        descriptor=ChannelDescriptor.from_wire(stored["descriptor"]),
        escrow=str(stored["escrow"]),
        chain_id=int(stored["chainId"]),
        opened=bool(stored["opened"]),
        uncertain_top_up=bool(stored.get("uncertainTopUp", False)),
    )


class JsonChannelStore:
    """A bigint-safe :class:`ChannelStore` over a string key-value backend."""

    def __init__(self, kv: JsonChannelKv) -> None:
        self._kv = kv

    async def get(self, key: str) -> ChannelEntry | None:
        value = await maybe_await(self._kv.get(_CHANNEL_PREFIX + key))
        if value is None:
            return None
        return deserialize_entry(json.loads(value))

    async def set(self, entry: ChannelEntry) -> None:
        value = json.dumps(serialize_entry(entry), separators=(",", ":"))
        await maybe_await(self._kv.set(_CHANNEL_PREFIX + entry_key(entry), value))

    async def delete(self, key: str) -> None:
        await maybe_await(self._kv.delete(_CHANNEL_PREFIX + key))


def create_json_channel_store(kv: JsonChannelKv) -> JsonChannelStore:
    """Wrap a string key-value backend as a channel store."""
    return JsonChannelStore(kv)


async def store_get(store: ChannelStore, key: str) -> ChannelEntry | None:
    """Read ``key`` from a sync or async store."""
    return await maybe_await(store.get(key))


async def store_set(store: ChannelStore, entry: ChannelEntry) -> None:
    """Write ``entry`` to a sync or async store."""
    await maybe_await(store.set(entry))


async def store_delete(store: ChannelStore, key: str) -> None:
    """Delete ``key`` from a sync or async store."""
    await maybe_await(store.delete(key))


# ──────────────────────────────────────────────────────────────────
# In-process coordination
# ──────────────────────────────────────────────────────────────────

_locks: weakref.WeakKeyDictionary[Any, dict[str, asyncio.Lock]] = weakref.WeakKeyDictionary()
_funding_stores: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()


def store_lock(store: ChannelStore, key: str) -> asyncio.Lock:
    """The in-process lock for ``key`` on ``store``, created on first use."""
    locks = _locks.get(store)
    if locks is None:
        locks = {}
        _locks[store] = locks
    lock = locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        locks[key] = lock
    return lock


def register_funding_store(view: ChannelStore, backing: ChannelStore) -> None:
    """Share funding coordination between a manager's store view and its backing store."""
    _funding_stores[view] = _funding_stores.get(backing, backing)


async def with_funding_lock(
    store: ChannelStore, key: str, operation: Callable[[], Awaitable[T]]
) -> T:
    """Serialize funding decisions for callers sharing one backing store in this process."""
    async with store_lock(_funding_stores.get(store, store), f"funding:{key}"):
        return await operation()


class UncertainFundingError(Exception):
    """A top-up's outcome is unknown: its request failed after the transaction was sent."""


async def persist_channel(store: ChannelStore, entry: ChannelEntry) -> None:
    """Write ``entry``, preserving an unresolved top-up flag across stale copies."""
    key = entry_key(entry)
    async with store_lock(store, f"write:{key}"):
        current = await store_get(store, key)
        if current is not None and current.uncertain_top_up:
            if current.channel_id != entry.channel_id:
                raise UncertainFundingError(
                    "Session funding outcome is unknown; reconcile the pending payment before "
                    "replacing the channel."
                )
            entry.uncertain_top_up = True
        await store_set(store, entry)


async def delete_channel(store: ChannelStore, key: str) -> None:
    """Delete ``key``, keeping entries whose top-up outcome is unknown."""
    async with store_lock(store, f"write:{key}"):
        current = await store_get(store, key)
        if current is not None and current.uncertain_top_up:
            return
        await store_delete(store, key)
