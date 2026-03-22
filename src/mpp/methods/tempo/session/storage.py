"""Channel state persistence for Tempo session payments.

Provides the ``ChannelStore`` protocol and an in-memory implementation.
Ported from mpp-rs ``ChannelStore`` trait (session_method.rs).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol

from mpp.errors import VerificationError

if TYPE_CHECKING:
    from mpp.methods.tempo.session.types import ChannelState


class ChannelStore(Protocol):
    """Channel state persistence with atomic update semantics.

    Implementations must guarantee that ``update_channel`` executes
    the *updater* callback atomically (read-modify-write).
    """

    async def get_channel(self, channel_id: str) -> ChannelState | None: ...

    async def update_channel(
        self,
        channel_id: str,
        updater: Callable[[ChannelState | None], ChannelState | None],
    ) -> ChannelState | None: ...


class MemoryChannelStore:
    """In-memory channel store with per-key locking.

    Suitable for development and testing.
    Mirrors mpp-rs ``InMemoryChannelStore``.
    """

    def __init__(self) -> None:
        self._channels: dict[str, ChannelState] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, channel_id: str) -> asyncio.Lock:
        if channel_id not in self._locks:
            self._locks[channel_id] = asyncio.Lock()
        return self._locks[channel_id]

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        return self._channels.get(channel_id)

    async def update_channel(
        self,
        channel_id: str,
        updater: Callable[[ChannelState | None], ChannelState | None],
    ) -> ChannelState | None:
        async with self._get_lock(channel_id):
            current = self._channels.get(channel_id)
            result = updater(current)
            if result is None:
                self._channels.pop(channel_id, None)
            else:
                self._channels[channel_id] = result
            return result


async def deduct_from_channel(
    store: ChannelStore,
    channel_id: str,
    amount: int,
) -> ChannelState:
    """Atomically deduct *amount* from a channel's available balance.

    Raises ``VerificationError`` if the channel is not found or
    the available balance is insufficient.
    """

    def _updater(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            raise VerificationError("channel not found")
        available = current.highest_voucher_amount - current.spent
        if available < amount:
            raise VerificationError(
                f"insufficient balance: requested {amount}, available {available}"
            )
        return replace(current, spent=current.spent + amount, units=current.units + 1)

    result = await store.update_channel(channel_id, _updater)
    if result is None:
        raise VerificationError("channel not found")
    return result
