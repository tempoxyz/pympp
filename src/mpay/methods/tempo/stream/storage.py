"""Storage interface for channel and session state persistence.

Uses atomic update callbacks for read-modify-write safety.
Backends implement atomicity via their native mechanisms
(Python single-thread, database transactions, etc.).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from mpay.methods.tempo.stream.types import SignedVoucher


@dataclass
class ChannelState:
    """Channel state tracked by the server."""

    channel_id: str  # 0x-prefixed bytes32 hex
    payer: str  # 0x-prefixed address
    payee: str  # 0x-prefixed address
    token: str  # 0x-prefixed address
    authorized_signer: str  # 0x-prefixed address
    deposit: int  # uint128
    settled_on_chain: int  # uint128
    highest_voucher_amount: int  # uint128
    highest_voucher: SignedVoucher | None
    finalized: bool
    created_at: datetime
    active_session_id: str | None = None


@dataclass
class SessionState:
    """Session state for per-challenge accounting."""

    challenge_id: str
    channel_id: str  # 0x-prefixed bytes32 hex
    accepted_cumulative: int  # uint128
    spent: int  # uint128
    units: int
    created_at: datetime


class ChannelStorage(Protocol):
    """Storage interface for channel state persistence.

    Uses atomic update callbacks for read-modify-write safety.

    The ``update_channel`` and ``update_session`` methods accept a callback
    that receives the current state (or None) and returns the new state
    (or None to delete). Backends must execute the callback atomically.
    """

    async def get_channel(self, channel_id: str) -> ChannelState | None: ...

    async def get_session(self, challenge_id: str) -> SessionState | None: ...

    async def update_channel(
        self,
        channel_id: str,
        fn: Callable[[ChannelState | None], ChannelState | None],
    ) -> ChannelState | None:
        """Atomic read-modify-write for channel state. Return None to delete."""
        ...

    async def update_session(
        self,
        challenge_id: str,
        fn: Callable[[SessionState | None], SessionState | None],
    ) -> SessionState | None:
        """Atomic read-modify-write for session state. Return None to delete."""
        ...


class MemoryStorage:
    """In-memory implementation of ChannelStorage.

    Suitable for single-process servers and testing.
    """

    def __init__(self) -> None:
        self._channels: dict[str, ChannelState] = {}
        self._sessions: dict[str, SessionState] = {}

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        return self._channels.get(channel_id)

    async def get_session(self, challenge_id: str) -> SessionState | None:
        return self._sessions.get(challenge_id)

    async def update_channel(
        self,
        channel_id: str,
        fn: Callable[[ChannelState | None], ChannelState | None],
    ) -> ChannelState | None:
        current = self._channels.get(channel_id)
        result = fn(current)
        if result is not None:
            self._channels[channel_id] = result
        else:
            self._channels.pop(channel_id, None)
        return result

    async def update_session(
        self,
        challenge_id: str,
        fn: Callable[[SessionState | None], SessionState | None],
    ) -> SessionState | None:
        current = self._sessions.get(challenge_id)
        result = fn(current)
        if result is not None:
            self._sessions[challenge_id] = result
        else:
            self._sessions.pop(challenge_id, None)
        return result
