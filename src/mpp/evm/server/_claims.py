"""Authorization claims that stop one EIP-3009 authorization from settling twice."""

import heapq
import time
import warnings
from typing import Any

from mpp import store as _store

CLAIM_GRACE_SECONDS = 60
"""How long a claim outlives its authorization's ``validBefore``."""


class ClaimCacheFullError(Exception):
    """The in-process claim cache holds as many live claims as it may."""


def claim_key(*, chain_id: int, currency: str, payer: str, nonce: str) -> str:
    """Returns the replay key of an authorization (``chain:currency:from:nonce``)."""
    return ":".join(
        ("mpp:evm:authorization", str(chain_id), currency.lower(), payer.lower(), nonce.lower())
    )


def claim_expires(valid_before: int) -> int:
    """Returns when a claim may lapse (Unix ms): after its authorization can no longer settle."""
    return (valid_before + CLAIM_GRACE_SECONDS) * 1000


def is_claimed(value: Any | None) -> bool:
    """Returns whether a stored value is a live claim."""
    if value is None:
        return False
    return not _store.is_replay_marker(value) or value["expires"] > time.time() * 1000


class ClaimCache:
    """In-process claims that expire with their authorization.

    A claim only has to outlive its authorization's ``validBefore``, which the charge caps, so
    expired claims are pruned on write and memory is bounded by the payment rate times that
    window. Live claims, pending or settled, are never evicted: at ``max_entries`` new claims
    are refused (:class:`ClaimCacheFullError`) rather than forgetting a payment and inviting a
    second one. The expiry heap is compacted when rolled-back claims leave stale entries.
    """

    def __init__(self, max_entries: int = 1_000_000) -> None:
        self._limit = max_entries
        self._data: dict[str, Any] = {}
        self._heap: list[tuple[int, str]] = []

    async def get(self, key: str) -> Any | None:
        self._prune()
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def update[R](self, key: str, fn: _store.UpdateFn[R]) -> R:
        change = fn(self._data.get(key))
        match change:
            case _store.Set(value=value):
                self._data[key] = value
            case _store.Delete():
                self._data.pop(key, None)
            case _store.Noop():
                pass
        return change.result

    async def try_claim(self, key: str, expires: int) -> bool:
        self._prune()
        if is_claimed(self._data.get(key)):
            return False
        if len(self._data) >= self._limit:
            raise ClaimCacheFullError("in-process EVM claim cache is full; configure a store")
        self._data[key] = {"expires": expires, "type": _store.REPLAY_MARKER_TYPE}
        heapq.heappush(self._heap, (expires, key))
        if len(self._heap) > 2 * len(self._data) + 1024:
            self._heap = [(_expiry(value), name) for name, value in self._data.items()]
            heapq.heapify(self._heap)
        return True

    def _prune(self) -> None:
        now = int(time.time() * 1000)
        while self._heap and self._heap[0][0] <= now:
            expires, key = heapq.heappop(self._heap)
            value = self._data.get(key)
            if value is not None and _expiry(value) == expires:
                del self._data[key]


def _expiry(value: Any) -> int:
    return int(value["expires"]) if _store.is_replay_marker(value) else 2**63


_warned = False


def fallback_store() -> ClaimCache:
    """Returns a fresh in-process claim cache, warning once per process."""
    global _warned
    if not _warned:
        _warned = True
        warnings.warn(
            "evm.charge() has no `store` configured and is using an in-memory store. Replay "
            "protection is scoped to this instance, so an authorization accepted by one replica "
            "or worker process can be settled again through another. Pass a shared atomic store "
            "(e.g. `mpp.store.redis()`) when running more than one instance.",
            stacklevel=3,
        )
    return ClaimCache()
