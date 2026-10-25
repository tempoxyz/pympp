"""In-memory fallback store for Tempo server methods configured without ``store``."""

from __future__ import annotations

import warnings

from mpp import store as _store

_warned: set[str] = set()


def fallback_store(method: str) -> _store.AtomicStore:
    """Returns a fresh in-memory store, warning once per ``method`` per process.

    Replay protection backed by this store only covers the current instance.
    """
    if method not in _warned:
        _warned.add(method)
        warnings.warn(
            f"{method}() has no `store` configured and is using an in-memory store. Replay "
            "protection and payment state are scoped to this instance, so a credential accepted "
            "by one replica, worker process, or per-request `Mpp` instance can be accepted again "
            "by another. Pass a shared atomic store (e.g. `mpp.store.redis()`) when running more "
            "than one instance.",
            stacklevel=3,
        )
    return _store.memory()
