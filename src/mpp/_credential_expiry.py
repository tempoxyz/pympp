"""Expiry grace for credentials a server method can prove were paid in time (mppx).

A method may keep accepting some credentials for a bounded time after their challenge
expires: for a payment it can prove completed before the expiry, whose credential only
arrived later. The method enforces that proof itself; the generic expiry checks only
leave it room to.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from mpp import Credential

GraceFn = Callable[[Credential], float]
"""Seconds after its challenge expires that a method still accepts a credential."""


def grace_of(target: Any, credential: Credential) -> float:
    """The grace ``target`` (a server method or intent) gives ``credential``, in seconds.

    Targets without a ``_credential_grace`` function give none.
    """
    grace = getattr(target, "_credential_grace", None)
    if not callable(grace):
        return 0.0
    try:
        seconds = grace(credential)
    except Exception:  # noqa: BLE001 - a failing grace function grants none
        return 0.0
    if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
        return 0.0
    return float(seconds)


def is_expired(expires: datetime, now: datetime, grace: float = 0.0) -> bool:
    """Whether a challenge expiring at ``expires`` is past its grace of ``grace`` seconds."""
    return now >= expires + timedelta(seconds=grace) if grace > 0 else expires <= now
