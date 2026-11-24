"""Expiry grace for credentials a server method can prove were paid in time (mppx).

A method may keep accepting some credentials for a bounded time after their challenge
expires: for a payment it can prove completed before the expiry, whose credential only
arrived later. The method enforces that proof itself; the generic expiry checks only
leave it room to.

Only a challenge issued while the method allows a grace gets one: issuance marks it in its
HMAC-bound opaque metadata (:data:``EXPIRY_GRACE_KEY``), so a challenge issued without the
mark, by an earlier release or with no grace configured, is rejected at its expiry.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, cast

from mpp import Credential
from mpp._parsing import ParseError, _b64_decode

EXPIRY_GRACE_KEY = "_mppx_expiry_grace"
"""Reserved opaque metadata key marking a challenge whose method accepts some of its
credentials for a while after it expires (mppx). Bound by the challenge HMAC."""

GraceFn = Callable[[Credential], float]
"""Seconds after its challenge expires that a method still accepts a credential."""


def with_expiry_grace(meta: dict[str, str] | None, grace: bool) -> dict[str, str] | None:
    """``meta`` with the expiry grace marker when ``grace`` is true, else without any copy of it."""
    rest = {key: value for key, value in (meta or {}).items() if key != EXPIRY_GRACE_KEY}
    if grace:
        return {**rest, EXPIRY_GRACE_KEY: "1"}
    if meta is None or EXPIRY_GRACE_KEY not in meta:
        return meta
    return rest or None


def issuance_meta(target: Any, meta: dict[str, str] | None) -> dict[str, str] | None:
    """Opaque metadata for a challenge ``target`` (a server method or intent) issues.

    Carries the expiry grace marker when ``target`` allows a grace (its
    ``_issue_expiry_grace`` is true), and never otherwise.
    """
    return with_expiry_grace(meta, getattr(target, "_issue_expiry_grace", False) is True)


def has_expiry_grace(challenge: Any) -> bool:
    """Whether a challenge, or the echo a credential carries, has the expiry grace marker.

    Reads the opaque metadata the challenge HMAC covers: a dict on a challenge, its
    base64url encoding on an echo. Anything unreadable has no marker.
    """
    opaque: object = getattr(challenge, "opaque", None)
    if isinstance(opaque, str):
        try:
            opaque = _b64_decode(opaque)
        except (ParseError, ValueError, TypeError):
            return False
    if not isinstance(opaque, dict):
        return False
    return cast("dict[str, object]", opaque).get(EXPIRY_GRACE_KEY) == "1"


def grace_of(target: Any, credential: Credential) -> float:
    """The grace ``target`` (a server method or intent) gives ``credential``, in seconds.

    Targets without a ``_credential_grace`` function give none, and neither does a challenge
    issued without the expiry grace marker.
    """
    if not has_expiry_grace(credential.challenge):
        return 0.0
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
