"""Rolling limits for sponsored session top-ups, shared across server instances."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.fee_payer_policy import DEFAULT_POLICY
from mpp.store import CompareAndSetStore


__all__ = ["SessionSponsorshipLimit"]


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSponsorshipLimit:
    """Bound top-up sponsorship over a rolling window.

    Reservations consume the maximum permitted envelope fee for the entire window,
    including failed or uncertain attempts. This conservatively bounds fees without
    trusting client-supplied fee estimates or releasing capacity after each success.
    Share the store and policy across every instance using the same sponsor.
    """

    per_payer: int = 5
    """Maximum sponsored top-ups per payer across all its channels in the window."""
    max_total_fee: int = DEFAULT_POLICY.max_total_fee * 100
    """Aggregate maximum permitted fees across all payers, in attodollars."""
    max_transactions: int = 100
    """Aggregate top-up attempts; also bounds the retained rolling-window history."""
    window_seconds: int = 86_400
    """Rolling window duration, default 24 hours."""
    store: CompareAndSetStore | None = None
    """Shared atomic backend; defaults to the session channel store."""

    def __post_init__(self) -> None:
        for name in ("per_payer", "max_total_fee", "max_transactions", "window_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.store is not None and not isinstance(self.store, CompareAndSetStore):
            raise TypeError("sponsorship limit store must support compare_and_set")


class _Entry(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    at: float = Field(ge=0, allow_inf_nan=False)
    payer: str
    fee: int = Field(ge=0)


class _Usage(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    entries: list[_Entry]


async def reserve_top_up(
    *,
    limit: SessionSponsorshipLimit,
    store: CompareAndSetStore,
    chain_id: int,
    sponsor: str,
    payer: str,
    maximum_fee: int,
) -> None:
    """Atomically consume a payer allowance and aggregate fee allowance before broadcast."""
    key = f"mpp:session:sponsorship:{chain_id}:{sponsor.lower()}"
    payer = payer.lower()
    if maximum_fee < 0:
        raise VerificationFailedError("Invalid sponsorship fee limit")
    while True:
        now = time.time()
        raw = await store.get(key)
        try:
            usage = _Usage.model_validate_json(raw) if raw is not None else _Usage(entries=[])
        except (ValidationError, TypeError, ValueError) as error:
            raise VerificationFailedError("Invalid stored sponsorship usage") from error
        entries = [entry for entry in usage.entries if entry.at > now - limit.window_seconds]
        if (
            sum(entry.payer == payer for entry in entries) >= limit.per_payer
            or len(entries) >= limit.max_transactions
            or sum(entry.fee for entry in entries) + maximum_fee > limit.max_total_fee
        ):
            raise VerificationFailedError("Session top-up sponsorship allowance exhausted")
        entries.append(_Entry(at=now, payer=payer, fee=maximum_fee))
        value = json.dumps(_Usage(entries=entries).model_dump(), separators=(",", ":"))
        if await store.compare_and_set(key, raw, value):
            return
