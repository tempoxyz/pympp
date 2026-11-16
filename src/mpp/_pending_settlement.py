"""Retry credential creation while a Zone withdrawal settles (mppx ``PendingSettlement``)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from mpp.errors import ZoneSettlementPendingError

_T = TypeVar("_T")


async def resume(create: Callable[[bool], Awaitable[_T]], attempts: int) -> _T:
    """Create a credential, again for the same challenge while its withdrawal settles.

    Calls ``create`` up to ``attempts`` times in all, retrying only on
    :class:`~mpp.errors.ZoneSettlementPendingError`: each attempt resumes waiting for the
    withdrawal that pays the challenge, and requesting a new challenge would not settle it
    sooner. Any other error is raised at once, and cancelling the caller stops it.

    ``create`` takes whether to check the challenge's expiry: only the first attempt does,
    as mppx checks it once before resuming. A withdrawal that settled before the challenge
    expired can still be redeemed within the server's grace, so later attempts let the
    method look it up rather than fail with :class:`~mpp.errors.PaymentExpiredError`.
    """
    attempt = 1
    while True:
        try:
            return await create(attempt == 1)
        except ZoneSettlementPendingError:
            if attempt >= attempts:
                raise
        attempt += 1
