"""Recognizing the same Challenge offered again on a payment retry (mppx ``Fetch``)."""

from __future__ import annotations

from mpp import Challenge


def same_challenge(offered: Challenge, answered: Challenge) -> bool:
    """Whether ``offered`` is the Challenge ``answered`` was paid for.

    Its id binds its terms, so the id and the terms it binds identify it; display fields
    such as the description do not.
    """
    return _terms(offered) == _terms(answered)


def _terms(challenge: Challenge) -> tuple[object, ...]:
    return (
        challenge.id,
        challenge.method,
        challenge.intent,
        challenge.realm,
        challenge.request,
        challenge.digest,
        challenge.expires,
        challenge.opaque,
        challenge.header,
    )
