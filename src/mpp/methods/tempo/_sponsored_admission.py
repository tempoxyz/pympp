"""Atomic challenge and payer admission for locally sponsored charge transactions."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from mpp.errors import CredentialReplayedError, InternalPaymentError
from mpp.store import CompareAndSetStore, ExpiringStore


@dataclass(frozen=True, slots=True)
class Claim:
    key: str
    value: str
    created: bool


def _text(value: str | bytes | None) -> str | None:
    return value.decode() if isinstance(value, bytes) else value


def _key(kind: str, *scope: object) -> str:
    digest = hashlib.sha256(json.dumps(scope, separators=(",", ":")).encode()).hexdigest()
    return f"mpp:charge-admission:{kind}:{digest}"


async def claim_challenge(
    store: CompareAndSetStore,
    *,
    realm: str | None,
    chain_id: int,
    challenge_id: str | None,
    transaction_hash: str,
    payer: str,
    currency: str,
    amount: str,
    expires_at: float | None,
) -> Claim:
    """Bind a challenge permanently to one transaction until its acceptance window expires."""
    if not challenge_id:
        raise InternalPaymentError() from ValueError("Sponsored charges require a challenge ID")
    key = _key("challenge", realm, chain_id, challenge_id)
    value = json.dumps(
        {
            "hash": transaction_hash.lower(),
            "payer": payer.lower(),
            "currency": currency.lower(),
            "amount": amount,
        },
        sort_keys=True,
    )
    if expires_at is not None and isinstance(store, ExpiringStore):
        inserted = await store.put_if_absent_until(key, value, expires_at)
    else:
        inserted = await store.put_if_absent(key, value)
    if not inserted and _text(await store.get(key)) != value:
        raise CredentialReplayedError("Challenge is already bound to another transaction")
    return Claim(key, value, inserted)


async def claim_payer(
    store: CompareAndSetStore,
    *,
    chain_id: int,
    payer: str,
    currency: str,
    transaction_hash: str,
    expires_at: float,
) -> Claim:
    """Permit one pending transaction per chain, payer, and charge token before simulation."""
    key = _key("payer", chain_id, payer.lower(), currency.lower())
    value = json.dumps({"hash": transaction_hash.lower(), "expiresAt": expires_at}, sort_keys=True)
    while True:
        current = _text(await store.get(key))
        if current is not None:
            try:
                prior = json.loads(current)
                if prior["hash"] == transaction_hash.lower():
                    return Claim(key, current, False)
                if float(prior["expiresAt"]) > time.time():
                    raise InternalPaymentError() from RuntimeError(
                        "Payer has a pending sponsored transaction"
                    )
            except (TypeError, ValueError, KeyError) as error:
                raise InternalPaymentError() from error
        if await store.compare_and_set(key, current, value):
            return Claim(key, value, True)


async def release(store: CompareAndSetStore, claim: Claim) -> None:
    """Release only the exact claim this operation observed, preserving a newer owner."""
    await store.compare_and_set(claim.key, claim.value, None)
