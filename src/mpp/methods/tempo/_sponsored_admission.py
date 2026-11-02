"""Atomic challenge and payer admission for locally sponsored charge transactions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from mpp._typing import is_dict, is_list
from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationError
from mpp.store import CompareAndSetStore, ExpiringStore


@dataclass(frozen=True, slots=True)
class Claim:
    key: str
    value: str
    created: bool
    attempt: str | None = None


def _text(value: str | bytes | None) -> str | None:
    return value.decode() if isinstance(value, bytes) else value


def _key(kind: str, *scope: object) -> str:
    digest = hashlib.sha256(json.dumps(scope, separators=(",", ":")).encode()).hexdigest()
    return f"mpp:charge-admission:{kind}:{digest}"


async def ensure_atomic_store(store: CompareAndSetStore) -> None:
    """Verify that admission owners can be released before reserving any payment."""
    key = f"mpp:charge-admission:probe:{uuid4().hex}"
    try:
        if not await store.put_if_absent(key, "probe"):
            raise RuntimeError("Admission store probe could not be reserved")
        await release(store, Claim(key, "probe", True))
        if await store.get(key) is not None:
            raise RuntimeError("Admission store requires working compare_and_set")
    finally:
        await store.delete(key)


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
    key = _key("challenge", realm, chain_id, challenge_id, payer.lower())
    binding = {
        "hash": transaction_hash.lower(),
        "payer": payer.lower(),
        "currency": currency.lower(),
        "amount": amount,
    }
    attempt = uuid4().hex
    value = json.dumps({**binding, "attempts": [attempt], "retained": False}, sort_keys=True)
    for _ in range(100):
        if expires_at is not None and isinstance(store, ExpiringStore):
            inserted = await store.put_if_absent_until(key, value, expires_at)
        else:
            inserted = await store.put_if_absent(key, value)
        if inserted:
            return Claim(key, value, True, attempt)
        raw = await store.get(key)
        current = _text(raw)
        if current is None:
            continue
        try:
            parsed: object = json.loads(current)
        except ValueError as error:
            raise InternalPaymentError() from error
        if not is_dict(parsed):
            raise InternalPaymentError() from ValueError("Malformed challenge binding")
        bound = dict(parsed)
        if _binding(bound) != binding:
            raise CredentialReplayedError("Challenge is already bound to another transaction")
        attempts = _attempts(bound)
        # Legacy bindings cannot prove that every pre-upgrade attempt failed before submission.
        retained = bound.get("retained", True)
        adopted = json.dumps(
            {**binding, "attempts": [*attempts, attempt], "retained": retained}, sort_keys=True
        )
        if await store.compare_and_set(key, raw, adopted) or (
            isinstance(raw, bytes) and await store.compare_and_set(key, current, adopted)
        ):
            return Claim(key, adopted, False, attempt)
    raise InternalPaymentError() from RuntimeError("Challenge admission contention")


async def claim_payer(
    store: CompareAndSetStore,
    *,
    chain_id: int,
    payer: str,
    currency: str,
    transaction_hash: str,
    expires_at: float,
    reconciling: bool = False,
    wait_until: float = 0,
    receipt_hash: str | None = None,
    is_settled: Callable[[str, float], Awaitable[bool]] | None = None,
) -> Claim:
    """Permit one pending transaction per chain and payer before simulation."""
    key = _key("payer", chain_id, payer.lower())
    value = json.dumps(
        {
            "hash": transaction_hash.lower(),
            "receiptHash": receipt_hash or transaction_hash.lower(),
            "expiresAt": expires_at,
        },
        sort_keys=True,
    )
    if reconciling and expires_at <= time.time():
        # An expired envelope can only be reconciled, not newly included.
        return Claim(key, value, False)
    checked: str | None = None
    for _ in range(200):
        raw = await store.get(key)
        current = _text(raw)
        if current is not None:
            try:
                prior = json.loads(current)
                if reconciling and prior["hash"] == transaction_hash.lower():
                    return Claim(key, current, False)
                expiry = float(prior["expiresAt"])
            except (TypeError, ValueError, KeyError) as error:
                raise InternalPaymentError() from error
            if is_settled is not None and (checked != current or time.time() >= wait_until):
                if await is_settled(prior.get("receiptHash", prior["hash"]), expiry):
                    await release(store, Claim(key, current, False))
                    continue
                checked = current
            if expiry > time.time() and time.time() < wait_until:
                await asyncio.sleep(max(0, min(0.05, wait_until - time.time())))
                continue
            if not reconciling and prior["hash"] != transaction_hash.lower():
                raise VerificationError(
                    "Payer has another pending sponsored transaction; "
                    "this transaction was not submitted"
                )
            raise InternalPaymentError() from RuntimeError(
                "Payer's earlier submission is not confirmed settled or excluded by chain time"
            )
        # Wall-clock expiry cannot prove that a lagging chain excluded the transaction.
        # Retain unknown attempts until a later admission checks receipt and chain time.
        inserted = await store.put_if_absent(key, value)
        if inserted:
            return Claim(key, value, True)
    raise InternalPaymentError() from RuntimeError("Payer admission contention")


def _binding(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k not in ("adopted", "attempts", "retained")}


def _attempts(value: dict[str, Any]) -> list[str]:
    attempts = value.get("attempts", [])
    if (
        not is_list(attempts)
        or not all(isinstance(item, str) for item in attempts)
        or not isinstance(value.get("retained", True), bool)
    ):
        raise InternalPaymentError() from ValueError("Malformed challenge ownership")
    return attempts


async def release(
    store: CompareAndSetStore,
    claim: Claim,
    *,
    retain: bool = False,
    reset_retained: bool = False,
) -> None:
    """Release this attempt; keep shared bindings until all attempts safely finish."""
    for _ in range(100):
        raw = await store.get(claim.key)
        current = _text(raw)
        value = None
        if claim.attempt is None:
            if current != claim.value:
                return
        else:
            if current is None:
                return
            bound = json.loads(current)
            if not is_dict(bound) or _binding(bound) != _binding(json.loads(claim.value)):
                return
            attempts = _attempts(bound)
            if claim.attempt not in attempts:
                return
            attempts = [item for item in attempts if item != claim.attempt]
            retained = retain or (bound.get("retained", True) and not reset_retained)
            if not reset_retained and (attempts or retained):
                value = json.dumps(
                    {**_binding(bound), "attempts": attempts, "retained": retained}, sort_keys=True
                )
        if await store.compare_and_set(claim.key, raw, value):
            return
        if isinstance(raw, bytes) and await store.compare_and_set(claim.key, current, value):
            return
        if claim.attempt is None:
            return
    raise InternalPaymentError() from RuntimeError("Admission cleanup contention")
