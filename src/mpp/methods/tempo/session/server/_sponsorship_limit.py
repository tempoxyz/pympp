"""Limits on fee-payer-sponsored channel opens and top-ups (mppx ``server/SponsorshipLimit.ts``).

A server that sponsors fees lets each verified payer make ``per_day`` sponsored opens, and
separately ``per_day`` sponsored top-ups, per UTC day. The payer is what the transaction's
signatures prove, never the credential's client-supplied ``source``. Over the limit, or when no
signature proves a payer, the transaction is broadcast unsponsored, so it lands only if the
payer pays its own fees.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

from mpp.methods.tempo.session._protocol import OpenPayload, TopUpPayload
from mpp.store import CompareAndSetStore

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mpp.methods.tempo.session._protocol import SessionCredentialPayload
    from mpp.store import Store

__all__ = [
    "DEFAULT_PER_DAY",
    "SponsorshipLimit",
    "limit_fee_payer",
    "release",
    "reserve",
    "verified_payer",
]

DEFAULT_PER_DAY = 5
"""Sponsored opens, and separately sponsored top-ups, each verified payer may make per UTC day.

It is tempoxyz/mpp-proxy's ``DAILY_CHANNEL_OPEN_LIMIT``, the limit its proxy applied to sponsored
channel opens before the limit moved into mppx.
"""

_KEY_PREFIX = "mppx:session:sponsorship:"

_FeePayer = TypeVar("_FeePayer")


@dataclass(frozen=True, slots=True)
class SponsorshipLimit:
    """Limits on fee-payer-sponsored channel opens and top-ups (mppx ``sponsorshipLimit``).

    Args:
        store: Compare-and-set store holding one usage record per payer and chain; share it
            across instances (such as :class:`~mpp.stores.RedisStore`) so the limit holds for all.
        per_day: Sponsored opens, and separately sponsored top-ups, per payer per UTC day
            (default 5).
    """

    store: Store
    per_day: int = DEFAULT_PER_DAY

    def __post_init__(self) -> None:
        if isinstance(self.per_day, bool) or not isinstance(self.per_day, int) or self.per_day < 0:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError("`sponsorship_limit.per_day` must be a non-negative integer.")
        if not isinstance(self.store, CompareAndSetStore):
            raise TypeError(
                "`sponsorship_limit.store` must support compare_and_set (an atomic store)."
            )


# secp256r1 (P-256) domain parameters.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p256_verify(digest: bytes, r: int, s: int, x: int, y: int) -> bool:
    """ECDSA P-256 verification of a 32-byte digest, with a low ``s`` as ox's ``P256.verify``."""
    from Crypto.PublicKey import ECC

    if not (0 < r < _P256_N and 0 < s <= _P256_N // 2):
        return False
    try:
        public_key = ECC.EccPoint(x, y, curve="p256")
    except ValueError:
        return False
    generator = ECC.EccPoint(_P256_GX, _P256_GY, curve="p256")
    e = int.from_bytes(digest, "big") % _P256_N
    w = pow(s, -1, _P256_N)
    point = generator * (e * w % _P256_N) + public_key * (r * w % _P256_N)
    # The point at infinity has x = 0, which never equals a nonzero r.
    return int(point.x) % _P256_N == r


def _public_key_address(x: int, y: int) -> str:
    from eth_hash.auto import keccak

    return "0x" + keccak(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def _base64_bytes(value: str) -> bytes:
    """Decode base64, URL-safe or not, with or without padding."""
    normalized = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)


def _verified_webauthn_signer(payload: bytes, data: bytes) -> str | None:
    """The public-key address of a WebAuthn assertion over ``payload``, or None."""
    size = len(data) - 128
    webauthn_data = data[:size]
    authenticator_data: bytes | None = None
    client_data_json = ""
    for split in range(37, size):
        candidate = webauthn_data[split:].decode("utf-8", errors="replace")
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                json.loads(candidate)
            except ValueError:
                continue
            authenticator_data, client_data_json = webauthn_data[:split], candidate
            break
    if authenticator_data is None:
        return None
    flags = authenticator_data[32]
    # User presence; and a backup-state bit only on a backup-eligible credential.
    if flags & 0x01 != 0x01 or (flags & 0x08 != 0x08 and flags & 0x10 == 0x10):
        return None
    # A JSON text from "{" to "}" is an object.
    client = cast(dict[str, Any], json.loads(client_data_json))
    challenge = client.get("challenge")
    if client.get("type") != "webauthn.get" or not isinstance(challenge, str) or not challenge:
        return None
    try:
        if _base64_bytes(challenge) != payload:
            return None
    except ValueError:
        return None
    r, s, x, y = (int.from_bytes(data[size + i : size + i + 32], "big") for i in range(0, 128, 32))
    signed = authenticator_data + hashlib.sha256(client_data_json.encode()).digest()
    if not _p256_verify(hashlib.sha256(signed).digest(), r, s, x, y):
        return None
    return _public_key_address(x, y)


def _verified_signer(payload: bytes, signature: bytes) -> str | None:
    """The address that provably produced ``signature`` over ``payload``, or None.

    secp256k1 recovery is inherently verified; P256 and WebAuthn envelopes carry a public key,
    so their signature is checked against it. Multisig and keychain have no single signer here.
    """
    if len(signature) == 65:
        from eth_account import Account

        from mpp.methods.tempo.intents import (
            _canonical_signature,  # pyright: ignore[reportPrivateUsage]
        )

        try:
            return str(Account._recover_hash(payload, signature=_canonical_signature(signature)))  # pyright: ignore[reportPrivateUsage]
        except Exception:
            return None
    type_id, data = signature[:1], signature[1:]
    if type_id == b"\x01" and len(data) == 129:
        r, s, x, y = (int.from_bytes(data[i : i + 32], "big") for i in range(0, 128, 32))
        digest = hashlib.sha256(payload).digest() if data[128] != 0 else payload
        return _public_key_address(x, y) if _p256_verify(digest, r, s, x, y) else None
    if type_id == b"\x02" and len(data) >= 128:
        return _verified_webauthn_signer(payload, data)
    return None


_TRANSACTION_RE = re.compile(r"^0x7[68][0-9a-fA-F]+$")


def verified_payer(serialized_transaction: str) -> str | None:
    """The verified signer of a serialized Tempo transaction, lowercased, or None.

    A credential's ``source`` is client-supplied and unverified at this point, and so are the
    0x78 explicit sender slot and a keychain signature's account, so limits key on what the
    signatures prove:

    - a direct signature: its signer;
    - an access key authorized in the same transaction: the account that signed the
      authorization, so fresh keys do not get a fresh quota;
    - an access key authorized earlier: the key itself (its account link is only checked on
      chain).
    """
    if not _TRANSACTION_RE.fullmatch(serialized_transaction):
        return None
    try:
        return _verified_payer(bytes.fromhex(serialized_transaction[2:]))
    except Exception:
        return None


def _verified_payer(raw: bytes) -> str | None:
    from eth_hash.auto import keccak

    from mpp._typing import is_list
    from mpp.methods.tempo import _rlp as rlp
    from mpp.methods.tempo.intents import (
        _decode_signed_transaction,  # pyright: ignore[reportPrivateUsage]
    )

    decoded = _decode_signed_transaction(raw)
    if decoded is None:
        return None
    fields, signature, sign_payload = decoded
    if signature[:1] not in (b"\x03", b"\x04") or len(signature) == 65:
        return _lower(_verified_signer(sign_payload, signature))
    user_address, inner = signature[1:21], signature[21:]
    if len(user_address) != 20:
        return None
    # Keychain V2 signs over the account too: keccak256(0x04 || sigHash || userAddress).
    access_payload = (
        keccak(b"\x04" + sign_payload + user_address) if signature[0] == 0x04 else sign_payload
    )
    access_key = _verified_signer(access_payload, inner)
    if access_key is None:
        return None
    if len(fields) == 14:
        return _lower(access_key)
    authorization = fields[13]
    if not is_list(authorization) or len(authorization) != 2:
        return None
    items, authorization_signature = authorization
    if (
        not is_list(items)
        or len(items) < 3
        or not isinstance(items[2], bytes)
        or not isinstance(authorization_signature, bytes)
        or not authorization_signature
        or "0x" + items[2].hex() != access_key.lower()
    ):
        return None
    return _lower(_verified_signer(keccak(rlp.encode(items)), authorization_signature))


def _lower(address: str | None) -> str | None:
    return address.lower() if address is not None else None


def _read_usage(raw: Any, day: str) -> dict[str, Any]:
    """The stored usage for the day, or for a later day already recorded (so a reservation
    that started before midnight counts against, not over, the new day's record)."""
    with contextlib.suppress(ValueError, TypeError):
        value: Any = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        if isinstance(value, dict):
            usage = cast(dict[str, Any], value)
            stored = usage.get("day")
            if isinstance(stored, str) and stored >= day:
                return {
                    "day": stored,
                    "open": int(usage.get("open", 0)),
                    "topUp": int(usage.get("topUp", 0)),
                }
    return {"day": day, "open": 0, "topUp": 0}


async def _update_usage(store: Store, key: str, day: str, change: Any) -> Any:
    """Apply change(usage) -> (usage or None, result) with compare-and-set until it sticks."""
    cas = cast(CompareAndSetStore, store)
    while True:
        raw = await cas.get(key)
        usage, result = change(_read_usage(raw, day))
        if usage is None:
            return result
        value = json.dumps(usage, separators=(",", ":"))
        if await cas.compare_and_set(key, raw, value) or (
            # Stores returning bytes may compare either the bytes or the text they were given.
            isinstance(raw, bytes) and await cas.compare_and_set(key, raw.decode(), value)
        ):
            return result


def _usage_key(chain_id: int, payer: str) -> str:
    return f"{_KEY_PREFIX}{chain_id}:{payer.lower()}"


def _day(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).astimezone(UTC).date().isoformat()


async def reserve(
    store: Store,
    *,
    action: Literal["open", "topUp"],
    chain_id: int,
    payer: str,
    per_day: int = DEFAULT_PER_DAY,
    now: datetime | None = None,
) -> bool:
    """Record one sponsored action for the payer on the current UTC day.

    Returns False, recording nothing, once the payer has used per_day of them.
    """

    def take(usage: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
        if usage[action] >= per_day:
            return None, False
        return {**usage, action: usage[action] + 1}, True

    return await _update_usage(store, _usage_key(chain_id, payer), _day(now), take)


async def release(
    store: Store,
    *,
    action: Literal["open", "topUp"],
    chain_id: int,
    payer: str,
    now: datetime | None = None,
) -> None:
    """Give back one action that reserve recorded, when its sponsored broadcast failed."""

    day = _day(now)

    def give_back(usage: dict[str, Any]) -> tuple[dict[str, Any] | None, None]:
        # Only the day the slot was reserved on: a newer day's record holds other requests.
        if usage["day"] != day or usage[action] <= 0:
            return None, None
        return {**usage, action: usage[action] - 1}, None

    await _update_usage(store, _usage_key(chain_id, payer), day, give_back)


async def limit_fee_payer(
    *,
    chain_id: int,
    fee_payer: _FeePayer | None,
    limit: SponsorshipLimit | None,
    payload: SessionCredentialPayload,
) -> tuple[_FeePayer | None, Callable[[], Awaitable[None]] | None]:
    """The fee payer when the credential's open or top-up may be sponsored, else None, and a
    callback that gives the reserved slot back when the sponsored broadcast fails.

    None once its verified payer used the day's sponsored transactions, or when no signature
    proves a payer: the transaction is then broadcast as the payer signed it, paying its own
    fees.
    """
    if fee_payer is None or limit is None:
        return fee_payer, None
    if not isinstance(payload, (OpenPayload, TopUpPayload)):
        return fee_payer, None
    payer = verified_payer(payload.transaction)
    if payer is None:
        return None, None
    action: Literal["open", "topUp"] = "open" if isinstance(payload, OpenPayload) else "topUp"
    now = datetime.now(UTC)
    allowed = await reserve(
        limit.store,
        action=action,
        chain_id=chain_id,
        payer=payer,
        per_day=limit.per_day,
        now=now,
    )
    if not allowed:
        return None, None

    async def undo() -> None:
        await release(limit.store, action=action, chain_id=chain_id, payer=payer, now=now)

    return fee_payer, undo
