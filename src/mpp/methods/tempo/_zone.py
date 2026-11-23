"""Zone payments for the Tempo charge method.

A payer with a balance on a Zone pays a charge by withdrawing to the
recipient with a challenge-bound memo. The Zone's portal on Tempo settles the
withdrawal with ``processWithdrawals`` and emits ``WithdrawalProcessed``, which
identifies it by sender tag. Mirrors mppx's ``tempo/internal/zone.ts``.
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from mpp._typing import is_dict, is_list

if TYPE_CHECKING:
    from mpp.methods.tempo.schemas import ChargeRequest

DEFAULT_SETTLEMENT_TIMEOUT = 60.0
"""Default seconds a payer waits for a Zone withdrawal to settle on Tempo."""

LOOKBACK_BLOCKS = 7_200
"""Number of Tempo blocks searched back for a settled Zone withdrawal."""

POLLING_INTERVAL = 0.5
"""Seconds between polls for a settled Zone withdrawal."""

FIRST_SCAN_TIMEOUT = 10.0
"""Seconds the first search for a settled Zone withdrawal may take, whatever the timeout."""

REDEMPTION_GRACE = 300.0
"""Most seconds after its Challenge expires that a server accepts a ``zone`` credential.

The upper bound of the Tempo charge server's ``zone_credential_grace_ms`` (mppx
``Zone.redemptionGraceMs``). Past it no server redeems a withdrawal, so a client never
resumes waiting for one.
"""

ZONE_OUTBOX = "0x1c00000000000000000000000000000000000002"
"""The ZoneOutbox predeploy on every Zone, which takes withdrawal requests."""

# WithdrawalProcessed(address indexed to, bytes32 indexed senderTag, address token,
# uint128 amount, bool callbackSuccess)
WITHDRAWAL_PROCESSED_TOPIC = "0x65042ea6dad60c26f055e80ec401b3437c854ed586a0704d305bb4e9ea4518cf"
# WithdrawalRequested(uint64 indexed withdrawalIndex, address indexed sender, address token,
# address to, uint128 amount, uint128 fee, bytes32 memo, uint64 gasLimit,
# uint64 fallbackNonce, bytes data, bytes revealTo)
WITHDRAWAL_REQUESTED_TOPIC = "0x34ca953f3eed14157d2f660c7e92a5bd9c05be0d61a188830f3bf1cb7d094f96"
# processWithdrawals((address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)[],bytes32)
PROCESS_WITHDRAWALS_SELECTOR = "91aa3f04"
# requestWithdrawal(address,address,uint128,bytes32,uint64,address,bytes,bytes)
REQUEST_WITHDRAWAL_SELECTOR = "b3b200aa"
# calculateWithdrawalFee(uint64)
CALCULATE_WITHDRAWAL_FEE_SELECTOR = "7b9c9aa4"
# lastFallbackNonce()
LAST_FALLBACK_NONCE_SELECTOR = "3d1c5a93"

_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
"""A 32-byte hash as JSON-RPC returns it."""

MAX_SENDER_TAG_CANDIDATES = 64
"""Most sender tags derived for one withdrawal: the withdrawals its Zone block may hold.

Each candidate is a topic in every settlement poll's ``eth_getLogs`` filter.
"""

_WITHDRAWAL_TUPLE = "(address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)"
REQUESTED_DATA_TYPES = (
    "address",
    "address",
    "uint128",
    "uint128",
    "bytes32",
    "uint64",
    "uint64",
    "bytes",
    "bytes",
)
"""Types of the non-indexed ``WithdrawalRequested`` fields, in log data order."""

# Zone IDs from here up read as Zone chain IDs in viem/tempo's ``Addresses.zonePortal``,
# which maps them to another Zone's portal, so they are not valid Zone IDs (as mppx).
_MAX_ZONE_ID_EXCLUSIVE = 421_700_000
# Zones whose portals predate the deterministic address scheme.
_LEGACY_PORTALS = {
    6: "0x7069DeC4E64Fd07334A0933eDe836C17259c9B23",
    7: "0x3F5296303400B56271b476F5A0B9cBF74350D6Ac",
}

Accepted = Literal[True] | Sequence[int]
"""Zones a challenge accepts: a list of Zone IDs, or ``True`` for any Zone."""


@dataclass(frozen=True, slots=True)
class Withdrawal:
    """A withdrawal as ``ZonePortal.processWithdrawals`` receives it on Tempo."""

    token: str
    sender_tag: str
    to: str
    amount: int
    memo: str
    gas_limit: int
    fallback_nonce: int
    callback_data: str
    encrypted_sender: str


@dataclass(frozen=True, slots=True)
class ProcessedEvent:
    """A ``ZonePortal.WithdrawalProcessed`` event."""

    to: str
    sender_tag: str
    token: str
    amount: int
    callback_success: bool


@dataclass(frozen=True, slots=True)
class Settlement:
    """The Tempo transaction that processed a withdrawal, and whether its callback succeeded.

    A withdrawal whose callback failed bounced: the portal returned the amount
    to the payer's Zone balance instead of paying the recipient.
    """

    transaction_hash: str
    callback_success: bool


def is_id(zone_id: object) -> bool:
    """Return whether a value is a valid Zone ID: a positive integer below the Zone chain IDs.

    Values from ``421700000`` up are Zone chain IDs, which name another Zone;
    convert one with :func:`id_from_chain_id`.
    """
    return (
        isinstance(zone_id, int)
        and not isinstance(zone_id, bool)
        and 0 < zone_id < _MAX_ZONE_ID_EXCLUSIVE
    )


def is_accepted(zones: object, zone_id: object) -> bool:
    """Return whether a challenge's ``zones`` accepts withdrawals from a Zone."""
    if not is_id(zone_id):
        return False
    if zones is True:
        return True
    return is_list(zones) and any(is_id(accepted) and accepted == zone_id for accepted in zones)


def parse_accepted(zones: object) -> Accepted:
    """Parse a challenge's ``methodDetails.zones`` as servers do.

    Uses the charge request schema, so a client accepts exactly the ``zones``
    a server's ``ChargeIntent`` would: ``True``, or a non-empty list of Zone IDs.

    Raises:
        ValueError: If ``zones`` is malformed, as a server would reject the request.
    """
    from pydantic import TypeAdapter, ValidationError

    from mpp.methods.tempo.schemas import Zones

    try:
        return TypeAdapter(Zones).validate_python(zones)
    except ValidationError:
        raise ValueError(
            "Invalid methodDetails.zones: expected true or a non-empty list of Zone IDs."
        ) from None


def parse_request(request: object) -> ChargeRequest:
    """Parse a Zone-payable challenge's charge request as servers do.

    Uses the server's own ``ChargeRequest`` schema, so a client withdraws only
    for a request a server's ``ChargeIntent`` would accept: a malformed field,
    such as an unknown mode in ``methodDetails.supportedModes``, fails the
    whole request there.

    Raises:
        ValueError: If the request is malformed, as a server would reject it.
    """
    from pydantic import ValidationError

    from mpp.methods.tempo.schemas import ChargeRequest as Schema

    try:
        return Schema.model_validate(request)
    except ValidationError as error:
        location = error.errors()[0]["loc"]
        if location[:2] == ("methodDetails", "zones"):
            raise ValueError(
                "Invalid methodDetails.zones: expected true or a non-empty list of Zone IDs."
            ) from None
        field = ".".join(str(part) for part in location if not isinstance(part, int))
        raise ValueError(f"Invalid charge request: {field} is malformed.") from None


def portal_address(zone_id: int) -> str:
    """Return the Tempo portal address of the Zone with exactly this Zone ID.

    Unlike viem/tempo's ``Addresses.zonePortal``, a Zone chain ID is not
    normalized to its Zone: the portal is always the literal ID's, so a
    credential's ``zoneId`` is checked against the portal of the Zone it names.
    Convert a Zone chain ID with :func:`id_from_chain_id` first.
    """
    legacy = _LEGACY_PORTALS.get(zone_id)
    if legacy is not None:
        return legacy
    return _PORTAL_PREFIX + f"{zone_id:016x}"


_PORTAL_PREFIX = "0x5ad000000000000000000000"
"""Every deterministic Zone portal address is this prefix and an 8-byte Zone ID."""


def is_portal_address(address: str) -> bool:
    """Return whether an address is a Zone portal on Tempo.

    That is any deterministic portal (:func:`portal_address` of a Zone ID) or a legacy
    one. Portals pay out Zone withdrawals, so a transfer from one is a Zone settlement
    (mppx ``isPortalAddress``).
    """
    lowered = address.lower()
    if lowered.startswith(_PORTAL_PREFIX) and len(lowered) == 42:
        return True
    return any(lowered == legacy.lower() for legacy in _LEGACY_PORTALS.values())


def id_from_chain_id(chain_id: int) -> int:
    """Derive a Zone ID from a Zone chain ID.

    Zones on Tempo mainnet and Moderato use reserved bases (``421700000`` and
    ``1424310000``). Zones on any other parent chain use
    ``(parent_chain_id << 32) | zone_id``.

    Raises:
        ValueError: If the chain ID follows no known Zone scheme.
    """
    if chain_id >= 2**32:
        return chain_id % 2**32
    if 1_424_310_000 < chain_id < 1_424_320_000:
        return chain_id - 1_424_310_000
    if 421_700_000 < chain_id < 421_710_000:
        return chain_id - 421_700_000
    raise ValueError(f"Cannot derive a Zone ID from chain ID {chain_id}. Pass zone_id.")


def parent_chain_id_from_chain_id(chain_id: int) -> int | None:
    """Derive the parent Tempo chain ID of a Zone chain ID.

    Returns ``None`` when the chain ID follows no known Zone scheme.
    """
    if chain_id >= 2**32:
        return chain_id // 2**32
    if 1_424_310_000 < chain_id < 1_424_320_000:
        return 42_431
    if 421_700_000 < chain_id < 421_710_000:
        return 4_217
    return None


def _bytes(value: str) -> bytes:
    return bytes.fromhex(value.removeprefix("0x"))


def sender_tag(sender: str, transaction_hash: str, fallback_nonce: int) -> str:
    """Derive a withdrawal's sender tag, which identifies it in ``WithdrawalProcessed``.

    It is ``keccak256(abi.encodePacked(sender, transactionHash, uint64(fallbackNonce)))``,
    where ``transactionHash`` is the Zone transaction that requested the withdrawal.
    """
    from eth_hash.auto import keccak

    packed = _bytes(sender) + _bytes(transaction_hash) + fallback_nonce.to_bytes(8, "big")
    return "0x" + keccak(packed).hex()


class SenderTagUnderivableError(ValueError):
    """The Zone's outbox state names no withdrawal for a transaction, so its sender
    tags can't be derived. The state is fixed, so reading it again doesn't help."""


async def sender_tag_candidates(
    rpc_url: str,
    *,
    sender: str,
    transaction_hash: str,
    block_number: int | None = None,
    block_hash: str | None = None,
    client: Any | None = None,
) -> tuple[str, ...]:
    """Derive the sender tags a withdrawal transaction may carry when its receipt
    has no ``WithdrawalRequested`` event, as on a Zone RPC that redacts logs.

    The outbox numbers each withdrawal with the next ``lastFallbackNonce``, so the
    transaction's withdrawal took one of the nonces its block added. Every
    candidate hashes the payer's address and transaction, so only the payer's
    withdrawal can match one (mppx ``senderTagCandidates``).

    The block that includes the transaction is named by ``block_hash`` or
    ``block_number`` (exactly one). Both outbox reads are pinned to the hashes of
    that block and its parent (EIP-1898, ``requireCanonical``), so they describe
    one chain even when the Zone RPC's view of that height changes, and fail when
    the block is no longer canonical.

    Raises:
        SenderTagUnderivableError: If the block added no withdrawal, or more than
            ``MAX_SENDER_TAG_CANDIDATES``. Reading again returns the same state.
        ValueError: If neither or both of ``block_number`` and ``block_hash`` are
            given, the Zone RPC returned no valid block, or the outbox returned no
            nonce.
    """
    from mpp.methods.tempo._rpc import _rpc_call

    if (block_number is None) == (block_hash is None):
        raise ValueError("Name the withdrawal's Zone block by exactly one of number or hash.")
    rpc: dict[str, Any] = {} if client is None else {"client": client}

    if block_hash is not None:
        block_hash = block_hash.lower()
        header = await _rpc_call(rpc_url, "eth_getBlockByHash", [block_hash, False], **rpc)
    else:
        header = await _rpc_call(
            rpc_url, "eth_getBlockByNumber", [hex(block_number or 0), False], **rpc
        )
    block = _zone_block_header(header)
    if block is None or not (
        block[0] == block_hash if block_hash is not None else block[1] == block_number
    ):
        raise ValueError(
            f"Zone RPC returned no valid block for withdrawal transaction {transaction_hash}."
        )
    hash_, number, parent_hash = block
    if number == 0:
        raise SenderTagUnderivableError(
            f"Zone withdrawal transaction {transaction_hash} did not request a withdrawal "
            "from the outbox."
        )

    async def last_fallback_nonce(at: str) -> int:
        result = await _rpc_call(
            rpc_url,
            "eth_call",
            [
                {"to": ZONE_OUTBOX, "data": "0x" + LAST_FALLBACK_NONCE_SELECTOR},
                {"blockHash": at, "requireCanonical": True},
            ],
            **rpc,
        )
        if not isinstance(result, str):
            raise ValueError("Zone outbox returned no lastFallbackNonce.")
        return int(result, 16)

    # Both reads share one lifetime: when one fails, or the caller stops waiting, the
    # other is cancelled and awaited, so no read outlives the derivation's deadline.
    reads = [
        asyncio.ensure_future(last_fallback_nonce(parent_hash)),
        asyncio.ensure_future(last_fallback_nonce(hash_)),
    ]
    try:
        before, after = await asyncio.gather(*reads)
    finally:
        for read in reads:
            read.cancel()
        await asyncio.gather(*reads, return_exceptions=True)
    if after <= before:
        raise SenderTagUnderivableError(
            f"Zone withdrawal transaction {transaction_hash} did not request a withdrawal "
            "from the outbox."
        )
    # The nonces come from the Zone RPC, so a range no block could hold is refused
    # rather than hashed.
    if after - before > MAX_SENDER_TAG_CANDIDATES:
        raise SenderTagUnderivableError(
            f"Zone withdrawal transaction {transaction_hash} has {after - before} candidate "
            f"sender tags, more than {MAX_SENDER_TAG_CANDIDATES}."
        )
    return tuple(
        sender_tag(sender, transaction_hash, nonce) for nonce in range(before + 1, after + 1)
    )


def _zone_block_header(header: object) -> tuple[str, int, str] | None:
    """A Zone block's lowercase hash, number and parent hash, or ``None`` when invalid."""
    if not is_dict(header):
        return None
    hash_, number, parent_hash = (
        header.get("hash"),
        header.get("number"),
        header.get("parentHash"),
    )
    if not (
        isinstance(hash_, str)
        and isinstance(parent_hash, str)
        and isinstance(number, str)
        and _HASH.fullmatch(hash_)
        and _HASH.fullmatch(parent_hash)
    ):
        return None
    try:
        return hash_.lower(), int(number, 16), parent_hash.lower()
    except ValueError:
        return None


def _same(a: object, b: str) -> bool:
    return isinstance(a, str) and a.lower() == b.lower()


def _topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def find_processed_event(
    logs: Iterable[Any], *, portal: str, sender_tag: str
) -> ProcessedEvent | None:
    """Return the ``WithdrawalProcessed`` event a portal emitted for a sender tag.

    ``None`` when there is none, or more than one: the sender tag must name one
    withdrawal.
    """
    from eth_abi.abi import decode

    found: ProcessedEvent | None = None
    for log in logs:
        if not is_dict(log) or not _same(log.get("address"), portal):
            continue
        topics = log.get("topics")
        if not is_list(topics) or len(topics) != 3:
            continue
        if not _same(topics[0], WITHDRAWAL_PROCESSED_TOPIC) or not _same(topics[2], sender_tag):
            continue
        data = log.get("data")
        to_topic = topics[1]
        if not isinstance(data, str) or not isinstance(to_topic, str):
            continue
        try:
            token, amount, callback_success = decode(["address", "uint128", "bool"], _bytes(data))
        except Exception:
            continue
        if found is not None:
            return None
        found = ProcessedEvent(
            to=_topic_address(to_topic),
            sender_tag=sender_tag.lower(),
            token=str(token).lower(),
            amount=int(amount),
            callback_success=bool(callback_success),
        )
    return found


def find_withdrawal(
    calls: Iterable[tuple[str, str]], *, portal: str, sender_tag: str
) -> Withdrawal | None:
    """Find a sender tag's withdrawal in a settlement transaction's calls.

    ``calls`` are ``(to, data)`` pairs, ``data`` hex with or without its ``0x``
    prefix. Only top-level ``processWithdrawals`` calls to the portal count.
    ``None`` when there is none, or more than one: the sender tag must name one
    withdrawal.
    """
    from eth_abi.abi import decode

    tag = sender_tag.lower()
    found: Withdrawal | None = None
    for to, data in calls:
        hex_data = data.removeprefix("0x").lower()
        if not _same(to, portal) or not hex_data.startswith(PROCESS_WITHDRAWALS_SELECTOR):
            continue
        try:
            withdrawals, _ = decode(
                [f"{_WITHDRAWAL_TUPLE}[]", "bytes32"], bytes.fromhex(hex_data[8:])
            )
        except Exception:
            continue
        for item in withdrawals:
            token, item_tag, recipient, amount, memo, gas_limit, nonce, callback, encrypted = item
            if "0x" + item_tag.hex() != tag:
                continue
            if found is not None:
                return None
            found = Withdrawal(
                token=str(token).lower(),
                sender_tag=tag,
                to=str(recipient).lower(),
                amount=int(amount),
                memo="0x" + memo.hex(),
                gas_limit=int(gas_limit),
                fallback_nonce=int(nonce),
                callback_data="0x" + callback.hex(),
                encrypted_sender="0x" + encrypted.hex(),
            )
    return found


async def wait_for_settlement(
    rpc_url: str,
    *,
    portal: str,
    sender_tag: str,
    to: str | None = None,
    timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
    first_scan_limit: float | None = None,
    from_block: int | None = None,
    on_search_start: Callable[[int], None] | None = None,
    client: Any | None = None,
) -> Settlement:
    """Wait until a portal emits ``WithdrawalProcessed`` for a sender tag on Tempo.

    :func:`wait_for_settled_withdrawal` for one sender tag.
    """
    settlement, _ = await wait_for_settled_withdrawal(
        rpc_url,
        portal=portal,
        sender_tags=(sender_tag,),
        to=to,
        timeout=timeout,
        first_scan_limit=first_scan_limit,
        from_block=from_block,
        on_search_start=on_search_start,
        client=client,
    )
    return settlement


async def wait_for_settled_withdrawal(
    rpc_url: str,
    *,
    portal: str,
    sender_tags: Sequence[str],
    to: str | None = None,
    timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
    first_scan_limit: float | None = None,
    from_block: int | None = None,
    on_search_start: Callable[[int], None] | None = None,
    client: Any | None = None,
) -> tuple[Settlement, str]:
    """Wait until a portal emits ``WithdrawalProcessed`` for any of several sender
    tags on Tempo (mppx ``waitForSettledWithdrawal``).

    Searches the last ``LOOKBACK_BLOCKS`` blocks once, then the blocks added
    since every ``POLLING_INTERVAL`` seconds, for up to ``timeout`` seconds.
    The first search may take ``FIRST_SCAN_TIMEOUT`` seconds even when
    ``timeout`` is shorter (0 included), so a withdrawal that already settled
    is always found, but never more than ``first_scan_limit`` seconds, such as
    the time left before the Challenge expires. Later requests get only what is
    left of ``timeout``, so a slow RPC cannot stretch the wait past it.

    ``from_block`` starts the first search there instead (in ``LOOKBACK_BLOCKS``
    pages), so a retry still finds a withdrawal that settled longer ago than the
    lookback window; ``on_search_start`` receives the first search's start block.

    Returns:
        The Tempo transaction that processed the withdrawal, with the event's
        ``callbackSuccess`` (when it is false, the withdrawal bounced back to the
        payer's Zone balance and paid nothing), and the sender tag of the event.

    Raises:
        ValueError: If ``timeout`` or ``first_scan_limit`` is not a finite,
            non-negative number, or ``sender_tags`` is empty.
        TimeoutError: If the withdrawal did not settle in time.
    """
    from mpp.methods.tempo._rpc import _rpc_call

    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Zone settlement timeout must be a finite, non-negative number.")
    if first_scan_limit is not None and (
        not math.isfinite(first_scan_limit) or first_scan_limit < 0
    ):
        raise ValueError("Zone first scan limit must be a finite, non-negative number.")
    tags = tuple(dict.fromkeys(tag.lower() for tag in sender_tags))
    if not tags:
        raise ValueError("Zone settlement needs at least one sender tag.")
    # Several candidates match as an OR list of the sender tag topic.
    topics: list[str | list[str] | None] = [
        WITHDRAWAL_PROCESSED_TOPIC,
        None if to is None else "0x" + to.removeprefix("0x").lower().zfill(64),
        tags[0] if len(tags) == 1 else list(tags),
    ]

    started = time.monotonic()
    deadline = started + timeout
    # The first search gets at least FIRST_SCAN_TIMEOUT, so a short timeout still
    # finds a withdrawal that already settled, but stops at first_scan_limit
    # (the Challenge's expiry): a settlement found later yields an expired credential.
    first_scan_timeout = max(timeout, FIRST_SCAN_TIMEOUT)
    if first_scan_limit is not None:
        first_scan_timeout = min(first_scan_timeout, first_scan_limit)
    first_scan_deadline = started + first_scan_timeout
    first_scan = True

    def timed_out() -> TimeoutError:
        return TimeoutError(
            f"Zone withdrawal {' or '.join(tags)} did not settle on Tempo within {timeout}s."
        )

    async def call(method: str, params: list[Any]) -> Any:
        # Each request gets only what is left of the budget, so a slow RPC
        # cannot stretch the wait past ``timeout`` (or the first search's bound).
        remaining = (first_scan_deadline if first_scan else deadline) - time.monotonic()
        if remaining <= 0:
            raise timed_out()
        try:
            return await asyncio.wait_for(
                _rpc_call(rpc_url, method, params, client=client), remaining
            )
        except TimeoutError as error:
            raise timed_out() from error

    async def block_number() -> int:
        return int(await call("eth_blockNumber", []), 16)

    latest = await block_number()
    # Scan the lookback window (or from ``from_block``) once, then only blocks added
    # since the previous poll.
    start = max(latest - LOOKBACK_BLOCKS, 0) if from_block is None else max(from_block, 0)
    if on_search_start is not None:
        on_search_start(start)
    from_block = start
    while True:
        while from_block <= latest:
            to_block = min(latest, from_block + LOOKBACK_BLOCKS)
            logs = await call(
                "eth_getLogs",
                [
                    {
                        "address": portal,
                        "topics": topics,
                        "fromBlock": hex(from_block),
                        "toBlock": hex(to_block),
                    }
                ],
            )
            for log in logs if is_list(logs) else []:
                tx_hash = log.get("transactionHash") if is_dict(log) else None
                callback_success = _callback_success(log.get("data")) if is_dict(log) else None
                tag = _log_sender_tag(log, tags)
                if isinstance(tx_hash, str) and callback_success is not None and tag is not None:
                    return Settlement(tx_hash, callback_success), tag
            from_block = to_block + 1
        first_scan = False
        if time.monotonic() + POLLING_INTERVAL > deadline:
            raise timed_out()
        await asyncio.sleep(POLLING_INTERVAL)
        latest = await block_number()


def _log_sender_tag(log: object, tags: tuple[str, ...]) -> str | None:
    """The sender tag of a ``WithdrawalProcessed`` log, when it is one of ``tags``."""
    topics = log.get("topics") if is_dict(log) else None
    if not is_list(topics) or len(topics) != 3 or not isinstance(topics[2], str):
        return None
    tag = topics[2].lower()
    return tag if tag in tags else None


def _callback_success(data: object) -> bool | None:
    """Decode ``callbackSuccess`` from a ``WithdrawalProcessed`` log's data, or ``None``."""
    from eth_abi.abi import decode

    if not isinstance(data, str):
        return None
    try:
        _, _, callback_success = decode(["address", "uint128", "bool"], _bytes(data))
    except Exception:
        return None
    return bool(callback_success)
