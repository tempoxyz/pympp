"""Zone payments for the Tempo charge method.

A payer with a balance on a Zone pays a charge by withdrawing to the
recipient with a challenge-bound memo. The Zone's portal on Tempo settles the
withdrawal with ``processWithdrawals`` and emits ``WithdrawalProcessed``, which
identifies it by sender tag. Mirrors mppx's ``tempo/internal/zone.ts``.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from mpp._typing import is_dict, is_list

DEFAULT_SETTLEMENT_TIMEOUT = 60.0
"""Default seconds a payer waits for a Zone withdrawal to settle on Tempo."""

LOOKBACK_BLOCKS = 7_200
"""Number of Tempo blocks searched back for a settled Zone withdrawal."""

POLLING_INTERVAL = 0.5
"""Seconds between polls for a settled Zone withdrawal."""

FIRST_SCAN_TIMEOUT = 10.0
"""Seconds the first search for a settled Zone withdrawal may take, whatever the timeout."""

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

# Zone chain ID schemes (viem/tempo ``Addresses.zonePortal`` and ox ``ZoneId``).
_MAINNET_ZONE_CHAIN_ID_BASE = 421_700_000
_TESTNET_ZONE_CHAIN_ID_BASE = 1_424_310_000
_LEGACY_ZONE_CHAIN_ID_BASE = 4_217_000_000
_LEGACY_ZONE_CHAIN_ID_LIMIT = 4_218_000_000
_ZONE_CHAIN_ID_LIMIT = 2**31
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


def is_id(zone_id: object) -> bool:
    """Return whether a value is a valid Zone ID: a positive 32-bit integer."""
    return isinstance(zone_id, int) and not isinstance(zone_id, bool) and 0 < zone_id < 2**32


def is_accepted(zones: object, zone_id: object) -> bool:
    """Return whether a challenge's ``zones`` accepts withdrawals from a Zone."""
    if not is_id(zone_id):
        return False
    if zones is True:
        return True
    return is_list(zones) and any(is_id(accepted) and accepted == zone_id for accepted in zones)


def portal_address(zone_id: int) -> str:
    """Return the Tempo portal address of a Zone, as viem/tempo's ``Addresses.zonePortal``."""
    if _LEGACY_ZONE_CHAIN_ID_BASE <= zone_id < _LEGACY_ZONE_CHAIN_ID_LIMIT:
        zone_id -= _LEGACY_ZONE_CHAIN_ID_BASE
    elif _TESTNET_ZONE_CHAIN_ID_BASE <= zone_id < _ZONE_CHAIN_ID_LIMIT:
        zone_id -= _TESTNET_ZONE_CHAIN_ID_BASE
    elif _MAINNET_ZONE_CHAIN_ID_BASE <= zone_id < _TESTNET_ZONE_CHAIN_ID_BASE:
        zone_id -= _MAINNET_ZONE_CHAIN_ID_BASE
    legacy = _LEGACY_PORTALS.get(zone_id)
    if legacy is not None:
        return legacy
    return "0x5ad000000000000000000000" + f"{zone_id:016x}"


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


def _same(a: object, b: str) -> bool:
    return isinstance(a, str) and a.lower() == b.lower()


def _topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def find_processed_event(
    logs: Iterable[Any], *, portal: str, sender_tag: str
) -> ProcessedEvent | None:
    """Return the ``WithdrawalProcessed`` event a portal emitted for a sender tag."""
    from eth_abi.abi import decode

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
        return ProcessedEvent(
            to=_topic_address(to_topic),
            sender_tag=sender_tag.lower(),
            token=str(token).lower(),
            amount=int(amount),
            callback_success=bool(callback_success),
        )
    return None


def find_withdrawal(
    calls: Iterable[tuple[str, str]], *, portal: str, sender_tag: str
) -> Withdrawal | None:
    """Find a sender tag's withdrawal in a settlement transaction's calls.

    ``calls`` are ``(to, data)`` pairs, ``data`` hex with or without its ``0x``
    prefix. Only top-level ``processWithdrawals`` calls to the portal count.
    """
    from eth_abi.abi import decode

    tag = sender_tag.lower()
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
            return Withdrawal(
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
    return None


async def wait_for_settlement(
    rpc_url: str,
    *,
    portal: str,
    sender_tag: str,
    to: str | None = None,
    timeout: float = DEFAULT_SETTLEMENT_TIMEOUT,
    client: Any | None = None,
) -> str:
    """Wait until a portal emits ``WithdrawalProcessed`` for a sender tag on Tempo.

    Searches the last ``LOOKBACK_BLOCKS`` blocks once, then the blocks added
    since every ``POLLING_INTERVAL`` seconds, for up to ``timeout`` seconds.
    The first search always runs, for up to ``FIRST_SCAN_TIMEOUT`` seconds, so a
    ``timeout`` of 0 checks once.

    Returns:
        The hash of the Tempo transaction that settled the withdrawal.

    Raises:
        ValueError: If ``timeout`` is not a finite, non-negative number.
        TimeoutError: If the withdrawal did not settle in time.
    """
    from mpp.methods.tempo._rpc import _rpc_call

    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Zone settlement timeout must be a finite, non-negative number.")
    topics: list[str | None] = [
        WITHDRAWAL_PROCESSED_TOPIC,
        None if to is None else "0x" + to.removeprefix("0x").lower().zfill(64),
        sender_tag.lower(),
    ]

    started = time.monotonic()
    deadline = started + timeout
    # The first search may outlast a short timeout, so a withdrawal that already
    # settled is found even with none; FIRST_SCAN_TIMEOUT still bounds a stalled RPC.
    first_scan_deadline = max(deadline, started + FIRST_SCAN_TIMEOUT)
    first_scan = True

    def timed_out() -> TimeoutError:
        return TimeoutError(
            f"Zone withdrawal {sender_tag} did not settle on Tempo within {timeout}s."
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
    # Scan the lookback window once, then only blocks added since the previous poll.
    from_block = max(latest - LOOKBACK_BLOCKS, 0)
    while True:
        if from_block <= latest:
            logs = await call(
                "eth_getLogs",
                [
                    {
                        "address": portal,
                        "topics": topics,
                        "fromBlock": hex(from_block),
                        "toBlock": hex(latest),
                    }
                ],
            )
            for log in logs if is_list(logs) else []:
                tx_hash = log.get("transactionHash") if is_dict(log) else None
                if isinstance(tx_hash, str):
                    return tx_hash
            from_block = latest + 1
        first_scan = False
        if time.monotonic() + POLLING_INTERVAL > deadline:
            raise timed_out()
        await asyncio.sleep(POLLING_INTERVAL)
        latest = await block_number()
