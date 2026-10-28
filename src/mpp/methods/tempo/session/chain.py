"""TIP-1034 on-chain reads, writes and credential transaction checks (mppx precompile/Chain.ts).

Async JSON-RPC over httpx. Servers validate and broadcast client-signed `open`
and `topUp` transactions (co-signing them as fee payer when configured) and
send `settle` and `close` themselves; clients build and sign `open` and `topUp`
transactions and send `requestClose` and `withdraw`.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from mpp._defaults import DEFAULT_CONFIRMATION_TIMEOUT, DEFAULT_TIMEOUT
from mpp._typing import is_dict, is_list
from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods.tempo.session import abi
from mpp.methods.tempo.session.channel import compute_channel_id, expiring_nonce_hash
from mpp.methods.tempo.session.protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

T = TypeVar("T")

EXPIRING_NONCE_KEY = (1 << 256) - 1
"""TIP-1009 expiring nonce key (`U256::MAX`); session transactions always use it."""
EXPIRING_NONCE_VALID_BEFORE_SECS = 60
"""Seconds an expiring-nonce session transaction stays valid by default."""
DEFAULT_GAS_LIMIT = 1_000_000
"""Gas limit used when estimation fails."""
RECEIPT_POLL_INTERVAL = 0.5
"""Seconds between receipt lookups."""
STABLECOIN_DEX = "0xdec0000000000000000000000000000000000000"
"""Tempo stablecoin DEX, the only allowed auto-swap target."""

_APPROVE_SELECTOR = bytes.fromhex("095ea7b3")
_SWAP_EXACT_AMOUNT_OUT_SELECTOR = bytes.fromhex("f0122b75")

TransactionLabel = Literal["open", "topUp"]


# ──────────────────────────────────────────────────────────────────
# State and reads
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ChannelState:
    """On-chain channel state from the TIP20EscrowChannel precompile."""

    settled: int
    deposit: int
    close_requested_at: int


@dataclass(frozen=True, slots=True)
class Channel:
    """On-chain channel descriptor and state."""

    descriptor: ChannelDescriptor
    state: ChannelState


def _state(value: abi.ChannelStateTuple) -> ChannelState:
    # The ABI decoder already rejects words outside uint96.
    return ChannelState(
        settled=value.settled, deposit=value.deposit, close_requested_at=value.close_requested_at
    )


async def _rpc(
    rpc_url: str, method: str, params: list[Any], client: httpx.AsyncClient | None
) -> Any:
    from mpp.methods.tempo._rpc import _rpc_call  # pyright: ignore[reportPrivateUsage]

    return await _rpc_call(rpc_url, method, params, client=client)


def _block_tag(block: int | str | None) -> str:
    if block is None:
        return "latest"
    return hex(block) if isinstance(block, int) else block


async def _eth_call(
    rpc_url: str, to: str, data: str, block: int | str | None, client: httpx.AsyncClient | None
) -> str:
    result = await _rpc(rpc_url, "eth_call", [{"to": to, "data": data}, _block_tag(block)], client)
    if not isinstance(result, str):
        raise RuntimeError("eth_call returned no data")
    return result


async def get_channel(
    rpc_url: str,
    descriptor: ChannelDescriptor,
    *,
    escrow: str = ESCROW_ADDRESS,
    block: int | str | None = None,
    client: httpx.AsyncClient | None = None,
) -> Channel:
    """Read a channel's descriptor and state, optionally at `block`."""
    data = await _eth_call(rpc_url, escrow, abi.encode_get_channel(descriptor), block, client)
    chain_descriptor, state = abi.decode_get_channel(data)
    return Channel(descriptor=chain_descriptor, state=_state(state))


async def get_channel_state(
    rpc_url: str,
    channel_id: str,
    *,
    escrow: str = ESCROW_ADDRESS,
    block: int | str | None = None,
    client: httpx.AsyncClient | None = None,
) -> ChannelState:
    """Read a channel's state by ID, optionally at `block`."""
    data = await _eth_call(rpc_url, escrow, abi.encode_get_channel_state(channel_id), block, client)
    return _state(abi.decode_get_channel_state(data))


async def get_channel_states_batch(
    rpc_url: str,
    channel_ids: Sequence[str],
    *,
    escrow: str = ESCROW_ADDRESS,
    block: int | str | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[ChannelState]:
    """Read several channels' states in one call, optionally at one `block`."""
    data = await _eth_call(
        rpc_url, escrow, abi.encode_get_channel_states_batch(channel_ids), block, client
    )
    return [_state(state) for state in abi.decode_get_channel_states_batch(data)]


async def compute_channel_id_on_chain(
    rpc_url: str,
    descriptor: ChannelDescriptor,
    *,
    escrow: str = ESCROW_ADDRESS,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Ask the precompile for a descriptor's channel ID (`computeChannelId`)."""
    data = await _eth_call(rpc_url, escrow, abi.encode_compute_channel_id(descriptor), None, client)
    return abi.decode_bytes32(data)


async def readback_with_retry(
    read: Callable[[], Awaitable[T]],
    *,
    retries: int = 5,
    delay: float = 0.25,
    should_retry: Callable[[Exception], bool] | None = None,
) -> T:
    """Retry a read pinned to a just-mined block until a lagging RPC replica has it."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await read()
        except Exception as error:
            last_error = error
            if should_retry is not None and not should_retry(error):
                break
            if attempt < retries:
                await asyncio.sleep(delay)
    assert last_error is not None
    raise last_error


# ──────────────────────────────────────────────────────────────────
# Broadcast and receipts
# ──────────────────────────────────────────────────────────────────


async def send_raw_transaction(
    rpc_url: str, raw_tx: str, *, client: httpx.AsyncClient | None = None
) -> str:
    """Broadcast a raw transaction; returns its hash."""
    result = await _rpc(rpc_url, "eth_sendRawTransaction", [raw_tx], client)
    if not isinstance(result, str):
        raise RuntimeError("eth_sendRawTransaction returned no hash")
    return result


async def wait_for_successful_receipt(
    rpc_url: str,
    tx_hash: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = DEFAULT_CONFIRMATION_TIMEOUT,
) -> dict[str, Any]:
    """Wait for a transaction's receipt and reject a reverted one."""
    deadline = time.monotonic() + timeout
    while True:
        receipt = await _rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash], client)
        if is_dict(receipt):
            if receipt.get("status") not in ("0x1", 1):
                raise VerificationFailedError("precompile transaction reverted")
            return receipt
        if time.monotonic() >= deadline:
            raise TimeoutError(f"No receipt for {tx_hash} after {timeout:g}s")
        await asyncio.sleep(RECEIPT_POLL_INTERVAL)


ChannelEventName = Literal["ChannelOpened", "TopUp", "Settled", "ChannelClosed", "CloseRequested"]


def get_channel_event(
    receipt: Mapping[str, Any],
    name: ChannelEventName,
    channel_id: str,
    *,
    escrow: str | None = None,
) -> dict[str, Any]:
    """Return the args of exactly one `name` event for `channel_id` in a receipt.

    With `escrow`, only logs that address emitted count.
    """
    logs = receipt.get("logs")
    matches: list[dict[str, Any]] = []
    for log in logs if is_list(logs) else []:
        if not is_dict(log):
            continue
        if escrow is not None and str(log.get("address", "")).lower() != escrow.lower():
            continue
        topics = log.get("topics")
        if not is_list(topics) or not topics or str(topics[0]).lower() != abi.EVENT_TOPICS[name]:
            continue
        try:
            event = abi.decode_event([str(t) for t in topics], str(log.get("data", "0x")))
        except Exception:
            continue
        if event is not None and str(event.args["channelId"]).lower() == channel_id.lower():
            matches.append(event.args)
    if len(matches) != 1:
        raise VerificationFailedError(
            f"expected one {name} event for credential channelId in receipt"
        )
    return matches[0]


def _receipt_block(receipt: Mapping[str, Any]) -> int | None:
    block = receipt.get("blockNumber")
    if isinstance(block, str):
        return int(block, 16)
    return block if isinstance(block, int) else None


def validate_channel_opened_receipt(
    *,
    chain_id: int,
    descriptor: ChannelDescriptor,
    emitted_channel_id: str,
    emitted_deposit: int,
    emitted_expiring_nonce_hash: str,
    escrow: str,
    expected_channel_id: str,
    open_deposit: int,
) -> None:
    """Check a `ChannelOpened` event against the open calldata, descriptor and credential."""
    if emitted_channel_id.lower() != expected_channel_id.lower():
        raise VerificationFailedError("ChannelOpened channelId does not match credential")
    if emitted_expiring_nonce_hash.lower() != descriptor.expiring_nonce_hash.lower():
        raise VerificationFailedError("ChannelOpened expiringNonceHash does not match descriptor")
    if emitted_deposit != open_deposit:
        raise VerificationFailedError("ChannelOpened deposit does not match calldata")
    confirmed = compute_channel_id(descriptor, chain_id=chain_id, escrow=escrow)
    if confirmed.lower() != emitted_channel_id.lower():
        raise VerificationFailedError("descriptor does not match ChannelOpened channelId")


def validate_open_readback_state(*, emitted_deposit: int, state: ChannelState) -> None:
    """Check the state read back after an open."""
    if state.deposit != emitted_deposit or state.settled != 0 or state.close_requested_at != 0:
        raise VerificationFailedError("on-chain channel state does not match open receipt")


def validate_top_up_receipt(*, emitted_channel_id: str, expected_channel_id: str) -> None:
    """Check a `TopUp` event belongs to the credential's channel."""
    if emitted_channel_id.lower() != expected_channel_id.lower():
        raise VerificationFailedError("TopUp channelId does not match credential")


def validate_top_up_readback_state(*, new_deposit: int, state: ChannelState) -> None:
    """Check the state read back after a top-up."""
    if state.deposit != new_deposit:
        raise VerificationFailedError("on-chain channel state does not match topUp receipt")


# ──────────────────────────────────────────────────────────────────
# Calldata checks (mppx server/ChannelOps.ts)
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class OpenCall:
    """Decoded, uint96-checked `open` calldata."""

    payee: str
    operator: str
    token: str
    deposit: int
    salt: str
    authorized_signer: str


def _same_address(a: str, b: str) -> bool:
    return a.lower() == b.lower()


def parse_open_call(
    data: str,
    *,
    payee: str | None = None,
    operator: str | None = None,
    token: str | None = None,
    authorized_signer: str | None = None,
    deposit: int | None = None,
) -> OpenCall:
    """Decode `open` calldata and check it against the expected values given."""
    try:
        decoded = abi.decode_open(data)
    except ValueError as error:
        raise VerificationFailedError("Expected TIP-1034 open calldata") from error
    call = OpenCall(
        payee=decoded["payee"],
        operator=decoded["operator"],
        token=decoded["token"],
        deposit=decoded["deposit"],
        salt=decoded["salt"],
        authorized_signer=decoded["authorizedSigner"],
    )
    if payee is not None and not _same_address(call.payee, payee):
        raise VerificationFailedError("TIP-1034 open payee does not match challenge")
    if operator is not None and not _same_address(call.operator, operator):
        raise VerificationFailedError("TIP-1034 open operator does not match challenge")
    if token is not None and not _same_address(call.token, token):
        raise VerificationFailedError("TIP-1034 open token does not match challenge")
    if authorized_signer is not None and not _same_address(
        call.authorized_signer, authorized_signer
    ):
        raise VerificationFailedError("TIP-1034 open authorizedSigner does not match credential")
    if deposit is not None and call.deposit != deposit:
        raise VerificationFailedError("TIP-1034 open deposit does not match challenge")
    return call


def same_channel_descriptor(actual: ChannelDescriptor, expected: ChannelDescriptor) -> bool:
    """Compare descriptors, addresses and hashes case-insensitively."""
    return all(
        getattr(actual, field).lower() == getattr(expected, field).lower()
        for field in (
            "payer",
            "payee",
            "operator",
            "token",
            "salt",
            "authorized_signer",
            "expiring_nonce_hash",
        )
    )


def parse_top_up_call(
    data: str,
    *,
    descriptor: ChannelDescriptor | None = None,
    additional_deposit: int | None = None,
) -> tuple[ChannelDescriptor, int]:
    """Decode `topUp` calldata and check it against the expected values given."""
    try:
        call_descriptor, amount = abi.decode_top_up(data)
    except ValueError as error:
        raise VerificationFailedError("Expected TIP-1034 topUp calldata") from error
    if descriptor is not None and not same_channel_descriptor(call_descriptor, descriptor):
        raise VerificationFailedError("TIP-1034 topUp descriptor does not match stored channel")
    if additional_deposit is not None and amount != additional_deposit:
        raise VerificationFailedError("TIP-1034 topUp deposit does not match credential")
    return call_descriptor, amount


def descriptor_from_open(
    *,
    open_call: OpenCall,
    payer: str,
    expiring_nonce_hash: str,
    chain_id: int,
    escrow: str = ESCROW_ADDRESS,
    channel_id: str | None = None,
) -> ChannelDescriptor:
    """Build the descriptor an accepted `open` call creates, checking `channel_id` if given."""
    descriptor = ChannelDescriptor(
        payer=payer,
        payee=open_call.payee,
        operator=open_call.operator,
        token=open_call.token,
        salt=open_call.salt,
        authorized_signer=open_call.authorized_signer,
        expiring_nonce_hash=expiring_nonce_hash,
    )
    if channel_id is not None:
        computed = compute_channel_id(descriptor, chain_id=chain_id, escrow=escrow)
        if computed.lower() != channel_id.lower():
            raise VerificationFailedError(
                "TIP-1034 ChannelOpened channelId does not match descriptor"
            )
    return descriptor


def _validate_auto_swap_prefix(
    prefix_calls: Sequence[tuple[str, int, bytes]],
    *,
    amount_out: int,
    currency: str,
    label: TransactionLabel,
) -> None:
    """Allow only `approve` + `swapExactAmountOut` on the DEX buying the channel token."""
    from eth_abi.abi import decode, encode

    if not prefix_calls:
        return

    def fail(reason: str) -> VerificationFailedError:
        return VerificationFailedError(f"TIP-1034 {label} auto-swap {reason}")

    if len(prefix_calls) != 2:
        raise fail("must contain exactly approve and swap calls")
    (approve_to, approve_value, approve_data), (swap_to, swap_value, swap_data) = prefix_calls
    if not approve_data or not swap_data:
        raise fail("call is missing a target or calldata")
    if approve_value != 0 or swap_value != 0:
        raise fail("calls must not transfer native value")
    if not _same_address(swap_to, STABLECOIN_DEX):
        raise fail("targets the wrong DEX")
    if approve_data[:4] != _APPROVE_SELECTOR or swap_data[:4] != _SWAP_EXACT_AMOUNT_OUT_SELECTOR:
        raise fail("must contain approve followed by swapExactAmountOut")
    try:
        spender, approved = decode(["address", "uint256"], approve_data[4:])
    except Exception as error:
        raise fail("approval calldata is invalid") from error
    try:
        token_in, token_out, swap_amount_out, max_amount_in = decode(
            ["address", "address", "uint128", "uint128"], swap_data[4:]
        )
    except Exception as error:
        raise fail("swap calldata is invalid") from error
    if not _same_address(approve_to, token_in):
        raise fail("approval token does not match swap input")
    if not _same_address(spender, STABLECOIN_DEX):
        raise fail("approval spender is not the DEX")
    if approved != max_amount_in:
        raise fail("approval amount does not match swap maximum input")
    if not _same_address(token_out, currency):
        raise fail("output token does not match channel currency")
    if swap_amount_out <= 0 or swap_amount_out > amount_out:
        raise fail("output amount must be positive and not exceed channel deposit")
    if _same_address(token_in, token_out):
        raise fail("input and output tokens must differ")
    if approve_data[4:] != encode(["address", "uint256"], [spender, approved]):
        raise fail("approval calldata is not canonical")
    if swap_data[4:] != encode(
        ["address", "address", "uint128", "uint128"],
        [token_in, token_out, swap_amount_out, max_amount_in],
    ):
        raise fail("swap calldata is not canonical")


# ──────────────────────────────────────────────────────────────────
# Client-signed credential transactions (server side)
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ParsedCredentialTransaction:
    """A client-signed Tempo transaction carrying one escrow management call."""

    raw: str
    type_id: int
    sender: str
    chain_id: int
    calls: tuple[tuple[str, int, bytes], ...]
    valid_before: int | None

    @property
    def management_call(self) -> tuple[str, int, bytes]:
        return self.calls[-1]


def parse_credential_transaction(
    serialized_transaction: str,
    *,
    escrow_contract: str,
    label: TransactionLabel,
    fee_payer: bool = False,
) -> ParsedCredentialTransaction:
    """Decode a client-signed 0x76 (or, when sponsored, 0x78) management transaction.

    It must hold one escrow call, optionally preceded by an auto-swap's
    `approve` and `swapExactAmountOut`.
    """
    from mpp.methods.tempo import _rlp as rlp
    from mpp.methods.tempo.intents import (
        _transaction_sender,  # pyright: ignore[reportPrivateUsage]
    )

    try:
        tx_bytes = bytes.fromhex(serialized_transaction.removeprefix("0x"))
    except ValueError as error:
        raise BadRequestError("Invalid serialized transaction") from error
    allowed_types = (b"\x76", b"\x78") if fee_payer else (b"\x76",)
    if tx_bytes[:1] not in allowed_types:
        raise BadRequestError(
            "Only Tempo (0x76/0x78) transactions are supported"
            if fee_payer
            else "Only signed Tempo (0x76) transactions are supported without a fee payer"
        )
    try:
        fields = rlp.decode(tx_bytes[1:])
    except Exception as error:
        raise BadRequestError("Invalid serialized transaction") from error
    if not is_list(fields) or len(fields) not in (14, 15) or not is_list(fields[4]):
        raise BadRequestError("Invalid serialized transaction")

    calls: list[tuple[str, int, bytes]] = []
    for call in fields[4]:
        if not is_list(call) or len(call) != 3:
            raise BadRequestError("Invalid serialized transaction")
        to, value, data = call
        if not isinstance(to, bytes) or not isinstance(value, bytes) or not isinstance(data, bytes):
            raise BadRequestError("Invalid serialized transaction")
        calls.append(("0x" + to.hex(), int.from_bytes(value, "big"), data))

    if len(calls) not in (1, 3):
        raise VerificationFailedError(
            f"TIP-1034 {label} transaction must contain one management call, "
            "optionally preceded by an auto-swap"
        )
    to, _, data = calls[-1]
    if len(to) != 42 or not _same_address(to, escrow_contract):
        raise VerificationFailedError(f"TIP-1034 {label} transaction targets the wrong address")
    if not data:
        raise VerificationFailedError(f"TIP-1034 {label} transaction is missing calldata")

    sender = _transaction_sender(serialized_transaction)
    if sender is None:
        raise BadRequestError(
            "Transaction must be signed by the sender before fee payer co-signing"
        )
    chain_id = int.from_bytes(fields[0], "big") if isinstance(fields[0], bytes) else -1
    valid_before_raw = fields[8]
    valid_before = (
        int.from_bytes(valid_before_raw, "big")
        if isinstance(valid_before_raw, bytes) and valid_before_raw
        else None
    )
    from eth_utils.address import to_checksum_address

    return ParsedCredentialTransaction(
        raw=serialized_transaction,
        type_id=tx_bytes[0],
        sender=to_checksum_address(sender),
        chain_id=chain_id,
        calls=tuple(calls),
        valid_before=valid_before,
    )


def _challenge_max_valid_before(challenge_expires: str | None) -> int | None:
    if not challenge_expires:
        return None
    from datetime import datetime

    expires = datetime.fromisoformat(challenge_expires.replace("Z", "+00:00"))
    return int(expires.timestamp()) + 60


def _cosign(
    parsed: ParsedCredentialTransaction,
    *,
    chain_id: int,
    fee_payer: TempoAccount,
    fee_payer_policy: Mapping[str, int] | None,
    allowed_fee_tokens: Sequence[str],
    challenge_expires: str | None,
    require_remaining_validity: bool = True,
) -> tuple[str, Any, str]:
    """Check sponsorship policy and co-sign a 0x78 session envelope."""
    from mpp.errors import VerificationError
    from mpp.methods.tempo import _fee_payer
    from mpp.methods.tempo.fee_payer_policy import get_policy

    if parsed.type_id != 0x78:
        raise BadRequestError("Fee-sponsored session transactions must be 0x78 fee payer envelopes")
    if parsed.chain_id != chain_id:
        raise VerificationError(
            "Invalid transaction: fee-sponsored transaction chainId does not match challenge"
        )

    def validate_calls(calls: tuple[Any, ...]) -> None:
        for call in calls:
            if int(call.value) != 0:
                raise VerificationError(
                    "Invalid transaction: fee-sponsored transaction call value is not allowed"
                )

    return _fee_payer.cosign_fee_payer_envelope(
        parsed.raw,
        fee_payer=fee_payer,
        policy=lambda chain: get_policy(chain, fee_payer_policy),
        fee_token=allowed_fee_tokens[0] if allowed_fee_tokens else None,
        validate_calls=validate_calls,
        require_remaining_validity=require_remaining_validity,
        allowed_fee_tokens=allowed_fee_tokens,
        max_valid_before=_challenge_max_valid_before(challenge_expires),
    )


@dataclass(frozen=True, slots=True)
class ValidatedOpenTransaction:
    """Fields recovered from a validated client-signed `open` transaction."""

    descriptor: ChannelDescriptor
    expiring_nonce_hash: str
    open_deposit: int
    transaction: ParsedCredentialTransaction


def validate_open_credential_transaction(
    *,
    serialized_transaction: str,
    chain_id: int,
    escrow_contract: str,
    expected_authorized_signer: str,
    expected_channel_id: str,
    expected_currency: str,
    expected_expiring_nonce_hash: str,
    expected_operator: str,
    expected_payee: str,
    expected_payer: str,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
) -> ValidatedOpenTransaction:
    """Validate the immutable fields of a client-signed `open` transaction without sending it.

    The descriptor's payer is the transaction's sender (`expected_payer` is used
    only when no sender can be derived, as in mppx); the channel ID and
    expiring nonce hash must match the credential.
    """
    parsed = parse_credential_transaction(
        serialized_transaction,
        escrow_contract=escrow_contract,
        label="open",
        fee_payer=fee_payer is not None,
    )
    payer = parsed.sender or expected_payer
    _, _, data = parsed.management_call
    open_call = parse_open_call(
        "0x" + data.hex(),
        payee=expected_payee,
        token=expected_currency,
        operator=expected_operator,
        authorized_signer=expected_authorized_signer,
    )
    _validate_auto_swap_prefix(
        parsed.calls[:-1], amount_out=open_call.deposit, currency=expected_currency, label="open"
    )
    descriptor = descriptor_from_open(
        open_call=open_call,
        payer=payer,
        expiring_nonce_hash=expected_expiring_nonce_hash,
        chain_id=chain_id,
        escrow=escrow_contract,
        channel_id=expected_channel_id,
    )
    if fee_payer is not None:
        _cosign(
            parsed,
            chain_id=chain_id,
            fee_payer=fee_payer,
            fee_payer_policy=fee_payer_policy,
            allowed_fee_tokens=allowed_fee_tokens or [expected_currency],
            challenge_expires=challenge_expires,
        )
    computed_hash = expiring_nonce_hash(
        serialized_transaction, payer, fee_payer=True if fee_payer is not None else None
    )
    if computed_hash.lower() != descriptor.expiring_nonce_hash.lower():
        raise VerificationFailedError("credential expiringNonceHash does not match transaction")
    return ValidatedOpenTransaction(
        descriptor=descriptor,
        expiring_nonce_hash=computed_hash,
        open_deposit=open_call.deposit,
        transaction=parsed,
    )


@dataclass(frozen=True, slots=True)
class ValidatedTopUpTransaction:
    """A validated client-signed `topUp` transaction."""

    additional_deposit: int
    transaction: ParsedCredentialTransaction


def validate_top_up_credential_transaction(
    *,
    serialized_transaction: str,
    additional_deposit: int,
    chain_id: int,
    descriptor: ChannelDescriptor,
    escrow_contract: str,
    expected_channel_id: str,
    expected_currency: str,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
) -> ValidatedTopUpTransaction:
    """Validate the immutable fields of a client-signed `topUp` transaction."""
    parsed = parse_credential_transaction(
        serialized_transaction,
        escrow_contract=escrow_contract,
        label="topUp",
        fee_payer=fee_payer is not None,
    )
    _, _, data = parsed.management_call
    _, amount = parse_top_up_call(
        "0x" + data.hex(), descriptor=descriptor, additional_deposit=additional_deposit
    )
    _validate_auto_swap_prefix(
        parsed.calls[:-1], amount_out=additional_deposit, currency=expected_currency, label="topUp"
    )
    if fee_payer is not None:
        _cosign(
            parsed,
            chain_id=chain_id,
            fee_payer=fee_payer,
            fee_payer_policy=fee_payer_policy,
            allowed_fee_tokens=allowed_fee_tokens or [expected_currency],
            challenge_expires=challenge_expires,
        )
    return ValidatedTopUpTransaction(additional_deposit=amount, transaction=parsed)


async def _simulate_call(
    rpc_url: str, request: dict[str, Any], client: httpx.AsyncClient | None
) -> None:
    try:
        await _rpc(rpc_url, "eth_call", [request, "latest"], client)
    except RuntimeError as error:
        raise VerificationFailedError(f"{error}") from error


def _rpc_calls(calls: Sequence[tuple[str, int, bytes]]) -> list[dict[str, str]]:
    return [{"to": to, "value": hex(value), "data": "0x" + data.hex()} for to, value, data in calls]


def _sponsored_simulation_request(tx: Any, sender: str, fee_payer: str) -> dict[str, Any]:
    """The co-signed envelope as an `eth_call` request, without either signature.

    Mirrors mppx `FeePayer.sponsoredSimulationTransaction`.
    """
    request: dict[str, Any] = {
        "from": sender,
        "type": "0x76",
        "chainId": hex(tx.chain_id),
        "nonce": hex(tx.nonce),
        "nonceKey": hex(tx.nonce_key),
        "gas": hex(tx.gas_limit),
        "maxFeePerGas": hex(tx.max_fee_per_gas),
        "maxPriorityFeePerGas": hex(tx.max_priority_fee_per_gas),
        "feeToken": "0x" + bytes(tx.fee_token).hex(),
        "feePayer": fee_payer,
        "calls": _rpc_calls(
            [("0x" + bytes(c.to).hex(), int(c.value), bytes(c.data)) for c in tx.calls]
        ),
    }
    if tx.valid_before is not None:
        request["validBefore"] = hex(tx.valid_before)
    if tx.valid_after is not None:
        request["validAfter"] = hex(tx.valid_after)
    return request


async def simulate_credential_transaction(
    rpc_url: str,
    transaction: ParsedCredentialTransaction,
    *,
    fee_payer: TempoAccount | None = None,
    client: httpx.AsyncClient | None = None,
) -> None:
    """Simulate an unsponsored client-signed session transaction without broadcasting it.

    Sponsored transactions are simulated around co-signing, in
    :func:`send_credential_transaction`.
    """
    if fee_payer is not None:
        return
    await _simulate_call(
        rpc_url, {"from": transaction.sender, "calls": _rpc_calls(transaction.calls)}, client
    )


async def send_credential_transaction(
    rpc_url: str,
    transaction: ParsedCredentialTransaction,
    *,
    chain_id: int,
    label: TransactionLabel,
    expected_currency: str,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Broadcast a client-signed management transaction and wait for its receipt.

    With `fee_payer`, the 0x78 envelope is co-signed, simulated with
    `tempo_simulateV1` and checked for remaining validity before broadcast.
    """
    import httpx

    from mpp.methods.tempo import _fee_payer

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        raw = transaction.raw
        if fee_payer is not None:
            # Like mppx FeePayer.preflightSponsorship: execute the calls as the
            # sender (no fee fields) before co-signing, then the completed
            # envelope with its fee payer and fee token.
            await _simulate_call(
                rpc_url,
                {"from": transaction.sender, "calls": _rpc_calls(transaction.calls)},
                http,
            )
            raw, cosigned, sender = _cosign(
                transaction,
                chain_id=chain_id,
                fee_payer=fee_payer,
                fee_payer_policy=fee_payer_policy,
                allowed_fee_tokens=allowed_fee_tokens or [expected_currency],
                challenge_expires=challenge_expires,
            )
            await _simulate_call(
                rpc_url, _sponsored_simulation_request(cosigned, sender, fee_payer.address), http
            )
            if transaction.valid_before is not None:
                _fee_payer.assert_remaining_validity(transaction.valid_before)
        tx_hash = await send_raw_transaction(rpc_url, raw, client=http)
        try:
            return await wait_for_successful_receipt(rpc_url, tx_hash, client=http)
        except VerificationFailedError as error:
            raise VerificationFailedError(
                f"{label} precompile transaction reverted: {tx_hash}"
            ) from error
    finally:
        if owns_client:
            await http.aclose()


@dataclass(frozen=True, slots=True)
class BroadcastOpenResult:
    """A verified, mined `open` transaction."""

    tx_hash: str
    descriptor: ChannelDescriptor
    state: ChannelState
    expiring_nonce_hash: str
    open_deposit: int


async def broadcast_open_transaction(
    rpc_url: str,
    *,
    serialized_transaction: str,
    chain_id: int,
    escrow_contract: str,
    expected_authorized_signer: str,
    expected_channel_id: str,
    expected_currency: str,
    expected_expiring_nonce_hash: str,
    expected_operator: str,
    expected_payee: str,
    expected_payer: str,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
    before_broadcast: Callable[[ValidatedOpenTransaction], Awaitable[None] | None] | None = None,
    client: httpx.AsyncClient | None = None,
) -> BroadcastOpenResult:
    """Validate, broadcast and verify a client-signed `open` transaction.

    Checks the `ChannelOpened` event against the calldata and credential, then
    reads the channel back at the receipt's block.
    """
    validated = validate_open_credential_transaction(
        serialized_transaction=serialized_transaction,
        chain_id=chain_id,
        escrow_contract=escrow_contract,
        expected_authorized_signer=expected_authorized_signer,
        expected_channel_id=expected_channel_id,
        expected_currency=expected_currency,
        expected_expiring_nonce_hash=expected_expiring_nonce_hash,
        expected_operator=expected_operator,
        expected_payee=expected_payee,
        expected_payer=expected_payer,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        allowed_fee_tokens=allowed_fee_tokens,
        challenge_expires=challenge_expires,
    )
    if before_broadcast is not None:
        pending = before_broadcast(validated)
        if pending is not None:
            await pending
    receipt = await send_credential_transaction(
        rpc_url,
        validated.transaction,
        chain_id=chain_id,
        label="open",
        expected_currency=expected_currency,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        allowed_fee_tokens=allowed_fee_tokens,
        challenge_expires=challenge_expires,
        client=client,
    )
    opened = get_channel_event(
        receipt, "ChannelOpened", expected_channel_id, escrow=escrow_contract
    )
    validate_channel_opened_receipt(
        chain_id=chain_id,
        descriptor=validated.descriptor,
        emitted_channel_id=opened["channelId"],
        emitted_deposit=opened["deposit"],
        emitted_expiring_nonce_hash=opened["expiringNonceHash"],
        escrow=escrow_contract,
        expected_channel_id=expected_channel_id,
        open_deposit=validated.open_deposit,
    )
    block = _receipt_block(receipt)
    channel = await readback_with_retry(
        lambda: get_channel(
            rpc_url, validated.descriptor, escrow=escrow_contract, block=block, client=client
        )
    )
    validate_open_readback_state(emitted_deposit=opened["deposit"], state=channel.state)
    return BroadcastOpenResult(
        tx_hash=str(receipt["transactionHash"]),
        descriptor=validated.descriptor,
        state=channel.state,
        expiring_nonce_hash=opened["expiringNonceHash"],
        open_deposit=validated.open_deposit,
    )


@dataclass(frozen=True, slots=True)
class BroadcastTopUpResult:
    """A verified, mined `topUp` transaction."""

    tx_hash: str
    new_deposit: int
    state: ChannelState


async def broadcast_top_up_transaction(
    rpc_url: str,
    *,
    serialized_transaction: str,
    additional_deposit: int,
    chain_id: int,
    descriptor: ChannelDescriptor,
    escrow_contract: str,
    expected_channel_id: str,
    expected_currency: str,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> BroadcastTopUpResult:
    """Validate, broadcast and verify a client-signed `topUp` transaction."""
    validated = validate_top_up_credential_transaction(
        serialized_transaction=serialized_transaction,
        additional_deposit=additional_deposit,
        chain_id=chain_id,
        descriptor=descriptor,
        escrow_contract=escrow_contract,
        expected_channel_id=expected_channel_id,
        expected_currency=expected_currency,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        allowed_fee_tokens=allowed_fee_tokens,
        challenge_expires=challenge_expires,
    )
    receipt = await send_credential_transaction(
        rpc_url,
        validated.transaction,
        chain_id=chain_id,
        label="topUp",
        expected_currency=expected_currency,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        allowed_fee_tokens=allowed_fee_tokens,
        challenge_expires=challenge_expires,
        client=client,
    )
    topped_up = get_channel_event(receipt, "TopUp", expected_channel_id, escrow=escrow_contract)
    validate_top_up_receipt(
        emitted_channel_id=topped_up["channelId"], expected_channel_id=expected_channel_id
    )
    block = _receipt_block(receipt)
    state = await readback_with_retry(
        lambda: get_channel_state(
            rpc_url, topped_up["channelId"], escrow=escrow_contract, block=block, client=client
        )
    )
    validate_top_up_readback_state(new_deposit=topped_up["newDeposit"], state=state)
    return BroadcastTopUpResult(
        tx_hash=str(receipt["transactionHash"]), new_deposit=topped_up["newDeposit"], state=state
    )


# ──────────────────────────────────────────────────────────────────
# Building and sending transactions
# ──────────────────────────────────────────────────────────────────


async def _estimate_gas(
    rpc_url: str,
    sender: str,
    calls: Sequence[tuple[str, str]],
    client: httpx.AsyncClient | None,
    *,
    valid_before: int,
    required: bool = False,
) -> int:
    """Estimated gas plus headroom; ``required`` raises instead of using the default limit."""
    try:
        estimated = int(
            await _rpc(
                rpc_url,
                "eth_estimateGas",
                [
                    {
                        "from": sender,
                        "calls": [{"to": to, "value": "0x0", "data": data} for to, data in calls],
                        "nonceKey": hex(EXPIRING_NONCE_KEY),
                        # Expiring-nonce transactions must carry validBefore to execute.
                        "validBefore": hex(valid_before),
                    },
                    "latest",
                ],
                client,
            ),
            16,
        )
    except Exception:
        if required:
            raise
        return DEFAULT_GAS_LIMIT
    # Headroom for the expiring-nonce and signature checks the estimate may not price.
    return estimated + estimated // 5 + 25_000


async def _build_signed_transaction(
    account: TempoAccount,
    calls: Sequence[tuple[str, str]],
    *,
    rpc_url: str,
    chain_id: int | None,
    fee_token: str | None,
    awaiting_fee_payer: bool,
    root_account: str | None,
    valid_before: int | None,
    valid_after: int | None,
    client: httpx.AsyncClient | None,
    estimate_required: bool = False,
) -> tuple[Any, int]:
    """Build and sender-sign an expiring-nonce Tempo transaction; returns (tx, chain_id)."""
    # pytempo ships no type information.
    from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

    from mpp.methods.tempo.fee_payer_policy import get_policy

    sender = root_account or account.address
    chain_hex, gas_hex = await asyncio.gather(
        _rpc(rpc_url, "eth_chainId", [], client),
        _rpc(rpc_url, "eth_gasPrice", [], client),
    )
    rpc_chain_id = int(chain_hex, 16)
    if chain_id is not None and rpc_chain_id != chain_id:
        raise ValueError(f"Chain ID mismatch: RPC returned {rpc_chain_id}, expected {chain_id}")
    gas_price = int(gas_hex, 16)
    priority_fee = gas_price
    if awaiting_fee_payer:
        # Keep sponsored envelopes inside the server's default policy.
        priority_fee = min(gas_price, get_policy(rpc_chain_id).max_priority_fee_per_gas)
    valid_before = valid_before or int(time.time()) + EXPIRING_NONCE_VALID_BEFORE_SECS
    gas_limit = await _estimate_gas(
        rpc_url, sender, calls, client, valid_before=valid_before, required=estimate_required
    )
    tx = TempoTransaction.create(
        chain_id=rpc_chain_id,
        gas_limit=gas_limit,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=priority_fee,
        nonce=0,
        nonce_key=EXPIRING_NONCE_KEY,
        fee_token=fee_token,
        awaiting_fee_payer=awaiting_fee_payer,
        valid_before=valid_before,
        valid_after=valid_after,
        calls=tuple(Call.create(to=to, value=0, data=data) for to, data in calls),
    )
    if root_account is not None:
        from pytempo import sign_tx_access_key  # pyright: ignore[reportMissingTypeStubs]

        return sign_tx_access_key(tx, account.private_key, root_account), rpc_chain_id
    return tx.sign(account.private_key), rpc_chain_id


def _serialize_client_transaction(signed: Any, awaiting_fee_payer: bool) -> str:
    if awaiting_fee_payer:
        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        return "0x" + encode_fee_payer_envelope(signed).hex()
    return "0x" + signed.encode().hex()


def _random_valid_after() -> int:
    """Random past seconds that keep otherwise identical expiring transactions distinct."""
    latest = int(time.time()) - 60
    if latest <= 0:
        return 0
    return random.SystemRandom().randrange(latest)


async def build_open_transaction(
    account: TempoAccount,
    *,
    rpc_url: str,
    payee: str,
    token: str,
    deposit: int,
    chain_id: int | None = None,
    escrow: str = ESCROW_ADDRESS,
    operator: str = ZERO_ADDRESS,
    authorized_signer: str | None = None,
    salt: str | None = None,
    fee_payer: bool = False,
    fee_token: str | None = None,
    prefix_calls: Sequence[tuple[str, str]] = (),
    root_account: str | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, ChannelDescriptor, str]:
    """Build and sign an expiring-nonce `open` transaction (mppx `createOpenPayload`).

    Returns `(raw_tx, descriptor, channel_id)`. The payer is `root_account` when
    signing with an access key, else `account`; the authorized signer defaults
    to `account` (the access key, when one signs). With `fee_payer`, `raw_tx` is
    a 0x78 fee payer envelope for the server to co-sign. The fee token defaults
    to `token`. `prefix_calls` are `(to, data)` calls run first, such as an auto-swap.
    """
    payer = root_account or account.address
    signer = authorized_signer or account.address
    channel_salt = salt or "0x" + os.urandom(32).hex()
    open_data = abi.encode_open(
        payee=payee,
        operator=operator,
        token=token,
        deposit=deposit,
        salt=channel_salt,
        authorized_signer=signer,
    )
    signed, resolved_chain_id = await _build_signed_transaction(
        account,
        [*prefix_calls, (escrow, open_data)],
        rpc_url=rpc_url,
        chain_id=chain_id,
        fee_token=fee_token or token,
        awaiting_fee_payer=fee_payer,
        root_account=root_account,
        valid_before=valid_before,
        valid_after=None,
        client=client,
    )
    raw_tx = _serialize_client_transaction(signed, fee_payer)
    descriptor = ChannelDescriptor(
        payer=payer,
        payee=payee,
        operator=operator,
        token=token,
        salt=channel_salt,
        authorized_signer=signer,
        expiring_nonce_hash=expiring_nonce_hash(raw_tx, payer, fee_payer=fee_payer or None),
    )
    channel_id = compute_channel_id(descriptor, chain_id=resolved_chain_id, escrow=escrow)
    return raw_tx, descriptor, channel_id


async def build_top_up_transaction(
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    additional_deposit: int,
    *,
    rpc_url: str,
    chain_id: int | None = None,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: bool = False,
    fee_token: str | None = None,
    prefix_calls: Sequence[tuple[str, str]] = (),
    root_account: str | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Build and sign an expiring-nonce `topUp` transaction (mppx `createTopUpPayload`).

    Uses a random past `valid_after` so identical top-ups stay distinct.
    """
    signed, _ = await _build_signed_transaction(
        account,
        [*prefix_calls, (escrow, abi.encode_top_up(descriptor, additional_deposit))],
        rpc_url=rpc_url,
        chain_id=chain_id,
        fee_token=fee_token or descriptor.token,
        awaiting_fee_payer=fee_payer,
        root_account=root_account,
        valid_before=valid_before,
        valid_after=_random_valid_after(),
        client=client,
    )
    return _serialize_client_transaction(signed, fee_payer)


async def resolve_fee_token(
    rpc_url: str,
    account: str,
    candidates: Sequence[str],
    *,
    client: httpx.AsyncClient | None = None,
) -> str | None:
    """The first candidate fee token `account` holds, else the first candidate."""
    from mpp.methods.tempo._rpc import _tip20_balance  # pyright: ignore[reportPrivateUsage]

    for token in candidates:
        try:
            if await _tip20_balance(rpc_url, token, account, client=client) > 0:
                return token
        except Exception:
            continue
    return candidates[0] if candidates else None


async def _send_precompile_transaction(
    rpc_url: str,
    account: TempoAccount,
    data: str,
    label: str,
    *,
    escrow: str,
    fee_payer: TempoAccount | None,
    fee_payer_policy: Mapping[str, int] | None,
    fee_token: str | None,
    candidate_fee_tokens: Sequence[str] | None,
    valid_before: int | None,
    client: httpx.AsyncClient | None,
) -> str:
    """Sign and send one escrow call from `account`, sponsored by `fee_payer` when given."""
    from mpp.methods.tempo._defaults import fee_tokens_for_chain
    from mpp.methods.tempo.fee_payer_policy import get_policy

    sponsored = fee_payer is not None and not _same_address(fee_payer.address, account.address)
    resolved_fee_token = fee_token
    if fee_payer is not None and resolved_fee_token is None:
        candidates = candidate_fee_tokens
        if candidates is None:
            chain_id = int(await _rpc(rpc_url, "eth_chainId", [], client), 16)
            candidates = fee_tokens_for_chain(chain_id)
        resolved_fee_token = await resolve_fee_token(
            rpc_url, fee_payer.address, candidates, client=client
        )
    signed, chain_id = await _build_signed_transaction(
        account,
        [(escrow, data)],
        rpc_url=rpc_url,
        chain_id=None,
        fee_token=resolved_fee_token,
        awaiting_fee_payer=sponsored,
        root_account=None,
        valid_before=valid_before,
        valid_after=None,
        client=client,
        # Like viem, a call whose gas estimate fails (it would revert) is never sent.
        estimate_required=True,
    )
    if sponsored:
        assert fee_payer is not None
        policy = get_policy(chain_id, fee_payer_policy)
        if signed.gas_limit > policy.max_gas:
            raise BadRequestError("fee-payer policy maxGas exceeded")
        if signed.max_fee_per_gas > policy.max_fee_per_gas:
            raise BadRequestError("fee-payer policy maxFeePerGas exceeded")
        if signed.max_priority_fee_per_gas > policy.max_priority_fee_per_gas:
            raise BadRequestError("fee-payer policy maxPriorityFeePerGas exceeded")
        if signed.gas_limit * signed.max_fee_per_gas > policy.max_total_fee:
            raise BadRequestError("fee-payer policy maxTotalFee exceeded")
        signed = signed.sign(fee_payer.private_key, for_fee_payer=True)
    tx_hash = await send_raw_transaction(rpc_url, "0x" + signed.encode().hex(), client=client)
    if sponsored:
        try:
            await wait_for_successful_receipt(rpc_url, tx_hash, client=client)
        except VerificationFailedError as error:
            raise VerificationFailedError(
                f"{label} precompile transaction reverted: {tx_hash}"
            ) from error
    return tx_hash


async def settle_on_chain(
    rpc_url: str,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    cumulative_amount: int,
    signature: str,
    *,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Send `settle(descriptor, cumulativeAmount, signature)` as the payee or operator.

    Returns the transaction hash; a sponsored send also waits for a successful receipt.
    """
    return await _send_precompile_transaction(
        rpc_url,
        account,
        abi.encode_settle(descriptor, cumulative_amount, signature),
        "settle",
        escrow=escrow,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        candidate_fee_tokens=candidate_fee_tokens,
        valid_before=valid_before,
        client=client,
    )


async def close_on_chain(
    rpc_url: str,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    cumulative_amount: int,
    capture_amount: int,
    signature: str,
    *,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Send the payee's `close(descriptor, cumulativeAmount, captureAmount, signature)`."""
    return await _send_precompile_transaction(
        rpc_url,
        account,
        abi.encode_close(descriptor, cumulative_amount, capture_amount, signature),
        "close",
        escrow=escrow,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        candidate_fee_tokens=candidate_fee_tokens,
        valid_before=valid_before,
        client=client,
    )


async def top_up_on_chain(
    rpc_url: str,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    additional_deposit: int,
    *,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Send `topUp(descriptor, additionalDeposit)` directly as the payer."""
    return await _send_precompile_transaction(
        rpc_url,
        account,
        abi.encode_top_up(descriptor, additional_deposit),
        "topUp",
        escrow=escrow,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        candidate_fee_tokens=candidate_fee_tokens,
        valid_before=valid_before,
        client=client,
    )


async def request_close_on_chain(
    rpc_url: str,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    *,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Send the payer's `requestClose(descriptor)`, starting the close grace period."""
    return await _send_precompile_transaction(
        rpc_url,
        account,
        abi.encode_request_close(descriptor),
        "requestClose",
        escrow=escrow,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        candidate_fee_tokens=candidate_fee_tokens,
        valid_before=valid_before,
        client=client,
    )


async def withdraw_on_chain(
    rpc_url: str,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    *,
    escrow: str = ESCROW_ADDRESS,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    valid_before: int | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Send the payer's `withdraw(descriptor)` after the close grace period."""
    return await _send_precompile_transaction(
        rpc_url,
        account,
        abi.encode_withdraw(descriptor),
        "withdraw",
        escrow=escrow,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        candidate_fee_tokens=candidate_fee_tokens,
        valid_before=valid_before,
        client=client,
    )
