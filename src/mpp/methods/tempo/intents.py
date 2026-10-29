"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import attrs
from eth_abi.abi import decode
from eth_abi.exceptions import DecodingError

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_CONFIRMATION_TIMEOUT, DEFAULT_PAID_RETRY_TIMEOUT, DEFAULT_TIMEOUT
from mpp._did import parse_pkh_source
from mpp._typing import is_dict, is_list
from mpp._validation import Validation
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    PaymentExpiredError,
    VerificationError,
)
from mpp.methods.tempo import sponsor_budget as _sponsor_budget
from mpp.methods.tempo._defaults import PATH_USD, fee_tokens_for_chain, rpc_url_for_chain
from mpp.methods.tempo._rpc import _rpc_call, _tip20_balance
from mpp.methods.tempo.fee_payer_policy import MIN_REMAINING_VALIDITY_SECONDS, get_policy
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    Split,
    TransactionCredentialPayload,
)
from mpp.store import CompareAndSetStore, ExpiringStore, MemoryStore, Store

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

logger = logging.getLogger(__name__)

_warned_fallback_stores: set[str] = set()


def _challenge_expired(expires: str) -> bool:
    """Return whether a challenge ``expires`` timestamp has been reached."""
    return datetime.fromisoformat(expires.replace("Z", "+00:00")) <= datetime.now(UTC)


def _fallback_store(method: str) -> MemoryStore:
    """Create the in-memory replay store used when *method* has no store configured.

    Replay protection backed by this store only covers the current process, so this
    logs a warning once per *method* per process.
    """
    if method not in _warned_fallback_stores:
        _warned_fallback_stores.add(method)
        logger.warning(
            "%s has no store configured and is using an in-memory store. Replay "
            "protection is scoped to this process, so a credential accepted by one "
            "worker or replica can be accepted again by another, or after a restart. "
            "Pass a shared store (e.g. mpp.stores.RedisStore) via tempo.charge(store=...) "
            "when running more than one instance.",
            method,
        )
    return MemoryStore(max_entries=10_000)


TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_WITH_MEMO_SELECTOR = "95777d59"
APPROVE_SELECTOR = "095ea7b3"
# swapExactAmountOut(address,address,uint128,uint128)
SWAP_EXACT_AMOUNT_OUT_SELECTOR = "f0122b75"

SELECTOR_HEX_LEN = 8
ABI_WORD_HEX_LEN = 64
TRANSFER_CALL_DATA_HEX_LEN = SELECTOR_HEX_LEN + (2 * ABI_WORD_HEX_LEN)
TRANSFER_WITH_MEMO_CALL_DATA_HEX_LEN = SELECTOR_HEX_LEN + (3 * ABI_WORD_HEX_LEN)
APPROVE_CALL_DATA_HEX_LEN = SELECTOR_HEX_LEN + (2 * ABI_WORD_HEX_LEN)
SWAP_EXACT_AMOUNT_OUT_CALL_DATA_HEX_LEN = SELECTOR_HEX_LEN + (4 * ABI_WORD_HEX_LEN)

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_MEMO_TOPIC = "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
STABLECOIN_DEX = "0xdec0000000000000000000000000000000000000"

MAX_SPLITS = 10
MAX_TRANSFERS = MAX_SPLITS + 1
ALREADY_KNOWN_TRANSACTION_RE = re.compile(r"\b(?:already ?known|known transaction)\b", re.I)
# EIP-7966: the transaction was pooled but not confirmed within the sync timeout.
SYNC_CONFIRMATION_TIMEOUT_CODE = 4
# Seconds between receipt lookups; matches mppx's default Tempo polling interval.
RECEIPT_POLL_INTERVAL = 0.5
# Seconds past a transaction's ``valid_before`` after which it cannot be included.
VALID_BEFORE_GRACE = 2.0


def _assert_not_expired(valid_before: int) -> None:
    """Reject a sponsored transaction whose ``valid_before`` has passed."""
    if valid_before <= int(time.time()):
        raise VerificationError(
            f"Fee payer envelope expired: valid_before ({valid_before}) is not in the future"
        )


def _assert_remaining_validity(valid_before: int) -> None:
    """Reject a sponsored transaction that could expire before it is included."""
    _assert_not_expired(valid_before)
    # Leave time to simulate, broadcast and include the sponsored transaction.
    if valid_before < math.ceil(time.time()) + MIN_REMAINING_VALIDITY_SECONDS:
        raise VerificationError(
            "Invalid transaction: fee-sponsored transaction needs at least "
            f"{MIN_REMAINING_VALIDITY_SECONDS} seconds of remaining validity"
        )


def _transaction_valid_before(raw_tx: str) -> int | None:
    """Return a Tempo transaction's ``valid_before`` timestamp, if it has one."""
    try:
        from mpp.methods.tempo import _rlp as rlp

        tx_bytes = bytes.fromhex(_strip_0x(raw_tx))
        if tx_bytes[:1] not in (b"\x76", b"\x78"):
            return None
        decoded = rlp.decode(tx_bytes[1:])
    except Exception:
        return None
    if not is_list(decoded) or len(decoded) <= 8:
        return None
    valid_before = decoded[8]
    if not isinstance(valid_before, bytes) or not valid_before:
        return None
    return int.from_bytes(valid_before, "big")


def _raw_transaction_hash(raw_tx: str) -> str:
    """Return the transaction hash for a raw signed transaction."""
    from eth_hash.auto import keccak

    try:
        tx_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
    except ValueError as err:
        raise VerificationError("Invalid transaction signature") from err

    return "0x" + keccak(tx_bytes).hex()


def _canonical_signature(signature: bytes) -> bytes:
    """Encode secp256k1 recovery IDs as 27/28, including inside keychain signatures."""
    if len(signature) == 65 and signature[64] in (0, 1):
        return signature[:64] + bytes([signature[64] + 27])
    if len(signature) > 21 and signature[0] in (0x03, 0x04):
        return signature[:21] + _canonical_signature(signature[21:])
    return signature


def _canonical_raw_transaction(raw_tx: str) -> str:
    """Return the canonical encoding of a signed 0x76 Tempo transaction.

    Tempo nodes accept raw (0/1) secp256k1 recovery IDs and normalize them to
    27/28 before deriving the transaction hash. Broadcasting and hashing the
    canonical envelope keeps replay keys and receipt hashes equal to the node's.
    Anything that does not decode as a 0x76 transaction is returned unchanged.
    """
    from mpp.methods.tempo import _rlp as rlp

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        if tx_bytes[:1] != b"\x76":
            return raw_tx
        fields = rlp.decode(tx_bytes[1:])
    except Exception:
        return raw_tx
    if not is_list(fields) or len(fields) not in (14, 15):
        return raw_tx
    signature = fields[-1]
    if not isinstance(signature, bytes):
        return raw_tx
    canonical = _canonical_signature(signature)
    if canonical == signature:
        return raw_tx
    return "0x" + (b"\x76" + rlp.encode([*fields[:-1], canonical])).hex()


def _transaction_fee_token(raw_tx: str) -> str | None:
    """Return the fee token of a signed 0x76 Tempo transaction, if it sets one."""
    from mpp.methods.tempo import _rlp as rlp

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        fields = rlp.decode(tx_bytes[1:])
    except Exception as err:
        raise RuntimeError("fee-sponsored transaction feeToken is invalid") from err
    if tx_bytes[:1] != b"v" or not is_list(fields) or len(fields) < 11:
        raise RuntimeError("fee-sponsored transaction feeToken is invalid")
    fee_token = fields[10]
    if fee_token == b"":
        return None
    if not isinstance(fee_token, bytes) or len(fee_token) != 20:
        raise RuntimeError("fee-sponsored transaction feeToken is invalid")
    return "0x" + fee_token.hex()


def _transaction_sender(raw_tx: str) -> str | None:
    """Return the lowercase address of the account a Tempo transaction debits.

    The sender is derived from the sender signature: secp256k1 signatures are
    recovered over the sender signing hash; keychain, multisig, P256 and
    WebAuthn signatures name the account (keychain root, multisig account, or
    public-key address), which the chain authenticates at settlement. A 0x78
    fee payer envelope must also declare that sender in its sender slot.

    Returns ``None`` if the transaction is malformed or the sender cannot be
    derived.
    """
    from eth_account import Account
    from eth_hash.auto import keccak

    from mpp.methods.tempo import _rlp as rlp

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        fields = rlp.decode(tx_bytes[1:])
    except Exception:
        return None
    if tx_bytes[0] not in (0x76, 0x78) or not is_list(fields):
        return None
    if len(fields) not in (14, 15):
        return None
    is_envelope = tx_bytes[0] == 0x78
    sender_slot, signature = fields[11], fields[-1]
    if not isinstance(signature, bytes) or not signature:
        return None

    sender: str | None = None
    if len(signature) == 65:
        has_fee_payer = is_envelope or sender_slot != b""
        preimage = [
            *fields[:10],
            b"" if has_fee_payer else fields[10],
            b"\x00" if has_fee_payer else b"",
            *fields[12:-1],
        ]
        try:
            sender = Account._recover_hash(
                keccak(b"\x76" + rlp.encode(preimage)), signature=signature
            )
        except Exception:
            return None
    else:
        type_id, data = signature[0], signature[1:]
        if type_id in (0x03, 0x04) and len(data) > 20:
            sender = "0x" + data[:20].hex()
        elif type_id == 0x01 and len(data) == 129:
            sender = "0x" + keccak(data[64:128])[-20:].hex()
        elif type_id == 0x02 and len(data) >= 128:
            sender = "0x" + keccak(data[-64:])[-20:].hex()
        elif type_id == 0x05:
            try:
                account = rlp.decode(data)[0]
            except Exception:
                return None
            if isinstance(account, bytes) and len(account) == 20:
                sender = "0x" + account.hex()
    if sender is None:
        return None
    sender = sender.lower()
    if is_envelope and sender_slot != bytes.fromhex(sender[2:]):
        return None
    return sender


def _parse_memo_bytes(memo: str | None) -> bytes | None:
    """Parse a hex memo string into 32 bytes.

    Returns None when no memo is supplied. Raises VerificationError when a memo
    is explicitly provided but cannot be decoded as exactly 32 bytes of hex.
    """
    if memo is None:
        return None
    hex_str = memo[2:] if memo.startswith("0x") else memo
    try:
        b = bytes.fromhex(hex_str)
    except ValueError as err:
        raise VerificationError(f"Invalid memo hex: {memo}") from err
    if len(b) != 32:
        raise VerificationError(f"Memo must be exactly 32 bytes, got {len(b)}")
    return b


@dataclass
class Transfer:
    """A single transfer in a charge (primary or split)."""

    amount: int
    recipient: str
    memo: bytes | None = None


def get_transfers(
    total_amount: int,
    primary_recipient: str,
    primary_memo: str | None,
    splits: list[Split] | None,
) -> list[Transfer]:
    """Compute the ordered list of transfers for a charge.

    The primary transfer receives total_amount - sum(splits) and inherits
    the top-level memo. Split transfers follow in declaration order.
    """
    if not splits:
        return [
            Transfer(
                amount=total_amount,
                recipient=primary_recipient,
                memo=_parse_memo_bytes(primary_memo),
            )
        ]

    if len(splits) > MAX_SPLITS:
        raise VerificationError(f"Too many splits: {len(splits)} (max {MAX_SPLITS})")

    split_sum = 0
    split_transfers: list[Transfer] = []

    for s in splits:
        amt = int(s.amount)
        if amt <= 0:
            raise VerificationError("Split amount must be greater than zero")
        split_sum += amt
        split_transfers.append(
            Transfer(
                amount=amt,
                recipient=s.recipient,
                memo=_parse_memo_bytes(s.memo),
            )
        )

    if split_sum >= total_amount:
        raise VerificationError(
            f"Sum of splits ({split_sum}) must be less than total amount ({total_amount})"
        )

    primary_amount = total_amount - split_sum
    transfers = [
        Transfer(
            amount=primary_amount,
            recipient=primary_recipient,
            memo=_parse_memo_bytes(primary_memo),
        )
    ]
    transfers.extend(split_transfers)
    return transfers


def _match_single_transfer_calldata(
    call_data_hex: str,
    recipient: str,
    amount: int,
    memo: bytes | None,
) -> bool:
    """Check if ABI-encoded calldata matches a single expected transfer."""
    call_data_hex = _strip_0x(call_data_hex)
    if len(call_data_hex) < TRANSFER_CALL_DATA_HEX_LEN:
        return False

    selector = call_data_hex[:SELECTOR_HEX_LEN].lower()

    if memo is not None:
        if selector != TRANSFER_WITH_MEMO_SELECTOR:
            return False
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256", "bytes32"),
            TRANSFER_WITH_MEMO_CALL_DATA_HEX_LEN,
        )
    elif selector == TRANSFER_WITH_MEMO_SELECTOR:
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256", "bytes32"),
            TRANSFER_WITH_MEMO_CALL_DATA_HEX_LEN,
        )
    elif selector != TRANSFER_SELECTOR:
        return False
    else:
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256"),
            TRANSFER_CALL_DATA_HEX_LEN,
        )

    if decoded is None:
        return False

    decoded_to = decoded[0]
    decoded_amount = decoded[1]

    if decoded_to.lower() != recipient.lower():
        return False
    if decoded_amount != amount:
        return False

    if memo is not None:
        decoded_memo = decoded[2]
        if decoded_memo != memo:
            return False

    return True


@dataclass(frozen=True, slots=True)
class MatchedTransferLog:
    kind: Literal["memo", "transfer"]
    memo: str | None = None
    sender: str | None = None
    """Lowercase ``from`` address of the transfer."""


@dataclass(frozen=True, slots=True)
class SenderValidation:
    """Arguments passed to a ``validate_sender`` callback on a sender mismatch."""

    expected_sender: str
    """The expected sender: the address declared in the credential source."""
    sender: str
    """The actual ``from`` address on the transfer log."""
    source: str | None
    """The raw credential source DID, if provided."""


# Authorizes a transfer whose sender differs from the expected sender;
# return ``True`` to accept.
ValidateSender = Callable[[SenderValidation], bool]


def _rpc_error_msg(result: dict[str, Any]) -> str:
    """Extract error message from a JSON-RPC error response."""
    error_obj = result["error"]
    if is_dict(error_obj):
        msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
        data = error_obj.get("data", "")
        return f"{msg}: {data}" if data else msg
    return str(error_obj)


# JSON-RPC ``execution reverted`` (EIP-1474); other execution errors say "revert".
_EXECUTION_ERROR_CODES = frozenset({3})


def _is_ambiguous_broadcast_error(error: Exception | dict[str, Any]) -> bool:
    """Return true when a failed broadcast may have reached the mempool.

    ``error`` is the exception raised by the send, matched anywhere in its
    ``__cause__``/``__context__`` chain, or the JSON-RPC error response.
    Ambiguous outcomes, worth polling for a receipt:

    - Timeouts (including the local confirmation deadline) and lost
      connections after the request was sent. Connect and pool failures mean
      it was never sent.
    - HTTP 5xx responses. Other statuses are definitive.
    - JSON-RPC code 4, the EIP-7966 timeout for a pooled, unconfirmed transaction.
    - Messages matching "already known" or "known transaction".

    Everything else (e.g. -32601, -32602, insufficient funds) is definitive.
    """
    import httpx

    if isinstance(error, dict):
        rpc_error = error.get("error")
        if is_dict(rpc_error) and rpc_error.get("code") == SYNC_CONFIRMATION_TIMEOUT_CODE:
            return True
        return ALREADY_KNOWN_TRANSACTION_RE.search(_rpc_error_msg(error)) is not None

    seen: set[int] = set()
    cause: BaseException | None = error
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
            return False
        if isinstance(cause, httpx.HTTPStatusError):
            return cause.response.status_code >= 500
        if isinstance(
            cause,
            (TimeoutError, httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError),
        ):
            return True
        if ALREADY_KNOWN_TRANSACTION_RE.search(str(cause)):
            return True
        cause = cause.__cause__ or cause.__context__
    return False


# Kept for tests/test_tempo.py; nothing in the package calls it.
def _match_transfer_calldata(  # pyright: ignore[reportUnusedFunction]
    call_data_hex: str, request: ChargeRequest
) -> bool:
    """Check if ABI-encoded calldata matches the expected transfer parameters."""
    call_data_hex = _strip_0x(call_data_hex)
    if len(call_data_hex) < TRANSFER_CALL_DATA_HEX_LEN:
        return False

    selector = call_data_hex[:SELECTOR_HEX_LEN].lower()
    if selector == TRANSFER_WITH_MEMO_SELECTOR:
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256", "bytes32"),
            TRANSFER_WITH_MEMO_CALL_DATA_HEX_LEN,
        )
    elif selector != TRANSFER_SELECTOR:
        return False
    else:
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256"),
            TRANSFER_CALL_DATA_HEX_LEN,
        )

    if decoded is None:
        return False

    decoded_to = decoded[0]
    decoded_amount = decoded[1]

    if decoded_to.lower() != request.recipient.lower():
        return False
    if decoded_amount != int(request.amount):
        return False

    return True


def _strip_0x(hex_str: str) -> str:
    return hex_str[2:] if hex_str.startswith(("0x", "0X")) else hex_str


def _decode_static_call_args(
    call_data_hex: str,
    arg_types: tuple[str, ...],
    expected_hex_len: int,
) -> tuple[Any, ...] | None:
    call_data_hex = _strip_0x(call_data_hex)
    if len(call_data_hex) != expected_hex_len:
        return None

    try:
        args_bytes = bytes.fromhex(call_data_hex[SELECTOR_HEX_LEN:])
        return decode(arg_types, args_bytes, strict=True)
    except (ValueError, DecodingError):
        return None


def _validate_call_scope(calls: list[tuple[str, int, str]]) -> int:
    if not calls:
        raise VerificationError("Transaction contains no calls")

    selectors = [call_data[:8].lower() for _, _, call_data in calls]
    has_swap_prefix = selectors[0] == APPROVE_SELECTOR

    if has_swap_prefix:
        if len(selectors) < 3 or selectors[1] != SWAP_EXACT_AMOUNT_OUT_SELECTOR:
            raise VerificationError("Invalid transaction: disallowed call pattern")
        transfer_selectors = selectors[2:]
    else:
        if selectors[0] == SWAP_EXACT_AMOUNT_OUT_SELECTOR:
            raise VerificationError("Invalid transaction: disallowed call pattern")
        transfer_selectors = selectors

    if (
        not transfer_selectors
        or len(transfer_selectors) > MAX_TRANSFERS
        or any(
            selector not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR)
            for selector in transfer_selectors
        )
    ):
        raise VerificationError("Invalid transaction: disallowed call pattern")

    if has_swap_prefix:
        approve_to, approve_value, approve_data = calls[0]
        swap_to, swap_value, swap_data = calls[1]
        # Like mppx, no call may carry a native value.
        if approve_value or swap_value:
            raise VerificationError("Invalid transaction: call value is not allowed")
        decoded_approve = _decode_static_call_args(
            approve_data,
            ("address", "uint256"),
            APPROVE_CALL_DATA_HEX_LEN,
        )
        if decoded_approve is None:
            raise VerificationError("Invalid transaction: malformed approve call data")
        decoded_swap = _decode_static_call_args(
            swap_data,
            ("address", "address", "uint128", "uint128"),
            SWAP_EXACT_AMOUNT_OUT_CALL_DATA_HEX_LEN,
        )
        if decoded_swap is None:
            raise VerificationError("Invalid transaction: malformed swap call data")
        approve_spender = decoded_approve[0]
        swap_token_in = decoded_swap[0]

        if approve_to.lower() != swap_token_in.lower():
            raise VerificationError("Invalid transaction: approve target does not match swap token")
        if approve_spender.lower() != STABLECOIN_DEX.lower():
            raise VerificationError(
                "Invalid transaction: approve spender is not the stablecoin DEX"
            )
        if swap_to.lower() != STABLECOIN_DEX.lower():
            raise VerificationError("Invalid transaction: swap target is not the stablecoin DEX")

    return 2 if has_swap_prefix else 0


def _funding_currency(raw_tx: str, request: ChargeRequest) -> str | None:
    """Return the token a validated pull-mode transaction debits to fund the payment.

    A DEX auto-swap route (approve, swap, transfers) is funded by the approved
    swap input token; a direct transfer route by the charge currency. Call
    validation has already bound the route to the expected transfers.
    """
    from mpp.methods.tempo import _rlp as rlp

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        first_call = rlp.decode(tx_bytes[1:])[4][0]
        call_to, call_data = first_call[0], first_call[2]
    except Exception:
        return None
    if not isinstance(call_to, bytes) or not isinstance(call_data, bytes):
        return None
    if call_data[:4].hex() == APPROVE_SELECTOR:
        return "0x" + call_to.hex()
    return request.currency


def _rpc_transaction_calls(transaction: dict[str, Any]) -> list[tuple[str, int, str]] | None:
    """Normalize an RPC transaction's calls, or ``None`` if they are malformed.

    Tempo transactions list their batched ``calls``; any other transaction is
    treated as its single ``to``/``input`` call.
    """
    raw_calls = transaction.get("calls")
    if raw_calls is None:
        to = transaction.get("to")
        raw_calls = (
            [{"to": to, "value": transaction.get("value"), "input": transaction.get("input")}]
            if to
            else []
        )
    if not is_list(raw_calls):
        return None
    calls: list[tuple[str, int, str]] = []
    for call in raw_calls:
        if not is_dict(call):
            return None
        to = call.get("to")
        data = call.get("input", call.get("data"))
        value = call.get("value") or "0x0"
        if not isinstance(to, str) or not isinstance(data, str):
            return None
        try:
            value_int = int(value, 16) if isinstance(value, str) else int(value)
        except (TypeError, ValueError):
            return None
        calls.append((to.lower(), value_int, _strip_0x(data)))
    return calls


def _calls_funding_currency(
    calls: list[tuple[str, int, str]], request: ChargeRequest
) -> str | None:
    """Return the token a recognized payment route debits, or ``None``.

    Unrecognized calls leave the funding currency unknown; they do not
    invalidate a payment already verified from its receipt logs.
    """
    try:
        _validate_normalized_calls(calls, request)
    except Exception:
        return None
    if calls[0][2][:8].lower() == APPROVE_SELECTOR:
        return calls[0][0]
    return request.currency


def _validate_normalized_calls(
    calls: list[tuple[str, int, str]], request: ChargeRequest
) -> list[MatchedTransferLog]:
    """Validate calls against the expected transfers and return the payment legs."""
    prefix_len = _validate_call_scope(calls)
    if prefix_len == 2:
        approve = _decode_static_call_args(
            calls[0][2], ("address", "uint256"), APPROVE_CALL_DATA_HEX_LEN
        )
        swap = _decode_static_call_args(
            calls[1][2],
            ("address", "address", "uint128", "uint128"),
            SWAP_EXACT_AMOUNT_OUT_CALL_DATA_HEX_LEN,
        )
        # Call scope validation has already checked the canonical encoding.
        assert approve is not None and swap is not None
        token_in, token_out, amount_out, max_amount_in = swap
        if token_out.lower() != request.currency.lower():
            raise VerificationError(
                "Invalid transaction: swap output token does not match currency"
            )
        if token_in.lower() == token_out.lower():
            raise VerificationError("Invalid transaction: swap input and output tokens must differ")
        if not 0 < amount_out <= int(request.amount):
            raise VerificationError(
                "Invalid transaction: swap output must be positive and not exceed payment"
            )
        if max_amount_in <= 0 or approve[1] != max_amount_in:
            raise VerificationError(
                "Invalid transaction: approval must match positive swap maximum input"
            )
    payment_calls = calls[prefix_len:]

    expected = get_transfers(
        int(request.amount),
        request.recipient,
        None,
        request.methodDetails.splits,
    )

    if len(payment_calls) != len(expected):
        raise VerificationError("Invalid transaction: contains unauthorized extra calls")

    sorted_expected = sorted(expected, key=lambda t: 0 if t.memo else 1)
    used_calls: set[int] = set()
    legs: list[MatchedTransferLog] = []

    for transfer in sorted_expected:
        found = False
        for call_idx, (call_to, call_value, call_data) in enumerate(payment_calls):
            if call_idx in used_calls:
                continue
            if call_to.lower() != request.currency.lower():
                continue
            if call_value:
                continue
            if _match_single_transfer_calldata(
                call_data, transfer.recipient, transfer.amount, transfer.memo
            ):
                used_calls.add(call_idx)
                legs.append(_payment_call_leg(call_data))
                found = True
                break
        if not found:
            raise VerificationError("Invalid transaction: no matching payment call found")

    if len(used_calls) != len(payment_calls):
        raise VerificationError("Invalid transaction: contains unauthorized extra calls")
    return legs


def _payment_call_leg(call_data_hex: str) -> MatchedTransferLog:
    """Describe a validated payment call as a transfer leg for memo binding checks."""
    call_data_hex = _strip_0x(call_data_hex)
    if call_data_hex[:SELECTOR_HEX_LEN].lower() == TRANSFER_WITH_MEMO_SELECTOR:
        decoded = _decode_static_call_args(
            call_data_hex,
            ("address", "uint256", "bytes32"),
            TRANSFER_WITH_MEMO_CALL_DATA_HEX_LEN,
        )
        if decoded is not None:
            return MatchedTransferLog(kind="memo", memo="0x" + decoded[2].hex())
    return MatchedTransferLog(kind="transfer")


# ──────────────────────────────────────────────────────────────────
# Charge intent
# ──────────────────────────────────────────────────────────────────


class ChargeIntent:
    """Tempo charge intent for one-time payments.

    Verifies that a payment transaction matches the requested parameters.

    :func:`mpp.methods.tempo.server.charge` creates and configures one for its
    server methods. You can also create one directly to verify credentials.

    This class manages an HTTP client lifecycle. Use as an async context manager
    for automatic cleanup, or call `aclose()` explicitly when done.

    Example:
        from mpp.methods.tempo import ChargeIntent

        # chain_id resolves RPC automatically
        intent = ChargeIntent(chain_id=42431)

        # Or explicit rpc_url (overrides chain_id)
        intent = ChargeIntent(rpc_url="https://my-rpc.example.com")
    """

    name = "charge"

    def __init__(
        self,
        chain_id: int | None = None,
        rpc_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        store: Store | None = None,
        validate_sender: ValidateSender | None = None,
        confirmation_timeout: float = DEFAULT_CONFIRMATION_TIMEOUT,
        fee_payer: TempoAccount | None = None,
        fee_token: str | None = None,
        allowed_fee_tokens: Sequence[str] | None = None,
        sponsor_budget: _sponsor_budget.SponsorBudget | Literal[False] | None = None,
    ) -> None:
        """Initialize the charge intent.

        Args:
            chain_id: Tempo chain ID (4217 for mainnet, 42431 for
                testnet). Resolves the RPC URL automatically.
            rpc_url: Tempo RPC endpoint URL. Overrides ``chain_id``.
                One of them is required to verify credentials.
            http_client: Optional httpx client for making RPC calls.
                If provided, the caller is responsible for closing it.
            timeout: Request timeout in seconds (default: 30).
            store: Key-value store for tx hash replay protection. Defaults to
                an in-memory store capped at 10,000 entries on first settlement.
                New payments fail at capacity without evicting used hashes. Use a shared persistent
                store across server replicas and restarts. A warning is logged once per
                process when the in-memory default is used.
            validate_sender: Optional callback invoked when a hash-credential
                transfer's sender differs from the expected sender; return
                ``True`` to accept (e.g. smart-account / relayer flows).
            confirmation_timeout: Seconds to wait for a broadcast transaction's
                receipt (default: 30), shared by the synchronous send (at most
                two thirds of it) and, when its outcome is unknown (e.g. a read
                timeout or "already known"), polling for the receipt. Polling
                also stops once the transaction's ``valid_before`` has passed.
                Equivalent to mppx's ``confirmationTimeoutMs``.
            fee_payer: Account that co-signs and broadcasts sponsored
                (``feePayer``) transactions.
            fee_token: Token ``fee_payer`` pays gas in; it must be allowed.
            allowed_fee_tokens: Tokens a sponsored charge may pay gas in.
                Defaults to :func:`fee_tokens_for_chain` for a local fee payer;
                restricts an external ``feePayerUrl`` sponsor's token when set.
            sponsor_budget: Caps the fees ``fee_payer`` has in flight (default:
                :class:`~mpp.methods.tempo.sponsor_budget.SponsorBudget` on the
                replay store). Pass ``False`` only when it is enforced elsewhere.
        """
        if sponsor_budget is not None and sponsor_budget is not False:
            if not isinstance(sponsor_budget, _sponsor_budget.SponsorBudget):
                raise TypeError("sponsor_budget must be a SponsorBudget, False or None")
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self.fee_payer = fee_payer
        self.fee_token = fee_token
        self.allowed_fee_tokens = None if allowed_fee_tokens is None else tuple(allowed_fee_tokens)
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout
        self._store = store
        self._validate_sender = validate_sender
        self._confirmation_timeout = confirmation_timeout
        self._sponsor_budget = (
            None if sponsor_budget is False else sponsor_budget or _sponsor_budget.SponsorBudget()
        )
        self._sponsor_budget_shared = True

    async def __aenter__(self) -> ChargeIntent:
        """Enter async context, creating HTTP client if needed."""
        await self._get_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context, closing owned HTTP client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _get_rpc_url(self) -> str:
        """Return the RPC URL, raising if not configured."""
        if self.rpc_url is None:
            raise InternalPaymentError() from RuntimeError("No rpc_url configured on ChargeIntent")
        return self.rpc_url

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create an HTTP client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def _assert_rpc_chain_id(self, expected: int) -> None:
        """Check the settlement RPC against the authenticated charge request."""
        rpc_url = self._get_rpc_url()
        try:
            actual_hex = await _rpc_call(
                rpc_url, "eth_chainId", [], client=await self._get_client()
            )
            actual = int(actual_hex, 16)
        except Exception as error:
            raise InternalPaymentError() from error
        if actual != expected:
            raise InternalPaymentError() from RuntimeError(
                f"RPC chain ID {actual} does not match charge chain ID {expected}"
            )

    def _prepare_credential(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> tuple[ChargeRequest, CredentialPayload]:
        """Parse the charge request and credential payload."""
        req = ChargeRequest.model_validate(request)

        # Expiry is conveyed via the challenge-level expires auth-param,
        # not inside the request body.  Fail closed: reject if missing.
        challenge_expires = credential.challenge.expires
        if not challenge_expires:
            raise VerificationError("Request has expired (no expires)")
        if _challenge_expired(challenge_expires):
            raise VerificationError("Request has expired")

        payload_data = credential.payload
        if not isinstance(payload_data, dict) or "type" not in payload_data:
            raise VerificationError("Invalid credential payload")

        payload: CredentialPayload
        if payload_data["type"] == "hash":
            payload = HashCredentialPayload.model_validate(payload_data)
        elif payload_data["type"] == "transaction":
            payload = TransactionCredentialPayload.model_validate(payload_data)
        else:
            raise VerificationError(f"Invalid credential type: {payload_data['type']}")

        return req, payload

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation:
        """Validate a charge credential without consuming or broadcasting it.

        Push-mode credentials are verified against the chain without
        consuming the transaction hash's replay key; pull-mode transactions
        are decoded and checked against the request without being broadcast.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A validation record whose ``payer`` is the lowercase address of
            the paying account (the transaction sender in pull mode; the
            sender of the matched transfers in push mode, or ``None`` if they
            differ) and whose ``details`` carry the settlement ``mode`` and,
            in pull mode, the serialized transaction.

        Raises:
            VerificationError: If the credential is invalid.
            InternalPaymentError: If the credential cannot be checked, e.g.
                the RPC node is unreachable or misconfigured.
        """
        req, payload = self._prepare_credential(credential, request)

        if isinstance(payload, HashCredentialPayload):
            await self._ensure_hash_unused(payload.hash)
            receipt = await self._validate_hash(
                payload,
                req,
                challenge_id=credential.challenge.id,
                realm=credential.challenge.realm,
                source=credential.source,
            )
            payer = receipt.payer
            details: dict[str, Any] = {"mode": "push"}
        else:
            legs = self._validate_transaction_payload(payload.signature, req, strict=True)
            if legs is not None:
                self._assert_challenge_bound_memo(
                    legs,
                    challenge_id=credential.challenge.id,
                    realm=credential.challenge.realm,
                )
            payer = self._transaction_payer(
                payload.signature, credential.source, req.methodDetails.chainId
            )
            details = {"mode": "pull", "serialized_transaction": payload.signature}

        return Validation(
            credential=credential,
            details=details,
            intent=self.name,
            request=dict(request),
            payer=payer,
        )

    async def broadcast(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Perform the terminal charge operation.

        Push-mode credentials reserve the transaction hash's replay key
        before re-verification — so concurrent duplicates fail fast — and
        release it again if verification fails. Pull-mode transactions are
        broadcast to the network.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A receipt for the settled payment.

        Raises:
            VerificationError: If the credential is invalid
                (:class:`~mpp.errors.CredentialReplayedError` when the
                transaction hash is already claimed or its transfer is bound
                to another challenge).
            InternalPaymentError: If settlement cannot be confirmed, including
                any other failure after the transaction was broadcast.
        """
        # Defer the default so Mpp can inject its configured shared store.
        if self._store is None:
            self._store = _fallback_store("tempo.charge")

        req, payload = self._prepare_credential(credential, request)

        if isinstance(payload, HashCredentialPayload):
            store_key = await self._reserve_hash(payload.hash)
            try:
                receipt, sender = await self._validate_hash_and_sender(
                    payload,
                    req,
                    challenge_id=credential.challenge.id,
                    realm=credential.challenge.realm,
                    source=credential.source,
                )
            except (Exception, asyncio.CancelledError):
                if store_key is not None and self._store is not None:
                    await self._store.delete(store_key)
                raise
            # Only final hash receipts need this lookup; validation stays receipt-only.
            if sender is None:
                return receipt
            funding_currency = await self._hash_funding_currency(payload.hash, sender, req)
            if funding_currency is None:
                return receipt
            return replace(receipt, funding_currency=funding_currency)
        receipt = await self._broadcast_transaction(
            payload,
            req,
            challenge_id=credential.challenge.id,
            realm=credential.challenge.realm,
            source=credential.source,
            expires=credential.challenge.expires,
        )
        funding_currency = _funding_currency(payload.signature, req)
        if funding_currency is None:
            return receipt
        return replace(receipt, funding_currency=funding_currency)

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Backward-compatible terminal charge hook.

        Equivalent to :meth:`broadcast`; prefer :meth:`validate` for the
        non-mutating pre-check and :meth:`broadcast` for settlement.
        """
        return await self.broadcast(credential, request)

    async def _hash_funding_currency(
        self, tx_hash: str, sender: str, request: ChargeRequest
    ) -> str | None:
        """Return the token ``sender`` spent on transaction ``tx_hash``'s payment route.

        Lookup failures, another signer and unrecognized routes leave the
        already verified payment without a funding currency.
        """
        try:
            transaction = await _rpc_call(
                self._get_rpc_url(),
                "eth_getTransactionByHash",
                [tx_hash],
                client=await self._get_client(),
            )
        except Exception:
            return None
        if not is_dict(transaction):
            return None
        from_addr = transaction.get("from")
        if not isinstance(from_addr, str) or from_addr.lower() != sender.lower():
            return None
        calls = _rpc_transaction_calls(transaction)
        if not calls:
            return None
        return _calls_funding_currency(calls, request)

    async def _reserve_hash(self, tx_hash: str) -> str | None:
        if self._store is None:
            return None
        store_key = self._hash_store_key(tx_hash)
        if not await self._store.put_if_absent(store_key, tx_hash):
            raise CredentialReplayedError("Transaction hash already used")
        return store_key

    async def _ensure_hash_unused(self, tx_hash: str) -> None:
        if (
            self._store is not None
            and await self._store.get(self._hash_store_key(tx_hash)) is not None
        ):
            raise CredentialReplayedError("Transaction hash already used")

    @staticmethod
    def _hash_store_key(tx_hash: str) -> str:
        return f"mpp:charge:{tx_hash.lower()}"

    def _parse_hash_credential_source(
        self, source: str | None, expected_chain_id: int
    ) -> str | None:
        """Parse a hash credential source.

        Returns ``None`` if absent, the address for a ``did:pkh:eip155`` DID
        matching ``expected_chain_id``, else raises ``VerificationError``.
        """
        if source is None:
            return None
        parsed = parse_pkh_source(source)
        if parsed is None or parsed.chain_id != expected_chain_id:
            raise VerificationError("Hash credential source is invalid.")
        return parsed.address

    @staticmethod
    def _transaction_payer(raw_tx: str, source: str | None, chain_id: int) -> str | None:
        """Return a transaction credential's sender, binding its source if present.

        With a ``source``, it must be a ``did:pkh:eip155`` DID on ``chain_id``
        naming the account the transaction debits, else raises
        ``VerificationError``. Returns the lowercase sender address, or
        ``None`` if it cannot be derived and no source was given.
        """
        sender = _transaction_sender(raw_tx)
        if source is None:
            return sender
        parsed = parse_pkh_source(source)
        if parsed is None or parsed.chain_id != chain_id:
            raise VerificationError("Transaction credential source is invalid.")
        if sender is None or sender != parsed.address.lower():
            raise VerificationError("Transaction credential source does not match the sender.")
        return sender

    def _sender_authorized(
        self,
        from_address: str,
        expected_sender: str | None,
        source: str | None,
        validate_sender: ValidateSender | None,
    ) -> bool:
        """Whether ``from_address`` is an acceptable transfer sender.

        Matches when no expected sender is set or it equals ``from_address``.
        On a mismatch, an optional ``validate_sender`` callback may authorize it.
        """
        if not expected_sender or from_address.lower() == expected_sender.lower():
            return True
        if validate_sender is None:
            return False
        return bool(
            validate_sender(
                SenderValidation(
                    expected_sender=expected_sender,
                    sender=from_address,
                    source=source,
                )
            )
        )

    async def _validate_hash(
        self,
        payload: HashCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        source: str | None = None,
    ) -> Receipt:
        """Validate a transaction hash without consuming its replay key.

        The receipt's ``payer`` is the account the matched transfers debited,
        or ``None`` if they came from different senders.
        """
        receipt, _ = await self._validate_hash_and_sender(
            payload, request, challenge_id=challenge_id, realm=realm, source=source
        )
        return receipt

    async def _validate_hash_and_sender(
        self,
        payload: HashCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        source: str | None = None,
    ) -> tuple[Receipt, str | None]:
        """Validate a transaction hash and return its receipt and expected sender.

        The expected sender is the credential source's address, or else the
        transaction receipt's ``from``, as in mppx.
        """
        source_address = self._parse_hash_credential_source(source, request.methodDetails.chainId)

        await self._assert_rpc_chain_id(request.methodDetails.chainId)
        client = await self._get_client()
        receipt_data = await self._fetch_transaction_receipt(client, payload.hash)
        matched_logs = self._verify_receipt_transfers(
            receipt_data,
            request,
            challenge_id=challenge_id,
            realm=realm,
            source=source,
            source_address=source_address,
            validate_sender=self._validate_sender,
        )

        senders = {matched_log.sender for matched_log in matched_logs}
        payer = senders.pop() if len(senders) == 1 else None
        receipt_from = receipt_data.get("from")
        sender = source_address or (receipt_from if isinstance(receipt_from, str) else None)
        return replace(Receipt.success(payload.hash), payer=payer), sender

    def _assert_challenge_bound_memo(
        self,
        matched_logs: list[MatchedTransferLog],
        challenge_id: str,
        realm: str,
    ) -> None:
        """Require a challenge-bound memo and reject conflicting attribution.

        Every matched transfer carrying an MPP attribution memo must be bound to
        this challenge and realm; otherwise one split payment could authorize
        another challenge after this challenge's replay marker expires. Plain
        transfers and non-MPP memos remain allowed. A fixed split memo cannot
        exempt a transfer that is attributed to another challenge.
        """
        from mpp.methods.tempo._attribution import (
            is_mpp_memo,
            verify_challenge_binding,
            verify_server,
        )

        bound = False
        for matched_log in matched_logs:
            memo = matched_log.memo if matched_log.kind == "memo" else None
            if memo is None or not is_mpp_memo(memo):
                continue
            if not verify_server(memo, realm) or not verify_challenge_binding(memo, challenge_id):
                raise CredentialReplayedError("memo is not bound to this challenge")
            bound = True
        if not bound:
            # The transfer already settled to the recipient, so another payment
            # would not help this credential.
            raise CredentialReplayedError("memo is not bound to this challenge")

    async def _fetch_transaction_receipt(self, client: Any, tx_hash: str) -> dict[str, Any]:
        receipt_data = await self._get_transaction_receipt(client, tx_hash)
        if receipt_data is None:
            raise InternalPaymentError() from RuntimeError("Transaction not found")
        return receipt_data

    async def _get_transaction_receipt(self, client: Any, tx_hash: str) -> dict[str, Any] | None:
        """Return the receipt for ``tx_hash``, or ``None`` if it is not yet available."""
        rpc_url = self._get_rpc_url()
        try:
            receipt_data = await _rpc_call(
                rpc_url, "eth_getTransactionReceipt", [tx_hash], client=client
            )
        except Exception as err:
            raise InternalPaymentError() from err

        # A missing receipt may be a pending transaction, so it does not prove
        # the payment invalid.
        if not receipt_data:
            return None
        if not is_dict(receipt_data):
            raise InternalPaymentError() from RuntimeError("Invalid transaction receipt")

        return receipt_data

    async def _recover_broadcast_receipt(
        self,
        client: Any,
        raw_tx: str,
        tx_hash: str,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        deadline: float,
        error: Exception,
    ) -> Receipt:
        """Verify a broadcast transaction whose outcome is unknown.

        Polls for the receipt of ``tx_hash`` every ``RECEIPT_POLL_INTERVAL``
        until ``deadline`` (a ``time.monotonic()`` value), or until the
        transaction's ``valid_before`` (plus ``VALID_BEFORE_GRACE``) passes and
        it can no longer be included. Each lookup is bounded by the time left.
        When the validity cap ends polling, or has already passed, one final
        lookup still runs, since a transaction mined before expiry may have a
        late receipt. Raises the original broadcast ``error`` if no receipt
        arrives or a lookup fails.
        """
        poll_deadline = deadline
        valid_before = _transaction_valid_before(raw_tx)
        if valid_before is not None:
            expiry = time.monotonic() + valid_before + VALID_BEFORE_GRACE - time.time()
            poll_deadline = min(deadline, expiry)
        receipt_data = None
        lookup_failed = False
        while (remaining := poll_deadline - time.monotonic()) > 0:
            try:
                receipt_data = await asyncio.wait_for(
                    self._get_transaction_receipt(client, tx_hash), remaining
                )
            except Exception:
                lookup_failed = True
                break
            if receipt_data is not None:
                break
            await asyncio.sleep(min(RECEIPT_POLL_INTERVAL, poll_deadline - time.monotonic()))
        if receipt_data is None and not lookup_failed and poll_deadline < deadline:
            remaining = deadline - time.monotonic()
            try:
                receipt_data = await asyncio.wait_for(
                    self._get_transaction_receipt(client, tx_hash),
                    remaining if remaining > 0 else RECEIPT_POLL_INTERVAL,
                )
            except Exception:
                receipt_data = None
        if receipt_data is None:
            raise error

        return self._verify_recovered_receipt(
            receipt_data, tx_hash, request, challenge_id=challenge_id, realm=realm
        )

    async def _lookup_broadcast_receipt(
        self,
        client: Any,
        tx_hash: str,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        deadline: float,
        error: Exception,
    ) -> Receipt:
        """Verify a transaction whose broadcast returned a definitive-looking error.

        The node may have included the transaction before its reply failed, so
        one receipt lookup, bounded by the time left before ``deadline``, runs
        before giving up. Raises the original broadcast ``error`` if no receipt
        is found or the lookup fails.
        """
        remaining = deadline - time.monotonic()
        try:
            receipt_data = await asyncio.wait_for(
                self._get_transaction_receipt(client, tx_hash),
                remaining if remaining > 0 else RECEIPT_POLL_INTERVAL,
            )
        except Exception:
            receipt_data = None
        if receipt_data is None:
            raise error

        return self._verify_recovered_receipt(
            receipt_data, tx_hash, request, challenge_id=challenge_id, realm=realm
        )

    def _verify_recovered_receipt(
        self,
        receipt_data: dict[str, Any],
        tx_hash: str,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
    ) -> Receipt:
        """Verify a receipt found after a failed broadcast belongs to ``tx_hash``."""
        receipt_tx_hash = receipt_data.get("transactionHash")
        if not isinstance(receipt_tx_hash, str) or receipt_tx_hash.lower() != tx_hash.lower():
            raise VerificationError("Receipt transaction hash does not match submitted transaction")

        self._verify_receipt_transfers(
            receipt_data,
            request,
            challenge_id=challenge_id,
            realm=realm,
        )
        return Receipt.success(tx_hash)

    def _verify_receipt_transfers(
        self,
        receipt_data: dict[str, Any],
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        source: str | None = None,
        source_address: str | None = None,
        validate_sender: ValidateSender | None = None,
    ) -> list[MatchedTransferLog]:
        if receipt_data.get("status") != "0x1":
            raise VerificationError("Transaction reverted")

        # Bind the transfer sender only when a credential source is present;
        # no source means no sender filtering.
        expected_sender = source_address
        matched_logs = self._verify_transfer_logs(
            receipt_data,
            request,
            expected_sender=expected_sender,
            source=source,
            validate_sender=validate_sender,
            challenge_id=challenge_id,
            realm=realm,
        )
        if not matched_logs:
            raise VerificationError(
                "Transaction must contain a Transfer log matching request parameters"
            )

        self._assert_challenge_bound_memo(
            matched_logs,
            challenge_id=challenge_id,
            realm=realm,
        )

        # A neutral leg cannot be assigned to one of several challenges in a
        # batched receipt. Require every leg to be bound in that case, so two
        # charges cannot share a single plain or fixed-memo transfer.
        from mpp.methods.tempo._attribution import (
            is_mpp_memo,
            verify_challenge_binding,
            verify_server,
        )

        def is_bound(memo: str | None) -> bool:
            return (
                memo is not None
                and verify_server(memo, realm)
                and verify_challenge_binding(memo, challenge_id)
            )

        if any(not is_bound(log.memo) for log in matched_logs):
            for log in receipt_data.get("logs", []):
                topics = log.get("topics", [])
                if (
                    log.get("address", "").lower() == request.currency.lower()
                    and len(topics) == 4
                    and topics[0] == TRANSFER_WITH_MEMO_TOPIC
                    and is_mpp_memo(topics[3])
                    and not is_bound(topics[3])
                ):
                    raise CredentialReplayedError("Unbound split leg in a multi-challenge receipt")

        return matched_logs

    def _verify_single_transfer_log(
        self,
        receipt: dict[str, Any],
        currency: str,
        recipient: str,
        amount: int,
        memo: bytes | None,
        expected_sender: str | None = None,
        source: str | None = None,
        validate_sender: ValidateSender | None = None,
    ) -> list[MatchedTransferLog]:
        """Check if receipt contains matching Transfer/TransferWithMemo logs.

        Returns matched logs in priority order, with memo logs before plain
        transfers so downstream verification can inspect the memo.
        """
        memo_matches: list[MatchedTransferLog] = []
        transfer_matches: list[MatchedTransferLog] = []

        for log in receipt.get("logs", []):
            if log.get("address", "").lower() != currency.lower():
                continue
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue

            event_topic = topics[0]
            from_address = "0x" + topics[1][-40:]
            to_address = "0x" + topics[2][-40:]

            if to_address.lower() != recipient.lower():
                continue

            if event_topic == TRANSFER_WITH_MEMO_TOPIC:
                if len(topics) < 4:
                    continue
                data = log.get("data", "0x")
                if len(data) < 66:
                    continue
                log_amount = int(data[2:66], 16)
                if log_amount != amount:
                    continue
                log_memo = topics[3]
                if memo is not None:
                    expected_memo_hex = "0x" + memo.hex()
                    if log_memo.lower() != expected_memo_hex.lower():
                        continue
                if not self._sender_authorized(
                    from_address, expected_sender, source, validate_sender
                ):
                    continue
                memo_matches.append(
                    MatchedTransferLog(kind="memo", memo=log_memo, sender=from_address.lower())
                )
            elif event_topic == TRANSFER_TOPIC:
                if memo is not None:
                    continue
                data = log.get("data", "0x")
                if len(data) >= 66:
                    log_amount = int(data, 16)
                    if log_amount == amount and self._sender_authorized(
                        from_address, expected_sender, source, validate_sender
                    ):
                        transfer_matches.append(
                            MatchedTransferLog(kind="transfer", sender=from_address.lower())
                        )

        return memo_matches + transfer_matches

    def _verify_transfer_logs(
        self,
        receipt: dict[str, Any],
        request: ChargeRequest,
        expected_sender: str | None = None,
        source: str | None = None,
        validate_sender: ValidateSender | None = None,
        challenge_id: str | None = None,
        realm: str | None = None,
    ) -> list[MatchedTransferLog]:
        """Check if receipt contains matching Transfer or TransferWithMemo logs.

        Returns the payment legs. Empty list means no match. With
        ``challenge_id`` and ``realm``, legs bound to this challenge are chosen
        over interchangeable logs, so unrelated transfers in the same
        transaction (e.g. a batched payment for another challenge) are not
        mistaken for this payment.
        """

        def is_bound(memo: str) -> bool:
            if challenge_id is None or realm is None:
                return False
            from mpp.methods.tempo._attribution import verify_challenge_binding, verify_server

            return verify_server(memo, realm) and verify_challenge_binding(memo, challenge_id)

        def is_foreign(memo: str) -> bool:
            from mpp.methods.tempo._attribution import is_mpp_memo

            return challenge_id is not None and is_mpp_memo(memo) and not is_bound(memo)

        expected = get_transfers(
            int(request.amount),
            request.recipient,
            None,
            request.methodDetails.splits,
        )

        if len(expected) == 1:
            t = expected[0]
            matches = self._verify_single_transfer_log(
                receipt,
                request.currency,
                t.recipient,
                t.amount,
                t.memo,
                expected_sender,
                source,
                validate_sender,
            )
            # Prefer legs bound to this challenge over interchangeable logs,
            # e.g. an equal transfer for another challenge in the same batch.
            bound_matches = [
                match
                for match in matches
                if match.kind == "memo" and match.memo is not None and is_bound(match.memo)
            ]
            return bound_matches or matches

        # Multi-transfer: order-insensitive matching
        sorted_expected = sorted(expected, key=lambda t: 0 if t.memo else 1)
        logs: list[Any] = receipt.get("logs", [])
        indexed_logs = list(enumerate(logs))
        # TIP-20 emits Transfer and TransferWithMemo for one movement. Pair by
        # token, sender, recipient and amount, retaining the memo for attribution.
        # Count multiplicities rather than adjacency so routed payments work too.
        companions: dict[tuple[str, ...], list[int]] = {}
        for index, log in indexed_logs:
            topics = log.get("topics", [])
            if len(topics) == 3 and topics[0] == TRANSFER_TOPIC:
                key = tuple(
                    value.lower()
                    for value in (
                        log.get("address", ""),
                        topics[1],
                        topics[2],
                        log.get("data", "0x"),
                    )
                )
                companions.setdefault(key, []).append(index)
        paired: set[int] = set()
        for _, log in indexed_logs:
            topics = log.get("topics", [])
            if len(topics) == 4 and topics[0] == TRANSFER_WITH_MEMO_TOPIC:
                key = tuple(
                    value.lower()
                    for value in (
                        log.get("address", ""),
                        topics[1],
                        topics[2],
                        log.get("data", "0x"),
                    )
                )
                if candidates := companions.get(key):
                    paired.add(candidates.pop())
        indexed_logs = [(index, log) for index, log in indexed_logs if index not in paired]

        # Prefer memo logs so memo-less transfers still preserve attribution
        # memos for challenge binding verification when both log types exist.
        # Among memo logs, prefer ones bound to this challenge and try memos
        # bound elsewhere last, so interchangeable legs don't pick them.
        def log_rank(item: tuple[int, dict[str, Any]]) -> int:
            topics = item[1].get("topics") or [None]
            if topics[0] != TRANSFER_WITH_MEMO_TOPIC or len(topics) < 4:
                return 2
            memo = topics[3]
            if not isinstance(memo, str):
                return 1
            if is_bound(memo):
                return 0
            if is_foreign(memo):
                return 3
            return 1

        indexed_logs.sort(key=log_rank)
        used_logs: set[int] = set()
        all_matches: list[MatchedTransferLog] = []

        for transfer in sorted_expected:
            found = False
            for log_idx, log in indexed_logs:
                if log_idx in used_logs:
                    continue
                if log.get("address", "").lower() != request.currency.lower():
                    continue

                topics = log.get("topics", [])
                if len(topics) < 3:
                    continue

                event_topic = topics[0]
                from_addr = "0x" + topics[1][-40:]
                to_addr = "0x" + topics[2][-40:]

                if to_addr.lower() != transfer.recipient.lower():
                    continue

                if transfer.memo is not None:
                    if event_topic != TRANSFER_WITH_MEMO_TOPIC:
                        continue
                    if len(topics) < 4:
                        continue
                    data = log.get("data", "0x")
                    if len(data) < 66:
                        continue
                    log_amount = int(data[2:66], 16)
                    memo_topic = topics[3]
                    expected_hex = "0x" + transfer.memo.hex()
                    if (
                        log_amount == transfer.amount
                        and memo_topic.lower() == expected_hex.lower()
                        and self._sender_authorized(
                            from_addr, expected_sender, source, validate_sender
                        )
                    ):
                        used_logs.add(log_idx)
                        all_matches.append(
                            MatchedTransferLog(
                                kind="memo",
                                memo=memo_topic,
                                sender=from_addr.lower(),
                            )
                        )
                        found = True
                        break
                else:
                    data = log.get("data", "0x")
                    if event_topic == TRANSFER_WITH_MEMO_TOPIC:
                        if len(topics) < 4:
                            continue
                        if len(data) < 66:
                            continue
                        log_amount = int(data[2:66], 16)
                        if log_amount == transfer.amount and self._sender_authorized(
                            from_addr, expected_sender, source, validate_sender
                        ):
                            used_logs.add(log_idx)
                            all_matches.append(
                                MatchedTransferLog(
                                    kind="memo", memo=topics[3], sender=from_addr.lower()
                                )
                            )
                            found = True
                            break
                    elif event_topic == TRANSFER_TOPIC:
                        if len(data) < 66:
                            continue
                        log_amount = int(data, 16)
                        if log_amount == transfer.amount and self._sender_authorized(
                            from_addr, expected_sender, source, validate_sender
                        ):
                            used_logs.add(log_idx)
                            all_matches.append(
                                MatchedTransferLog(kind="transfer", sender=from_addr.lower())
                            )
                            found = True
                            break

            if not found:
                return []

        return all_matches

    async def _broadcast_transaction(
        self,
        payload: TransactionCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        source: str | None = None,
        expires: str | None = None,
    ) -> Receipt:
        """Verify and submit a signed transaction.

        Pre-validates the transaction contains the expected TIP-20 transfer call
        before broadcasting. For sponsored transactions (methodDetails.feePayer
        = True), co-signs locally if a fee payer account is configured, otherwise
        forwards to an external fee payer service. The external service must
        authorize the caller, validate and simulate the complete transaction,
        and enforce gas and spending limits before releasing its signature.
        A returned signature is broadcastable independently of this SDK, so
        simulation here cannot enforce an external sponsor's spending policy.
        For regular transactions, submits directly.
        """
        legs = self._validate_transaction_payload(payload.signature, request)
        if legs is not None:
            # Reject unbound or conflicting MPP memos before any funds move.
            self._assert_challenge_bound_memo(legs, challenge_id=challenge_id, realm=realm)
        sender = self._transaction_payer(payload.signature, source, request.methodDetails.chainId)

        client = await self._get_client()

        raw_tx = payload.signature

        # Simulation payload for the locally co-signed tx, if we sponsor it.
        simulate_payload: list[dict[str, Any]] | None = None
        # Outcome marker for a locally sponsored submission, keyed on the
        # client-signed envelope so it is stable across retries of a credential.
        broadcast_key: str | None = None
        reconciling = False
        legacy_record = False
        sponsored_fee: int | None = None
        reservation: _sponsor_budget.Reservation | None = None
        budget_store: CompareAndSetStore | None = None
        client_store_key: str | None = None
        recovery_expires_at = (
            datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
            if expires is not None
            else None
        )

        if request.methodDetails.feePayer:
            if self.fee_payer is not None:
                # Gas is paid in a supported fee token, not the charge currency:
                # Tempo only accepts fee tokens with Fee AMM liquidity.
                from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

                try:
                    fields, _, _, _ = decode_fee_payer_envelope(
                        bytes.fromhex(raw_tx.removeprefix("0x"))
                    )
                except ValueError as error:
                    raise VerificationError(str(error)) from error
                max_fee = int.from_bytes(fields[2], "big") * int.from_bytes(fields[3], "big")
                # Gas prices are attodollars; TIP-20 balances are microdollars.
                required_balance = max(1, (max_fee + 10**12 - 1) // 10**12)
                sponsored_fee = max_fee
                prior_transaction: Any = None
                if self._store is not None:
                    client_hash = _raw_transaction_hash(raw_tx).lower()
                    broadcast_key = f"mpp:charge-broadcast:{client_hash}"
                    client_store_key = f"mpp:charge-client:{client_hash}"
                    if await self._store.get(client_store_key) is not None:
                        raise CredentialReplayedError("Transaction hash already used")
                    prior_transaction = await self._store.get(broadcast_key)
                if isinstance(prior_transaction, bytes):
                    try:
                        prior_transaction = prior_transaction.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise InternalPaymentError() from error
                if prior_transaction is not None:
                    if isinstance(prior_transaction, str) and re.fullmatch(
                        r"0x[0-9a-fA-F]{40}", prior_transaction
                    ):
                        # Legacy records omit the sponsor signature. Recreate a
                        # candidate for receipt lookup only, never for resubmission
                        # or a conclusion that the original payment did not land.
                        raw_tx, _ = self._cosign_as_fee_payer(
                            raw_tx,
                            prior_transaction,
                            request=request,
                            require_remaining_validity=False,
                            allow_expired=True,
                        )
                        legacy_record = True
                    elif isinstance(prior_transaction, str) and prior_transaction.startswith(
                        "0x76"
                    ):
                        raw_tx = prior_transaction
                    else:
                        raise InternalPaymentError() from RuntimeError(
                            "Recovery record lacks the original signed transaction"
                        )
                    reconciling = True
                else:
                    fee_token = await self._resolve_fee_token(client, request, required_balance)
                    # Apply the floor after reserving the hash so a settled
                    # replay receives the terminal replay error even near expiry.
                    try:
                        raw_tx, simulate_payload = self._cosign_as_fee_payer(
                            raw_tx,
                            fee_token,
                            request=request,
                            require_remaining_validity=False,
                        )
                    except VerificationError as error:
                        if (
                            self._store is not None
                            and broadcast_key is not None
                            and (
                                await self._store.get(broadcast_key) is not None
                                or (
                                    recovery_expires_at is not None
                                    and recovery_expires_at <= time.time()
                                )
                            )
                        ):
                            raise InternalPaymentError() from error
                        raise

            else:
                fee_payer_url = request.methodDetails.feePayerUrl
                if not fee_payer_url:
                    raise InternalPaymentError() from RuntimeError(
                        "No fee payer configured: pass fee_payer to tempo.charge() "
                        "or provide a feePayerUrl in methodDetails"
                    )

                try:
                    sign_response = await client.post(
                        fee_payer_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_signRawTransaction",
                            "params": [raw_tx],
                            "id": 1,
                        },
                    )
                    sign_response.raise_for_status()
                    sign_result = sign_response.json()
                except Exception as err:
                    raise InternalPaymentError() from err

                if "error" in sign_result:
                    raise InternalPaymentError() from RuntimeError(
                        f"Fee payer signing failed: {_rpc_error_msg(sign_result)}"
                    )

                raw_tx = sign_result.get("result")
                if not raw_tx:
                    raise InternalPaymentError() from RuntimeError(
                        "Fee payer returned no signed transaction"
                    )

                # A configured allowlist also restricts the external sponsor's
                # token choice; without one, the sponsor picks its own token.
                allowed_fee_tokens = self.allowed_fee_tokens
                if allowed_fee_tokens is not None:
                    try:
                        sponsored_fee_token = _transaction_fee_token(raw_tx)
                        if sponsored_fee_token is None or sponsored_fee_token.lower() not in {
                            token.lower() for token in allowed_fee_tokens
                        }:
                            raise RuntimeError("fee-sponsored transaction feeToken is not allowed")
                    except RuntimeError as error:
                        raise InternalPaymentError() from error

            # Fee payer signing must not change who the transaction debits.
            if sender is not None and _transaction_sender(raw_tx) != sender:
                raise VerificationError("Fee payer transaction sender does not match the sender.")

        # Nodes normalize accepted signature encodings before deriving transaction
        # hashes. Broadcast the same canonical envelope so replay keys match the node.
        raw_tx = _canonical_raw_transaction(raw_tx)

        rpc_url = self._get_rpc_url()

        reserved_tx_hash: str | None = None
        store_keys: list[str] = []
        if self._store is not None:
            reserved_tx_hash = _raw_transaction_hash(raw_tx)
            keys = [f"mpp:charge:{reserved_tx_hash.lower()}"]
            if client_store_key is not None:
                keys.insert(0, client_store_key)
            try:
                for key in keys:
                    if not await self._store.put_if_absent(key, reserved_tx_hash):
                        raise CredentialReplayedError("Transaction hash already used")
                    store_keys.append(key)
            except (Exception, asyncio.CancelledError) as error:
                for key in store_keys:
                    await self._store.delete(key)
                if isinstance(error, (CredentialReplayedError, asyncio.CancelledError)):
                    raise
                raise InternalPaymentError() from error

        broadcast_attempted = False
        # True while a submitted transaction may still be included. The broadcast
        # marker is then kept: unlike the replay reservation it survives the
        # failure, so a retry of a locally sponsored submission whose outcome is
        # unknown is reconciled instead of refused as unpaid. Definitive
        # rejections and unsponsored submissions retain nothing.
        outcome_unknown = False
        # True when this attempt created the broadcast marker, so a definitive
        # outcome removes it again.
        marker_created = False
        verified = False
        try:
            if reconciling:
                prior = await self._check_sponsored_validity(
                    client,
                    raw_tx,
                    broadcast_key,
                    request,
                    challenge_id,
                    realm,
                    reconcile=True,
                    legacy_record=legacy_record,
                )
                if prior is not None:
                    verified = True
                    await self._clear_broadcast_marker(broadcast_key)
                    return prior
            # Locally sponsored transactions must pass simulation before broadcast.
            if simulate_payload is not None:
                prior = await self._check_sponsored_validity(
                    client, raw_tx, broadcast_key, request, challenge_id, realm
                )
                if prior is not None:
                    return prior
                # Simulate before reserving, like mppx, so a transaction that
                # reverts (such as one from an unfunded key) never holds sponsor
                # budget that honest charges wait on.
                await self._simulate_before_broadcast(client, simulate_payload, rpc_url)
                prior = await self._check_sponsored_validity(
                    client, raw_tx, broadcast_key, request, challenge_id, realm
                )
                if prior is not None:
                    return prior
                budget_store, reservation = await self._reserve_sponsor_budget(
                    client, raw_tx, sponsored_fee, request, recovery_expires_at
                )
                # Chain state can change while waiting for budget: re-simulate so
                # the sponsor doesn't pay gas for a transaction that now reverts.
                if reservation is not None and reservation.waited:
                    await self._simulate_before_broadcast(client, simulate_payload, rpc_url)
                # The store reservation and budget wait can take a while:
                # recheck the sponsored window right before submission.
                prior = await self._check_sponsored_validity(
                    client, raw_tx, broadcast_key, request, challenge_id, realm
                )
                if prior is not None:
                    return prior

            # The send and any receipt recovery share one confirmation deadline.
            # The send may use at most two thirds of it, leaving the rest for
            # receipt recovery.
            deadline = time.monotonic() + self._confirmation_timeout
            send_timeout_ms = round(self._confirmation_timeout * 1000) * 2 // 3
            send_timeout = send_timeout_ms / 1000
            if self._store is not None and broadcast_key is not None and not reconciling:
                # Persist the marker before sending, and fail closed: a submission
                # whose outcome could be lost must not be broadcast at all.
                try:
                    if recovery_expires_at is not None and isinstance(self._store, ExpiringStore):
                        valid_before = _transaction_valid_before(raw_tx)
                        marker_expires_at = max(
                            recovery_expires_at,
                            valid_before + VALID_BEFORE_GRACE
                            if valid_before is not None
                            else recovery_expires_at,
                        )
                        marker_created = await self._store.put_if_absent_until(
                            broadcast_key, raw_tx, marker_expires_at
                        )
                    else:
                        marker_created = await self._store.put_if_absent(broadcast_key, raw_tx)
                except Exception as err:
                    raise InternalPaymentError() from err
                if not marker_created:
                    raise InternalPaymentError() from RuntimeError(
                        "Another submission owns this credential's recovery record"
                    )
            # Authorize before the irreversible send: a challenge that expired
            # during sponsorship or simulation must not be settled.
            if expires is not None and _challenge_expired(expires):
                if reconciling:
                    raise InternalPaymentError() from RuntimeError(
                        "Earlier submission of this transaction has an unknown outcome"
                    )
                raise PaymentExpiredError(expires)
            if (
                reservation is not None
                and budget_store is not None
                and not await _sponsor_budget.transition(budget_store, reservation, "broadcasting")
            ):
                raise VerificationError(
                    "Sponsor budget reservation ownership was lost before broadcast"
                )
            broadcast_attempted = True
            outcome_unknown = True
            try:
                response = await asyncio.wait_for(
                    client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_sendRawTransactionSync",
                            "params": [raw_tx, send_timeout_ms],
                            "id": 1,
                        },
                    ),
                    send_timeout,
                )
                response.raise_for_status()
                result = response.json()
            except Exception as error:
                send_error = error
                if isinstance(error, TimeoutError):
                    # The local deadline cut the send off before it settled.
                    send_error = TimeoutError(
                        f"Transaction submission timed out after {send_timeout:g}s"
                    )
                if not _is_ambiguous_broadcast_error(send_error):
                    outcome_unknown = False
                    raise
                receipt = await self._recover_broadcast_receipt(
                    client,
                    raw_tx,
                    reserved_tx_hash or _raw_transaction_hash(raw_tx),
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                    deadline=deadline,
                    error=send_error,
                )
                verified = True
                await self._clear_broadcast_marker(broadcast_key)
                return receipt

            if "error" in result:
                rpc_error = VerificationError(
                    f"Transaction submission failed: {_rpc_error_msg(result)}"
                )
                if not _is_ambiguous_broadcast_error(result):
                    outcome_unknown = False
                    # The node answered, so it may have included the transaction
                    # before its reply failed: look for a receipt once.
                    receipt = await self._lookup_broadcast_receipt(
                        client,
                        reserved_tx_hash or _raw_transaction_hash(raw_tx),
                        request,
                        challenge_id=challenge_id,
                        realm=realm,
                        deadline=deadline,
                        error=rpc_error,
                    )
                    verified = True
                    await self._clear_broadcast_marker(broadcast_key)
                    return receipt
                receipt = await self._recover_broadcast_receipt(
                    client,
                    raw_tx,
                    reserved_tx_hash or _raw_transaction_hash(raw_tx),
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                    deadline=deadline,
                    error=rpc_error,
                )
                verified = True
                await self._clear_broadcast_marker(broadcast_key)
                return receipt

            receipt_data = result.get("result")
            if not receipt_data:
                raise VerificationError("No transaction receipt returned")
            # The transaction was included: its outcome is known.
            outcome_unknown = False
            if not is_dict(receipt_data):
                raise VerificationError("Invalid transaction receipt")

            self._verify_receipt_transfers(
                receipt_data,
                request,
                challenge_id=challenge_id,
                realm=realm,
            )

            receipt_tx_hash = receipt_data.get("transactionHash")
            if not receipt_tx_hash:
                raise VerificationError("No transaction hash returned")
            if not isinstance(receipt_tx_hash, str):
                raise VerificationError("Invalid transaction hash returned")

            if reserved_tx_hash is not None and receipt_tx_hash.lower() != reserved_tx_hash.lower():
                raise VerificationError(
                    "Receipt transaction hash does not match submitted transaction"
                )

            verified = True
            await self._clear_broadcast_marker(broadcast_key)
            return Receipt.success(receipt_tx_hash)
        except (Exception, asyncio.CancelledError) as err:
            # Only successful verification consumes a payment. Failed or cancelled
            # attempts must let retries acquire the reservation and verify again.
            if not verified and self._store is not None:
                if marker_created and not outcome_unknown:
                    await self._clear_broadcast_marker(broadcast_key)
                for key in store_keys:
                    await self._store.delete(key)
            # Expiry may have removed an earlier attempt's recovery record
            # while this request was signing or simulating. Absence no longer
            # proves that asking for a new payment is safe.
            if (
                broadcast_key is not None
                and recovery_expires_at is not None
                and recovery_expires_at <= time.time()
                and isinstance(err, VerificationError)
            ):
                raise InternalPaymentError() from err
            # Once broadcast, the transaction may have landed: never report a
            # retryable verification failure that would invite a second payment.
            if (
                broadcast_attempted
                and isinstance(err, Exception)
                and not isinstance(err, (CredentialReplayedError, InternalPaymentError))
            ):
                raise InternalPaymentError() from err
            raise
        finally:
            if reservation is not None and budget_store is not None:
                try:
                    # A transaction that may still land keeps its fee reserved
                    # until a receipt is observed or it expires.
                    if outcome_unknown and not verified:
                        await _sponsor_budget.transition(budget_store, reservation, "pending")
                    else:
                        await _sponsor_budget.release(budget_store, reservation)
                except Exception:
                    # The reservation expires on its own; the settlement outcome wins.
                    logger.exception("Sponsor budget cleanup failed")

    def _sponsor_budget_store(self) -> CompareAndSetStore | None:
        """Return the store holding the local fee payer's in-flight budget, if enforced."""
        budget = self._sponsor_budget
        if budget is None or self.fee_payer is None:
            return None
        if budget.store is not None:
            return budget.store
        if self._sponsor_budget_shared and isinstance(self._store, CompareAndSetStore):
            return self._store
        if self._sponsor_budget_shared:
            self._sponsor_budget_shared = False
            logger.warning(
                "tempo.charge's store has no compare_and_set, so the sponsor budget is "
                "scoped to this process. Pass SponsorBudget(store=...) with a shared store."
            )
        return _sponsor_budget.process_store()

    async def _reserve_sponsor_budget(
        self,
        client: Any,
        raw_tx: str,
        fee: int | None,
        request: ChargeRequest,
        challenge_expires_at: float | None,
    ) -> tuple[CompareAndSetStore | None, _sponsor_budget.Reservation | None]:
        """Reserve a locally sponsored transaction's fee before it is broadcast."""
        budget = self._sponsor_budget
        store = self._sponsor_budget_store()
        valid_before = _transaction_valid_before(raw_tx)
        if (
            budget is None
            or store is None
            or self.fee_payer is None
            or fee is None
            or valid_before is None
        ):
            return None, None
        # The transaction can still be included for a short grace after
        # valid_before, so it stays reserved until then.
        expires_at = int((valid_before + VALID_BEFORE_GRACE) * 1000)
        # Stop waiting once the transaction falls below the sponsored validity
        # floor (it could not be broadcast anyway), or before the client gives
        # up on its paid retry: the confirmation wait still follows.
        max_wait = max(1.0, DEFAULT_PAID_RETRY_TIMEOUT - self._confirmation_timeout)
        wait_until = min(
            (valid_before - MIN_REMAINING_VALIDITY_SECONDS) * 1000,
            math.ceil((time.time() + max_wait) * 1000),
        )
        if challenge_expires_at is not None:
            # Round up, so a wait that runs out has the challenge expired too.
            wait_until = min(wait_until, math.ceil(challenge_expires_at * 1000))

        async def is_settled(tx_hash: str) -> bool:
            return await self._get_transaction_receipt(client, tx_hash) is not None

        sponsor = self.fee_payer.address
        while True:
            try:
                reservation = await _sponsor_budget.reserve(
                    store,
                    budget,
                    chain_id=request.methodDetails.chainId,
                    sponsor=sponsor,
                    transaction_hash=_raw_transaction_hash(raw_tx),
                    fee=fee,
                    expires_at=expires_at,
                    wait_until=wait_until,
                    is_settled=is_settled,
                )
                return store, reservation
            except NotImplementedError:
                # A replay store without usable compare-and-set (such as Redis
                # denying EVAL) keeps working with a process-scoped budget.
                if budget.store is not None or not self._sponsor_budget_shared:
                    raise
                self._sponsor_budget_shared = False
                logger.warning(
                    "tempo.charge's store cannot compare_and_set, so the sponsor budget "
                    "is scoped to this process. Pass SponsorBudget(store=...) with a "
                    "shared store that supports it."
                )
                store = _sponsor_budget.process_store()

    async def _check_sponsored_validity(
        self,
        client: Any,
        raw_tx: str,
        broadcast_key: str | None,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        *,
        reconcile: bool = False,
        legacy_record: bool = False,
    ) -> Receipt | None:
        """Apply the sponsored validity floor before a first submission.

        If this server already submitted the transaction (an earlier attempt
        whose outcome was unknown), the floor does not apply: the existing
        transaction is reconciled instead. Returns its receipt if it settled,
        and raises ``InternalPaymentError`` while its outcome is unknown, so the
        caller is never asked to pay again for a payment that may still land.
        """
        valid_before = _transaction_valid_before(raw_tx)
        if valid_before is None:
            if reconcile:
                raise InternalPaymentError() from RuntimeError("Recovery transaction has no expiry")
            return None
        if not reconcile:
            try:
                _assert_remaining_validity(valid_before)
            except VerificationError as error:
                if (
                    self._store is not None
                    and broadcast_key is not None
                    and (await self._store.get(broadcast_key) is not None)
                ):
                    raise InternalPaymentError() from error
                raise
            return None
        tx_hash = _raw_transaction_hash(raw_tx)
        receipt_data = await self._get_transaction_receipt(client, tx_hash)
        if receipt_data is None:
            if (
                not legacy_record
                and valid_before >= math.ceil(time.time()) + MIN_REMAINING_VALIDITY_SECONDS
            ):
                # Re-send only the exact previously simulated, signed envelope.
                # This cannot authorize a second transaction or a new gas budget.
                return None
            if (
                not legacy_record
                and valid_before + VALID_BEFORE_GRACE < time.time()
                and (await self._confirm_not_included(client, tx_hash, valid_before))
            ):
                # Chain time is past its inclusion window with no receipt: it
                # never landed.
                await self._clear_broadcast_marker(broadcast_key)
                raise VerificationError(
                    "Fee payer envelope expired: valid_before "
                    f"({valid_before}) is not in the future"
                )
            raise InternalPaymentError() from RuntimeError(
                "Earlier submission of this transaction has an unknown outcome"
            )
        receipt_tx_hash = receipt_data.get("transactionHash")
        if not isinstance(receipt_tx_hash, str) or receipt_tx_hash.lower() != tx_hash.lower():
            raise VerificationError("Receipt transaction hash does not match submitted transaction")
        self._verify_receipt_transfers(
            receipt_data, request, challenge_id=challenge_id, realm=realm
        )
        return Receipt.success(tx_hash)

    async def _confirm_not_included(self, client: Any, tx_hash: str, valid_before: int) -> bool:
        """Return whether chain time shows ``tx_hash`` can no longer be included.

        A missing receipt and the local clock alone do not prove that: the
        latest block must be at or past ``valid_before``, and a receipt lookup
        made after reading that block must still find nothing.
        """
        try:
            block = await _rpc_call(
                self._get_rpc_url(), "eth_getBlockByNumber", ["latest", False], client=client
            )
            block_timestamp = int(block["timestamp"], 16)
        except Exception as err:
            raise InternalPaymentError() from err
        if block_timestamp < valid_before:
            return False
        return await self._get_transaction_receipt(client, tx_hash) is None

    async def _clear_broadcast_marker(self, broadcast_key: str | None) -> None:
        """Drop a broadcast outcome marker once its transaction has settled."""
        if self._store is not None and broadcast_key is not None:
            # Best effort: the payment is confirmed either way.
            with contextlib.suppress(Exception):
                await self._store.delete(broadcast_key)

    async def _resolve_fee_token(
        self, client: Any, request: ChargeRequest, required_balance: int = 1
    ) -> str:
        """Choose the token a local fee payer pays gas in.

        Uses the configured ``fee_token``, else the first allowed fee token the
        fee payer holds enough of to cover the gas budget, else the first allowed fee token.
        """
        fee_payer = self.fee_payer
        if fee_payer is None:
            raise InternalPaymentError() from RuntimeError("No fee payer account configured")
        allowed = self.allowed_fee_tokens or fee_tokens_for_chain(request.methodDetails.chainId)
        configured = self.fee_token
        if configured is not None:
            if configured.lower() not in {token.lower() for token in allowed}:
                raise InternalPaymentError() from RuntimeError(
                    "fee-sponsored transaction feeToken is not allowed"
                )
            return configured
        rpc_url = self._get_rpc_url()
        for token in allowed:
            try:
                if (
                    await _tip20_balance(rpc_url, token, fee_payer.address, client=client)
                    >= required_balance
                ):
                    return token
            except Exception:
                continue
        return allowed[0]

    def _cosign_as_fee_payer(
        self,
        raw_tx: str,
        fee_token: str | None = None,
        request: ChargeRequest | None = None,
        *,
        require_remaining_validity: bool = True,
        allow_expired: bool = False,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Co-sign a client-signed transaction as fee payer.

        Deserializes the client's 0x78 fee payer envelope, optionally validates
        the payment calls against ``request``, sets the fee token, and co-signs.
        Returns ``(raw_0x76_hex, simulate_payload)`` where ``simulate_payload``
        is the ``tempo_simulateV1`` request for the co-signed tx.

        Authorization-bearing envelopes are rejected before signing because
        their authorization fields cannot yet be faithfully simulated.

        With ``require_remaining_validity=False`` only an already expired
        ``valid_before`` is rejected here; the caller must enforce
        ``MIN_REMAINING_VALIDITY_SECONDS`` before broadcasting. With
        ``allow_expired=True`` as well, an expired one is not rejected either,
        so the caller can reconcile an earlier submission of it.
        """
        # pytempo ships no type information.
        from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]
        from pytempo.models import (  # pyright: ignore[reportMissingTypeStubs]
            Signature,
            as_address,
        )

        from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

        if self.fee_payer is None:
            raise InternalPaymentError() from RuntimeError("No fee payer account configured")

        try:
            all_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
            decoded, sender_addr_bytes, sender_sig, key_auth = decode_fee_payer_envelope(all_bytes)
        except Exception as err:
            raise VerificationError("Failed to deserialize client transaction") from err

        if key_auth is not None or decoded[12]:
            raise VerificationError(
                "Authorization-bearing transactions cannot be simulated and are not "
                "supported by local fee-payer cosigning"
            )

        # Cosigning recovers the sender via secp256k1 ECDSA, so only a raw
        # 65-byte signature is supported; other envelopes (keychain, P256,
        # WebAuthn) are rejected up front.
        if len(sender_sig) != 65:
            if sender_sig and sender_sig[0] in (0x03, 0x04):
                raise VerificationError(
                    "Access-key (keychain) signed fee-payer envelopes are not "
                    "supported by local cosigning"
                )
            raise VerificationError(
                "Only 65-byte secp256k1 sender signatures are supported by local "
                "fee-payer cosigning"
            )

        def _int(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        # Fee-payer invariants (matches mpp-rs cosign_fee_payer_transaction)
        if decoded[10]:
            raise VerificationError(
                "Fee payer transaction must not include fee_token (server sets it)"
            )

        nonce_key = _int(decoded[6])
        if nonce_key != (1 << 256) - 1:
            raise VerificationError("Fee payer envelope must use expiring nonce key (U256::MAX)")

        valid_before_raw = decoded[8]
        if not valid_before_raw:
            raise VerificationError("Fee payer envelope must include valid_before")
        valid_before = _int(valid_before_raw)
        if require_remaining_validity:
            _assert_remaining_validity(valid_before)
        elif not allow_expired:
            _assert_not_expired(valid_before)

        chain_id = _int(decoded[0])
        policy = get_policy(chain_id)

        gas_limit = _int(decoded[3])
        if gas_limit > policy.max_gas:
            raise VerificationError("Invalid transaction: gas limit exceeds sponsor policy")

        max_priority_fee_per_gas = _int(decoded[1])
        max_fee_per_gas = _int(decoded[2])
        if max_fee_per_gas > policy.max_fee_per_gas:
            raise VerificationError("Invalid transaction: max fee per gas exceeds sponsor policy")
        if max_priority_fee_per_gas > max_fee_per_gas:
            raise VerificationError(
                "Invalid transaction: max priority fee per gas exceeds max fee per gas"
            )
        if max_priority_fee_per_gas > policy.max_priority_fee_per_gas:
            raise VerificationError(
                "Invalid transaction: max priority fee per gas exceeds sponsor policy"
            )
        if gas_limit * max_fee_per_gas > policy.max_total_fee:
            raise VerificationError("Invalid transaction: total fee budget exceeds sponsor policy")
        if valid_before > int(time.time()) + policy.max_validity_window_seconds:
            raise VerificationError("Invalid transaction: validity window exceeds sponsor policy")

        if decoded[5]:
            raise VerificationError("Invalid transaction: access list is not allowed")

        calls = tuple(Call(to=c[0], value=_int(c[1]), data=c[2]) for c in decoded[4])

        if request is not None:
            self._validate_calls(calls, request)

        tx_for_recovery = TempoTransaction(
            chain_id=chain_id,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas_limit=gas_limit,
            calls=calls,
            access_list=(),
            nonce_key=_int(decoded[6]),
            nonce=_int(decoded[7]),
            valid_before=_int(decoded[8]) if decoded[8] else None,
            valid_after=_int(decoded[9]) if decoded[9] else None,
            fee_token=decoded[10] if decoded[10] else None,
            # Part of the sender's signing hash; must be carried through.
            tempo_authorization_list=tuple(decoded[12]),
            awaiting_fee_payer=True,
            key_authorization=key_auth,  # type: ignore[arg-type]
        )
        sender_hash = tx_for_recovery.get_signing_hash(for_fee_payer=False)

        from eth_account import Account

        try:
            recovered_address = Account._recover_hash(sender_hash, signature=sender_sig)
        except Exception as err:
            raise VerificationError("Invalid sender signature") from err
        envelope_address = "0x" + sender_addr_bytes.hex()

        if recovered_address.lower() != envelope_address.lower():
            raise VerificationError("Sender address does not match recovered signer")

        tx_to_sign = attrs.evolve(
            tx_for_recovery,
            sender_signature=Signature(
                r=int.from_bytes(sender_sig[:32], "big"),
                s=int.from_bytes(sender_sig[32:64], "big"),
                v=sender_sig[64],
            ),
            sender_address=as_address(recovered_address),
            fee_token=fee_token or PATH_USD,
        )

        try:
            cosigned = tx_to_sign.sign(self.fee_payer.private_key, for_fee_payer=True)
        except Exception as err:
            raise InternalPaymentError() from err

        raw_cosigned = "0x" + cosigned.encode().hex()

        return raw_cosigned, self._build_simulate_payload(cosigned, recovered_address)

    def _build_simulate_payload(self, tx: Any, sender: str) -> list[dict[str, Any]]:
        """Build the ``eth_call`` requests that check a co-signed 0x76 tx.

        Like mppx's ``preflightSponsorship``, the calls are simulated twice:
        first from the sender with no fee fields, so the sender's fee balance is
        irrelevant, then as the final sponsored transaction with its concrete
        fee payer and fee token. ``eth_call`` carries neither signature, and
        every public Tempo RPC serves it (``tempo_simulateV1`` is refused).

        Must not be called for a tx that carries a ``key_authorization`` or a
        non-empty ``tempo_authorization_list``: those fields cannot yet be
        faithfully serialized here, so the request would describe a different
        transaction than the one broadcast. Local cosigning rejects these
        envelopes before applying the sponsor signature.
        """
        if getattr(tx, "key_authorization", None) is not None or getattr(
            tx, "tempo_authorization_list", ()
        ):
            raise VerificationError(
                "Cannot build a faithful simulation request for an "
                "authorization-bearing transaction"
            )
        calls = [
            {
                "to": "0x" + bytes(c.to).hex(),
                "value": hex(c.value),
                "data": "0x" + c.data.hex(),
            }
            for c in tx.calls
        ]
        sender_request: dict[str, Any] = {"type": "0x76", "from": sender, "calls": calls}
        if self.fee_payer is None:
            raise InternalPaymentError() from RuntimeError("No fee payer to simulate")
        fee_payer = self.fee_payer.address
        sponsored: dict[str, Any] = {
            "type": "0x76",
            "from": sender,
            "calls": calls,
            "chainId": hex(tx.chain_id),
            "nonce": hex(tx.nonce),
            "nonceKey": hex(tx.nonce_key),
            "gas": hex(tx.gas_limit),
            "maxFeePerGas": hex(tx.max_fee_per_gas),
            "maxPriorityFeePerGas": hex(tx.max_priority_fee_per_gas),
            "feeToken": "0x" + bytes(tx.fee_token).hex(),
            # The node rejects ``feePayer: true`` in eth_call; name the sponsor.
            "feePayer": fee_payer,
        }
        if tx.valid_before is not None:
            sponsored["validBefore"] = hex(tx.valid_before)
        if tx.valid_after is not None:
            sponsored["validAfter"] = hex(tx.valid_after)
        return [sender_request, sponsored]

    async def _simulate_before_broadcast(
        self, client: Any, simulate_payload: list[dict[str, Any]], rpc_url: str
    ) -> None:
        """Simulate the co-signed tx with ``eth_call`` and raise if it would fail.

        Fails closed: a transport error or an unreadable reply is an internal
        error; an execution error is a verification failure.
        """
        for request in simulate_payload:
            try:
                response = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_call",
                        "params": [request, "latest"],
                        "id": 1,
                    },
                )
                response.raise_for_status()
                result = response.json()
            except Exception as err:
                raise InternalPaymentError() from err
            if not is_dict(result):
                raise InternalPaymentError() from RuntimeError(
                    "Pre-broadcast simulation returned an unreadable reply"
                )
            if "error" not in result:
                if "result" not in result:
                    raise InternalPaymentError() from RuntimeError(
                        "Pre-broadcast simulation returned no result"
                    )
                continue
            error = result.get("error")
            code = error.get("code") if is_dict(error) else None
            message = _rpc_error_msg(result)
            if code in _EXECUTION_ERROR_CODES or "revert" in message.lower():
                raise VerificationError(
                    f"Sponsored transaction would revert in pre-broadcast simulation: {message}"
                )
            raise InternalPaymentError() from RuntimeError(
                f"Pre-broadcast simulation failed: {message}"
            )

    def _validate_calls(self, calls: tuple[Any, ...], request: ChargeRequest) -> None:
        """Validate that calls match all expected transfers."""
        normalized_calls = [
            ("0x" + bytes(call.to).hex(), int(call.value), call.data.hex()) for call in calls
        ]
        _validate_normalized_calls(normalized_calls, request)

    def _validate_transaction_payload(
        self,
        signature: str,
        request: ChargeRequest,
        *,
        strict: bool = False,
    ) -> list[MatchedTransferLog] | None:
        """Validate a transaction, failing closed for advisory validation.

        Returns the payment legs, or ``None`` when non-strict validation could
        not decode the transaction.
        """
        try:
            from mpp.methods.tempo import _rlp as rlp
        except ImportError as error:
            if strict:
                raise InternalPaymentError() from error
            return None
        try:
            tx_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
        except ValueError as error:
            if strict:
                raise VerificationError("Invalid serialized transaction") from error
            return None
        if not tx_bytes or tx_bytes[0] not in (0x76, 0x78):
            if strict:
                raise VerificationError("Only Tempo (0x76/0x78) transactions are supported")
            return None
        try:
            decoded = rlp.decode(tx_bytes[1:])
        except Exception as error:
            if strict:
                raise VerificationError("Invalid serialized transaction") from error
            return None
        if not is_list(decoded) or len(decoded) < 5:
            if strict:
                raise VerificationError("Invalid serialized transaction")
            return None

        if not isinstance(decoded[0], bytes):
            raise VerificationError("Invalid transaction chain ID")
        if int.from_bytes(decoded[0], "big") != request.methodDetails.chainId:
            raise VerificationError("Transaction chain ID does not match charge chain ID")

        calls_data: list[Any] = decoded[4] if len(decoded) > 4 else []
        if not calls_data:
            raise VerificationError("Transaction contains no calls")

        normalized_calls: list[tuple[str, int, str]] = []
        for call_item in calls_data:
            call_fields: Sequence[Any] = call_item
            if not isinstance(call_fields, (list, tuple)) or len(call_fields) < 3:
                raise VerificationError("Invalid transaction: malformed call data")

            call_to_raw, call_value_raw, call_data_raw = (
                call_fields[0],
                call_fields[1],
                call_fields[2],
            )
            if not isinstance(call_to_raw, bytes) or not isinstance(call_data_raw, bytes):
                raise VerificationError("Invalid transaction: malformed call data")

            if isinstance(call_value_raw, bytes):
                call_value = int.from_bytes(call_value_raw, "big") if call_value_raw else 0
            elif isinstance(call_value_raw, int):
                call_value = call_value_raw
            else:
                raise VerificationError("Invalid transaction: malformed call data")

            normalized_calls.append(("0x" + call_to_raw.hex(), call_value, call_data_raw.hex()))

        return _validate_normalized_calls(normalized_calls, request)
