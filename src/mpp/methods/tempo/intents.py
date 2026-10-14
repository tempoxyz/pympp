"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import attrs
from eth_abi.abi import decode
from eth_abi.exceptions import DecodingError

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_CONFIRMATION_TIMEOUT, DEFAULT_TIMEOUT
from mpp._did import parse_pkh_source
from mpp._validation import Validation
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    VerificationError,
)
from mpp.methods.tempo._defaults import PATH_USD, fee_tokens_for_chain, rpc_url_for_chain
from mpp.methods.tempo._rpc import _rpc_call, _tip20_balance
from mpp.methods.tempo.fee_payer_policy import get_policy
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    Split,
    TransactionCredentialPayload,
)
from mpp.store import MemoryStore, Store

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_WITH_MEMO_SELECTOR = "95777d59"
APPROVE_SELECTOR = "095ea7b3"
SWAP_EXACT_AMOUNT_OUT_SELECTOR = "b30d91d5"

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


def _transaction_valid_before(raw_tx: str) -> int | None:
    """Return a Tempo transaction's ``valid_before`` timestamp, if it has one."""
    try:
        import rlp

        tx_bytes = bytes.fromhex(_strip_0x(raw_tx))
        if tx_bytes[:1] not in (b"\x76", b"\x78"):
            return None
        decoded = rlp.decode(tx_bytes[1:])
    except Exception:
        return None
    if not isinstance(decoded, list) or len(decoded) <= 8:
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
    import rlp
    from eth_account import Account
    from eth_hash.auto import keccak

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        fields = rlp.decode(tx_bytes[1:])
    except Exception:
        return None
    if tx_bytes[0] not in (0x76, 0x78) or not isinstance(fields, list):
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


def _rpc_error_msg(result: dict) -> str:
    """Extract error message from a JSON-RPC error response."""
    error_obj = result["error"]
    if isinstance(error_obj, dict):
        msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
        data = error_obj.get("data", "")
        return f"{msg}: {data}" if data else msg
    return str(error_obj)


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
        if isinstance(rpc_error, dict) and rpc_error.get("code") == SYNC_CONFIRMATION_TIMEOUT_CODE:
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


def _match_transfer_calldata(call_data_hex: str, request: ChargeRequest) -> bool:
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
        approve_to, _, approve_data = calls[0]
        swap_to, _, swap_data = calls[1]
        decoded_approve = _decode_static_call_args(
            approve_data,
            ("address", "uint256"),
            APPROVE_CALL_DATA_HEX_LEN,
        )
        if decoded_approve is None:
            raise VerificationError("Invalid transaction: malformed approve call data")
        decoded_swap = _decode_static_call_args(
            swap_data,
            ("address", "address", "uint256", "uint256"),
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


def _validate_normalized_calls(calls: list[tuple[str, int, str]], request: ChargeRequest) -> None:
    prefix_len = _validate_call_scope(calls)
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
                found = True
                break
        if not found:
            raise VerificationError("Invalid transaction: no matching payment call found")

    if len(used_calls) != len(payment_calls):
        raise VerificationError("Invalid transaction: contains unauthorized extra calls")


# ──────────────────────────────────────────────────────────────────
# Charge intent
# ──────────────────────────────────────────────────────────────────


class ChargeIntent:
    """Tempo charge intent for one-time payments.

    Verifies that a payment transaction matches the requested parameters.

    When used via ``tempo()``, the ``rpc_url`` and ``fee_payer`` are read
    from the parent method automatically. You can also pass ``rpc_url``
    directly for standalone use.

    This class manages an HTTP client lifecycle. Use as an async context manager
    for automatic cleanup, or call `aclose()` explicitly when done.

    Example:
        from mpp.methods.tempo import tempo, ChargeIntent

        # chain_id resolves RPC automatically
        method = tempo(
            chain_id=42431,
            intents={"charge": ChargeIntent()},
        )

        # Or standalone with chain_id
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
    ) -> None:
        """Initialize the charge intent.

        Args:
            chain_id: Tempo chain ID (4217 for mainnet, 42431 for
                testnet). Resolves the RPC URL automatically.
            rpc_url: Tempo RPC endpoint URL. Overrides ``chain_id``.
                If neither is set, will be inherited from ``tempo()``.
            http_client: Optional httpx client for making RPC calls.
                If provided, the caller is responsible for closing it.
            timeout: Request timeout in seconds (default: 30).
            store: Key-value store for tx hash replay protection. Defaults to
                an in-memory store capped at 10,000 entries on first settlement.
                New payments fail at capacity without evicting used hashes. Use a shared persistent
                store across server replicas and restarts.
            validate_sender: Optional callback invoked when a hash-credential
                transfer's sender differs from the expected sender; return
                ``True`` to accept (e.g. smart-account / relayer flows).
            confirmation_timeout: Seconds to wait for a broadcast transaction's
                receipt (default: 30), shared by the synchronous send (at most
                two thirds of it) and, when its outcome is unknown (e.g. a read
                timeout or "already known"), polling for the receipt. Polling
                also stops once the transaction's ``valid_before`` has passed.
                Equivalent to mppx's ``confirmationTimeoutMs``.
        """
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self._method = None
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout
        self._store = store
        self._validate_sender = validate_sender
        self._confirmation_timeout = confirmation_timeout

    @property
    def fee_payer(self) -> TempoAccount | None:
        """Fee payer account, read from the parent method."""
        return getattr(self._method, "fee_payer", None) if self._method else None

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
        expires = datetime.fromisoformat(challenge_expires.replace("Z", "+00:00"))
        if expires < datetime.now(UTC):
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
            self._validate_transaction_payload(payload.signature, req, strict=True)
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
            self._store = MemoryStore(max_entries=10_000)

        req, payload = self._prepare_credential(credential, request)

        if isinstance(payload, HashCredentialPayload):
            store_key = await self._reserve_hash(payload.hash)
            try:
                return await self._validate_hash(
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
        return await self._broadcast_transaction(
            payload,
            req,
            challenge_id=credential.challenge.id,
            realm=credential.challenge.realm,
            source=credential.source,
        )

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
        return replace(Receipt.success(payload.hash), payer=payer)

    def _assert_challenge_bound_memo(
        self,
        matched_logs: list[MatchedTransferLog],
        challenge_id: str,
        realm: str,
    ) -> None:
        from mpp.methods.tempo._attribution import verify_challenge_binding, verify_server

        bound = any(
            matched_log.kind == "memo"
            and matched_log.memo is not None
            and verify_server(matched_log.memo, realm)
            and verify_challenge_binding(matched_log.memo, challenge_id)
            for matched_log in matched_logs
        )
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
        if not isinstance(receipt_data, dict):
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
    ) -> list[MatchedTransferLog]:
        """Check if receipt contains matching Transfer or TransferWithMemo logs.

        Returns matched logs. Empty list means no match.
        """
        expected = get_transfers(
            int(request.amount),
            request.recipient,
            None,
            request.methodDetails.splits,
        )

        if len(expected) == 1:
            t = expected[0]
            return self._verify_single_transfer_log(
                receipt,
                request.currency,
                t.recipient,
                t.amount,
                t.memo,
                expected_sender,
                source,
                validate_sender,
            )

        # Multi-transfer: order-insensitive matching
        sorted_expected = sorted(expected, key=lambda t: 0 if t.memo else 1)
        indexed_logs = list(enumerate(receipt.get("logs", [])))
        # Prefer memo logs so memo-less transfers still preserve attribution
        # memos for challenge binding verification when both log types exist.
        indexed_logs.sort(
            key=lambda item: (
                0 if item[1].get("topics", [None])[0] == TRANSFER_WITH_MEMO_TOPIC else 1
            )
        )
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
                                kind="memo", memo=memo_topic, sender=from_addr.lower()
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
    ) -> Receipt:
        """Verify and submit a signed transaction.

        Pre-validates the transaction contains the expected TIP-20 transfer call
        before broadcasting. For sponsored transactions (methodDetails.feePayer
        = True), co-signs locally if a fee payer account is configured, otherwise
        forwards to an external fee payer service. For regular transactions,
        submits directly.
        """
        self._validate_transaction_payload(payload.signature, request)
        sender = self._transaction_payer(payload.signature, source, request.methodDetails.chainId)

        client = await self._get_client()

        raw_tx = payload.signature

        # Simulation payload for the locally co-signed tx, if we sponsor it.
        simulate_payload: dict[str, Any] | None = None

        if request.methodDetails.feePayer:
            if self.fee_payer is not None:
                # Gas is paid in a supported fee token, not the charge currency:
                # Tempo only accepts fee tokens with Fee AMM liquidity.
                from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

                fields, _, _, _ = decode_fee_payer_envelope(
                    bytes.fromhex(raw_tx.removeprefix("0x"))
                )
                max_fee = int.from_bytes(fields[2], "big") * int.from_bytes(fields[3], "big")
                # Gas prices are attodollars; TIP-20 balances are microdollars.
                required_balance = max(1, (max_fee + 10**12 - 1) // 10**12)
                fee_token = await self._resolve_fee_token(client, request, required_balance)
                raw_tx, simulate_payload = self._cosign_as_fee_payer(
                    raw_tx, fee_token, request=request
                )
            else:
                fee_payer_url = request.methodDetails.feePayerUrl
                if not fee_payer_url:
                    raise InternalPaymentError() from RuntimeError(
                        "No fee payer configured: set feePayer on the tempo() method "
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

            # Fee payer signing must not change who the transaction debits.
            if sender is not None and _transaction_sender(raw_tx) != sender:
                raise VerificationError("Fee payer transaction sender does not match the sender.")

        rpc_url = self._get_rpc_url()

        reserved_tx_hash: str | None = None
        store_key: str | None = None
        if self._store is not None:
            reserved_tx_hash = _raw_transaction_hash(raw_tx)
            store_key = f"mpp:charge:{reserved_tx_hash.lower()}"
            if not await self._store.put_if_absent(store_key, reserved_tx_hash):
                raise CredentialReplayedError("Transaction hash already used")

        broadcast_attempted = False
        try:
            # Locally sponsored transactions must pass simulation before broadcast.
            if simulate_payload is not None:
                await self._simulate_before_broadcast(client, simulate_payload, rpc_url)

            # The send and any receipt recovery share one confirmation deadline.
            # The send may use at most two thirds of it, leaving the rest for
            # receipt recovery.
            deadline = time.monotonic() + self._confirmation_timeout
            send_timeout_ms = round(self._confirmation_timeout * 1000) * 2 // 3
            send_timeout = send_timeout_ms / 1000
            broadcast_attempted = True
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
                    raise
                return await self._recover_broadcast_receipt(
                    client,
                    raw_tx,
                    reserved_tx_hash or _raw_transaction_hash(raw_tx),
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                    deadline=deadline,
                    error=send_error,
                )

            if "error" in result:
                rpc_error = VerificationError(
                    f"Transaction submission failed: {_rpc_error_msg(result)}"
                )
                if not _is_ambiguous_broadcast_error(result):
                    raise rpc_error
                return await self._recover_broadcast_receipt(
                    client,
                    raw_tx,
                    reserved_tx_hash or _raw_transaction_hash(raw_tx),
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                    deadline=deadline,
                    error=rpc_error,
                )

            receipt_data = result.get("result")
            if not receipt_data:
                raise VerificationError("No transaction receipt returned")
            if not isinstance(receipt_data, dict):
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

            return Receipt.success(receipt_tx_hash)
        except (Exception, asyncio.CancelledError) as err:
            # Only successful verification consumes a payment. Failed or cancelled
            # attempts must let retries acquire the reservation and verify again.
            if self._store is not None and store_key is not None:
                await self._store.delete(store_key)
            # Once broadcast, the transaction may have landed: never report a
            # retryable verification failure that would invite a second payment.
            if (
                broadcast_attempted
                and isinstance(err, Exception)
                and not isinstance(err, (CredentialReplayedError, InternalPaymentError))
            ):
                raise InternalPaymentError() from err
            raise

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
        chain_id = request.methodDetails.chainId
        if chain_id is None:
            chain_id = getattr(self._method, "chain_id", None)
        allowed = getattr(self._method, "allowed_fee_tokens", None) or (
            fee_tokens_for_chain(chain_id) if chain_id is not None else (PATH_USD,)
        )
        configured = getattr(self._method, "fee_token", None)
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
        self, raw_tx: str, fee_token: str | None = None, request: ChargeRequest | None = None
    ) -> tuple[str, dict[str, Any]]:
        """Co-sign a client-signed transaction as fee payer.

        Deserializes the client's 0x78 fee payer envelope, optionally validates
        the payment calls against ``request``, sets the fee token, and co-signs.
        Returns ``(raw_0x76_hex, simulate_payload)`` where ``simulate_payload``
        is the ``tempo_simulateV1`` request for the co-signed tx.

        Authorization-bearing envelopes are rejected before signing because
        their authorization fields cannot yet be faithfully simulated.
        """
        from pytempo import Call, TempoTransaction
        from pytempo.models import Signature, as_address

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
        if valid_before <= int(time.time()):
            raise VerificationError(
                f"Fee payer envelope expired: valid_before ({valid_before}) is not in the future"
            )

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

    def _build_simulate_payload(self, tx: Any, sender: str) -> dict[str, Any]:
        """Build a ``tempo_simulateV1`` payload for the co-signed 0x76 tx.

        Carries the recovered sender as ``from`` (the node needs it to model the
        sender) plus the sponsor fields (``feeToken``, ``feePayerSignature``) so
        the node simulates the same tx we are about to broadcast.

        Must not be called for a tx that carries a ``key_authorization`` or a
        non-empty ``tempo_authorization_list``: those fields cannot yet be
        faithfully serialized here, so the resulting payload would describe a
        different transaction than the one broadcast. Local cosigning rejects
        these envelopes before applying the sponsor signature.
        """
        if getattr(tx, "key_authorization", None) is not None or getattr(
            tx, "tempo_authorization_list", ()
        ):
            raise VerificationError(
                "Cannot build a faithful tempo_simulateV1 payload for an "
                "authorization-bearing transaction"
            )

        sig = tx.fee_payer_signature
        parity = sig.v if sig.v in (0, 1) else sig.v - 27

        # The node rebuilds the batch as ``calls[]`` followed by the top-level
        # call appended last; an absent top-level ``to`` is read as a CREATE and
        # rejected. So we put the final call top-level and the rest in ``calls``
        # to preserve order.
        last_call = tx.calls[-1]
        leading_calls = tx.calls[:-1]

        tx_request: dict[str, Any] = {
            "from": sender,
            "type": "0x76",
            "chainId": hex(tx.chain_id),
            "nonce": hex(tx.nonce),
            "nonceKey": hex(tx.nonce_key),
            "gas": hex(tx.gas_limit),
            "maxFeePerGas": hex(tx.max_fee_per_gas),
            "maxPriorityFeePerGas": hex(tx.max_priority_fee_per_gas),
            "feeToken": "0x" + bytes(tx.fee_token).hex(),
            "feePayerSignature": {
                # Fixed 32-byte r/s so leading zeros are not dropped.
                "r": f"0x{sig.r:064x}",
                "s": f"0x{sig.s:064x}",
                "yParity": hex(parity),
            },
            # Top-level payment call so the node does not read this as a CREATE.
            "to": "0x" + bytes(last_call.to).hex(),
            "value": hex(last_call.value),
            "data": "0x" + last_call.data.hex(),
        }
        if leading_calls:
            tx_request["calls"] = [
                {
                    "to": "0x" + bytes(c.to).hex(),
                    "value": hex(c.value),
                    "data": "0x" + c.data.hex(),
                }
                for c in leading_calls
            ]
        if tx.valid_before is not None:
            tx_request["validBefore"] = hex(tx.valid_before)
        if tx.valid_after is not None:
            tx_request["validAfter"] = hex(tx.valid_after)

        return {
            "blockStateCalls": [{"calls": [tx_request]}],
            # We only care about execution outcome, not mempool admission.
            "validation": False,
            "traceTransfers": False,
            "returnFullTransactions": False,
        }

    async def _simulate_before_broadcast(
        self, client: Any, simulate_payload: dict[str, Any], rpc_url: str
    ) -> None:
        """Simulate the co-signed tx and raise if it would revert.

        Fails closed: any RPC/transport error is treated as a failed check.
        """
        try:
            response = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "tempo_simulateV1",
                    "params": [simulate_payload, "latest"],
                    "id": 1,
                },
            )
            response.raise_for_status()
            result = response.json()
        except Exception as err:
            raise InternalPaymentError() from err

        if "error" in result:
            raise InternalPaymentError() from RuntimeError(
                f"Pre-broadcast simulation failed: {_rpc_error_msg(result)}"
            )

        rpc_result = result.get("result")
        blocks = rpc_result.get("blocks") if isinstance(rpc_result, dict) else None
        block0 = blocks[0] if isinstance(blocks, list) and blocks else None
        calls = block0.get("calls") if isinstance(block0, dict) else None
        call = None
        if isinstance(calls, list) and calls and isinstance(calls[0], dict):
            call = calls[0]
        if call is None:
            raise InternalPaymentError() from RuntimeError(
                "Pre-broadcast simulation returned no call results"
            )

        status = call.get("status")
        if status in ("0x1", 1, True):
            return

        detail = (call.get("error") or {}).get("message") or "no revert reason returned"
        raise VerificationError(
            f"Sponsored transaction would revert in pre-broadcast simulation: {detail}"
        )

    def _validate_calls(self, calls: tuple, request: ChargeRequest) -> None:
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
    ) -> None:
        """Validate a transaction, failing closed for advisory validation."""
        try:
            import rlp
        except ImportError as error:
            if strict:
                raise InternalPaymentError() from error
            return
        try:
            tx_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
        except ValueError as error:
            if strict:
                raise VerificationError("Invalid serialized transaction") from error
            return
        if not tx_bytes or tx_bytes[0] not in (0x76, 0x78):
            if strict:
                raise VerificationError("Only Tempo (0x76/0x78) transactions are supported")
            return
        try:
            decoded = rlp.decode(tx_bytes[1:])
        except Exception as error:
            if strict:
                raise VerificationError("Invalid serialized transaction") from error
            return
        if not isinstance(decoded, list) or len(decoded) < 5:
            if strict:
                raise VerificationError("Invalid serialized transaction")
            return

        if not isinstance(decoded[0], bytes):
            raise VerificationError("Invalid transaction chain ID")
        if int.from_bytes(decoded[0], "big") != request.methodDetails.chainId:
            raise VerificationError("Transaction chain ID does not match charge chain ID")

        calls_data = decoded[4] if len(decoded) > 4 else []
        if not calls_data:
            raise VerificationError("Transaction contains no calls")

        normalized_calls: list[tuple[str, int, str]] = []
        for call_item in calls_data:
            if not isinstance(call_item, (list, tuple)) or len(call_item) < 3:
                raise VerificationError("Invalid transaction: malformed call data")

            call_to_raw, call_value_raw, call_data_raw = call_item[0], call_item[1], call_item[2]
            if not isinstance(call_to_raw, bytes) or not isinstance(call_data_raw, bytes):
                raise VerificationError("Invalid transaction: malformed call data")

            if isinstance(call_value_raw, bytes):
                call_value = int.from_bytes(call_value_raw, "big") if call_value_raw else 0
            elif isinstance(call_value_raw, int):
                call_value = call_value_raw
            else:
                raise VerificationError("Invalid transaction: malformed call data")

            normalized_calls.append(("0x" + call_to_raw.hex(), call_value, call_data_raw.hex()))

        _validate_normalized_calls(normalized_calls, request)
