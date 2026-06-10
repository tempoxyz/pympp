"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import attrs

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_TIMEOUT
from mpp.errors import VerificationError
from mpp.methods.tempo._defaults import PATH_USD, rpc_url_for_chain
from mpp.methods.tempo.fee_payer_policy import get_policy
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    Split,
    TransactionCredentialPayload,
)
from mpp.store import Store

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_WITH_MEMO_SELECTOR = "95777d59"
APPROVE_SELECTOR = "095ea7b3"
SWAP_EXACT_AMOUNT_OUT_SELECTOR = "b30d91d5"

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_MEMO_TOPIC = "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
STABLECOIN_DEX = "0xdec0000000000000000000000000000000000000"

MAX_SPLITS = 10
MAX_TRANSFERS = MAX_SPLITS + 1
ALREADY_KNOWN_TRANSACTION_RE = re.compile(r"\b(?:already known|known transaction)\b")


def _raw_transaction_hash(raw_tx: str) -> str:
    """Return the transaction hash for a raw signed transaction."""
    from eth_hash.auto import keccak

    try:
        tx_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
    except ValueError as err:
        raise VerificationError("Invalid transaction signature") from err

    return "0x" + keccak(tx_bytes).hex()


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
    if len(call_data_hex) < 136:
        return False

    selector = call_data_hex[:8].lower()

    if memo is not None:
        if selector != TRANSFER_WITH_MEMO_SELECTOR:
            return False
    elif selector == TRANSFER_WITH_MEMO_SELECTOR:
        if len(call_data_hex) < 200:
            return False
    elif selector != TRANSFER_SELECTOR:
        return False

    decoded_to = "0x" + call_data_hex[32:72]
    decoded_amount = int(call_data_hex[72:136], 16)

    if decoded_to.lower() != recipient.lower():
        return False
    if decoded_amount != amount:
        return False

    if memo is not None:
        if len(call_data_hex) < 200:
            return False
        decoded_memo = bytes.fromhex(call_data_hex[136:200])
        if decoded_memo != memo:
            return False

    return True


@dataclass(frozen=True, slots=True)
class MatchedTransferLog:
    kind: Literal["memo", "transfer"]
    memo: str | None = None


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


_PKH_SOURCE_RE = re.compile(r"did:pkh:eip155:(0|[1-9][0-9]*):(.+)")
_PKH_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _parse_pkh_source(source: str) -> tuple[str, int] | None:
    """Parse a ``did:pkh:eip155:<chainId>:<address>`` DID.

    Returns ``(address, chain_id)`` or ``None`` if malformed.
    """
    match = _PKH_SOURCE_RE.fullmatch(source)
    if match is None:
        return None
    address = match.group(2)
    if _PKH_ADDRESS_RE.fullmatch(address) is None:
        return None
    try:
        chain_id = int(match.group(1))
    except ValueError:
        return None
    return address, chain_id


def _rpc_error_msg(result: dict) -> str:
    """Extract error message from a JSON-RPC error response."""
    error_obj = result["error"]
    if isinstance(error_obj, dict):
        msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
        data = error_obj.get("data", "")
        return f"{msg}: {data}" if data else msg
    return str(error_obj)


def _is_already_known_transaction_error(result: dict[str, Any]) -> bool:
    """Return true when an RPC send error means the tx was already accepted."""
    if "error" not in result:
        return False
    msg = _rpc_error_msg(result).lower()
    return ALREADY_KNOWN_TRANSACTION_RE.search(msg) is not None


def _match_transfer_calldata(call_data_hex: str, request: ChargeRequest) -> bool:
    """Check if ABI-encoded calldata matches the expected transfer parameters."""
    if len(call_data_hex) < 136:
        return False

    selector = call_data_hex[:8].lower()
    expected_memo = request.methodDetails.memo

    if expected_memo:
        if selector != TRANSFER_WITH_MEMO_SELECTOR:
            return False
    elif selector == TRANSFER_WITH_MEMO_SELECTOR:
        if len(call_data_hex) < 200:
            return False
    elif selector != TRANSFER_SELECTOR:
        return False

    decoded_to = "0x" + call_data_hex[32:72]
    decoded_amount = int(call_data_hex[72:136], 16)

    if decoded_to.lower() != request.recipient.lower():
        return False
    if decoded_amount != int(request.amount):
        return False

    if expected_memo:
        if len(call_data_hex) < 200:
            return False
        decoded_memo = "0x" + call_data_hex[136:200]
        memo_clean = expected_memo.lower()
        if not memo_clean.startswith("0x"):
            memo_clean = "0x" + memo_clean
        if decoded_memo.lower() != memo_clean:
            return False

    return True


def _decode_call_address_arg(call_data_hex: str, arg_index: int) -> str:
    start = 8 + (arg_index * 64)
    end = start + 64
    if len(call_data_hex) < end:
        raise VerificationError("Invalid transaction: malformed call data")
    return "0x" + call_data_hex[start + 24 : end]


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
        approve_spender = _decode_call_address_arg(approve_data, 0)
        swap_token_in = _decode_call_address_arg(swap_data, 0)

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
        request.methodDetails.memo,
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
            store: Optional key-value store for tx hash replay protection.
                When provided, each verified hash is recorded and subsequent
                attempts to reuse it are rejected.
            validate_sender: Optional callback invoked when a hash-credential
                transfer's sender differs from the expected sender; return
                ``True`` to accept (e.g. smart-account / relayer flows).
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
            raise VerificationError("No rpc_url configured on ChargeIntent")
        return self.rpc_url

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create an HTTP client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify a charge credential.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A receipt indicating success or failure.

        Raises:
            VerificationError: If verification fails.
        """
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

        if isinstance(payload, HashCredentialPayload):
            return await self._verify_hash(
                payload,
                req,
                challenge_id=credential.challenge.id,
                realm=credential.challenge.realm,
                source=credential.source,
            )
        else:
            return await self._verify_transaction(
                payload,
                req,
                challenge_id=credential.challenge.id,
                realm=credential.challenge.realm,
            )

    def _parse_hash_credential_source(
        self, source: str | None, expected_chain_id: int
    ) -> str | None:
        """Parse a hash credential source.

        Returns ``None`` if absent, the address for a ``did:pkh:eip155`` DID
        matching ``expected_chain_id``, else raises ``VerificationError``.
        """
        if source is None:
            return None
        parsed = _parse_pkh_source(source)
        if parsed is None or parsed[1] != expected_chain_id:
            raise VerificationError("Hash credential source is invalid.")
        return parsed[0]

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

    async def _verify_hash(
        self,
        payload: HashCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
        source: str | None = None,
    ) -> Receipt:
        """Verify a credential with a transaction hash."""
        # Validate the source before reserving the hash.
        source_address = self._parse_hash_credential_source(source, request.methodDetails.chainId)

        client = await self._get_client()

        store_key: str | None = None
        if self._store is not None:
            store_key = f"mpp:charge:{payload.hash.lower()}"
            if not await self._store.put_if_absent(store_key, payload.hash):
                raise VerificationError("Transaction hash already used")

        try:
            receipt_data = await self._fetch_transaction_receipt(client, payload.hash)
            self._verify_receipt_transfers(
                receipt_data,
                request,
                challenge_id=challenge_id,
                realm=realm,
                source=source,
                source_address=source_address,
                validate_sender=self._validate_sender,
            )
        except Exception:
            if self._store is not None and store_key is not None:
                await self._store.delete(store_key)
            raise

        return Receipt.success(payload.hash)

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
            raise VerificationError(
                "Payment verification failed: memo is not bound to this challenge."
            )

    async def _fetch_transaction_receipt(self, client: Any, tx_hash: str) -> dict[str, Any]:
        rpc_url = self._get_rpc_url()
        response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1,
            },
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            raise VerificationError("RPC request failed")

        receipt_data = result.get("result")
        if not receipt_data:
            raise VerificationError("Transaction not found")
        if not isinstance(receipt_data, dict):
            raise VerificationError("Invalid transaction receipt")

        return receipt_data

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

        # Only verify challenge binding when using auto-generated attribution memos.
        # Explicit memos (set by the server) are strictly matched by _verify_transfer_logs
        # but are NOT challenge-bound. Callers that set explicit memos are responsible
        # for ensuring memo uniqueness per challenge to prevent cross-challenge hash reuse.
        if request.methodDetails.memo is None:
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
                memo_matches.append(MatchedTransferLog(kind="memo", memo=log_memo))
            elif event_topic == TRANSFER_TOPIC:
                if memo is not None:
                    continue
                data = log.get("data", "0x")
                if len(data) >= 66:
                    log_amount = int(data, 16)
                    if log_amount == amount and self._sender_authorized(
                        from_address, expected_sender, source, validate_sender
                    ):
                        transfer_matches.append(MatchedTransferLog(kind="transfer"))

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
            request.methodDetails.memo,
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
                        all_matches.append(MatchedTransferLog(kind="memo", memo=memo_topic))
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
                            all_matches.append(MatchedTransferLog(kind="memo", memo=topics[3]))
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
                            all_matches.append(MatchedTransferLog(kind="transfer"))
                            found = True
                            break

            if not found:
                return []

        return all_matches

    async def _verify_transaction(
        self,
        payload: TransactionCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
    ) -> Receipt:
        """Verify and submit a signed transaction.

        Pre-validates the transaction contains the expected TIP-20 transfer call
        before broadcasting. For sponsored transactions (methodDetails.feePayer
        = True), co-signs locally if a fee payer account is configured, otherwise
        forwards to an external fee payer service. For regular transactions,
        submits directly.
        """
        self._validate_transaction_payload(payload.signature, request)

        client = await self._get_client()

        raw_tx = payload.signature

        if request.methodDetails.feePayer:
            if self.fee_payer is not None:
                raw_tx = self._cosign_as_fee_payer(raw_tx, request.currency, request=request)
            else:
                fee_payer_url = request.methodDetails.feePayerUrl
                if not fee_payer_url:
                    raise VerificationError(
                        "No fee payer configured: set feePayer on the tempo() method "
                        "or provide a feePayerUrl in methodDetails"
                    )

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

                if "error" in sign_result:
                    raise VerificationError(
                        f"Fee payer signing failed: {_rpc_error_msg(sign_result)}"
                    )

                raw_tx = sign_result.get("result")
                if not raw_tx:
                    raise VerificationError("Fee payer returned no signed transaction")

        rpc_url = self._get_rpc_url()
        reserved_tx_hash: str | None = None
        store_key: str | None = None
        if self._store is not None:
            reserved_tx_hash = _raw_transaction_hash(raw_tx)
            store_key = f"mpp:charge:{reserved_tx_hash.lower()}"
            if not await self._store.put_if_absent(store_key, reserved_tx_hash):
                receipt_data = await self._fetch_transaction_receipt(client, reserved_tx_hash)
                self._verify_receipt_transfers(
                    receipt_data,
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                )
                return Receipt.success(reserved_tx_hash)

        try:
            response = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransactionSync",
                    "params": [raw_tx],
                    "id": 1,
                },
            )
            response.raise_for_status()
            result = response.json()
        except Exception:
            if self._store is not None and store_key is not None:
                await self._store.delete(store_key)
            raise

        if "error" in result:
            if _is_already_known_transaction_error(result):
                tx_hash = reserved_tx_hash or _raw_transaction_hash(raw_tx)
                receipt_data = await self._fetch_transaction_receipt(client, tx_hash)
                self._verify_receipt_transfers(
                    receipt_data,
                    request,
                    challenge_id=challenge_id,
                    realm=realm,
                )
                return Receipt.success(tx_hash)

            if self._store is not None and store_key is not None:
                await self._store.delete(store_key)
            raise VerificationError(f"Transaction submission failed: {_rpc_error_msg(result)}")

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
            raise VerificationError("Receipt transaction hash does not match submitted transaction")

        return Receipt.success(receipt_tx_hash)

    def _cosign_as_fee_payer(
        self, raw_tx: str, fee_token: str | None = None, request: ChargeRequest | None = None
    ) -> str:
        """Co-sign a client-signed transaction as fee payer.

        Deserializes the client's 0x78 fee payer envelope, optionally validates
        the payment calls against ``request``, sets the fee token, and co-signs.
        Returns the fully co-signed 0x76 transaction hex.
        """
        from pytempo import Call, TempoTransaction
        from pytempo.models import Signature, as_address

        from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

        if self.fee_payer is None:
            raise VerificationError("No fee payer account configured")

        try:
            all_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
            decoded, sender_addr_bytes, sender_sig, key_auth = decode_fee_payer_envelope(all_bytes)
        except Exception as err:
            raise VerificationError("Failed to deserialize client transaction") from err

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
            awaiting_fee_payer=True,
            key_authorization=key_auth,
        )
        sender_hash = tx_for_recovery.get_signing_hash(for_fee_payer=False)

        from eth_account import Account

        recovered_address = Account._recover_hash(sender_hash, signature=sender_sig)
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
            raise VerificationError("Fee payer signing failed") from err

        return "0x" + cosigned.encode().hex()

    def _validate_calls(self, calls: tuple, request: ChargeRequest) -> None:
        """Validate that calls match all expected transfers."""
        normalized_calls = [
            ("0x" + bytes(call.to).hex(), int(call.value), call.data.hex()) for call in calls
        ]
        _validate_normalized_calls(normalized_calls, request)

    def _validate_transaction_payload(self, signature: str, request: ChargeRequest) -> None:
        """Best-effort pre-broadcast check. Silently skips if decoding fails."""
        try:
            import rlp
        except ImportError:
            return
        try:
            tx_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
        except ValueError:
            return
        if not tx_bytes or tx_bytes[0] not in (0x76, 0x78):
            return
        try:
            decoded = rlp.decode(tx_bytes[1:])
        except Exception:
            return
        if not isinstance(decoded, list) or len(decoded) < 5:
            return

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
