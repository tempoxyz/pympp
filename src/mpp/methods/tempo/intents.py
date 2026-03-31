"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import attrs

from mpp import Credential, Receipt
from mpp.errors import VerificationError
from mpp.methods.tempo._defaults import PATH_USD, rpc_url_for_chain
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


DEFAULT_TIMEOUT = 30.0

# Receipt polling: 20 * 0.5s = ~10s, enough for testnet block times (~2-4s).
MAX_RECEIPT_RETRY_ATTEMPTS = 20
RECEIPT_RETRY_DELAY_SECONDS = 0.5

TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_WITH_MEMO_SELECTOR = "95777d59"

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_MEMO_TOPIC = "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

MAX_SPLITS = 10


def _parse_memo_bytes(memo: str | None) -> bytes | None:
    """Parse a hex memo string into 32 bytes, or None if invalid."""
    if memo is None:
        return None
    hex_str = memo[2:] if memo.startswith("0x") else memo
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        return None
    return b if len(b) == 32 else None


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
        return [Transfer(
            amount=total_amount,
            recipient=primary_recipient,
            memo=_parse_memo_bytes(primary_memo),
        )]

    if len(splits) > MAX_SPLITS:
        raise VerificationError(f"Too many splits: {len(splits)} (max {MAX_SPLITS})")

    split_sum = 0
    split_transfers: list[Transfer] = []

    for s in splits:
        amt = int(s.amount)
        if amt <= 0:
            raise VerificationError("Split amount must be greater than zero")
        split_sum += amt
        split_transfers.append(Transfer(
            amount=amt,
            recipient=s.recipient,
            memo=_parse_memo_bytes(s.memo),
        ))

    if split_sum >= total_amount:
        raise VerificationError(
            f"Sum of splits ({split_sum}) must be less than total amount ({total_amount})"
        )

    primary_amount = total_amount - split_sum
    transfers = [Transfer(
        amount=primary_amount,
        recipient=primary_recipient,
        memo=_parse_memo_bytes(primary_memo),
    )]
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
    elif selector not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR):
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


def _rpc_error_msg(result: dict) -> str:
    """Extract error message from a JSON-RPC error response."""
    error_obj = result["error"]
    if isinstance(error_obj, dict):
        msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
        data = error_obj.get("data", "")
        return f"{msg}: {data}" if data else msg
    return str(error_obj)


def _match_transfer_calldata(call_data_hex: str, request: ChargeRequest) -> bool:
    """Check if ABI-encoded calldata matches the expected transfer parameters."""
    if len(call_data_hex) < 136:
        return False

    selector = call_data_hex[:8].lower()
    expected_memo = request.methodDetails.memo

    if expected_memo:
        if selector != TRANSFER_WITH_MEMO_SELECTOR:
            return False
    elif selector not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR):
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
        """
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self._method = None
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout
        self._store = store

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
            )
        else:
            return await self._verify_transaction(payload, req)

    async def _verify_hash(
        self,
        payload: HashCredentialPayload,
        request: ChargeRequest,
        challenge_id: str,
        realm: str,
    ) -> Receipt:
        """Verify a credential with a transaction hash."""
        client = await self._get_client()

        rpc_url = self._get_rpc_url()
        response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [payload.hash],
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

        if receipt_data.get("status") != "0x1":
            raise VerificationError("Transaction reverted")

        matched_logs = self._verify_transfer_logs(receipt_data, request)
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

        if self._store is not None:
            store_key = f"mpp:charge:{payload.hash.lower()}"
            if not await self._store.put_if_absent(store_key, payload.hash):
                raise VerificationError("Transaction hash already used")

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

    def _verify_single_transfer_log(
        self,
        receipt: dict[str, Any],
        currency: str,
        recipient: str,
        amount: int,
        memo: bytes | None,
        expected_sender: str | None = None,
    ) -> bool:
        """Check if receipt contains a matching Transfer/TransferWithMemo log."""
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
            if expected_sender and from_address.lower() != expected_sender.lower():
                continue

            if memo is not None:
                if event_topic != TRANSFER_WITH_MEMO_TOPIC:
                    continue
                if len(topics) < 4:
                    continue
                data = log.get("data", "0x")
                if len(data) < 66:
                    continue
                log_amount = int(data[2:66], 16)
                memo_topic = topics[3]
                expected_memo_hex = "0x" + memo.hex()
                if log_amount == amount and memo_topic.lower() == expected_memo_hex.lower():
                    return True
            else:
                if event_topic not in (TRANSFER_TOPIC, TRANSFER_WITH_MEMO_TOPIC):
                    continue
                data = log.get("data", "0x")
                if len(data) >= 66:
                    log_amount = int(data[2:66], 16) if event_topic == TRANSFER_WITH_MEMO_TOPIC else int(data, 16)
                    if log_amount == amount:
                        return True

        return False

    def _verify_transfer_logs(
        self,
        receipt: dict[str, Any],
        request: ChargeRequest,
        expected_sender: str | None = None,
    ) -> bool:
        """Check if receipt contains matching Transfer or TransferWithMemo logs."""
        expected = get_transfers(
            int(request.amount),
            request.recipient,
            request.methodDetails.memo,
            request.methodDetails.splits,
        )

        if len(expected) == 1:
            t = expected[0]
            return self._verify_single_transfer_log(
                receipt, request.currency, t.recipient, t.amount, t.memo,
                expected_sender,
            )

        # Multi-transfer: order-insensitive matching
        sorted_expected = sorted(expected, key=lambda t: (0 if t.memo else 1))
        logs = receipt.get("logs", [])
        used_logs: set[int] = set()

        for transfer in sorted_expected:
            found = False
            for log_idx, log in enumerate(logs):
                if log_idx in used_logs:
                    continue
                if log.get("address", "").lower() != request.currency.lower():
                    continue

                topics = log.get("topics", [])
                if len(topics) < 3:
                    continue

                event_topic = topics[0]
                from_address = "0x" + topics[1][-40:]
                to_address = "0x" + topics[2][-40:]

                if to_address.lower() != transfer.recipient.lower():
                    continue
                if expected_sender and from_address.lower() != expected_sender.lower():
                    continue

                if transfer.memo is not None:
                    if event_topic != TRANSFER_WITH_MEMO_TOPIC:
                        continue
                    if len(topics) < 4:
                        continue
                    data = log.get("data", "0x")
                    if len(data) < 66:
                        continue
                    amount = int(data[2:66], 16)
                    memo_topic = topics[3]
                    expected_memo_hex = "0x" + transfer.memo.hex()
                    if amount == transfer.amount and memo_topic.lower() == expected_memo_hex.lower():
                        used_logs.add(log_idx)
                        found = True
                        break
                else:
                    if event_topic not in (TRANSFER_TOPIC, TRANSFER_WITH_MEMO_TOPIC):
                        continue
                    data = log.get("data", "0x")
                    if len(data) >= 66:
                        amount = int(data[2:66], 16) if event_topic == TRANSFER_WITH_MEMO_TOPIC else int(data, 16)
                        if amount == transfer.amount:
                            used_logs.add(log_idx)
                            found = True
                            break

            if not found:
                return False

        return True

    async def _verify_transaction(
        self,
        payload: TransactionCredentialPayload,
        request: ChargeRequest,
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
        response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [raw_tx],
                "id": 1,
            },
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            raise VerificationError(f"Transaction submission failed: {_rpc_error_msg(result)}")

        tx_hash = result.get("result")
        if not tx_hash:
            raise VerificationError("No transaction hash returned")

        receipt_data = None
        for attempt in range(MAX_RECEIPT_RETRY_ATTEMPTS):
            receipt_response = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1,
                },
            )
            receipt_response.raise_for_status()
            receipt_result = receipt_response.json()

            if "error" in receipt_result:
                raise VerificationError("Failed to fetch transaction receipt")

            receipt_data = receipt_result.get("result")
            if receipt_data:
                break

            if attempt < MAX_RECEIPT_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RECEIPT_RETRY_DELAY_SECONDS)

        if not receipt_data:
            raise VerificationError("Transaction receipt not found after retries")

        if receipt_data.get("status") != "0x1":
            raise VerificationError("Transaction reverted")

        if not self._verify_transfer_logs(receipt_data, request):
            raise VerificationError(
                "Transaction must contain a Transfer log matching request parameters"
            )

        if self._store is not None:
            store_key = f"mpp:charge:{tx_hash.lower()}"
            if not await self._store.put_if_absent(store_key, tx_hash):
                raise VerificationError("Transaction hash already used")

        return Receipt.success(tx_hash)

    def _cosign_as_fee_payer(
        self, raw_tx: str, fee_token: str | None = None, request: ChargeRequest | None = None
    ) -> str:
        """Co-sign a client-signed transaction as fee payer.

        Deserializes the client's 0x78 fee payer envelope, optionally validates
        the payment calls against ``request``, sets the fee token, and co-signs.
        Returns the fully co-signed 0x76 transaction hex.
        """
        from pytempo import Call, TempoTransaction
        from pytempo.models import as_address

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

        calls = tuple(Call(to=c[0], value=_int(c[1]), data=c[2]) for c in decoded[4])

        if request is not None:
            self._validate_calls(calls, request)

        tx_for_recovery = TempoTransaction(
            chain_id=_int(decoded[0]),
            max_priority_fee_per_gas=_int(decoded[1]),
            max_fee_per_gas=_int(decoded[2]),
            gas_limit=_int(decoded[3]),
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
            sender_signature=sender_sig,
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
        expected = get_transfers(
            int(request.amount),
            request.recipient,
            request.methodDetails.memo,
            request.methodDetails.splits,
        )

        sorted_expected = sorted(expected, key=lambda t: (0 if t.memo else 1))
        used_calls: set[int] = set()

        for transfer in sorted_expected:
            found = False
            for call_idx, call in enumerate(calls):
                if call_idx in used_calls:
                    continue
                call_to = "0x" + bytes(call.to).hex()
                if call_to.lower() != request.currency.lower():
                    continue
                if call.value:
                    continue
                if _match_single_transfer_calldata(
                    call.data.hex(), transfer.recipient, transfer.amount, transfer.memo
                ):
                    used_calls.add(call_idx)
                    found = True
                    break
            if not found:
                raise VerificationError("Invalid transaction: no matching payment call found")

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

        expected = get_transfers(
            int(request.amount),
            request.recipient,
            request.methodDetails.memo,
            request.methodDetails.splits,
        )

        sorted_expected = sorted(expected, key=lambda t: (0 if t.memo else 1))
        used_calls: set[int] = set()

        for transfer in sorted_expected:
            found = False
            for call_idx, call_item in enumerate(calls_data):
                if call_idx in used_calls:
                    continue
                if not isinstance(call_item, (list, tuple)) or len(call_item) < 3:
                    continue
                call_to_bytes, call_data_bytes = call_item[0], call_item[2]
                if not call_to_bytes or not call_data_bytes:
                    continue
                to_hex = call_to_bytes.hex() if isinstance(call_to_bytes, bytes) else str(call_to_bytes)
                if ("0x" + to_hex).lower() != request.currency.lower():
                    continue
                raw = call_data_bytes
                data_hex = raw.hex() if isinstance(raw, bytes) else str(raw)
                if _match_single_transfer_calldata(
                    data_hex, transfer.recipient, transfer.amount, transfer.memo
                ):
                    used_calls.add(call_idx)
                    found = True
                    break
            if not found:
                raise VerificationError("Invalid transaction: no matching payment call found")
