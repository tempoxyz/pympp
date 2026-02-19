"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import attrs

from mpp import Credential, Receipt
from mpp.errors import VerificationError
from mpp.methods.tempo._defaults import DEFAULT_FEE_PAYER_URL, PATH_USD, rpc_url_for_chain
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    TransactionCredentialPayload,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount


DEFAULT_TIMEOUT = 30.0

# Receipt polling configuration
#
# After submitting a transaction, we poll for the receipt since it won't be
# available until the transaction is included in a block. Block times vary:
# - Tempo mainnet: ~400ms
# - Tempo testnet: ~2-4s (can be slower under load)
#
# For comparison, viem's waitForTransactionReceipt uses:
# - 6 retries with exponential backoff (200ms, 400ms, 800ms, 1.6s, 3.2s, 6.4s)
# - 180s total timeout
#
# We use a simpler fixed-delay approach that provides ~10s total wait time,
# sufficient for testnet latency while keeping the implementation simple.
MAX_RECEIPT_RETRY_ATTEMPTS = 20
RECEIPT_RETRY_DELAY_SECONDS = 0.5

# TIP-20 function selectors
TRANSFER_SELECTOR = "a9059cbb"  # keccak256("transfer(address,uint256)")[:4]
TRANSFER_WITH_MEMO_SELECTOR = "95777d59"  # transferWithMemo(address,uint256,bytes32)

# Event topic hashes
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_MEMO_TOPIC = "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


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
        """
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self._method = None
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

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

        expires = datetime.fromisoformat(req.expires.replace("Z", "+00:00"))
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
            return await self._verify_hash(payload, req)
        else:
            return await self._verify_transaction(payload, req)

    async def _verify_hash(
        self,
        payload: HashCredentialPayload,
        request: ChargeRequest,
    ) -> Receipt:
        """Verify a credential with a transaction hash."""
        client = await self._get_client()

        response = await client.post(
            self.rpc_url,
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

        if not self._verify_transfer_logs(receipt_data, request):
            raise VerificationError(
                "Transaction must contain a Transfer log matching request parameters"
            )

        return Receipt.success(payload.hash)

    def _verify_transfer_logs(
        self,
        receipt: dict[str, Any],
        request: ChargeRequest,
        expected_sender: str | None = None,
    ) -> bool:
        """Check if receipt contains matching Transfer or TransferWithMemo logs.

        Args:
            receipt: Transaction receipt from RPC.
            request: The charge request with expected amount/currency/recipient.
            expected_sender: If provided, validates the 'from' address in the
                Transfer log matches this address (for payer identity verification).

        Returns:
            True if a matching Transfer/TransferWithMemo log is found,
            False otherwise.
        """
        expected_memo = request.methodDetails.memo

        for log in receipt.get("logs", []):
            if log.get("address", "").lower() != request.currency.lower():
                continue

            topics = log.get("topics", [])
            if len(topics) < 3:
                continue

            event_topic = topics[0]
            from_address = "0x" + topics[1][-40:]
            to_address = "0x" + topics[2][-40:]

            if to_address.lower() != request.recipient.lower():
                continue

            if expected_sender and from_address.lower() != expected_sender.lower():
                continue

            if expected_memo:
                if event_topic != TRANSFER_WITH_MEMO_TOPIC:
                    continue
                # TransferWithMemo has 3 indexed params (from, to, memo)
                # so memo is in topics[3] and only amount is in data
                if len(topics) < 4:
                    continue
                data = log.get("data", "0x")
                if len(data) < 66:
                    continue
                amount = int(data[2:66], 16)
                memo = topics[3]
                memo_clean = expected_memo.lower()
                if not memo_clean.startswith("0x"):
                    memo_clean = "0x" + memo_clean
                if amount == int(request.amount) and memo.lower() == memo_clean:
                    return True
            else:
                if event_topic != TRANSFER_TOPIC:
                    continue
                data = log.get("data", "0x")
                if len(data) >= 66:
                    amount = int(data, 16)
                    if amount == int(request.amount):
                        return True

        return False

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
                fee_payer_url = request.methodDetails.feePayerUrl or DEFAULT_FEE_PAYER_URL

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
                    error_obj = sign_result["error"]
                    if isinstance(error_obj, dict):
                        error_msg = (
                            error_obj.get("message") or error_obj.get("name") or str(error_obj)
                        )
                    else:
                        error_msg = str(error_obj)
                    raise VerificationError(f"Fee payer signing failed: {error_msg}")

                raw_tx = sign_result.get("result")
                if not raw_tx:
                    raise VerificationError("Fee payer returned no signed transaction")

        response = await client.post(
            self.rpc_url,
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
            error_obj = result["error"]
            if isinstance(error_obj, dict):
                error_msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
                error_data = error_obj.get("data", "")
            else:
                error_msg = str(error_obj)
                error_data = ""
            full_error = f"{error_msg}: {error_data}" if error_data else error_msg
            raise VerificationError(f"Transaction submission failed: {full_error}")

        tx_hash = result.get("result")
        if not tx_hash:
            raise VerificationError("No transaction hash returned")

        receipt_data = None
        for attempt in range(MAX_RECEIPT_RETRY_ATTEMPTS):
            receipt_response = await client.post(
                self.rpc_url,
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

        return Receipt.success(tx_hash)

    def _cosign_as_fee_payer(
        self, raw_tx: str, fee_token: str | None = None, request: ChargeRequest | None = None
    ) -> str:
        """Co-sign a client-signed transaction as fee payer.

        Deserializes the client's transaction, validates it contains the
        expected payment call, sets the fee token, and signs with domain
        ``0x78``. The resulting transaction contains both the client's
        signature and the fee payer's signature.

        Args:
            raw_tx: Hex-encoded client-signed transaction (0x76...).
            fee_token: TIP-20 token address for fee payment.
                Defaults to pathUSD.
            request: The charge request to validate against. When provided,
                the transaction calls are checked to ensure they target the
                expected currency with the correct transfer parameters.

        Returns:
            Hex-encoded co-signed transaction ready for broadcast.

        Raises:
            VerificationError: If deserialization, validation, or signing fails.
        """
        import rlp
        from pytempo import Call, TempoTransaction
        from pytempo.models import as_address

        if self.fee_payer is None:
            raise VerificationError("No fee payer account configured")

        try:
            all_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
            if not all_bytes or all_bytes[0] != 0x76:
                raise ValueError("Not a Tempo transaction")
            decoded = rlp.decode(all_bytes[1:])
        except Exception as err:
            raise VerificationError("Failed to deserialize client transaction") from err

        def _int(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        calls = tuple(Call(to=c[0], value=_int(c[1]), data=c[2]) for c in decoded[4])

        # Validate the transaction calls match the expected payment before
        # co-signing.  Without this check the server would sponsor arbitrary
        # transactions submitted by any sender.
        if request is not None:
            self._validate_cosign_calls(calls, request)

        # Recover sender address from the sender's signature
        sender_sig = decoded[-1]  # last field
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
        )
        sender_hash = tx_for_recovery.get_signing_hash(for_fee_payer=False)

        from eth_account import Account

        sender_address = Account._recover_hash(sender_hash, signature=sender_sig)

        # Reconstruct with sender signature and address
        resolved_fee_token = fee_token or PATH_USD
        fee_token_bytes = bytes.fromhex(
            resolved_fee_token[2:] if resolved_fee_token.startswith("0x") else resolved_fee_token
        )

        tx_to_sign = attrs.evolve(
            tx_for_recovery,
            sender_signature=sender_sig,
            sender_address=as_address(sender_address),
            fee_token=fee_token_bytes,
        )

        try:
            cosigned = tx_to_sign.sign(self.fee_payer.private_key, for_fee_payer=True)
        except Exception as err:
            raise VerificationError("Fee payer signing failed") from err

        return "0x" + cosigned.encode().hex()

    def _validate_cosign_calls(self, calls: tuple, request: ChargeRequest) -> None:
        """Validate that decoded transaction calls match the charge request.

        Ensures the server only co-signs transactions that target the
        expected currency contract with a valid transfer selector,
        correct recipient, and correct amount.

        Args:
            calls: Decoded Call tuples from the transaction.
            request: The charge request with expected parameters.

        Raises:
            VerificationError: If no call matches the expected payment.
        """
        expected_memo = request.methodDetails.memo

        for call in calls:
            call_to = call.to if isinstance(call.to, bytes) else bytes.fromhex(
                call.to[2:] if isinstance(call.to, str) and call.to.startswith("0x") else str(call.to)
            )
            call_to_hex = "0x" + call_to.hex()

            if call_to_hex.lower() != request.currency.lower():
                continue

            if call.value and int.from_bytes(call.value, "big") if isinstance(call.value, bytes) else (call.value or 0):
                if isinstance(call.value, int) and call.value != 0:
                    continue
                elif isinstance(call.value, bytes) and int.from_bytes(call.value, "big") != 0:
                    continue

            call_data = call.data if isinstance(call.data, bytes) else bytes.fromhex(
                call.data[2:] if isinstance(call.data, str) and call.data.startswith("0x") else str(call.data)
            )
            call_data_hex = call_data.hex()

            if len(call_data_hex) < 8:
                continue

            selector = call_data_hex[:8].lower()

            if expected_memo:
                if selector != TRANSFER_WITH_MEMO_SELECTOR:
                    continue
            elif selector not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR):
                continue

            if len(call_data_hex) < 136:
                continue
            decoded_to = "0x" + call_data_hex[32:72]
            decoded_amount = int(call_data_hex[72:136], 16)

            if decoded_to.lower() != request.recipient.lower():
                continue

            if decoded_amount != int(request.amount):
                continue

            if expected_memo:
                if len(call_data_hex) < 200:
                    continue
                decoded_memo = "0x" + call_data_hex[136:200]
                memo_clean = expected_memo.lower()
                if not memo_clean.startswith("0x"):
                    memo_clean = "0x" + memo_clean
                if decoded_memo.lower() != memo_clean:
                    continue

            return

        raise VerificationError("Invalid transaction: no matching payment call found")

    def _validate_transaction_payload(self, signature: str, request: ChargeRequest) -> None:
        """Validate that a signed transaction contains the expected call.

        Deserializes the transaction and checks that it contains a call to the
        expected currency contract with the correct function selector and
        parameters.

        This is a security enhancement to reject malicious transactions before
        broadcasting. If decoding fails, we skip validation and rely on
        post-broadcast log verification as the fallback.

        Args:
            signature: The signed transaction hex (0x76-prefixed for Tempo).
            request: The charge request with expected parameters.

        Raises:
            VerificationError: If the transaction decodes successfully but
                doesn't match expected parameters.
        """
        try:
            import rlp
        except ImportError:
            return

        try:
            tx_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
        except ValueError:
            return

        if not tx_bytes or tx_bytes[0] != 0x76:
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

        expected_memo = request.methodDetails.memo

        for call_item in calls_data:
            if not isinstance(call_item, (list, tuple)) or len(call_item) < 3:
                continue

            call_to_bytes = call_item[0]
            call_data_bytes = call_item[2]

            if not call_to_bytes or not call_data_bytes:
                continue

            call_to = (
                "0x" + call_to_bytes.hex()
                if isinstance(call_to_bytes, bytes)
                else str(call_to_bytes)
            )
            call_data = (
                call_data_bytes.hex()
                if isinstance(call_data_bytes, bytes)
                else str(call_data_bytes)
            )

            if call_to.lower() != request.currency.lower():
                continue

            if len(call_data) < 8:
                continue

            selector = call_data[:8].lower()

            if expected_memo:
                if selector != TRANSFER_WITH_MEMO_SELECTOR:
                    continue
            elif selector not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR):
                continue

            if len(call_data) < 136:
                continue
            decoded_to = "0x" + call_data[32:72]
            decoded_amount = int(call_data[72:136], 16)

            if decoded_to.lower() != request.recipient.lower():
                continue

            if decoded_amount != int(request.amount):
                continue

            if expected_memo:
                if len(call_data) < 200:
                    continue
                decoded_memo = "0x" + call_data[136:200]
                memo_clean = expected_memo.lower()
                if not memo_clean.startswith("0x"):
                    memo_clean = "0x" + memo_clean
                if decoded_memo.lower() != memo_clean:
                    continue

            return

        raise VerificationError("Invalid transaction: no matching payment call found")
