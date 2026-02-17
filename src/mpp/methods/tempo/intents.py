"""Tempo payment intents (server-side verification).

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpp import Credential, Receipt
from mpp.methods.tempo._defaults import DEFAULT_FEE_PAYER_URL
from mpp.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    TransactionCredentialPayload,
)
from mpp.server.intent import VerificationError

if TYPE_CHECKING:
    import httpx


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
TRANSFER_WITH_MEMO_SELECTOR = "b452ef41"  # keccak256("transferWithMemo(...)")[:4]

# Event topic hashes
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_MEMO_TOPIC = "0x97e41cc1bb1f9e89199e4cb296a2ce65e20810e029dbbf3e3b46096f31e4fb48"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


# ──────────────────────────────────────────────────────────────────
# Charge intent
# ──────────────────────────────────────────────────────────────────


class ChargeIntent:
    """Tempo charge intent for one-time payments.

    Verifies that a payment transaction matches the requested parameters.

    When used via ``tempo()``, the ``rpc_url`` is propagated automatically
    from the method level. You can also pass it directly for standalone use.

    This class manages an HTTP client lifecycle. Use as an async context manager
    for automatic cleanup, or call `aclose()` explicitly when done.

    Example:
        from mpp.methods.tempo import tempo, ChargeIntent

        # rpc_url propagated from tempo()
        method = tempo(
            rpc_url="https://rpc.tempo.xyz",
            intents={"charge": ChargeIntent()},
        )

        # Or standalone
        intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")
    """

    name = "charge"

    def __init__(
        self,
        rpc_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the charge intent.

        Args:
            rpc_url: Tempo RPC endpoint URL. If not set, will be inherited
                from the ``tempo()`` factory.
            http_client: Optional httpx client for making RPC calls. If provided,
                the caller is responsible for closing it.
            timeout: Request timeout in seconds (default: 30).
        """
        self.rpc_url = rpc_url
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

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
                data = log.get("data", "0x")
                if len(data) < 130:
                    continue
                amount = int(data[2:66], 16)
                memo = "0x" + data[66:130]
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
        = True), forwards to fee payer service. For regular transactions,
        submits directly.
        """
        self._validate_transaction_payload(payload.signature, request)

        client = await self._get_client()

        if request.methodDetails.feePayer:
            fee_payer_url = request.methodDetails.feePayerUrl or DEFAULT_FEE_PAYER_URL
            response = await client.post(
                fee_payer_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [payload.signature],
                    "id": 1,
                },
            )
        else:
            response = await client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [payload.signature],
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
