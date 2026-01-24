"""Tempo payment intents.

Implements the charge intent for Tempo payments.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpay import Receipt
from mpay.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    TransactionCredentialPayload,
)
from mpay.server.intent import VerificationError

if TYPE_CHECKING:
    import httpx

    from mpay import Credential


DEFAULT_TIMEOUT = 30.0


class ChargeIntent:
    """Tempo charge intent for one-time payments.

    Verifies that a payment transaction matches the requested parameters.

    This class manages an HTTP client lifecycle. Use as an async context manager
    for automatic cleanup, or call `aclose()` explicitly when done.

    Example:
        from mpay.methods.tempo import ChargeIntent

        # As context manager (recommended)
        async with ChargeIntent(rpc_url="https://rpc.tempo.xyz") as intent:
            receipt = await intent.verify(
                credential=Credential(id="...", payload={"type": "hash", ...}),
                request={"amount": "1000", "asset": "0x...", ...},
            )

        # Or with external client
        async with httpx.AsyncClient() as client:
            intent = ChargeIntent(rpc_url="...", http_client=client)
            receipt = await intent.verify(...)
    """

    name = "charge"

    def __init__(
        self,
        rpc_url: str,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the charge intent.

        Args:
            rpc_url: Tempo RPC endpoint URL.
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
            raise VerificationError(f"RPC error: {result['error']}")

        receipt_data = result.get("result")
        if not receipt_data:
            raise VerificationError("Transaction not found")

        if receipt_data.get("status") != "0x1":
            return Receipt.failed(payload.hash)

        if not self._verify_transfer_logs(receipt_data, request):
            raise VerificationError(
                "Transaction must contain a Transfer log matching request parameters"
            )

        return Receipt.success(payload.hash)

    def _verify_transfer_logs(
        self,
        receipt: dict[str, Any],
        request: ChargeRequest,
    ) -> bool:
        """Check if receipt contains matching Transfer logs."""
        transfer_topic = (
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        )

        for log in receipt.get("logs", []):
            if log.get("address", "").lower() != request.asset.lower():
                continue

            topics = log.get("topics", [])
            if len(topics) < 3 or topics[0] != transfer_topic:
                continue

            to_address = "0x" + topics[2][-40:]
            if to_address.lower() != request.destination.lower():
                continue

            data = log.get("data", "0x")
            if len(data) >= 66:
                amount = int(data, 16)
                if str(amount) == request.amount:
                    return True

        return False

    async def _verify_transaction(
        self,
        payload: TransactionCredentialPayload,
        request: ChargeRequest,
    ) -> Receipt:
        """Verify and submit a signed transaction."""
        client = await self._get_client()

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
            raise VerificationError(f"Transaction failed: {result['error']}")

        tx_hash = result.get("result")
        if not tx_hash:
            raise VerificationError("No transaction hash returned")

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

        receipt_data = receipt_result.get("result")
        is_success = receipt_data and receipt_data.get("status") == "0x1"

        if is_success:
            return Receipt.success(tx_hash)
        return Receipt.failed(tx_hash)
