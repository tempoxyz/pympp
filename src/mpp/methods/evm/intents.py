"""EVM payment intents (server-side verification).

Implements the charge intent for standard EVM chains (e.g. Base): broadcasts
a client-signed ERC-20 transfer transaction to an EVM JSON-RPC endpoint and
confirms the mined receipt contains a matching ``Transfer`` log.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from eth_account.typed_transactions.typed_transaction import TypedTransaction
from eth_hash.auto import keccak
from hexbytes import HexBytes

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_TIMEOUT
from mpp.errors import VerificationError
from mpp.methods.evm._defaults import rpc_url_for_chain
from mpp.methods.evm._rpc import _rpc_call
from mpp.store import Store

SELECTOR_HEX_LEN = 8
ABI_WORD_HEX_LEN = 64
TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_CALL_DATA_HEX_LEN = SELECTOR_HEX_LEN + (2 * ABI_WORD_HEX_LEN)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

RECEIPT_POLL_INTERVAL = 1.0


class ChargeIntent:
    """EVM charge intent for one-time payments.

    Verifies that a client-signed ERC-20 transfer transaction matches the
    requested amount/currency/recipient, broadcasts it, and confirms the
    mined receipt contains a matching ``Transfer`` log.

    When used via ``evm()``, ``rpc_url`` is read from the parent method
    automatically. You can also pass ``rpc_url``/``chain_id`` directly for
    standalone use.

    Example:
        from mpp.methods.evm import evm, ChargeIntent, BASE_CHAIN_ID

        method = evm(chain_id=BASE_CHAIN_ID, intents={"charge": ChargeIntent()})

        # Or standalone
        intent = ChargeIntent(chain_id=BASE_CHAIN_ID)
    """

    name = "charge"

    def __init__(
        self,
        chain_id: int | None = None,
        rpc_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        store: Store | None = None,
    ) -> None:
        """Initialize the charge intent.

        Args:
            chain_id: EVM chain ID (8453 for Base mainnet, 84532 for Base
                Sepolia). Resolves the RPC URL automatically.
            rpc_url: EVM JSON-RPC endpoint URL. Overrides ``chain_id``. If
                neither is set, will be inherited from ``evm()``.
            timeout: Request timeout in seconds, also used as the deadline
                for waiting on a transaction receipt.
            store: Optional key-value store for tx hash replay protection.
                When provided, each broadcast hash is recorded and
                subsequent attempts to reuse it are rejected.
        """
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self._method = None
        self._timeout = timeout
        self._store = store

    def _get_rpc_url(self) -> str:
        if self.rpc_url is None:
            raise VerificationError("No rpc_url configured on ChargeIntent")
        return self.rpc_url

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify a charge credential and settle it on-chain.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A receipt for the settled payment.

        Raises:
            VerificationError: If verification fails or the transaction
                hash was already used.
        """
        amount = int(request["amount"])
        currency = request["currency"]
        recipient = request["recipient"]

        challenge_expires = credential.challenge.expires
        if not challenge_expires:
            raise VerificationError("Request has expired (no expires)")
        expires = datetime.fromisoformat(challenge_expires.replace("Z", "+00:00"))
        if expires < datetime.now(UTC):
            raise VerificationError("Request has expired")

        payload = credential.payload
        if not isinstance(payload, dict) or payload.get("type") != "transaction":
            raise VerificationError("Invalid credential payload")
        raw_tx = payload.get("signature")
        if not isinstance(raw_tx, str):
            raise VerificationError("Invalid credential payload")

        tx_hash = self._validate_transaction(
            raw_tx, currency=currency, recipient=recipient, amount=amount
        )

        store_key = f"mpp:evm:charge:{tx_hash.lower()}"
        if self._store is not None and not await self._store.put_if_absent(store_key, tx_hash):
            raise VerificationError("Transaction hash already used")

        try:
            receipt_data = await self._broadcast(raw_tx, tx_hash)
            self._verify_receipt_transfer(
                receipt_data, currency=currency, recipient=recipient, amount=amount
            )
        except Exception:
            if self._store is not None:
                await self._store.delete(store_key)
            raise

        return Receipt.success(tx_hash, method="evm")

    def _validate_transaction(
        self,
        raw_tx: str,
        *,
        currency: str,
        recipient: str,
        amount: int,
    ) -> str:
        """Decode the signed transaction and check it matches the request.

        Returns:
            The transaction hash (0x-prefixed hex).
        """
        try:
            decoded_tx = TypedTransaction.from_bytes(HexBytes(raw_tx))
            decoded = decoded_tx.as_dict()
        except Exception as err:
            raise VerificationError("Invalid serialized transaction") from err

        to_address = "0x" + decoded["to"].hex()
        if to_address.lower() != currency.lower():
            raise VerificationError("Invalid transaction: does not call the expected currency")
        if decoded.get("value"):
            raise VerificationError("Invalid transaction: must not transfer native value")

        call_data_hex = decoded["data"].hex()
        if len(call_data_hex) != TRANSFER_CALL_DATA_HEX_LEN:
            raise VerificationError("Invalid transaction: unexpected call data")
        if call_data_hex[:SELECTOR_HEX_LEN].lower() != TRANSFER_SELECTOR:
            raise VerificationError("Invalid transaction: not an ERC-20 transfer")

        decoded_to = (
            "0x" + call_data_hex[SELECTOR_HEX_LEN : SELECTOR_HEX_LEN + ABI_WORD_HEX_LEN][-40:]
        )
        decoded_amount = int(call_data_hex[SELECTOR_HEX_LEN + ABI_WORD_HEX_LEN :], 16)

        if decoded_to.lower() != recipient.lower():
            raise VerificationError("Invalid transaction: recipient does not match request")
        if decoded_amount != amount:
            raise VerificationError("Invalid transaction: amount does not match request")

        # NOTE: TypedTransaction.hash() returns the pre-signature signing
        # hash, not the on-chain transaction hash. The transaction hash used
        # to identify a broadcast tx is keccak256 of the full signed,
        # type-prefixed transaction bytes (EIP-2718).
        return "0x" + keccak(HexBytes(raw_tx)).hex()

    async def _broadcast(self, raw_tx: str, tx_hash: str) -> dict[str, Any]:
        """Submit the raw transaction and poll until it is mined."""
        rpc_url = self._get_rpc_url()

        try:
            await _rpc_call(rpc_url, "eth_sendRawTransaction", [raw_tx])
        except RuntimeError as err:
            message = str(err).lower()
            if "already known" not in message and "nonce too low" not in message:
                raise VerificationError(f"Transaction submission failed: {err}") from err

        deadline = time.monotonic() + self._timeout
        while True:
            receipt_data = await _rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
            if receipt_data:
                return receipt_data
            if time.monotonic() >= deadline:
                raise VerificationError("Timed out waiting for transaction receipt")
            await asyncio.sleep(RECEIPT_POLL_INTERVAL)

    def _verify_receipt_transfer(
        self,
        receipt_data: dict[str, Any],
        *,
        currency: str,
        recipient: str,
        amount: int,
    ) -> None:
        if receipt_data.get("status") != "0x1":
            raise VerificationError("Transaction reverted")

        for log in receipt_data.get("logs", []):
            if log.get("address", "").lower() != currency.lower():
                continue
            topics = log.get("topics", [])
            if len(topics) < 3 or topics[0].lower() != TRANSFER_TOPIC:
                continue
            to_address = "0x" + topics[2][-40:]
            if to_address.lower() != recipient.lower():
                continue
            data = log.get("data", "0x")
            if len(data) < 66:
                continue
            if int(data, 16) == amount:
                return

        raise VerificationError(
            "Transaction must contain a Transfer log matching request parameters"
        )
