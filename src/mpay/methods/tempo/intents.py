"""Tempo payment intents (server-side verification).

Implements the charge and stream intents for Tempo payments.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpay import Credential, Receipt
from mpay.methods.tempo._defaults import DEFAULT_FEE_PAYER_URL, RPC_URL
from mpay.methods.tempo.schemas import (
    ChargeRequest,
    CredentialPayload,
    HashCredentialPayload,
    TransactionCredentialPayload,
)
from mpay.methods.tempo.stream.chain import (
    broadcast_open_transaction,
    broadcast_top_up_transaction,
    close_on_chain,
    get_on_chain_channel,
    settle_on_chain,
)
from mpay.methods.tempo.stream.errors import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelConflictError,
    ChannelNotFoundError,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
    StreamError,
)
from mpay.methods.tempo.stream.receipt import create_stream_receipt
from mpay.methods.tempo.stream.storage import ChannelState, SessionState
from mpay.methods.tempo.stream.voucher import (
    parse_voucher_from_payload,
    verify_voucher,
)
from mpay.server.intent import VerificationError

if TYPE_CHECKING:
    import httpx

    from mpay.methods.tempo.account import TempoAccount
    from mpay.methods.tempo.stream.chain import OnChainChannel
    from mpay.methods.tempo.stream.storage import ChannelStorage
    from mpay.methods.tempo.stream.types import SignedVoucher, StreamReceipt


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
TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
TRANSFER_WITH_MEMO_TOPIC = (
    "0x97e41cc1bb1f9e89199e4cb296a2ce65e20810e029dbbf3e3b46096f31e4fb48"
)

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


# ──────────────────────────────────────────────────────────────────
# Charge intent
# ──────────────────────────────────────────────────────────────────


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
                request={"amount": "1000", "currency": "0x...", ...},
            )

        # Or with external client
        async with httpx.AsyncClient() as client:
            intent = ChargeIntent(rpc_url="...", http_client=client)
            receipt = await intent.verify(...)
    """

    name = "charge"

    def __init__(
        self,
        rpc_url: str = RPC_URL,
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
            raise VerificationError(
                f"Invalid credential type: {payload_data['type']}"
            )

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
                "Transaction must contain a Transfer log "
                "matching request parameters"
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

            if (
                expected_sender
                and from_address.lower() != expected_sender.lower()
            ):
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
                if (
                    amount == int(request.amount)
                    and memo.lower() == memo_clean
                ):
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
            fee_payer_url = (
                request.methodDetails.feePayerUrl or DEFAULT_FEE_PAYER_URL
            )
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
                error_msg = (
                    error_obj.get("message")
                    or error_obj.get("name")
                    or str(error_obj)
                )
                error_data = error_obj.get("data", "")
            else:
                error_msg = str(error_obj)
                error_data = ""
            full_error = (
                f"{error_msg}: {error_data}" if error_data else error_msg
            )
            raise VerificationError(
                f"Transaction submission failed: {full_error}"
            )

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
                raise VerificationError(
                    "Failed to fetch transaction receipt"
                )

            receipt_data = receipt_result.get("result")
            if receipt_data:
                break

            if attempt < MAX_RECEIPT_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RECEIPT_RETRY_DELAY_SECONDS)

        if not receipt_data:
            raise VerificationError(
                "Transaction receipt not found after retries"
            )

        if receipt_data.get("status") != "0x1":
            raise VerificationError("Transaction reverted")

        if not self._verify_transfer_logs(receipt_data, request):
            raise VerificationError(
                "Transaction must contain a Transfer log "
                "matching request parameters"
            )

        return Receipt.success(tx_hash)

    def _validate_transaction_payload(
        self, signature: str, request: ChargeRequest
    ) -> None:
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
            tx_bytes = bytes.fromhex(
                signature[2:] if signature.startswith("0x") else signature
            )
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
        expected_selector = (
            TRANSFER_WITH_MEMO_SELECTOR if expected_memo else TRANSFER_SELECTOR
        )

        for call_item in calls_data:
            if (
                not isinstance(call_item, (list, tuple))
                or len(call_item) < 3
            ):
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
            if selector != expected_selector:
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

        raise VerificationError(
            "Invalid transaction: no matching payment call found"
        )


# ──────────────────────────────────────────────────────────────────
# Stream intent
# ──────────────────────────────────────────────────────────────────


@dataclass
class StreamIntent:
    """Server-side stream payment intent.

    Verifies stream credentials and manages channel/session state.

    Example::

        from mpay.methods.tempo.stream import MemoryStorage
        from mpay.methods.tempo import StreamIntent

        storage = MemoryStorage()
        intent = StreamIntent(
            storage=storage,
            rpc_url="https://rpc.tempo.xyz",
            escrow_contract="0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70",
        )
    """

    name: str = "stream"

    storage: ChannelStorage = None  # type: ignore[assignment]
    rpc_url: str = RPC_URL
    escrow_contract: str = ""
    chain_id: int = 42431
    min_voucher_delta: int = 0
    fee_payer: TempoAccount | None = None
    account: TempoAccount | None = None  # Server account for settle/close

    def __post_init__(self) -> None:
        if self.storage is None:
            raise ValueError(
                "storage is required for StreamIntent. "
                "Use MemoryStorage() for single-process servers."
            )

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify a stream credential.

        Dispatches to the appropriate handler based on the credential
        payload's ``action`` field.

        Args:
            credential: The credential to verify.
            request: The challenge request parameters.

        Returns:
            A Receipt containing the StreamReceipt data.

        Raises:
            StreamError: On verification failure.
        """
        payload = credential.payload
        action = payload.get("action")

        challenge = credential.challenge
        method_details = _get_method_details(challenge, self)

        resolved_fee_payer = (
            self.fee_payer if method_details.get("feePayer") else None
        )
        effective_min_delta = (
            int(method_details["minVoucherDelta"])
            if method_details.get("minVoucherDelta")
            else self.min_voucher_delta
        )

        if action == "open":
            stream_receipt = await _handle_open(
                self.storage,
                self.rpc_url,
                challenge,
                payload,
                method_details,
                resolved_fee_payer,
                request,
            )
        elif action == "topUp":
            stream_receipt = await _handle_top_up(
                self.storage,
                self.rpc_url,
                challenge,
                payload,
                method_details,
                resolved_fee_payer,
            )
        elif action == "voucher":
            stream_receipt = await _handle_voucher(
                self.storage,
                self.rpc_url,
                effective_min_delta,
                challenge,
                payload,
                method_details,
            )
        elif action == "close":
            stream_receipt = await _handle_close(
                self.storage,
                self.rpc_url,
                challenge,
                payload,
                method_details,
                self.account,
            )
        else:
            raise StreamError(f"unknown action: {action}")

        return Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference=stream_receipt.channel_id,
            extra=stream_receipt.to_dict(),
        )


def _get_method_details(
    challenge: Any,
    intent: StreamIntent,
) -> dict[str, Any]:
    """Extract methodDetails from challenge, falling back to intent."""
    if hasattr(challenge, "request"):
        req = (
            challenge.request
            if isinstance(challenge.request, dict)
            else {}
        )
    elif isinstance(challenge, dict):
        req = challenge.get("request", {})
    else:
        req = {}

    md = req.get("methodDetails", {})
    if not isinstance(md, dict):
        md = {}

    return {
        "escrowContract": md.get(
            "escrowContract", intent.escrow_contract
        ),
        "chainId": md.get("chainId", intent.chain_id),
        "channelId": md.get("channelId"),
        "minVoucherDelta": md.get("minVoucherDelta"),
        "feePayer": md.get("feePayer"),
    }


# ──────────────────────────────────────────────────────────────────
# Stream public helpers: charge() and settle()
# ──────────────────────────────────────────────────────────────────


async def charge(
    storage: ChannelStorage,
    challenge_id: str,
    amount: int,
) -> SessionState:
    """Charge against an active session's balance.

    Args:
        storage: Channel storage backend.
        challenge_id: The session/challenge ID.
        amount: Amount to charge (base units).

    Returns:
        Updated session state.

    Raises:
        InsufficientBalanceError: If available balance < amount.
        ChannelClosedError: If session not found.
    """
    session = await storage.update_session(
        challenge_id,
        lambda current: _charge_update(current, amount),
    )
    if session is None:
        raise ChannelClosedError("session not found")
    return session


def _charge_update(
    current: SessionState | None, amount: int
) -> SessionState | None:
    if current is None:
        return None
    available = current.accepted_cumulative - current.spent
    if available < amount:
        raise InsufficientBalanceError(
            f"requested {amount}, available {available}"
        )
    return replace(
        current, spent=current.spent + amount, units=current.units + 1
    )


async def settle(
    storage: ChannelStorage,
    rpc_url: str,
    escrow_contract: str,
    channel_id: str,
    account: TempoAccount,
) -> str:
    """One-shot settle: submit highest voucher on-chain.

    Args:
        storage: Channel storage backend.
        rpc_url: Tempo RPC endpoint.
        escrow_contract: Escrow contract address.
        channel_id: Channel to settle.
        account: Server account for signing the settle transaction.

    Returns:
        Transaction hash.
    """
    channel = await storage.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    if channel.highest_voucher is None:
        raise StreamError("no voucher to settle")

    settled_amount = channel.highest_voucher.cumulative_amount
    tx_hash = await settle_on_chain(
        rpc_url, escrow_contract, channel.highest_voucher, account
    )

    await storage.update_channel(
        channel_id,
        lambda current: _settle_update(current, settled_amount),
    )
    return tx_hash


def _settle_update(
    current: ChannelState | None, settled_amount: int
) -> ChannelState | None:
    if current is None:
        return None
    next_settled = max(settled_amount, current.settled_on_chain)
    return replace(current, settled_on_chain=next_settled)


# ──────────────────────────────────────────────────────────────────
# Stream shared voucher verification
# ──────────────────────────────────────────────────────────────────


def _validate_voucher(
    voucher: SignedVoucher,
    on_chain: OnChainChannel,
    authorized_signer: str,
    method_details: dict[str, Any],
) -> None:
    """Validate voucher bounds and signature.

    Raises:
        ChannelClosedError: If the channel is finalized.
        StreamError: If voucher amount is below settled amount.
        AmountExceedsDepositError: If voucher amount exceeds deposit.
        InvalidSignatureError: If the EIP-712 signature doesn't match.
    """
    if on_chain.finalized:
        raise ChannelClosedError("channel is finalized on-chain")
    if voucher.cumulative_amount < on_chain.settled:
        raise StreamError(
            "voucher cumulativeAmount is below on-chain settled amount"
        )
    if voucher.cumulative_amount > on_chain.deposit:
        raise AmountExceedsDepositError(
            "voucher amount exceeds on-chain deposit"
        )
    is_valid = verify_voucher(
        method_details["escrowContract"],
        method_details["chainId"],
        voucher,
        authorized_signer,
    )
    if not is_valid:
        raise InvalidSignatureError("invalid voucher signature")


async def _accept_voucher(
    storage: ChannelStorage,
    challenge_id: str,
    channel_id: str,
    accepted_cumulative: int,
) -> SessionState | None:
    """Atomically upsert a session with a new acceptedCumulative.

    Safe under concurrent requests: cumulative semantics mean the highest
    acceptedCumulative always wins.
    """

    def update(existing: SessionState | None) -> SessionState | None:
        base = existing or SessionState(
            challenge_id=challenge_id,
            channel_id=channel_id,
            accepted_cumulative=0,
            spent=0,
            units=0,
            created_at=datetime.now(UTC),
        )
        next_accepted = max(accepted_cumulative, base.accepted_cumulative)
        return replace(base, accepted_cumulative=next_accepted)

    return await storage.update_session(challenge_id, update)


def _validate_on_chain_channel(
    on_chain: OnChainChannel,
    recipient: str,
    currency: str,
    amount: int | None = None,
) -> None:
    """Validate on-chain channel state matches server expectations."""
    if on_chain.deposit == 0:
        raise ChannelNotFoundError("channel not funded on-chain")
    if on_chain.finalized:
        raise ChannelClosedError("channel is finalized on-chain")
    if on_chain.payee.lower() != recipient.lower():
        raise StreamError(
            "on-chain payee does not match server destination"
        )
    if on_chain.token.lower() != currency.lower():
        raise StreamError("on-chain token does not match server token")
    if amount is not None and on_chain.deposit - on_chain.settled < amount:
        raise InsufficientBalanceError(
            "channel available balance insufficient for requested amount"
        )


async def _verify_and_accept_voucher(
    storage: ChannelStorage,
    rpc_url: str,
    min_voucher_delta: int,
    challenge: Any,
    channel: ChannelState,
    channel_id: str,
    voucher: SignedVoucher,
    on_chain: OnChainChannel,
    method_details: dict[str, Any],
) -> StreamReceipt:
    """Shared logic for verifying an incremental voucher.

    Updates channel state and creates/updates the session.
    """
    challenge_id = (
        challenge.id if hasattr(challenge, "id") else challenge["id"]
    )

    if on_chain.finalized:
        raise ChannelClosedError("channel is finalized on-chain")

    if voucher.cumulative_amount < on_chain.settled:
        raise StreamError(
            "voucher cumulativeAmount is below on-chain settled amount"
        )

    if voucher.cumulative_amount > on_chain.deposit:
        raise AmountExceedsDepositError(
            "voucher amount exceeds on-chain deposit"
        )

    # Non-increasing voucher -> idempotent: return current highest
    if voucher.cumulative_amount <= channel.highest_voucher_amount:
        session = await _accept_voucher(
            storage,
            challenge_id,
            channel_id,
            channel.highest_voucher_amount,
        )
        if session is None:
            raise StreamError("failed to create session")
        return create_stream_receipt(
            challenge_id=challenge_id,
            channel_id=channel_id,
            accepted_cumulative=channel.highest_voucher_amount,
            spent=session.spent,
            units=session.units,
        )

    delta = voucher.cumulative_amount - channel.highest_voucher_amount
    if delta < min_voucher_delta:
        raise DeltaTooSmallError(
            f"voucher delta {delta} below minimum {min_voucher_delta}"
        )

    _validate_voucher(
        voucher, on_chain, channel.authorized_signer, method_details
    )

    # Update channel with new highest voucher (atomic)
    await storage.update_channel(
        channel_id,
        lambda current: _update_highest_voucher(
            current, voucher, on_chain.deposit
        ),
    )

    session = await _accept_voucher(
        storage, challenge_id, channel_id, voucher.cumulative_amount
    )
    if session is None:
        raise StreamError("failed to create session")

    return create_stream_receipt(
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=voucher.cumulative_amount,
        spent=session.spent,
        units=session.units,
    )


def _update_highest_voucher(
    current: ChannelState | None,
    voucher: SignedVoucher,
    deposit: int,
) -> ChannelState | None:
    if current is None:
        raise ChannelNotFoundError("channel not found")
    if voucher.cumulative_amount > current.highest_voucher_amount:
        return replace(
            current,
            deposit=deposit,
            highest_voucher_amount=voucher.cumulative_amount,
            highest_voucher=voucher,
        )
    return current


# ──────────────────────────────────────────────────────────────────
# Stream action handlers
# ──────────────────────────────────────────────────────────────────


async def _handle_open(
    storage: ChannelStorage,
    rpc_url: str,
    challenge: Any,
    payload: dict[str, Any],
    method_details: dict[str, Any],
    fee_payer: TempoAccount | None,
    request: dict[str, Any],
) -> StreamReceipt:
    """Handle 'open' action: broadcast open tx, verify voucher, create channel."""
    challenge_id = (
        challenge.id if hasattr(challenge, "id") else challenge["id"]
    )
    channel_id = payload["channelId"]

    voucher = parse_voucher_from_payload(
        channel_id, payload["cumulativeAmount"], payload["signature"]
    )

    # Get recipient and currency from challenge request.
    # challenge.request may be a base64 string (ChallengeEcho) or a dict.
    if hasattr(challenge, "request") and isinstance(challenge.request, dict):
        ch_request = challenge.request
    elif isinstance(challenge, dict):
        ch_request = challenge.get("request", {})
    else:
        ch_request = {}
    recipient = ch_request.get("recipient") or request.get("recipient")
    currency = ch_request.get("currency") or request.get("currency")
    if not recipient:
        raise StreamError("could not resolve recipient from challenge")
    if not currency:
        raise StreamError("could not resolve currency from challenge")
    amount_str = ch_request.get("amount", request.get("amount"))
    amount = int(amount_str) if amount_str else None

    result = await broadcast_open_transaction(
        rpc_url=rpc_url,
        serialized_transaction=payload["transaction"],
        escrow_contract=method_details["escrowContract"],
        channel_id=channel_id,
        recipient=recipient,
        currency=currency,
        fee_payer=fee_payer,
    )
    on_chain = result.on_chain

    _validate_on_chain_channel(on_chain, recipient, currency, amount)

    # Resolve authorized signer: zero address -> use payer
    authorized_signer = (
        on_chain.payer
        if on_chain.authorized_signer == ZERO_ADDRESS
        else on_chain.authorized_signer
    )

    _validate_voucher(voucher, on_chain, authorized_signer, method_details)

    session = await _accept_voucher(
        storage, challenge_id, channel_id, voucher.cumulative_amount
    )
    if session is None:
        raise StreamError("failed to create session")

    existing_channel = await storage.get_channel(channel_id)
    stale_session_id: str | None = None
    if existing_channel and existing_channel.active_session_id:
        active_session = await storage.get_session(
            existing_channel.active_session_id
        )
        if active_session is None:
            stale_session_id = existing_channel.active_session_id

    try:
        await storage.update_channel(
            channel_id,
            lambda existing: _open_channel_update(
                existing,
                challenge_id,
                stale_session_id,
                voucher,
                on_chain,
                authorized_signer,
            ),
        )
    except Exception:
        # Clean up pre-created session on conflict/failure
        await storage.update_session(challenge_id, lambda _: None)
        raise

    return create_stream_receipt(
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=voucher.cumulative_amount,
        spent=session.spent,
        units=session.units,
    )


def _open_channel_update(
    existing: ChannelState | None,
    challenge_id: str,
    stale_session_id: str | None,
    voucher: SignedVoucher,
    on_chain: OnChainChannel,
    authorized_signer: str,
) -> ChannelState:
    if existing is not None:
        # Check for concurrent stream
        if (
            existing.active_session_id
            and existing.active_session_id != challenge_id
            and existing.active_session_id != stale_session_id
        ):
            raise ChannelConflictError(
                "another stream is active on this channel"
            )

        if voucher.cumulative_amount < existing.settled_on_chain:
            raise StreamError(
                "voucher amount is below settled on-chain amount"
            )

        if voucher.cumulative_amount > existing.highest_voucher_amount:
            return replace(
                existing,
                deposit=on_chain.deposit,
                highest_voucher_amount=voucher.cumulative_amount,
                highest_voucher=voucher,
                authorized_signer=authorized_signer,
                active_session_id=challenge_id,
            )
        return replace(
            existing,
            deposit=on_chain.deposit,
            authorized_signer=authorized_signer,
            active_session_id=challenge_id,
        )

    return ChannelState(
        channel_id=voucher.channel_id,
        payer=on_chain.payer,
        payee=on_chain.payee,
        token=on_chain.token,
        authorized_signer=authorized_signer,
        deposit=on_chain.deposit,
        settled_on_chain=0,
        highest_voucher_amount=voucher.cumulative_amount,
        highest_voucher=voucher,
        active_session_id=challenge_id,
        finalized=False,
        created_at=datetime.now(UTC),
    )


async def _handle_top_up(
    storage: ChannelStorage,
    rpc_url: str,
    challenge: Any,
    payload: dict[str, Any],
    method_details: dict[str, Any],
    fee_payer: TempoAccount | None,
) -> StreamReceipt:
    """Handle 'topUp' action: broadcast topUp tx, update deposit.

    Per spec Section 8.3.2, topUp payloads contain only the transaction
    and additionalDeposit -- no voucher.
    """
    challenge_id = (
        challenge.id if hasattr(challenge, "id") else challenge["id"]
    )
    channel_id = payload["channelId"]

    channel = await storage.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")

    declared_deposit = int(payload["additionalDeposit"])

    _tx_hash, on_chain_deposit = await broadcast_top_up_transaction(
        rpc_url=rpc_url,
        serialized_transaction=payload["transaction"],
        escrow_contract=method_details["escrowContract"],
        channel_id=channel_id,
        declared_deposit=declared_deposit,
        previous_deposit=channel.deposit,
        fee_payer=fee_payer,
    )

    await storage.update_channel(
        channel_id,
        lambda current: (
            replace(current, deposit=on_chain_deposit) if current else None
        ),
    )

    session = await storage.get_session(challenge_id)

    return create_stream_receipt(
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=(
            session.accepted_cumulative
            if session
            else channel.highest_voucher_amount
        ),
        spent=session.spent if session else 0,
        units=session.units if session else 0,
    )


async def _handle_voucher(
    storage: ChannelStorage,
    rpc_url: str,
    min_voucher_delta: int,
    challenge: Any,
    payload: dict[str, Any],
    method_details: dict[str, Any],
) -> StreamReceipt:
    """Handle 'voucher' action: verify and accept a new voucher."""
    channel_id = payload["channelId"]

    channel = await storage.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    if channel.finalized:
        raise ChannelClosedError("channel is finalized")

    voucher = parse_voucher_from_payload(
        channel_id, payload["cumulativeAmount"], payload["signature"]
    )

    on_chain = await get_on_chain_channel(
        rpc_url, method_details["escrowContract"], channel_id
    )

    return await _verify_and_accept_voucher(
        storage=storage,
        rpc_url=rpc_url,
        min_voucher_delta=min_voucher_delta,
        challenge=challenge,
        channel=channel,
        channel_id=channel_id,
        voucher=voucher,
        on_chain=on_chain,
        method_details=method_details,
    )


async def _handle_close(
    storage: ChannelStorage,
    rpc_url: str,
    challenge: Any,
    payload: dict[str, Any],
    method_details: dict[str, Any],
    server_account: TempoAccount | None,
) -> StreamReceipt:
    """Handle 'close' action: verify final voucher, close channel."""
    challenge_id = (
        challenge.id if hasattr(challenge, "id") else challenge["id"]
    )
    channel_id = payload["channelId"]

    channel = await storage.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    if channel.finalized:
        raise ChannelClosedError("channel is already finalized")

    voucher = parse_voucher_from_payload(
        channel_id, payload["cumulativeAmount"], payload["signature"]
    )

    if voucher.cumulative_amount < channel.highest_voucher_amount:
        raise StreamError(
            "close voucher amount must be >= highest accepted voucher"
        )

    on_chain = await get_on_chain_channel(
        rpc_url, method_details["escrowContract"], channel_id
    )

    if on_chain.finalized:
        raise ChannelClosedError("channel is finalized on-chain")

    if voucher.cumulative_amount < on_chain.settled:
        raise StreamError(
            "close voucher cumulativeAmount is below "
            "on-chain settled amount"
        )

    if voucher.cumulative_amount > on_chain.deposit:
        raise AmountExceedsDepositError(
            "close voucher amount exceeds on-chain deposit"
        )

    is_valid = verify_voucher(
        method_details["escrowContract"],
        method_details["chainId"],
        voucher,
        channel.authorized_signer,
    )
    if not is_valid:
        raise InvalidSignatureError("invalid voucher signature")

    session = await storage.get_session(challenge_id)

    tx_hash: str | None = None
    if server_account is not None:
        tx_hash = await close_on_chain(
            rpc_url,
            method_details["escrowContract"],
            voucher,
            server_account,
        )

    await storage.update_channel(
        channel_id,
        lambda current: _close_channel_update(
            current, voucher, on_chain.deposit
        ),
    )
    await storage.update_session(challenge_id, lambda _: None)

    return create_stream_receipt(
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=voucher.cumulative_amount,
        spent=session.spent if session else 0,
        units=session.units if session else 0,
        tx_hash=tx_hash,
    )


def _close_channel_update(
    current: ChannelState | None,
    voucher: SignedVoucher,
    deposit: int,
) -> ChannelState | None:
    if current is None:
        return None
    return replace(
        current,
        deposit=deposit,
        highest_voucher_amount=voucher.cumulative_amount,
        highest_voucher=voucher,
        active_session_id=None,
        finalized=True,
    )
