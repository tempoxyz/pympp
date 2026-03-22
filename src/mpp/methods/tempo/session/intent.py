"""Tempo session intent for pay-as-you-go payment channels.

Handles the full channel lifecycle: open, voucher, topUp, close.
Ported from mpp-rs ``session_method.rs``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mpp import Credential, Receipt
from mpp.errors import VerificationError
from mpp.methods.tempo._defaults import (
    ESCROW_CONTRACTS,
    TESTNET_CHAIN_ID,
    rpc_url_for_chain,
)
from mpp.methods.tempo.session.chain import (
    broadcast_and_confirm,
    get_on_chain_channel,
)
from mpp.methods.tempo.session.storage import ChannelStore, MemoryChannelStore
from mpp.methods.tempo.session.types import (
    ChannelState,
    ClosePayload,
    OpenPayload,
    SessionMethodDetails,
    TopUpPayload,
    VoucherPayload,
    parse_session_payload,
)
from mpp.methods.tempo.session.voucher import verify_voucher

if TYPE_CHECKING:
    import httpx

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEFAULT_TIMEOUT = 30.0


def _parse_uint(value: str, name: str = "amount") -> int:
    """Parse a string as a non-negative integer, raising VerificationError."""
    try:
        n = int(value)
    except (ValueError, TypeError) as e:
        raise VerificationError(f"invalid {name}: {value}") from e
    if n < 0:
        raise VerificationError(f"invalid {name}: must be non-negative, got {n}")
    return n


class SessionIntent:
    """Tempo session intent for pay-as-you-go payment channels.

    Implements the ``Intent`` protocol (``name`` + ``verify``).

    Example::

        from mpp.methods.tempo import tempo, SessionIntent
        from mpp.methods.tempo.session import MemoryChannelStore

        mpp = Mpp.create(
            method=tempo(
                intents={"session": SessionIntent(
                    store=MemoryChannelStore(),
                    rpc_url="https://rpc.tempo.xyz",
                )},
            ),
        )

        @app.get("/session")
        @mpp.pay(amount="0.000075", intent="session")
        async def handler(request, credential, receipt):
            return {"data": "paid content"}
    """

    name = "session"

    def __init__(
        self,
        store: ChannelStore | None = None,
        rpc_url: str | None = None,
        chain_id: int | None = None,
        escrow_contract: str | None = None,
        min_voucher_delta: int = 0,
        close_signer_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if rpc_url is None and chain_id is not None:
            rpc_url = rpc_url_for_chain(chain_id)
        self.rpc_url = rpc_url
        self.chain_id = chain_id or TESTNET_CHAIN_ID
        self.escrow_contract = escrow_contract or ESCROW_CONTRACTS.get(self.chain_id)
        self.min_voucher_delta = min_voucher_delta
        self.close_signer_key = close_signer_key
        self.store: ChannelStore = store or MemoryChannelStore()
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

    async def __aenter__(self) -> SessionIntent:
        await self._get_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _get_rpc_url(self) -> str:
        if self.rpc_url is None:
            raise VerificationError("No rpc_url configured on SessionIntent")
        return self.rpc_url

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    # ── config resolution ───────────────────────────────────────

    def _resolve_details(
        self, request: dict[str, Any]
    ) -> tuple[str, int, int]:
        """Resolve (escrow, chain_id, min_delta) from request methodDetails with config fallback.

        Mirrors mpp-rs ``resolve_method_details`` / ``resolve_escrow`` / ``resolve_chain_id``.
        """
        method_details = request.get("methodDetails")
        if method_details and isinstance(method_details, dict):
            details = SessionMethodDetails.model_validate(method_details)
        else:
            details = None

        escrow = (
            (details.escrow_contract if details else None)
            or self.escrow_contract
        )
        if escrow is None:
            raise VerificationError("No escrow_contract configured")

        chain_id = (
            (details.chain_id if details else None)
            or self.chain_id
        )

        min_delta = self.min_voucher_delta
        if details and details.min_voucher_delta is not None:
            min_delta = _parse_uint(details.min_voucher_delta, "minVoucherDelta")

        return escrow, chain_id, min_delta

    # ── verify (entry point) ─────────────────────────────────────

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        payload_data = credential.payload
        if not isinstance(payload_data, dict) or "action" not in payload_data:
            raise VerificationError("Invalid session credential payload")

        payload = parse_session_payload(payload_data)
        escrow, chain_id, min_delta = self._resolve_details(request)

        match payload:
            case OpenPayload():
                return await self._handle_open(payload, escrow, chain_id)
            case VoucherPayload():
                return await self._handle_voucher(payload, escrow, chain_id, min_delta)
            case TopUpPayload():
                return await self._handle_top_up(payload, escrow)
            case ClosePayload():
                return await self._handle_close(payload, escrow, chain_id)

    # ── handle_open ──────────────────────────────────────────────

    async def _handle_open(
        self,
        payload: OpenPayload,
        escrow: str,
        chain_id: int,
    ) -> Receipt:
        client = await self._get_client()
        rpc_url = self._get_rpc_url()

        tx_hash = await broadcast_and_confirm(client, rpc_url, payload.transaction)

        on_chain = await get_on_chain_channel(
            client, rpc_url, escrow, payload.channel_id
        )

        if on_chain.deposit == 0:
            raise VerificationError("channel not funded on-chain")
        if on_chain.finalized:
            raise VerificationError("channel is finalized on-chain")
        if on_chain.close_requested_at != 0:
            raise VerificationError("channel has a pending close request")

        authorized_signer = (
            on_chain.payer
            if on_chain.authorized_signer == ZERO_ADDRESS
            else on_chain.authorized_signer
        )

        cumulative_amount = _parse_uint(payload.cumulative_amount, "cumulativeAmount")

        if cumulative_amount > on_chain.deposit:
            raise VerificationError("voucher amount exceeds on-chain deposit")
        if cumulative_amount < on_chain.settled:
            raise VerificationError(
                "voucher cumulativeAmount is below on-chain settled amount"
            )

        sig_bytes = _parse_signature(payload.signature)
        if not verify_voucher(
            escrow,
            chain_id,
            payload.channel_id,
            cumulative_amount,
            sig_bytes,
            authorized_signer,
        ):
            raise VerificationError("invalid voucher signature")

        channel_id = payload.channel_id

        def _updater(existing: ChannelState | None) -> ChannelState | None:
            if existing is not None:
                if cumulative_amount > existing.highest_voucher_amount:
                    return replace(
                        existing,
                        deposit=on_chain.deposit,
                        highest_voucher_amount=cumulative_amount,
                        highest_voucher_signature=sig_bytes,
                        authorized_signer=authorized_signer,
                    )
                return replace(
                    existing,
                    deposit=on_chain.deposit,
                    authorized_signer=authorized_signer,
                )
            return ChannelState(
                channel_id=channel_id,
                chain_id=chain_id,
                escrow_contract=escrow,
                payer=on_chain.payer,
                payee=on_chain.payee,
                token=on_chain.token,
                authorized_signer=authorized_signer,
                deposit=on_chain.deposit,
                settled_on_chain=on_chain.settled,
                highest_voucher_amount=cumulative_amount,
                highest_voucher_signature=sig_bytes,
                created_at=datetime.now(UTC).isoformat(),
            )

        updated = await self.store.update_channel(channel_id, _updater)
        if updated is None:
            raise VerificationError("failed to create channel")

        return Receipt.success(tx_hash)

    # ── handle_voucher ───────────────────────────────────────────

    async def _handle_voucher(
        self,
        payload: VoucherPayload,
        escrow: str,
        chain_id: int,
        min_delta: int,
    ) -> Receipt:
        channel = await self.store.get_channel(payload.channel_id)
        if channel is None:
            raise VerificationError("channel not found")
        if channel.finalized:
            raise VerificationError("channel is finalized")

        cumulative_amount = _parse_uint(payload.cumulative_amount, "cumulativeAmount")

        # Use cached channel state (no RPC per voucher — critical for performance).
        return await self._verify_and_accept_voucher(
            channel_id=payload.channel_id,
            channel=channel,
            cumulative_amount=cumulative_amount,
            signature_str=payload.signature,
            escrow=escrow,
            chain_id=chain_id,
            min_delta=min_delta,
            deposit=channel.deposit,
            settled=channel.settled_on_chain,
            finalized=False,
            close_requested_at=0,
        )

    # ── handle_top_up ────────────────────────────────────────────

    async def _handle_top_up(
        self,
        payload: TopUpPayload,
        escrow: str,
    ) -> Receipt:
        channel = await self.store.get_channel(payload.channel_id)
        if channel is None:
            raise VerificationError("channel not found")

        client = await self._get_client()
        rpc_url = self._get_rpc_url()

        await broadcast_and_confirm(client, rpc_url, payload.transaction)

        on_chain = await get_on_chain_channel(
            client, rpc_url, escrow, payload.channel_id
        )

        if on_chain.deposit <= channel.deposit:
            raise VerificationError("channel deposit did not increase after topUp")

        new_deposit = on_chain.deposit

        def _updater(current: ChannelState | None) -> ChannelState | None:
            if current is None:
                raise VerificationError("channel not found")
            return replace(current, deposit=new_deposit)

        updated = await self.store.update_channel(payload.channel_id, _updater)
        state = updated if updated is not None else channel
        return Receipt.success(state.channel_id)

    # ── handle_close ─────────────────────────────────────────────

    async def _handle_close(
        self,
        payload: ClosePayload,
        escrow: str,
        chain_id: int,
    ) -> Receipt:
        channel = await self.store.get_channel(payload.channel_id)
        if channel is None:
            raise VerificationError("channel not found")
        if channel.finalized:
            raise VerificationError("channel is already finalized")

        cumulative_amount = _parse_uint(payload.cumulative_amount, "cumulativeAmount")

        if cumulative_amount < channel.highest_voucher_amount:
            raise VerificationError(
                "close voucher amount must be >= highest accepted voucher"
            )

        client = await self._get_client()
        rpc_url = self._get_rpc_url()

        on_chain = await get_on_chain_channel(
            client, rpc_url, escrow, payload.channel_id
        )

        if on_chain.finalized:
            raise VerificationError("channel is finalized on-chain")
        if cumulative_amount < on_chain.settled:
            raise VerificationError(
                "close voucher cumulativeAmount is below on-chain settled amount"
            )
        if cumulative_amount > on_chain.deposit:
            raise VerificationError("close voucher amount exceeds on-chain deposit")

        sig_bytes = _parse_signature(payload.signature)
        if not verify_voucher(
            escrow,
            chain_id,
            payload.channel_id,
            cumulative_amount,
            sig_bytes,
            channel.authorized_signer,
        ):
            raise VerificationError("invalid voucher signature")

        close_tx_hash: str | None = None
        if self.close_signer_key is not None:
            close_tx_hash = await self._submit_close_tx(
                client, rpc_url, escrow, payload.channel_id,
                cumulative_amount, sig_bytes, chain_id,
            )

        def _updater(current: ChannelState | None) -> ChannelState | None:
            if current is None:
                return None
            return replace(
                current,
                deposit=on_chain.deposit,
                highest_voucher_amount=cumulative_amount,
                highest_voucher_signature=sig_bytes,
                finalized=True,
            )

        updated = await self.store.update_channel(payload.channel_id, _updater)

        reference = close_tx_hash
        if reference is None:
            reference = (
                updated.channel_id
                if updated is not None
                else channel.channel_id
            )
        return Receipt.success(reference)

    # ── _verify_and_accept_voucher (shared voucher logic) ──────

    async def _verify_and_accept_voucher(
        self,
        channel_id: str,
        channel: ChannelState,
        cumulative_amount: int,
        signature_str: str,
        escrow: str,
        chain_id: int,
        min_delta: int,
        deposit: int,
        settled: int,
        finalized: bool,
        close_requested_at: int,
    ) -> Receipt:
        if finalized:
            raise VerificationError("channel is finalized on-chain")
        if close_requested_at != 0:
            raise VerificationError("channel has a pending close request")
        if cumulative_amount < settled:
            raise VerificationError(
                "voucher cumulativeAmount is below on-chain settled amount"
            )
        if cumulative_amount > deposit:
            raise VerificationError("voucher amount exceeds on-chain deposit")

        # Stale or equal voucher — accept idempotently but still verify
        # the signature to prevent channel hijacking.  Skip ecrecover only
        # for exact replays of the already-verified highest voucher.
        if cumulative_amount <= channel.highest_voucher_amount:
            sig_bytes = _parse_signature(signature_str)
            is_exact_replay = (
                channel.highest_voucher_signature is not None
                and channel.highest_voucher_signature == sig_bytes
                and cumulative_amount == channel.highest_voucher_amount
            )
            if not is_exact_replay:
                if not verify_voucher(
                    escrow, chain_id, channel_id,
                    cumulative_amount, sig_bytes,
                    channel.authorized_signer,
                ):
                    raise VerificationError("invalid voucher signature")
            return Receipt.success(channel.channel_id)

        delta = cumulative_amount - channel.highest_voucher_amount
        if delta < min_delta:
            raise VerificationError(
                f"voucher delta {delta} below minimum {min_delta}"
            )

        sig_bytes = _parse_signature(signature_str)
        if not verify_voucher(
            escrow, chain_id, channel_id,
            cumulative_amount, sig_bytes,
            channel.authorized_signer,
        ):
            raise VerificationError("invalid voucher signature")

        def _updater(current: ChannelState | None) -> ChannelState | None:
            if current is None:
                raise VerificationError("channel not found")
            if cumulative_amount > current.highest_voucher_amount:
                return replace(
                    current,
                    highest_voucher_amount=cumulative_amount,
                    highest_voucher_signature=sig_bytes,
                    deposit=deposit,
                )
            return current

        updated = await self.store.update_channel(channel_id, _updater)
        if updated is None:
            raise VerificationError("channel not found")
        return Receipt.success(updated.channel_id)

    # ── _submit_close_tx ─────────────────────────────────────────

    async def _submit_close_tx(
        self,
        client: httpx.AsyncClient,
        rpc_url: str,
        escrow: str,
        channel_id: str,
        cumulative_amount: int,
        signature_bytes: bytes,
        chain_id: int,
    ) -> str:
        """Build, sign, and submit a close transaction on-chain."""
        from eth_abi import encode
        from eth_utils import keccak
        from pytempo import Call, TempoTransaction

        try:
            close_selector = keccak(b"close(bytes32,uint128,bytes)")[:4]
            channel_id_bytes = bytes.fromhex(
                channel_id[2:] if channel_id.startswith("0x") else channel_id
            )
        except ValueError as e:
            raise VerificationError(f"invalid hex in close tx params: {e}") from e

        inner_encoded = encode(
            ["bytes32", "uint128", "bytes"],
            [channel_id_bytes, cumulative_amount, signature_bytes],
        )
        calldata = close_selector + inner_encoded

        from eth_account import Account

        try:
            signer = Account.from_key(self.close_signer_key)
        except Exception as e:
            raise VerificationError(f"invalid close_signer_key: {e}") from e

        # Get nonce and gas price concurrently
        import asyncio

        nonce_coro = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [signer.address, "pending"],
                "id": 1,
            },
        )
        gas_coro = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
                "params": [],
                "id": 1,
            },
        )
        nonce_resp, gas_resp = await asyncio.gather(nonce_coro, gas_coro)

        nonce_resp.raise_for_status()
        nonce_result = nonce_resp.json()
        if "error" in nonce_result:
            raise VerificationError("failed to get nonce for close tx")
        nonce = int(nonce_result["result"], 16)

        gas_resp.raise_for_status()
        gas_result = gas_resp.json()
        if "error" in gas_result:
            raise VerificationError("failed to get gas price for close tx")
        gas_price = int(gas_result["result"], 16)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=2_000_000,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            calls=(Call.create(to=escrow, value=0, data=calldata),),
        )

        signed = tx.sign(signer.key)
        raw_tx = "0x" + signed.encode().hex()

        return await broadcast_and_confirm(client, rpc_url, raw_tx)


def _parse_signature(sig_hex: str) -> bytes:
    """Parse a hex signature string to bytes."""
    s = sig_hex[2:] if sig_hex.startswith("0x") else sig_hex
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise VerificationError(f"Invalid signature hex: {e}") from e
