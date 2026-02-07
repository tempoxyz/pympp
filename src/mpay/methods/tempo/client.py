"""Tempo payment methods for client-side credential creation.

Implements charge (TempoMethod) and stream (StreamMethod) client methods.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mpay import Challenge, Credential
from mpay.methods.tempo._defaults import DEFAULT_FEE_PAYER_URL, RPC_URL
from mpay.methods.tempo.intents import ChargeIntent
from mpay.methods.tempo.stream.chain import (
    compute_channel_id,
    encode_approve_call,
    encode_open_call,
    get_on_chain_channel,
    get_tx_params,
)
from mpay.methods.tempo.stream.voucher import sign_voucher

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount
    from mpay.server.intent import Intent


DEFAULT_GAS_LIMIT = 100_000
STREAM_GAS_LIMIT = 2_000_000


class TransactionError(Exception):
    """Transaction building or submission failed.

    Error messages are sanitized to avoid leaking sensitive transaction data.
    """


# ──────────────────────────────────────────────────────────────────
# Charge client method
# ──────────────────────────────────────────────────────────────────


@dataclass
class TempoMethod:
    """Tempo payment method implementation.

    Handles client-side credential creation for Tempo payments.

    Example:
        from mpay.methods.tempo import tempo, TempoAccount

        account = TempoAccount.from_key("0x...")
        method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")

        # Use with client
        from mpay.client import get
        response = await get("https://api.example.com", methods=[method])
    """

    name: str = "tempo"
    account: TempoAccount | None = None
    root_account: str | None = None
    rpc_url: str = RPC_URL
    currency: str | None = None
    recipient: str | None = None
    decimals: int = 6
    _intents: dict[str, Intent] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self._intents:
            self._intents = {
                "charge": ChargeIntent(rpc_url=self.rpc_url),
            }

    @property
    def intents(self) -> dict[str, Intent]:
        """Available intents for this method."""
        return self._intents

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        For the charge intent, this builds and signs a TempoTransaction (type 0x76)
        with a fee payer placeholder. The server will forward this to a fee payer
        service which adds its signature and broadcasts.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential with the signed transaction.

        Raises:
            ValueError: If no account is configured or intent is unsupported.
            TransactionError: If transaction building fails.
        """
        if self.account is None:
            raise ValueError("No account configured for signing")

        if challenge.intent != "charge":
            raise ValueError(f"Unsupported intent: {challenge.intent}")

        request = challenge.request
        nonce_key = request.get("nonce_key", 0)
        if isinstance(nonce_key, str):
            if nonce_key.startswith("0x"):
                nonce_key = int(nonce_key, 16)
            else:
                nonce_key = int(nonce_key)

        method_details = request.get("methodDetails", {})
        memo = (
            method_details.get("memo")
            if isinstance(method_details, dict)
            else None
        )

        raw_tx, chain_id = await self._build_tempo_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            nonce_key=nonce_key,
            memo=memo,
        )

        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{self.account.address}",
        )

    async def _build_tempo_transfer(
        self,
        amount: str,
        currency: str,
        recipient: str,
        nonce_key: int = 0,
        memo: str | None = None,
    ) -> tuple[str, int]:
        """Build a client-signed Tempo transaction.

        Creates a TempoTransaction (type 0x76) with fee token set to the
        transfer currency, allowing gas to be paid in the same token.

        Args:
            amount: Transfer amount as string.
            currency: TIP-20 token contract address.
            recipient: Recipient address.
            nonce_key: 2D nonce key for parallel transaction streams.
            memo: Optional 32-byte memo (hex string) for transferWithMemo.

        Returns:
            Tuple of (raw signed transaction hex, chain ID).
        """
        from pytempo import Call, TempoTransaction

        if self.account is None:
            raise ValueError("No account configured")

        if memo:
            transfer_data = self._encode_transfer_with_memo(
                recipient, int(amount), memo
            )
        else:
            transfer_data = self._encode_transfer(recipient, int(amount))

        chain_id, nonce, gas_price = await get_tx_params(
            self.rpc_url, self.account.address
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=DEFAULT_GAS_LIMIT,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            nonce=nonce,
            nonce_key=nonce_key,
            fee_token=currency,
            calls=(
                Call.create(
                    to=currency, value=0, data=transfer_data
                ),
            ),
        )

        signed_tx = tx.sign(self.account.private_key)
        return "0x" + signed_tx.encode().hex(), chain_id

    def _encode_transfer(self, to: str, amount: int) -> str:
        """Encode a TIP-20 transfer call.

        Selector: 0xa9059cbb = keccak256("transfer(address,uint256)")[:4]
        """
        selector = "a9059cbb"
        to_padded = to[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        return f"0x{selector}{to_padded}{amount_padded}"

    def _encode_transfer_with_memo(
        self, to: str, amount: int, memo: str
    ) -> str:
        """Encode a TIP-20 transferWithMemo call.

        Selector: 0xb452ef41 = keccak256(
            "transferWithMemo(address,uint256,bytes32)"
        )[:4]
        """
        selector = "b452ef41"
        to_padded = to[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        memo_clean = memo[2:] if memo.startswith("0x") else memo
        memo_padded = memo_clean.lower().zfill(64)
        return f"0x{selector}{to_padded}{amount_padded}{memo_padded}"


# ──────────────────────────────────────────────────────────────────
# Stream client method
# ──────────────────────────────────────────────────────────────────


def _random_salt() -> str:
    """Generate a random 32-byte salt as 0x-prefixed hex."""
    return "0x" + secrets.token_hex(32)


@dataclass
class _ChannelEntry:
    """Tracks a locally-managed channel."""

    channel_id: str
    salt: str
    cumulative_amount: int
    opened: bool


@dataclass
class StreamMethod:
    """Client-side stream payment method.

    Supports two modes:

    - **Auto mode** (``deposit`` set): Manages the full channel lifecycle
      (open, incremental vouchers, channel recovery) automatically.
    - **Manual mode** (``context.action`` set): Caller provides explicit
      action parameters (open, topUp, voucher, close).

    Example (auto mode)::

        from mpay.methods.tempo import TempoAccount, StreamMethod

        account = TempoAccount.from_key("0x...")
        method = StreamMethod(
            account=account,
            deposit=10_000_000,
        )

    Example (manual mode)::

        method = StreamMethod(account=account)
        # Then pass context with action/channelId/etc. to create_credential
    """

    name: str = "tempo"
    account: TempoAccount | None = None
    rpc_url: str = RPC_URL
    deposit: int | None = None
    escrow_contract: str | None = None
    currency: str | None = None
    recipient: str | None = None
    decimals: int = 6

    _channels: dict[str, _ChannelEntry] = field(default_factory=dict)
    _escrow_map: dict[str, str] = field(default_factory=dict)

    @property
    def intents(self) -> dict[str, Any]:
        """Available intents -- stream only."""
        return {}

    async def create_credential(
        self,
        challenge: Challenge,
        context: dict[str, Any] | None = None,
    ) -> Credential:
        """Create a stream credential for the given challenge.

        Args:
            challenge: Payment challenge from the server.
            context: Optional manual-mode context with action, channelId, etc.

        Returns:
            A Credential with the stream payload.
        """
        if self.account is None:
            raise ValueError("No account configured for signing")

        account = self.account

        if context and context.get("action"):
            payload = await self._manual_credential(
                challenge, account, context
            )
        elif self.deposit is not None:
            payload = await self._auto_manage_credential(challenge, account)
        else:
            raise ValueError(
                "No action in context and no deposit configured. "
                "Either provide context with action/channelId/"
                "cumulativeAmount, "
                "or configure deposit for auto-management."
            )

        chain_id = self._resolve_chain_id(challenge)
        return Credential(
            challenge=challenge.to_echo(),
            payload=payload,
            source=f"did:pkh:eip155:{chain_id}:{account.address}",
        )

    # ──────────────────────────────────────────────────────────
    # Auto-management mode
    # ──────────────────────────────────────────────────────────

    async def _auto_manage_credential(
        self,
        challenge: Challenge,
        account: TempoAccount,
    ) -> dict[str, Any]:
        """Auto-manage channel lifecycle: open, cumulative vouchers."""
        md = self._get_method_details(challenge)
        chain_id = md.get("chainId", 0)
        escrow = self._resolve_escrow(challenge, chain_id)
        payee = challenge.request.get("recipient", "")
        currency = challenge.request.get("currency", "")
        amount = int(challenge.request.get("amount", "0"))
        deposit = self.deposit

        if deposit is None:
            raise ValueError("deposit must be set for auto-management")

        key = self._channel_key(payee, currency, escrow)
        entry = self._channels.get(key)

        if entry is None:
            suggested = md.get("channelId")
            if suggested:
                entry = await self._try_recover_channel(
                    escrow, suggested, key
                )

        if entry is not None and entry.opened:
            entry.cumulative_amount += amount
            payload = await self._voucher_payload(
                account,
                entry.channel_id,
                entry.cumulative_amount,
                escrow,
                chain_id,
            )
        else:
            entry, payload = await self._open_channel(
                account,
                escrow,
                payee,
                currency,
                deposit,
                amount,
                chain_id,
            )
            self._channels[key] = entry
            self._escrow_map[entry.channel_id] = escrow

        return payload

    async def _open_channel(
        self,
        account: TempoAccount,
        escrow_contract: str,
        payee: str,
        currency: str,
        deposit: int,
        initial_amount: int,
        chain_id: int,
    ) -> tuple[_ChannelEntry, dict[str, Any]]:
        """Open a new payment channel."""
        from pytempo import Call, TempoTransaction

        salt = _random_salt()

        channel_id = await compute_channel_id(
            rpc_url=self.rpc_url,
            escrow_contract=escrow_contract,
            payer=account.address,
            payee=payee,
            token=currency,
            deposit=deposit,
            salt=salt,
            authorized_signer=account.address,
        )

        approve_data = encode_approve_call(escrow_contract, deposit)
        open_data = encode_open_call(
            payee, currency, deposit, salt, account.address
        )

        chain_id_val, nonce, gas_price = await get_tx_params(
            self.rpc_url, account.address
        )

        tx = TempoTransaction.create(
            chain_id=chain_id_val,
            gas_limit=STREAM_GAS_LIMIT,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            nonce=nonce,
            nonce_key=0,
            fee_token=currency,
            calls=(
                Call.create(
                    to=currency, value=0, data=approve_data
                ),
                Call.create(
                    to=escrow_contract, value=0, data=open_data
                ),
            ),
        )
        signed = tx.sign(account.private_key)
        transaction = "0x" + signed.encode().hex()

        from mpay.methods.tempo.stream.types import Voucher

        voucher = Voucher(
            channel_id=channel_id, cumulative_amount=initial_amount
        )
        signature = sign_voucher(
            account, voucher, escrow_contract, chain_id
        )

        entry = _ChannelEntry(
            channel_id=channel_id,
            salt=salt,
            cumulative_amount=initial_amount,
            opened=True,
        )

        payload: dict[str, Any] = {
            "action": "open",
            "type": "transaction",
            "channelId": channel_id,
            "transaction": transaction,
            "authorizedSigner": account.address,
            "cumulativeAmount": str(initial_amount),
            "signature": signature,
        }

        return entry, payload

    async def _try_recover_channel(
        self,
        escrow_contract: str,
        channel_id: str,
        key: str,
    ) -> _ChannelEntry | None:
        """Attempt to recover an existing channel from on-chain state."""
        import logging

        try:
            on_chain = await get_on_chain_channel(
                self.rpc_url, escrow_contract, channel_id
            )
            if on_chain.deposit > 0 and not on_chain.finalized:
                entry = _ChannelEntry(
                    channel_id=channel_id,
                    salt="0x",
                    cumulative_amount=on_chain.settled,
                    opened=True,
                )
                self._channels[key] = entry
                self._escrow_map[channel_id] = escrow_contract
                return entry
        except Exception:
            logging.getLogger(__name__).debug(
                "channel recovery failed for %s, will open new channel",
                channel_id,
                exc_info=True,
            )
        return None

    # ──────────────────────────────────────────────────────────
    # Manual mode
    # ──────────────────────────────────────────────────────────

    async def _manual_credential(
        self,
        challenge: Challenge,
        account: TempoAccount,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Build credential payload for a manually-specified action."""
        md = self._get_method_details(challenge)
        chain_id = md.get("chainId", 0)
        channel_id = context.get("channelId", "")
        escrow = self._resolve_escrow(challenge, chain_id, channel_id)
        self._escrow_map[channel_id] = escrow

        action = context["action"]

        if action == "open":
            transaction = context.get("transaction")
            cumulative_amount = context.get("cumulativeAmount")
            if not transaction:
                raise ValueError("transaction required for open action")
            if cumulative_amount is None:
                raise ValueError(
                    "cumulativeAmount required for open action"
                )

            from mpay.methods.tempo.stream.types import Voucher

            voucher = Voucher(
                channel_id=channel_id,
                cumulative_amount=int(cumulative_amount),
            )
            signature = sign_voucher(account, voucher, escrow, chain_id)
            return {
                "action": "open",
                "type": "transaction",
                "channelId": channel_id,
                "transaction": transaction,
                "authorizedSigner": context.get(
                    "authorizedSigner", account.address
                ),
                "cumulativeAmount": str(cumulative_amount),
                "signature": signature,
            }

        elif action == "topUp":
            transaction = context.get("transaction")
            additional_deposit = context.get("additionalDeposit")
            if not transaction:
                raise ValueError("transaction required for topUp action")
            if additional_deposit is None:
                raise ValueError(
                    "additionalDeposit required for topUp action"
                )
            return {
                "action": "topUp",
                "type": "transaction",
                "channelId": channel_id,
                "transaction": transaction,
                "additionalDeposit": str(additional_deposit),
            }

        elif action == "voucher":
            cumulative_amount = context.get("cumulativeAmount")
            if cumulative_amount is None:
                raise ValueError(
                    "cumulativeAmount required for voucher action"
                )
            return await self._voucher_payload(
                account,
                channel_id,
                int(cumulative_amount),
                escrow,
                chain_id,
            )

        elif action == "close":
            cumulative_amount = context.get("cumulativeAmount")
            if cumulative_amount is None:
                raise ValueError(
                    "cumulativeAmount required for close action"
                )

            from mpay.methods.tempo.stream.types import Voucher

            voucher = Voucher(
                channel_id=channel_id,
                cumulative_amount=int(cumulative_amount),
            )
            signature = sign_voucher(account, voucher, escrow, chain_id)
            return {
                "action": "close",
                "channelId": channel_id,
                "cumulativeAmount": str(cumulative_amount),
                "signature": signature,
            }

        else:
            raise ValueError(f"unknown action: {action}")

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    async def _voucher_payload(
        self,
        account: TempoAccount,
        channel_id: str,
        cumulative_amount: int,
        escrow_contract: str,
        chain_id: int,
    ) -> dict[str, Any]:
        """Build a voucher credential payload."""
        from mpay.methods.tempo.stream.types import Voucher

        voucher = Voucher(
            channel_id=channel_id,
            cumulative_amount=cumulative_amount,
        )
        signature = sign_voucher(
            account, voucher, escrow_contract, chain_id
        )
        return {
            "action": "voucher",
            "channelId": channel_id,
            "cumulativeAmount": str(cumulative_amount),
            "signature": signature,
        }

    def _channel_key(
        self, payee: str, currency: str, escrow: str
    ) -> str:
        """Generate a cache key for a (payee, currency, escrow) triple."""
        return f"{payee.lower()}:{currency.lower()}:{escrow.lower()}"

    def _get_method_details(
        self, challenge: Challenge
    ) -> dict[str, Any]:
        """Extract methodDetails from a challenge."""
        md = challenge.request.get("methodDetails", {})
        return md if isinstance(md, dict) else {}

    def _resolve_chain_id(self, challenge: Challenge) -> int:
        md = self._get_method_details(challenge)
        return md.get("chainId", 42431)

    def _resolve_escrow(
        self,
        challenge: Challenge,
        chain_id: int,
        channel_id: str | None = None,
    ) -> str:
        """Resolve the escrow contract address."""
        if channel_id:
            cached = self._escrow_map.get(channel_id)
            if cached:
                return cached

        md = self._get_method_details(challenge)
        challenge_escrow = md.get("escrowContract")
        if challenge_escrow:
            return challenge_escrow

        if self.escrow_contract:
            return self.escrow_contract

        defaults = {
            4217: "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70",
            42431: "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70",
        }
        escrow = defaults.get(chain_id)
        if escrow:
            return escrow

        raise ValueError(
            "No escrowContract available. Provide it in parameters "
            "or ensure the server challenge includes it."
        )


# ──────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────


def tempo(
    account: TempoAccount | None = None,
    rpc_url: str = RPC_URL,
    root_account: str | None = None,
    currency: str | None = None,
    recipient: str | None = None,
    decimals: int = 6,
    intents: dict[str, Intent] | None = None,
) -> TempoMethod:
    """Create a Tempo payment method.

    Args:
        account: Account for signing transactions.
        rpc_url: Tempo RPC endpoint URL.
        root_account: Root account address for access key signing.
        currency: Default currency address for charges.
        recipient: Default recipient address for charges.
        decimals: Token decimal places for amount conversion (default: 6).
        intents: Additional intents to register (merged with default charge).

    Returns:
        A configured TempoMethod instance.

    Example:
        from mpay.methods.tempo import tempo, TempoAccount

        account = TempoAccount.from_key("0x...")
        method = tempo(account=account)
    """
    method = TempoMethod(
        account=account,
        rpc_url=rpc_url,
        root_account=root_account,
        currency=currency,
        recipient=recipient,
        decimals=decimals,
    )
    if intents:
        method._intents.update(intents)
    return method
