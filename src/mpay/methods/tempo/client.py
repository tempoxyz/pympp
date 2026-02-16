"""Tempo payment methods for client-side credential creation.

Implements the charge (TempoMethod) client method.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mpay import Challenge, Credential
from mpay.methods.tempo._attribution import encode as encode_attribution
from mpay.methods.tempo._defaults import RPC_URL
from mpay.methods.tempo._rpc import get_tx_params

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount
    from mpay.server.intent import Intent


DEFAULT_GAS_LIMIT = 100_000


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
    client_id: str | None = None
    _intents: dict[str, Intent] = field(default_factory=dict)

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
        memo = method_details.get("memo") if isinstance(method_details, dict) else None
        if memo is None:
            memo = encode_attribution(server_id=challenge.realm, client_id=self.client_id)

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
            transfer_data = self._encode_transfer_with_memo(recipient, int(amount), memo)
        else:
            transfer_data = self._encode_transfer(recipient, int(amount))

        chain_id, nonce, gas_price = await get_tx_params(self.rpc_url, self.account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=DEFAULT_GAS_LIMIT,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            nonce=nonce,
            nonce_key=nonce_key,
            fee_token=currency,
            calls=(Call.create(to=currency, value=0, data=transfer_data),),
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

    def _encode_transfer_with_memo(self, to: str, amount: int, memo: str) -> str:
        """Encode a TIP-20 transferWithMemo call.

        Selector: 0xb452ef41 = keccak256(
            "transferWithMemo(address,uint256,bytes32)"
        )[:4]
        """
        selector = "b452ef41"
        to_padded = to[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        memo_clean = memo[2:] if memo.startswith("0x") else memo
        if len(memo_clean) != 64:
            raise ValueError(f"memo must be exactly 32 bytes (64 hex chars), got {len(memo_clean)}")
        return f"0x{selector}{to_padded}{amount_padded}{memo_clean.lower()}"


# ──────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────


def tempo(
    intents: dict[str, Intent],
    account: TempoAccount | None = None,
    rpc_url: str = RPC_URL,
    root_account: str | None = None,
    currency: str | None = None,
    recipient: str | None = None,
    decimals: int = 6,
    client_id: str | None = None,
) -> TempoMethod:
    """Create a Tempo payment method.

    Args:
        intents: Intents to register (e.g. charge).
        account: Account for signing transactions.
        rpc_url: Tempo RPC endpoint URL.
        root_account: Root account address for access key signing.
        currency: Default currency address for charges.
        recipient: Default recipient address for charges.
        decimals: Token decimal places for amount conversion (default: 6).
        client_id: Optional client identity for attribution memos.

    Returns:
        A configured TempoMethod instance.

    Example:
        from mpay.methods.tempo import ChargeIntent

        method = tempo(
            intents={"charge": ChargeIntent()},
        )
    """
    method = TempoMethod(
        account=account,
        rpc_url=rpc_url,
        root_account=root_account,
        currency=currency,
        recipient=recipient,
        decimals=decimals,
        client_id=client_id,
    )
    method._intents = dict(intents)
    return method
