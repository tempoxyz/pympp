"""Tempo payment method for client-side credential creation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mpay import Challenge, ChallengeEcho, Credential
from mpay.methods.tempo.intents import ChargeIntent

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount
    from mpay.server.intent import Intent


DEFAULT_GAS_LIMIT = 100_000
DEFAULT_TIMEOUT = 30.0


class TransactionError(Exception):
    """Transaction building or submission failed.

    Error messages are sanitized to avoid leaking sensitive transaction data.
    """


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
    rpc_url: str = "https://rpc.tempo.xyz"
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

    async def _get_chain_id(self) -> int:
        """Get and cache the chain ID from RPC."""
        if hasattr(self, "_chain_id_cache"):
            return self._chain_id_cache

        import httpx

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.post(
                self.rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
            )
            response.raise_for_status()
            result = response.json()
            if "error" in result:
                raise TransactionError("Failed to fetch chain ID")
            self._chain_id_cache = int(result["result"], 16)
        return self._chain_id_cache

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

        raw_tx = await self._build_tempo_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            nonce_key=nonce_key,
        )
        chain_id = await self._get_chain_id()
        challenge_echo = ChallengeEcho(
            id=challenge.id,
            realm=challenge.realm or "",
            method=challenge.method,
            intent=challenge.intent,
            request=challenge.request,
            digest=challenge.digest,
            expires=challenge.expires,
            description=challenge.description,
        )
        return Credential(
            challenge=challenge_echo,
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{self.account.address}",
        )

    async def _build_tempo_transfer(
        self,
        amount: str,
        currency: str,
        recipient: str,
        nonce_key: int = 0,
    ) -> str:
        """Build a client-signed Tempo transaction for fee sponsorship.

        Creates a TempoTransaction (type 0x76) with a fee payer placeholder,
        signed by the client. The server will forward this to a fee payer
        service which adds its signature and broadcasts.

        Args:
            amount: Transfer amount as string.
            currency: TIP-20 token contract address.
            recipient: Recipient address.
            nonce_key: 2D nonce key for parallel transaction streams (default: 0).

        Returns:
            Raw signed transaction hex (0x76-prefixed).
        """
        import httpx
        from pytempo import Call, TempoTransaction

        if self.account is None:
            raise ValueError("No account configured")

        transfer_data = self._encode_transfer(recipient, int(amount))

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            chain_resp = await client.post(
                self.rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
            )
            chain_resp.raise_for_status()
            chain_result = chain_resp.json()
            if "error" in chain_result:
                raise TransactionError("Failed to fetch chain ID")
            chain_id = int(chain_result["result"], 16)

            nonce_resp = await client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "tempo_getTransactionCount",
                    "params": [self.account.address, nonce_key, "pending"],
                    "id": 1,
                },
            )
            nonce_resp.raise_for_status()
            nonce_result = nonce_resp.json()
            if "error" in nonce_result:
                raise TransactionError("Failed to fetch Tempo nonce")
            nonce = int(nonce_result["result"], 16)

            gas_resp = await client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_gasPrice",
                    "params": [],
                    "id": 1,
                },
            )
            gas_resp.raise_for_status()
            gas_result = gas_resp.json()
            if "error" in gas_result:
                raise TransactionError("Failed to fetch gas price")
            gas_price = int(gas_result["result"], 16)

            # Build a sponsored Tempo transaction (type 0x76) with fee payer placeholder
            tx = TempoTransaction.create(
                chain_id=chain_id,
                gas_limit=DEFAULT_GAS_LIMIT,
                max_fee_per_gas=gas_price,
                max_priority_fee_per_gas=gas_price,
                nonce=nonce,
                nonce_key=nonce_key,
                awaiting_fee_payer=True,
                calls=(Call.create(to=currency, value=0, data=transfer_data),),
            )

            signed_tx = tx.sign(self.account.private_key)
            return "0x" + signed_tx.encode().hex()

    def _encode_transfer(self, to: str, amount: int) -> str:
        """Encode a TIP-20 transfer call."""
        selector = "a9059cbb"
        to_padded = to[2:].lower().zfill(64)
        amount_padded = hex(amount)[2:].zfill(64)
        return f"0x{selector}{to_padded}{amount_padded}"


def tempo(
    account: TempoAccount | None = None,
    rpc_url: str = "https://rpc.tempo.xyz",
    root_account: str | None = None,
) -> TempoMethod:
    """Create a Tempo payment method.

    Args:
        account: Account for signing transactions.
        rpc_url: Tempo RPC endpoint URL.
        root_account: Root account address for access key signing.

    Returns:
        A configured TempoMethod instance.

    Example:
        from mpay.methods.tempo import tempo, TempoAccount

        account = TempoAccount.from_key("0x...")
        method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")
    """
    return TempoMethod(
        account=account,
        rpc_url=rpc_url,
        root_account=root_account,
    )
