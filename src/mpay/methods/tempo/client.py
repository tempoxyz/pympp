"""Tempo payment method for client-side credential creation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mpay import Challenge, Credential
from mpay.methods.tempo.intents import ChargeIntent

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount
    from mpay.server.intent import Intent


DEFAULT_GAS_LIMIT = 100_000
DEFAULT_TIMEOUT = 30.0
DEFAULT_FEE_PAYER_URL = "https://sponsor.moderato.tempo.xyz"


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

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        For the charge intent, this builds and signs a transfer transaction,
        then returns a credential with the signed transaction.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential that satisfies the challenge.

        Raises:
            ValueError: If no account is configured or intent is unsupported.
            TransactionError: If transaction building or submission fails.
        """
        if self.account is None:
            raise ValueError("No account configured for signing")

        if challenge.intent != "charge":
            raise ValueError(f"Unsupported intent: {challenge.intent}")

        request = challenge.request
        fee_payer = request.get("fee_payer", False)

        if fee_payer:
            raw_tx = await self._build_sponsored_transfer(
                amount=request["amount"],
                asset=request["asset"],
                destination=request["destination"],
            )
            return Credential(
                id=challenge.id,
                payload={"type": "transaction", "signature": raw_tx},
                source=f"did:pkh:eip155:1:{self.account.address}",
            )
        else:
            tx_hash = await self._build_and_sign_transfer(
                amount=request["amount"],
                asset=request["asset"],
                destination=request["destination"],
            )
            return Credential(
                id=challenge.id,
                payload={"type": "hash", "hash": tx_hash},
                source=f"did:pkh:eip155:1:{self.account.address}",
            )

    async def _build_and_sign_transfer(
        self,
        amount: str,
        asset: str,
        destination: str,
    ) -> str:
        """Build, sign, and submit a transfer transaction.

        Uses eth-account for proper EIP-155 transaction signing.

        Returns the transaction hash.
        """
        import httpx

        if self.account is None:
            raise ValueError("No account configured")

        transfer_data = self._encode_transfer(destination, int(amount))

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
                    "method": "eth_getTransactionCount",
                    "params": [self.account.address, "pending"],
                    "id": 1,
                },
            )
            nonce_resp.raise_for_status()
            nonce_result = nonce_resp.json()
            if "error" in nonce_result:
                raise TransactionError("Failed to fetch nonce")
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

            tx = {
                "nonce": nonce,
                "gasPrice": gas_price,
                "gas": DEFAULT_GAS_LIMIT,
                "to": asset,
                "value": 0,
                "data": transfer_data,
                "chainId": chain_id,
            }

            signed = self.account.sign_transaction(tx)
            raw_tx = signed.raw_transaction.hex()
            if not raw_tx.startswith("0x"):
                raw_tx = "0x" + raw_tx

            send_resp = await client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [raw_tx],
                    "id": 1,
                },
            )
            send_resp.raise_for_status()
            result = send_resp.json()

            if "error" in result:
                raise TransactionError("Transaction submission failed")

            tx_hash = result.get("result")
            if not tx_hash:
                raise TransactionError("No transaction hash returned")

            return tx_hash

    async def _build_sponsored_transfer(
        self,
        amount: str,
        asset: str,
        destination: str,
    ) -> str:
        """Build a client-signed Tempo transaction for fee sponsorship.

        Creates a TempoTransaction (type 0x76) with a fee payer placeholder,
        signed by the client. The server will forward this to a fee payer
        service which adds its signature and broadcasts.

        Returns the raw signed transaction hex (0x76-prefixed).
        """
        import httpx
        from pytempo import create_tempo_transaction

        if self.account is None:
            raise ValueError("No account configured")

        transfer_data = self._encode_transfer(destination, int(amount))

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
                    "params": [self.account.address, 0, "pending"],
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

            tx = create_tempo_transaction(
                to=asset,
                value=0,
                data=transfer_data,
                gas=DEFAULT_GAS_LIMIT,
                max_fee_per_gas=gas_price,
                max_priority_fee_per_gas=gas_price,
                nonce=nonce,
                nonce_key=0,
                chain_id=chain_id,
                _will_have_fee_payer=True,
            )

            tx.sign(self.account.private_key)
            return "0x" + tx.encode().hex()

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
