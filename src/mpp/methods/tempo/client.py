"""Tempo payment methods for client-side credential creation.

Implements the charge (TempoMethod) client method.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mpp import Challenge, Credential
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import (
    CHAIN_RPC_URLS,
    RPC_URL,
    default_currency_for_chain,
    rpc_url_for_chain,
)
from mpp.methods.tempo._rpc import estimate_gas, get_tx_params

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount
    from mpp.server.intent import Intent


# Tempo AA (type-0x76) transactions have higher intrinsic gas than legacy txs
# (~270k for a single TIP-20 transfer). A safe static limit avoids the need for
# AA-aware eth_estimateGas calls, matching the approach used by mpp-rs.
DEFAULT_GAS_LIMIT = 1_000_000
EXPIRING_NONCE_KEY = (1 << 256) - 1  # U256::MAX
FEE_PAYER_VALID_BEFORE_SECS = 25


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
        from mpp.methods.tempo import tempo, TempoAccount

        account = TempoAccount.from_key("0x...")
        method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")

        # Use with client
        from mpp.client import get
        response = await get("https://api.example.com", methods=[method])
    """

    name: str = "tempo"
    account: TempoAccount | None = None
    fee_payer: TempoAccount | None = None
    root_account: str | None = None
    rpc_url: str = RPC_URL
    chain_id: int | None = None
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
        method_details = request.get("methodDetails", {})
        use_fee_payer = (
            method_details.get("feePayer", False) if isinstance(method_details, dict) else False
        )

        nonce_key = request.get("nonce_key", 0)
        if isinstance(nonce_key, str):
            if nonce_key.startswith("0x"):
                nonce_key = int(nonce_key, 16)
            else:
                nonce_key = int(nonce_key)

        memo = method_details.get("memo") if isinstance(method_details, dict) else None
        if memo is None:
            memo = encode_attribution(server_id=challenge.realm, client_id=self.client_id)

        # Resolve RPC URL from challenge's chainId (like mppx), falling back
        # to the method-level rpc_url.
        rpc_url = self.rpc_url
        expected_chain_id: int | None = None
        challenge_chain_id = (
            method_details.get("chainId") if isinstance(method_details, dict) else None
        )
        if challenge_chain_id is not None:
            try:
                parsed_chain_id = int(challenge_chain_id)
            except (TypeError, ValueError):
                pass
            else:
                resolved = CHAIN_RPC_URLS.get(parsed_chain_id)
                if resolved is not None:
                    rpc_url = resolved
                    # Only enforce mismatch check when we resolved to a known
                    # RPC URL — for unknown chains we fall back to the user's
                    # custom rpc_url and can't verify the chain ID.
                    expected_chain_id = parsed_chain_id

        # Also check against the method-level chain_id if set.
        if expected_chain_id is None and self.chain_id is not None:
            expected_chain_id = self.chain_id

        raw_tx, chain_id = await self._build_tempo_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            nonce_key=nonce_key,
            memo=memo,
            rpc_url=rpc_url,
            expected_chain_id=expected_chain_id,
            awaiting_fee_payer=use_fee_payer,
        )

        # When signing with an access key, the credential source is the
        # root account (the smart wallet), not the access key.
        source_address = self.root_account if self.root_account else self.account.address

        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{source_address}",
        )

    async def _build_tempo_transfer(
        self,
        amount: str,
        currency: str,
        recipient: str,
        nonce_key: int = 0,
        memo: str | None = None,
        rpc_url: str | None = None,
        expected_chain_id: int | None = None,
        awaiting_fee_payer: bool = False,
    ) -> tuple[str, int]:
        """Build a client-signed Tempo transaction.

        Creates a TempoTransaction (type 0x76) with fee token set to the
        transfer currency, allowing gas to be paid in the same token.

        When ``awaiting_fee_payer`` is True, the transaction is built with
        a fee payer placeholder so a sponsoring service can co-sign it
        before broadcast. Uses expiring nonces (nonce_key=U256::MAX,
        nonce=0) with a ``valid_before`` window for replay protection.

        Args:
            amount: Transfer amount as string.
            currency: TIP-20 token contract address.
            recipient: Recipient address.
            nonce_key: 2D nonce key for parallel transaction streams.
            memo: Optional 32-byte memo (hex string) for transferWithMemo.
            rpc_url: RPC URL to use. Defaults to ``self.rpc_url``.
            expected_chain_id: If set, verify the RPC reports this chain ID.
            awaiting_fee_payer: If True, build for fee payer sponsorship.

        Returns:
            Tuple of (raw signed transaction hex, chain ID).

        Raises:
            TransactionError: If the RPC's chain ID doesn't match expected.
        """
        from pytempo import Call, TempoTransaction

        if self.account is None:
            raise ValueError("No account configured")

        resolved_rpc = rpc_url or self.rpc_url

        if memo:
            transfer_data = self._encode_transfer_with_memo(recipient, int(amount), memo)
        else:
            transfer_data = self._encode_transfer(recipient, int(amount))

        # When using an access key, fetch nonce from the root account
        # (smart wallet), not the access key address.
        nonce_address = self.root_account if self.root_account else self.account.address

        chain_id, on_chain_nonce, gas_price = await get_tx_params(resolved_rpc, nonce_address)

        if expected_chain_id is not None and chain_id != expected_chain_id:
            raise TransactionError(
                f"Chain ID mismatch: RPC returned {chain_id}, "
                f"expected {expected_chain_id} from challenge"
            )

        if awaiting_fee_payer:
            resolved_nonce_key = EXPIRING_NONCE_KEY
            resolved_nonce = 0
            valid_before = int(time.time()) + FEE_PAYER_VALID_BEFORE_SECS
        else:
            resolved_nonce_key = nonce_key
            resolved_nonce = on_chain_nonce
            valid_before = None

        gas_limit = DEFAULT_GAS_LIMIT
        try:
            estimated = await estimate_gas(resolved_rpc, nonce_address, currency, transfer_data)
            gas_limit = max(gas_limit, estimated + 5_000)
        except Exception:
            pass

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            nonce=resolved_nonce,
            nonce_key=resolved_nonce_key,
            fee_token=None if awaiting_fee_payer else currency,
            awaiting_fee_payer=awaiting_fee_payer,
            valid_before=valid_before,
            calls=(Call.create(to=currency, value=0, data=transfer_data),),
        )

        if self.root_account:
            from pytempo import sign_tx_access_key

            signed_tx = sign_tx_access_key(tx, self.account.private_key, self.root_account)
        else:
            signed_tx = tx.sign(self.account.private_key)

        if awaiting_fee_payer:
            from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

            return "0x" + encode_fee_payer_envelope(signed_tx).hex(), chain_id

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

        Selector: 0x95777d59 = keccak256(
            "transferWithMemo(address,uint256,bytes32)"
        )[:4]
        """
        selector = "95777d59"
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
    fee_payer: TempoAccount | None = None,
    chain_id: int | None = None,
    rpc_url: str | None = None,
    root_account: str | None = None,
    currency: str | None = None,
    recipient: str | None = None,
    decimals: int = 6,
    client_id: str | None = None,
) -> TempoMethod:
    """Create a Tempo payment method.

    Args:
        intents: Intents to register (e.g. charge).
        account: Account for signing transactions (client-side).
        fee_payer: Account for co-signing sponsored transactions
            (server-side). When set, the server signs with domain
            ``0x78`` and broadcasts directly — no external fee payer
            service needed.
        chain_id: Tempo chain ID (4217 for mainnet, 42431 for testnet).
            Resolves the RPC URL automatically from known chains.
        rpc_url: Tempo RPC endpoint URL. Overrides the URL resolved
            from ``chain_id``. Defaults to mainnet if neither is set.
        root_account: Root account address for access key signing.
        currency: Default currency address for charges.
        recipient: Default recipient address for charges.
        decimals: Token decimal places for amount conversion (default: 6).
        client_id: Optional client identity for attribution memos.

    Returns:
        A configured TempoMethod instance.

    Example:
        from mpp.methods.tempo import ChargeIntent, TempoAccount

        # Server with fee payer — sponsors gas for clients
        method = tempo(
            chain_id=42431,
            fee_payer=TempoAccount.from_env("FEE_PAYER_KEY"),
            intents={"charge": ChargeIntent()},
        )

        # Client
        method = tempo(
            account=TempoAccount.from_key("0x..."),
            intents={"charge": ChargeIntent()},
        )
    """
    if rpc_url is None:
        rpc_url = rpc_url_for_chain(chain_id) if chain_id else RPC_URL

    if currency is None:
        currency = default_currency_for_chain(chain_id)

    method = TempoMethod(
        account=account,
        fee_payer=fee_payer,
        rpc_url=rpc_url,
        chain_id=chain_id,
        root_account=root_account,
        currency=currency,
        recipient=recipient,
        decimals=decimals,
        client_id=client_id,
    )
    for intent in intents.values():
        if hasattr(intent, "rpc_url") and intent.rpc_url is None:  # type: ignore[union-attr]
            intent.rpc_url = rpc_url  # type: ignore[union-attr]
        if hasattr(intent, "_method"):
            intent._method = method  # type: ignore[union-attr]
    method._intents = dict(intents)
    return method
