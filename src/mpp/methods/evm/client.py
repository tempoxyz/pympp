"""EVM payment method for client-side credential creation.

Implements the charge (EvmMethod) client method: builds and signs a plain
EIP-1559 transaction calling ``transfer(address,uint256)`` on the requested
ERC-20 currency, since standard EVM chains (e.g. Base) have none of Tempo's
native extensions (memos, MACH fee tokens, escrow, access keys).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from mpp import Challenge, Credential
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods.evm._defaults import (
    BASE_CHAIN_ID,
    BASE_RPC_URL,
    default_currency_for_chain,
    rpc_url_for_chain,
)
from mpp.methods.evm._rpc import _rpc_call

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mpp.methods.evm.account import EvmAccount
    from mpp.server.intent import Intent, VerifiableIntent

DEFAULT_GAS_LIMIT = 100_000
TRANSFER_SELECTOR = "a9059cbb"
ABI_WORD_HEX_LEN = 64

_CHAIN_ID_UNSET = object()


class TransactionError(Exception):
    """Transaction building or submission failed."""


def _encode_transfer(to: str, amount: int) -> str:
    """Encode an ERC-20 ``transfer(address,uint256)`` call.

    Selector: 0xa9059cbb = keccak256("transfer(address,uint256)")[:4]
    """
    to_padded = to[2:].lower().zfill(ABI_WORD_HEX_LEN)
    amount_padded = hex(amount)[2:].zfill(ABI_WORD_HEX_LEN)
    return f"0x{TRANSFER_SELECTOR}{to_padded}{amount_padded}"


# ──────────────────────────────────────────────────────────────────
# Charge client method
# ──────────────────────────────────────────────────────────────────


@dataclass
class EvmMethod:
    """EVM payment method implementation (e.g. Base).

    Handles client-side credential creation for EVM payments: builds and
    signs a standard ERC-20 transfer transaction for the requested amount,
    currency, and recipient.

    Example:
        from mpp.methods.evm import evm, EvmAccount

        account = EvmAccount.from_key("0x...")
        method = evm(account=account, intents={"charge": ChargeIntent()})

        from mpp.client import get
        response = await get("https://api.example.com", methods=[method])
    """

    name: str = "evm"
    account: EvmAccount | None = None
    rpc_url: str = BASE_RPC_URL
    chain_id: int | None = BASE_CHAIN_ID
    currency: str | None = None
    recipient: str | None = None
    decimals: int = 6
    client_id: str | None = None
    _intents: dict[str, Intent | VerifiableIntent] = field(default_factory=dict)
    can_offer: CanOfferFn | None = field(default=None, kw_only=True)
    on_payment_success: PaymentSuccessHandler | None = field(default=None, kw_only=True)

    @property
    def intents(self) -> dict[str, Intent | VerifiableIntent]:
        """Available intents for this method."""
        return self._intents

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given charge challenge.

        Builds and signs a plain ERC-20 transfer transaction matching the
        challenge's amount, currency, and recipient.

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
        challenge_chain_id = (
            method_details.get("chainId") if isinstance(method_details, dict) else None
        )
        expected_chain_id = (
            int(challenge_chain_id) if challenge_chain_id is not None else self.chain_id
        )

        raw_tx, chain_id = await self._build_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            expected_chain_id=expected_chain_id,
        )

        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{self.account.address}",
        )

    async def _build_transfer(
        self,
        amount: str,
        currency: str,
        recipient: str,
        expected_chain_id: int | None,
    ) -> tuple[str, int]:
        """Build and sign a standard EIP-1559 ERC-20 transfer transaction.

        Returns:
            Tuple of (raw signed transaction hex, chain ID).

        Raises:
            TransactionError: If the RPC's chain ID doesn't match expected.
        """
        from eth_account import Account

        if self.account is None:
            raise ValueError("No account configured")

        data = _encode_transfer(recipient, int(amount))

        chain_id_hex, nonce_hex, priority_fee_hex, latest_block = await asyncio.gather(
            _rpc_call(self.rpc_url, "eth_chainId", []),
            _rpc_call(self.rpc_url, "eth_getTransactionCount", [self.account.address, "pending"]),
            _rpc_call(self.rpc_url, "eth_maxPriorityFeePerGas", []),
            _rpc_call(self.rpc_url, "eth_getBlockByNumber", ["latest", False]),
        )
        chain_id = int(chain_id_hex, 16)
        if expected_chain_id is not None and chain_id != expected_chain_id:
            raise TransactionError(
                f"Chain ID mismatch: RPC returned {chain_id}, "
                f"expected {expected_chain_id} from client policy"
            )

        nonce = int(nonce_hex, 16)
        max_priority_fee_per_gas = int(priority_fee_hex, 16)
        base_fee_per_gas = int(latest_block["baseFeePerGas"], 16)
        max_fee_per_gas = base_fee_per_gas * 2 + max_priority_fee_per_gas

        try:
            gas_hex = await _rpc_call(
                self.rpc_url,
                "eth_estimateGas",
                [{"from": self.account.address, "to": currency, "data": data}, "latest"],
            )
            gas_limit = max(DEFAULT_GAS_LIMIT, int(gas_hex, 16) + 10_000)
        except Exception:
            gas_limit = DEFAULT_GAS_LIMIT

        tx = {
            "chainId": chain_id,
            "nonce": nonce,
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "maxFeePerGas": max_fee_per_gas,
            "gas": gas_limit,
            "to": currency,
            "value": 0,
            "data": data,
            "type": 2,
        }
        signed = Account.sign_transaction(tx, self.account.private_key)
        return "0x" + signed.raw_transaction.hex(), chain_id


# ──────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────


def evm(
    intents: Mapping[str, Intent | VerifiableIntent],
    account: EvmAccount | None = None,
    chain_id: int | None | object = _CHAIN_ID_UNSET,
    rpc_url: str | None = None,
    currency: str | None = None,
    recipient: str | None = None,
    decimals: int = 6,
    client_id: str | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> EvmMethod:
    """Create an EVM payment method (Base mainnet by default).

    Unlike :func:`mpp.methods.tempo.tempo`, this settles payments with a plain
    ERC-20 ``transfer`` instead of a native account-abstraction transaction,
    since standard EVM chains have none of Tempo's extensions.

    Args:
        intents: Intents to register (e.g. charge).
        account: Account for signing transactions (client-side).
        chain_id: EVM chain ID (default: 8453 for Base mainnet, use 84532
            for Base Sepolia). Resolves the RPC URL and default USDC
            currency automatically from known chains.
        rpc_url: EVM JSON-RPC endpoint URL. Overrides the URL resolved from
            ``chain_id``. Defaults to Base mainnet if neither is set.
        currency: Default currency (ERC-20 contract address) for charges.
        recipient: Default recipient address for charges.
        decimals: Token decimal places for amount conversion (default: 6,
            matching USDC).
        client_id: Optional client identity (unused, kept for parity with
            ``tempo()``).
        can_offer: Optional callback that filters this method's composed offers.
        on_payment_success: Optional callback invoked after successful verification.

    Returns:
        A configured EvmMethod instance.

    Example:
        from mpp.methods.evm import evm, ChargeIntent, EvmAccount, BASE_CHAIN_ID

        # Server
        method = evm(
            chain_id=BASE_CHAIN_ID,
            recipient="0x...",
            intents={"charge": ChargeIntent()},
        )

        # Client
        method = evm(
            account=EvmAccount.from_key("0x..."),
            intents={"charge": ChargeIntent()},
        )
    """
    resolved_chain_id = (
        BASE_CHAIN_ID if chain_id is _CHAIN_ID_UNSET else cast("int | None", chain_id)
    )

    if rpc_url is None:
        if resolved_chain_id is None:
            raise ValueError("chain_id or rpc_url is required")
        rpc_url = rpc_url_for_chain(resolved_chain_id)

    if currency is None:
        currency = default_currency_for_chain(resolved_chain_id)

    method = EvmMethod(
        account=account,
        rpc_url=rpc_url,
        chain_id=resolved_chain_id,
        currency=currency,
        recipient=recipient,
        decimals=decimals,
        client_id=client_id,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
    )
    for intent in intents.values():
        if hasattr(intent, "rpc_url") and intent.rpc_url is None:  # type: ignore[union-attr]
            intent.rpc_url = rpc_url  # type: ignore[union-attr]
        if hasattr(intent, "_method"):
            intent._method = method  # type: ignore[union-attr]
    method._intents = dict(intents)
    return method
