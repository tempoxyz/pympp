"""Generic EVM payment method (e.g. Base) for HTTP 402 authentication.

pympp ships payment method implementations for Tempo (its own chain, using
native account-abstraction transactions) and Stripe. This module is the
equivalent for any standard EVM chain: it plugs into the same
``Method``/``Intent`` protocols that ``mpp.methods.tempo`` implements, but
moves value with a plain ERC-20 ``transfer`` instead of Tempo's native
transaction type, since standard EVM chains (e.g. Base) have none of Tempo's
extensions (memos, MACH fee tokens, escrow, access keys).

Client side: builds and signs a standard EIP-1559 transaction calling
``transfer(address,uint256)`` on the requested ERC-20 currency.

Server side: broadcasts that signed transaction to an EVM JSON-RPC endpoint
and confirms the mined receipt contains a matching ``Transfer`` log.

Example:
    # Client-side
    from mpp.client import get
    from mpp.methods.evm import evm, EvmAccount, ChargeIntent

    account = EvmAccount.from_key("0x...")
    response = await get(
        "https://api.example.com/resource",
        methods=[evm(
            account=account,
            intents={"charge": ChargeIntent()},
        )],
    )

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.evm import evm, ChargeIntent

    server = Mpp.create(
        method=evm(
            recipient="0x...",
            intents={"charge": ChargeIntent()},
        ),
    )
"""

from typing import Any

from mpp._lazy_exports import load_lazy_attr
from mpp.methods.evm._defaults import (
    BASE_CHAIN_ID,
    BASE_RPC_URL,
    BASE_SEPOLIA_CHAIN_ID,
    BASE_SEPOLIA_RPC_URL,
    BASE_SEPOLIA_USDC,
    BASE_USDC,
    default_currency_for_chain,
    rpc_url_for_chain,
)

_EXTRA_INSTALL_HINT = 'Install the "evm" extra to use this module: pip install "pympp[evm]"'

_LAZY_EXPORTS = {
    "mpp.methods.evm.account": ("EvmAccount",),
    "mpp.methods.evm.client": ("EvmMethod", "TransactionError", "evm"),
    "mpp.methods.evm.intents": ("ChargeIntent",),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)
