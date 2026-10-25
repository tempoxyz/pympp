"""EVM payment method: EIP-3009 charges for MPP and x402 clients.

Example:
    # Server: serve native MPP and x402 clients from one endpoint
    from mpp.methods.evm import BASE_USDC
    from mpp.methods.evm import server as evm
    from mpp.server import Mpp

    server = Mpp(
        methods=evm.charge(
            currency=BASE_USDC,
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            facilitator="https://facilitator.example.com",
        ),
    )

    # Client: pay native evm/charge challenges
    from eth_account import Account
    from mpp.client import Mpp as Client
    from mpp.methods.evm import client as evm

    method = evm.charge(currency=BASE_USDC, account=Account.from_key("0x..."))
    async with Client(methods=[method]) as client:
        response = await client.fetch("https://api.example.com/paid")
"""

from typing import Any

from mpp._lazy_exports import load_lazy_attr
from mpp.methods.evm.assets import (
    BASE,
    BASE_SEPOLIA,
    BASE_SEPOLIA_USDC,
    BASE_USDC,
    CELO,
    CELO_SEPOLIA,
    CELO_SEPOLIA_USDC,
    CELO_USDC,
    CELO_USDT,
    EvmAsset,
)

_EXTRA_INSTALL_HINT = 'Install the "evm" extra to use this module: pip install "pympp[evm]"'

_LAZY_EXPORTS = {
    "mpp.methods.evm.client": ("AuthorizationConfig", "evm"),
    "mpp.methods.evm.intents": (
        "Authorization",
        "AuthorizationPayload",
        "ChargeIntent",
        "ChargeRequest",
        "SettleFn",
        "charge",
    ),
    "mpp.methods.evm._eip3009": ("challenge_hash",),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)
