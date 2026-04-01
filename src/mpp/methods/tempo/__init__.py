"""Tempo payment method for HTTP 402 authentication.

Example:
    # Client-side
    from mpp.client import get
    from mpp.methods.tempo import tempo, TempoAccount, ChargeIntent

    account = TempoAccount.from_key("0x...")
    response = await get(
        "https://api.example.com/resource",
        methods=[tempo(
            account=account,
            intents={"charge": ChargeIntent()},
        )],
    )

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.tempo import tempo, ChargeIntent

    server = Mpp.create(
        method=tempo(
            chain_id=42431,
            intents={"charge": ChargeIntent()},
        ),
    )
"""

from typing import Any

from mpp._lazy_exports import load_lazy_attr
from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    default_currency_for_chain,
    escrow_contract_for_chain,
)

_EXTRA_INSTALL_HINT = 'Install the "tempo" extra to use this module: pip install "pympp[tempo]"'

_LAZY_EXPORTS = {
    "mpp.methods.tempo.account": ("TempoAccount",),
    "mpp.methods.tempo.client": ("TempoMethod", "TransactionError", "tempo"),
    "mpp.methods.tempo.intents": ("ChargeIntent",),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)
