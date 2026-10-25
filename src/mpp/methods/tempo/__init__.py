"""Tempo payment method for HTTP 402 authentication: the charge intent.

Example:
    # Client-side
    from mpp.client import Client
    from mpp.methods.tempo import TempoAccount
    from mpp.methods.tempo import client as tempo

    account = TempoAccount.from_key("0x...")
    async with Client(methods=[tempo.charge(account=account)]) as client:
        response = await client.get("https://api.example.com/resource")

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.tempo import server as tempo

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))
"""

from typing import Any

from mpp._did import PkhSource, parse_pkh_source
from mpp._lazy_exports import load_lazy_attr
from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    MACH,
    OUSD,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    default_currencies_for_chain,
    default_currency_for_chain,
    escrow_contract_for_chain,
    fee_tokens_for_chain,
)

_EXTRA_INSTALL_HINT = 'Install the "tempo" extra to use this module: pip install "pympp[tempo]"'

_LAZY_EXPORTS = {
    "mpp.methods.tempo.account": ("TempoAccount",),
    "mpp.methods.tempo.client": ("TempoMethod", "TransactionError"),
    "mpp.methods.tempo.intents": (
        "ChargeIntent",
        "Transfer",
        "SenderValidation",
        "ValidateSender",
        "get_transfers",
    ),
    "mpp.methods.tempo.relay": ("Relay", "RelayErrorCode"),
    "mpp.methods.tempo.schemas": ("ChargeInput", "ChargePayload", "Split"),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)
