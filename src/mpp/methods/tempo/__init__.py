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

from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    TESTNET_CHAIN_ID,
    escrow_contract_for_chain,
)
from mpp.methods.tempo.account import TempoAccount
from mpp.methods.tempo.client import TempoMethod, TransactionError, tempo
from mpp.methods.tempo.intents import ChargeIntent
