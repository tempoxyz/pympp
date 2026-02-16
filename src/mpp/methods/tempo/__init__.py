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
    from mpp.server import verify_or_challenge
    from mpp.methods.tempo import ChargeIntent

    intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")
    result = await verify_or_challenge(
        authorization=request.headers.get("Authorization"),
        intent=intent,
        request={"amount": "1000", ...},
        realm="api.example.com",
    )
"""

from mpp.methods.tempo.account import TempoAccount
from mpp.methods.tempo.client import TempoMethod, TransactionError, tempo
from mpp.methods.tempo.intents import ChargeIntent
