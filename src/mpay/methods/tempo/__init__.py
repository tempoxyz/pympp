"""Tempo payment method for HTTP 402 authentication.

Example:
    # Client-side
    from mpay.client import get
    from mpay.methods.tempo import tempo, TempoAccount, ChargeIntent

    account = TempoAccount.from_key("0x...")
    response = await get(
        "https://api.example.com/resource",
        methods=[tempo(
            account=account,
            intents={"charge": ChargeIntent()},
        )],
    )

    # Server-side
    from mpay.server import verify_or_challenge
    from mpay.methods.tempo import ChargeIntent

    intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")
    result = await verify_or_challenge(
        authorization=request.headers.get("Authorization"),
        intent=intent,
        request={"amount": "1000", ...},
        realm="api.example.com",
    )
"""

from mpay.methods.tempo.account import TempoAccount
from mpay.methods.tempo.client import StreamMethod, TempoMethod, TransactionError, tempo
from mpay.methods.tempo.intents import ChargeIntent, StreamIntent
