"""Sub-cent metered API paid through one MPP session (a TIP-1034 payment channel).

Every call to /api/quote costs 0.00001 and is paid with an off-chain voucher on the
caller's channel. The server settles on chain every 100 calls and when the caller closes.
"""

import asyncio
import logging
import os
import random

import uvicorn
from localnet import fund_on_localnet
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Credential, Receipt
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.session.server import SessionSettlementContext, SettlementSchedule
from mpp.server import Mpp, pay
from mpp.stores import SQLiteStore

RPC_URL = os.environ.get("TEMPO_RPC_URL", "http://localhost:18645")
CURRENCY = os.environ.get("TEMPO_CURRENCY", PATH_USD)
# Development keys for the localnet: set your own anywhere else.
PAYEE_KEY = os.environ.get(
    "PAYEE_KEY", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
SPONSOR_KEY = os.environ.get(
    "SPONSOR_KEY", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdcab365"
)
STORE_PATH = os.environ.get("STORE_PATH", "sessions.db")
PORT = int(os.environ.get("PORT", "8000"))

log = logging.getLogger("server")


def on_settlement(event: SessionSettlementContext) -> None:
    log.info(
        "%s settlement: +%d (total %d) on %s… tx %s",
        event.trigger,
        event.delta,
        event.amount,
        event.channel_id[:10],
        event.tx_hash,
    )


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


def create_app(mpp: Mpp) -> Starlette:
    @pay(mpp.session(amount="0.00001", unit_type="request", suggested_deposit="0.002"))
    async def quote(request: Request, credential: Credential, receipt: Receipt) -> JSONResponse:
        session = receipt.extensions or {}
        return JSONResponse(
            {
                "symbol": "TEMPO/USD",
                "price": round(random.uniform(0.99, 1.01), 5),
                "call": session.get("units"),
                "spent": session.get("spent"),
            }
        )

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/api/quote", quote, methods=["GET", "POST"]),
        ]
    )


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    payee = TempoAccount.from_key(PAYEE_KEY)
    sponsor = TempoAccount.from_key(SPONSOR_KEY)
    await fund_on_localnet(RPC_URL, CURRENCY, payee.address, sponsor.address)
    store = await SQLiteStore.create(STORE_PATH)
    mpp = Mpp(
        methods=[
            tempo.session(
                account=payee,
                currency=CURRENCY,
                rpc_url=RPC_URL,
                store=store,
                fee_payer=sponsor,
                settlement_schedule=SettlementSchedule(units=100),
                on_session_settlement=on_settlement,
            )
        ],
        secret_key=os.environ.get("MPP_SECRET_KEY", "session-metered-api-dev-secret"),
    )
    log.info("payee %s, fee sponsor %s, rpc %s", payee.address, sponsor.address, RPC_URL)
    config = uvicorn.Config(create_app(mpp), host="0.0.0.0", port=PORT, log_level="warning")
    try:
        await uvicorn.Server(config).serve()
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(main())
