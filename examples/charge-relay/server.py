"""Payment-gated FastAPI route settled by the Tempo API relay."""

import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mpp import Challenge
from mpp.methods.tempo import ChargeIntent, Relay, TempoAccount, tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID
from mpp.server import Mpp

api_key = os.environ.get("TEMPO_API_KEY")
if api_key is None:
    raise RuntimeError("TEMPO_API_KEY is required")

recipient = os.environ.get("PAYMENT_DESTINATION")
if recipient is None:
    recipient = TempoAccount.from_key("0x" + secrets.token_hex(32)).address

relay = Relay(
    api_key=api_key,
    api_base_url=os.environ.get("TEMPO_API_URL", "https://api.tempo.xyz"),
)
payments = Mpp.create(
    method=tempo(
        chain_id=TESTNET_CHAIN_ID,
        currency=PATH_USD,
        recipient=recipient,
        intents={"charge": ChargeIntent()},
        relay=relay,
    ),
    secret_key=os.environ.get("MPP_SECRET_KEY", "local-relay-example-secret"),
)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield
    await relay.aclose()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/photo")
async def photo(request: Request):
    payment = await payments.charge(
        authorization=request.headers.get("Authorization"),
        amount="0.01",
        description="Random photo",
    )
    if isinstance(payment, Challenge):
        return JSONResponse(
            {"error": "Payment required"},
            status_code=402,
            headers={"WWW-Authenticate": payment.to_www_authenticate(payments.realm)},
        )

    _, receipt = payment
    return JSONResponse(
        {"url": "https://picsum.photos/1024/1024"},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=5173)
