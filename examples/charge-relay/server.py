"""FastAPI charge server backed by the Tempo API MPP relay."""

import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mpp import Challenge
from mpp.methods.tempo import ChargeIntent, Relay, TempoAccount, tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID
from mpp.server import Mpp

api_key = os.environ.get("TEMPO_API_KEY")
if not api_key:
    raise RuntimeError("Set TEMPO_API_KEY to a Tempo API key with the mpp:write scope")

TEMPO_API_URL = os.environ.get("TEMPO_API_URL", "https://api.tempo.xyz")
RECIPIENT = os.environ.get("PAYMENT_DESTINATION")
if not RECIPIENT:
    RECIPIENT = TempoAccount.from_key("0x" + secrets.token_hex(32)).address

payments = Mpp.create(
    method=tempo(
        chain_id=TESTNET_CHAIN_ID,
        currency=PATH_USD,
        recipient=RECIPIENT,
        intents={"charge": ChargeIntent()},
        relay=Relay(api_key=api_key, api_base_url=TEMPO_API_URL),
    ),
    secret_key=os.environ.get(
        "MPP_SECRET_KEY",
        "pympp-demo-tempo-api-relay-secret-key",
    ),
)

app = FastAPI()


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/photo")
async def photo(request: Request):
    result = await payments.charge(
        authorization=request.headers.get("Authorization"),
        amount="0.01",
        chain_id=TESTNET_CHAIN_ID,
        description="Random stock photo",
    )
    if isinstance(result, Challenge):
        return JSONResponse(
            status_code=402,
            content={"error": "Payment required"},
            headers={"WWW-Authenticate": result.to_www_authenticate(payments.realm)},
        )

    _, receipt = result
    return JSONResponse(
        content={"url": "https://picsum.photos/1024/1024"},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "5173")))
