"""An x402 server built only from Coinbase's official x402 package.

GET /weather costs 0.0001 TestUSDC (100 base units), paid with the x402
"exact" scheme and settled by the facilitator at FACILITATOR_URL.
"""

import os

import uvicorn
from common import NETWORK, recipient, token_address
from fastapi import FastAPI
from x402 import x402ResourceServer
from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption, RouteConfig
from x402.http.middleware.fastapi import payment_middleware
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.schemas import AssetAmount

FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "http://127.0.0.1:4022")

server = x402ResourceServer(HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR_URL)))
server.register(NETWORK, ExactEvmScheme())  # type: ignore[arg-type]

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(
            scheme="exact",
            network=NETWORK,
            pay_to=recipient.address,
            # A custom token has no default price conversion, so the price is an
            # explicit amount with its EIP-712 domain name and version.
            price=AssetAmount(
                amount="100",
                asset=token_address(),
                extra={"name": "USDC", "version": "2"},
            ),
        ),
        description="Current weather",
        mime_type="application/json",
    )
}

app = FastAPI()
app.middleware("http")(payment_middleware(routes, server))


@app.get("/weather")
async def weather() -> dict[str, str]:
    return {"city": "Lisbon", "forecast": "sunny", "temperature": "21C"}


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "4021")))
