"""Payment-protected API server using FastAPI and the Machine Payments Protocol."""

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from mpp import Credential, Receipt
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID
from mpp.server import Mpp, pay
from mpp.server import Request as PaymentRequest

app = FastAPI(
    title="Payment-Protected API",
    description="Example API demonstrating Machine Payments Protocol payment protection",
)

DESTINATION = os.environ.get(
    "PAYMENT_DESTINATION", "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
)

# Optional: set FEE_PAYER_KEY to sponsor gas for clients.
# When set, the server co-signs 0x78 fee payer envelopes locally.
fee_payer_key = os.environ.get("FEE_PAYER_KEY")
fee_payer = TempoAccount.from_key(fee_payer_key) if fee_payer_key else None

server = Mpp(
    methods=tempo.charge(
        chain_id=TESTNET_CHAIN_ID,
        currency=PATH_USD,
        recipient=DESTINATION,
        fee_payer=fee_payer,
    ),
)


@app.get("/free")
async def free_endpoint():
    """A free endpoint that anyone can access."""
    return {"message": "This content is free!"}


@app.get("/paid")
async def paid_endpoint(request: Request):
    """A paid endpoint that requires payment to access."""
    handler = server.charge(amount="0.001", fee_payer=fee_payer is not None)
    result = await handler(
        PaymentRequest(request.method, str(request.url), headers=dict(request.headers))
    )
    if result.status != 200:
        challenge = result.challenge
        return Response(challenge.body, challenge.status, headers=dict(challenge.headers))

    return result.with_receipt(
        JSONResponse(
            {
                "message": "This is paid content!",
                "payer": result.credential.source,
                "tx": result.receipt.reference,
            }
        )
    )


@app.get("/paid-decorator")
@pay(server.charge(amount="0.001"))
async def paid_decorator_endpoint(request: Request, credential: Credential, receipt: Receipt):
    """A paid endpoint using the pay() decorator."""
    return {
        "message": "This is paid content!",
        "payer": credential.source,
        "tx": receipt.reference,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
