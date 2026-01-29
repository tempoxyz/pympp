"""Payment-protected API server using FastAPI and the Machine Payments Protocol."""

import os
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mpay import Challenge, Credential, Receipt
from mpay.methods.tempo import TempoMethod
from mpay.server import Mpay

app = FastAPI(
    title="Payment-Protected API",
    description="Example API demonstrating Machine Payments Protocol payment protection",
)

RPC_URL = os.environ.get("TEMPO_RPC_URL", "https://rpc.testnet.tempo.xyz/")
DESTINATION = os.environ.get(
    "PAYMENT_DESTINATION", "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
)
SECRET_KEY = os.environ.get("PAYMENT_SECRET_KEY", "example-server-secret-key")
ALPHA_USD = "0x20c0000000000000000000000000000000000001"

# Create payment handler with bound secret_key
payment = Mpay(
    method=TempoMethod(rpc_url=RPC_URL),
    realm="localhost:8000",
    secret_key=SECRET_KEY,
)


def get_payment_request():
    """Build payment request with fresh expiration."""
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    if expires.endswith("+00:00"):
        expires = expires[:-6] + "Z"
    return {
        "amount": "1000",
        "currency": ALPHA_USD,
        "recipient": DESTINATION,
        "expires": expires,
        "methodDetails": {"feePayer": True},
    }


@app.get("/free")
async def free_endpoint():
    """A free endpoint that anyone can access."""
    return {"message": "This content is free!"}


@app.get("/paid")
async def paid_endpoint(request: Request):
    """A paid endpoint that requires payment to access."""
    result = await payment.charge(
        authorization=request.headers.get("Authorization"),
        request=get_payment_request(),
    )

    if isinstance(result, Challenge):
        return JSONResponse(
            status_code=402,
            content={"error": "Payment required"},
            headers={"WWW-Authenticate": result.to_www_authenticate(payment.realm)},
        )

    credential, receipt = result
    return {
        "message": "This is paid content!",
        "payer": credential.source,
        "tx": receipt.reference,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
