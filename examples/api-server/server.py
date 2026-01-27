"""Payment-protected API server using FastAPI and the Machine Payments Protocol."""

import os
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Request

from mpay import Credential, Receipt
from mpay.methods.tempo import ChargeIntent
from mpay.server import requires_payment

app = FastAPI(
    title="Payment-Protected API",
    description="Example API demonstrating Machine Payments Protocol payment protection",
)

RPC_URL = os.environ.get("TEMPO_RPC_URL", "https://rpc.testnet.tempo.xyz/")
DESTINATION = os.environ.get(
    "PAYMENT_DESTINATION", "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
)

intent = ChargeIntent(rpc_url=RPC_URL)


def get_payment_request(_request=None):
    """Build payment request with fresh expiration."""
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    if expires.endswith("+00:00"):
        expires = expires[:-6] + "Z"
    return {
        "amount": "1000",
        "currency": "0x20c0000000000000000000000000000000000001",
        "recipient": DESTINATION,
        "expires": expires,
        "methodDetails": {"feePayer": True},
    }


@app.get("/free")
async def free_endpoint():
    """A free endpoint that anyone can access."""
    return {"message": "This content is free!"}


@app.get("/paid")
@requires_payment(intent=intent, request=get_payment_request, realm="localhost:8000")
async def paid_endpoint(request: Request, credential: Credential, receipt: Receipt):
    """A paid endpoint that requires payment to access."""
    return {
        "message": "This is paid content!",
        "payer": credential.source,
        "tx": receipt.reference,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
