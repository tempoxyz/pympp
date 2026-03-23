"""Stripe payment-protected API server.

Demonstrates the Machine Payments Protocol with Stripe's Shared Payment
Token (SPT) flow. Two endpoints:

- POST /api/create-spt  — proxy for SPT creation (requires secret key)
- GET  /api/fortune     — paid endpoint ($1.00 per fortune)
"""

import base64
import os
import random

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mpp import Challenge
from mpp.methods.stripe import ChargeIntent, stripe
from mpp.server import Mpp

app = FastAPI(title="Stripe Fortune Server")

SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]

server = Mpp.create(
    method=stripe(
        network_id=os.environ.get("STRIPE_NETWORK_ID", "internal"),
        payment_method_types=["card"],
        currency="usd",
        decimals=2,
        recipient=os.environ.get("STRIPE_ACCOUNT", "acct_default"),
        intents={"charge": ChargeIntent(secret_key=SECRET_KEY)},
    ),
)

FORTUNES = [
    "A beautiful, smart, and loving person will come into your life.",
    "A dubious friend may be an enemy in camouflage.",
    "A faithful friend is a strong defense.",
    "A fresh start will put you on your way.",
    "A golden egg of opportunity falls into your lap this month.",
    "A good time to finish up old tasks.",
    "A light heart carries you through all the hard times ahead.",
    "A smooth long journey! Great expectations.",
]


@app.post("/api/create-spt")
async def create_spt(request: Request):
    """Proxy endpoint for SPT creation.

    The client calls this with a payment method ID and challenge details.
    We call Stripe's test SPT endpoint using our secret key.
    """
    body = await request.json()

    params = {
        "payment_method": body["paymentMethod"],
        "usage_limits[currency]": body["currency"],
        "usage_limits[max_amount]": body["amount"],
        "usage_limits[expires_at]": str(body["expiresAt"]),
    }
    if body.get("networkId"):
        params["seller_details[network_id]"] = body["networkId"]

    import httpx

    auth_value = base64.b64encode(f"{SECRET_KEY}:".encode()).decode()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.stripe.com/v1/test_helpers/shared_payment/granted_tokens",
            headers={
                "Authorization": f"Basic {auth_value}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=params,
        )
        response.raise_for_status()
        result = response.json()

    return {"spt": result["id"]}


@app.get("/api/fortune")
async def fortune(request: Request):
    """Paid endpoint — returns a fortune for $1.00."""
    result = await server.charge(
        authorization=request.headers.get("Authorization"),
        amount="1",
    )

    if isinstance(result, Challenge):
        return JSONResponse(
            status_code=402,
            content={"error": "Payment required"},
            headers={"WWW-Authenticate": result.to_www_authenticate(server.realm)},
        )

    credential, receipt = result
    return {
        "fortune": random.choice(FORTUNES),
        "receipt": receipt.reference,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
