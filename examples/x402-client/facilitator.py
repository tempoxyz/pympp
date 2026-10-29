"""Coinbase's official x402 facilitator, settling on the chain, behind HTTP.

Exposes the facilitator API the x402 resource server calls: POST /verify,
POST /settle and GET /supported.
"""

import asyncio
import os
from typing import Any

import uvicorn
from common import NETWORK, RPC_URL, facilitator_account
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from x402 import x402FacilitatorSync
from x402.mechanisms.evm import FacilitatorWeb3Signer
from x402.mechanisms.evm.exact import register_exact_evm_facilitator
from x402.schemas import PaymentPayload, PaymentRequirements

facilitator = x402FacilitatorSync()
register_exact_evm_facilitator(
    facilitator,
    FacilitatorWeb3Signer(private_key=facilitator_account.key.hex(), rpc_url=RPC_URL),
    networks=NETWORK,
)


def dump(result: Any) -> JSONResponse:
    return JSONResponse(result.model_dump(by_alias=True, exclude_none=True))


async def parse(request: Request) -> tuple[PaymentPayload, PaymentRequirements]:
    body = await request.json()
    return (
        PaymentPayload.model_validate(body["paymentPayload"]),
        PaymentRequirements.model_validate(body["paymentRequirements"]),
    )


async def verify(request: Request) -> JSONResponse:
    # web3 blocks, so the sync facilitator runs in a thread.
    return dump(await asyncio.to_thread(facilitator.verify, *await parse(request)))


async def settle(request: Request) -> JSONResponse:
    return dump(await asyncio.to_thread(facilitator.settle, *await parse(request)))


async def supported(request: Request) -> JSONResponse:
    return dump(facilitator.get_supported())


app = Starlette(
    routes=[
        Route("/verify", verify, methods=["POST"]),
        Route("/settle", settle, methods=["POST"]),
        Route("/supported", supported, methods=["GET"]),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "4022")))
