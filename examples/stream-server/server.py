"""Streaming payment server using payment channels.

Demonstrates per-token pricing for a chat-like SSE endpoint.
Clients open a payment channel and stream incremental vouchers
as they consume tokens.
"""

import asyncio
import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from mpay import Challenge
from mpay.methods.tempo import StreamIntent, tempo
from mpay.methods.tempo.stream.storage import MemoryStorage
from mpay.server import Mpay

app = FastAPI(
    title="Stream Payment Server",
    description="SSE endpoint with per-token streaming payments",
)

DESTINATION = os.environ.get(
    "PAYMENT_DESTINATION",
    "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
)
PATH_USD = "0x20c0000000000000000000000000000000000001"
ESCROW = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
RPC_URL = os.environ.get("TEMPO_RPC_URL", "https://rpc.moderato.tempo.xyz/")
PRICE_PER_TOKEN = "0.000075"

storage = MemoryStorage()

mpay = Mpay.create(
    method=tempo(
        currency=PATH_USD,
        recipient=DESTINATION,
        intents={
            "stream": StreamIntent(
                storage=storage,
                rpc_url=RPC_URL,
                escrow_contract=ESCROW,
            ),
        },
    ),
)


def generate_tokens(prompt: str) -> list[str]:
    """Generate mock response tokens."""
    return [
        "The",
        " answer",
        " to",
        " your",
        " question",
        " is",
        " 42.",
        " That",
        "'s",
        " always",
        " the",
        " answer.",
    ]


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/chat")
async def chat(request: Request, prompt: str = "Hello!"):
    """SSE chat endpoint protected by streaming payment."""
    result = await mpay.stream(
        authorization=request.headers.get("Authorization"),
        amount=PRICE_PER_TOKEN,
        unit_type="token",
    )

    if isinstance(result, Challenge):
        return JSONResponse(
            status_code=402,
            content={"error": "Payment required"},
            headers={
                "WWW-Authenticate": result.to_www_authenticate(mpay.realm),
            },
        )

    credential, receipt = result

    tokens = generate_tokens(prompt)

    async def event_stream():
        for token in tokens:
            data = json.dumps({"token": token})
            yield f"data: {data}\n\n"
            await asyncio.sleep(0.05)
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Payment-Receipt": receipt.to_payment_receipt(),
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
