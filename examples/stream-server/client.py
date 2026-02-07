"""Stream payment client example.

Connects to the stream server, opens a payment channel,
and consumes an SSE endpoint with per-token streaming payments.
"""

import asyncio
import json
import os
import sys

import httpx

from mpay.client import PaymentTransport
from mpay.methods.tempo import StreamMethod, TempoAccount
from mpay.methods.tempo._defaults import ALPHA_USD, ESCROW_CONTRACT, TESTNET_RPC_URL

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY", "")
RPC_URL = os.environ.get("TEMPO_RPC_URL", TESTNET_RPC_URL)


async def main() -> None:
    if not PRIVATE_KEY:
        print("Set PRIVATE_KEY env var (0x-prefixed hex)")
        sys.exit(1)

    account = TempoAccount.from_key(PRIVATE_KEY)
    print(f"Client account: {account.address}")

    method = StreamMethod(
        account=account,
        deposit=10_000_000,
        rpc_url=RPC_URL,
        escrow_contract=ESCROW_CONTRACT,
        currency=ALPHA_USD,
    )

    prompt = sys.argv[1] if len(sys.argv) > 1 else "Tell me something interesting"
    print(f"\nPrompt: {prompt}")

    transport = PaymentTransport(methods=[method])
    async with httpx.AsyncClient(transport=transport, timeout=60.0) as client:
        response = await client.get(
            f"{BASE_URL}/api/chat?prompt={prompt}",
        )

        if not response.is_success:
            print(f"Error: {response.status_code}")
            print(response.text)
            sys.exit(1)

        receipt = response.headers.get("payment-receipt")
        if receipt:
            print(f"Payment-Receipt: {receipt[:40]}...")

        for line in response.text.split("\n"):
            if not line.startswith("data: "):
                continue
            data = line[6:].strip()
            if data == "[DONE]":
                continue
            try:
                token = json.loads(data)["token"]
                print(token, end="", flush=True)
            except (json.JSONDecodeError, KeyError):
                pass

    print("\n\nStream complete.")


if __name__ == "__main__":
    asyncio.run(main())
