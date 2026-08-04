"""Fund a disposable Moderato account and pay the relay-backed example."""

import asyncio
import json
import os
import secrets

import httpx

from mpp import Receipt
from mpp.client import Client
from mpp.methods.tempo import ChargeIntent, TempoAccount, tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID, TESTNET_RPC_URL


async def rpc(client: httpx.AsyncClient, method: str, params: list[object]) -> object:
    response = await client.post(
        TESTNET_RPC_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    response.raise_for_status()
    result = response.json()
    if "error" in result:
        error = result["error"]
        detail = error.get("message", error) if isinstance(error, dict) else error
        raise RuntimeError(str(detail))
    return result["result"]


async def fund(account: TempoAccount) -> None:
    """Fund a test account and wait until its pathUSD balance is visible."""
    balance_call = "0x70a08231" + "0" * 24 + account.address[2:].lower()
    async with httpx.AsyncClient(timeout=30) as client:
        await rpc(client, "tempo_fundAddress", [account.address])
        for _ in range(60):
            balance = await rpc(
                client,
                "eth_call",
                [{"to": PATH_USD, "data": balance_call}, "latest"],
            )
            if int(str(balance), 16) > 0:
                return
            await asyncio.sleep(0.5)
    raise RuntimeError("Moderato faucet funding was not visible after 30 seconds")


async def main() -> None:
    account = TempoAccount.from_key(
        os.environ.get("TEMPO_PRIVATE_KEY", "0x" + secrets.token_hex(32))
    )
    await fund(account)

    method = tempo(
        account=account,
        chain_id=TESTNET_CHAIN_ID,
        rpc_url=TESTNET_RPC_URL,
        intents={"charge": ChargeIntent()},
    )
    url = os.environ.get("PAYMENT_URL", "http://127.0.0.1:5173/api/photo")
    async with Client(methods=[method]) as client:
        response = await client.get(url)
    response.raise_for_status()

    receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
    print(
        json.dumps(
            {
                "body": response.json(),
                "payer": account.address,
                "receipt": {
                    "method": receipt.method,
                    "reference": receipt.reference,
                    "status": receipt.status,
                    "timestamp": receipt.timestamp.isoformat(),
                },
                "status": response.status_code,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
