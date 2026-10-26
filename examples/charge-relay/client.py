"""Fund a disposable Moderato account and call the paid example route."""

import asyncio
import json
import os
import secrets

import httpx

from mpp import Receipt
from mpp.client import Mpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID, TESTNET_RPC_URL
from mpp.methods.tempo._rpc import _rpc_call, _tip20_balance


async def fund(account: TempoAccount) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        await _rpc_call(TESTNET_RPC_URL, "tempo_fundAddress", [account.address], client=client)
        for _ in range(60):
            balance = await _tip20_balance(
                TESTNET_RPC_URL,
                PATH_USD,
                account.address,
                client=client,
            )
            if balance > 0:
                return
            await asyncio.sleep(0.5)
    raise RuntimeError("Moderato funding was not visible after 30 seconds")


async def main() -> None:
    account = TempoAccount.from_key(
        os.environ.get("TEMPO_PRIVATE_KEY", "0x" + secrets.token_hex(32))
    )
    await fund(account)

    method = tempo.charge(account=account, chain_id=TESTNET_CHAIN_ID, rpc_url=TESTNET_RPC_URL)
    async with Mpp(methods=[method]) as mpp:
        response = await mpp.fetch(os.environ.get("PAYMENT_URL", "http://127.0.0.1:8000/photo"))
    response.raise_for_status()

    receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
    print(
        json.dumps(
            {
                "payer": account.address,
                "response": response.json(),
                "status": response.status_code,
                "receipt": {
                    "method": receipt.method,
                    "reference": receipt.reference,
                    "status": receipt.status,
                    "timestamp": receipt.timestamp.isoformat(),
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
