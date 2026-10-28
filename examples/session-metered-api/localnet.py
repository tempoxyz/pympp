"""Small JSON-RPC helpers shared by server.py and agent.py."""

import asyncio
from typing import Any

import httpx

LOCALNET_CHAIN_ID = 1337


async def rpc(rpc_url: str, method: str, *params: object) -> Any:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}
        )
    body = response.json()
    if "error" in body:
        raise RuntimeError(f"{method} failed: {body['error']}")
    return body["result"]


async def chain_id(rpc_url: str) -> int:
    return int(await rpc(rpc_url, "eth_chainId"), 16)


async def balance(rpc_url: str, token: str, address: str) -> int:
    data = "0x70a08231" + address.removeprefix("0x").lower().zfill(64)
    return int(await rpc(rpc_url, "eth_call", {"to": token, "data": data}, "latest"), 16)


async def fund_on_localnet(rpc_url: str, token: str, *addresses: str) -> None:
    """Fund addresses from the localnet faucet (`tempo_fundAddress`); no-op on other chains."""
    if await chain_id(rpc_url) != LOCALNET_CHAIN_ID:
        return
    for address in addresses:
        await rpc(rpc_url, "tempo_fundAddress", address)
        for _ in range(100):
            if await balance(rpc_url, token, address) > 0:
                break
            await asyncio.sleep(0.2)
        else:
            raise RuntimeError(f"{address} was not funded")
