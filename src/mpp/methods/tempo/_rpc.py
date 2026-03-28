"""Low-level JSON-RPC helpers for Tempo transactions."""

from __future__ import annotations

import asyncio
from typing import Any

from mpp._defaults import DEFAULT_TIMEOUT


async def _rpc_call(
    rpc_url: str,
    method: str,
    params: list[Any],
    *,
    client: Any | None = None,
) -> Any:
    """Make a JSON-RPC call."""
    import httpx

    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}

    if client is not None:
        resp = await client.post(rpc_url, json=payload)
    else:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
            resp = await c.post(rpc_url, json=payload)

    resp.raise_for_status()
    result = resp.json()
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


async def get_tx_params(
    rpc_url: str, sender: str, *, client: Any | None = None
) -> tuple[int, int, int]:
    """Fetch chain_id, nonce, and gas_price for building a transaction.

    All three RPC calls are issued concurrently via asyncio.gather.
    """
    chain_id_hex, nonce_hex, gas_hex = await asyncio.gather(
        _rpc_call(rpc_url, "eth_chainId", [], client=client),
        _rpc_call(
            rpc_url,
            "eth_getTransactionCount",
            [sender, "pending"],
            client=client,
        ),
        _rpc_call(rpc_url, "eth_gasPrice", [], client=client),
    )
    return int(chain_id_hex, 16), int(nonce_hex, 16), int(gas_hex, 16)


async def estimate_gas(
    rpc_url: str,
    from_addr: str,
    to: str,
    data: str,
    *,
    client: Any | None = None,
) -> int:
    """Estimate gas for a call via eth_estimateGas."""
    result = await _rpc_call(
        rpc_url,
        "eth_estimateGas",
        [{"from": from_addr, "to": to, "data": data}, "latest"],
        client=client,
    )
    return int(result, 16)
