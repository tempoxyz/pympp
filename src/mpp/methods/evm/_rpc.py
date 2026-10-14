"""Low-level JSON-RPC helper for the EVM payment method."""

from __future__ import annotations

from typing import Any

from mpp._defaults import DEFAULT_TIMEOUT


async def _rpc_call(
    rpc_url: str,
    method: str,
    params: list[Any],
    *,
    client: Any | None = None,
) -> Any:
    """Make a JSON-RPC call, raising ``RuntimeError`` on an RPC error."""
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
