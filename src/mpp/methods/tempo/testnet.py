"""Tempo testnet utilities."""
from __future__ import annotations

import httpx

TEMPO_TESTNET_RPC = "https://rpc.moderato.tempo.xyz"
TEMPO_MAINNET_RPC = "https://rpc.tempo.xyz"
TEMPO_TESTNET_CHAIN_ID = 42431
TEMPO_MAINNET_CHAIN_ID = 4217


async def fund_testnet_address(address: str, rpc_url: str = TEMPO_TESTNET_RPC) -> bool:
    """Fund an address via the Tempo testnet faucet RPC method.

    Uses the ``tempo_fundAddress`` JSON-RPC method available on the Moderato
    testnet. Mainnet calls will fail — this is intentional.

    Args:
        address: The EVM address to fund (e.g. ``"0xABCD...1234"``).
        rpc_url: Testnet RPC URL. Defaults to Moderato testnet.

    Returns:
        ``True`` if the faucet request was accepted, ``False`` otherwise.

    Example::

        funded = await fund_testnet_address("0xYourAddress")

    Docs: https://docs.tempo.xyz/quickstart/faucet
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "tempo_fundAddress",
        "params": [address],
        "id": 1,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(rpc_url, json=payload, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return "error" not in data
        except Exception:
            return False


async def check_connection(rpc_url: str = TEMPO_MAINNET_RPC) -> dict:
    """Check connectivity to a Tempo RPC endpoint.

    Returns a dict with ``connected`` (bool), ``chain_id`` (int), and
    ``block`` (int) on success, or ``connected=False`` with an ``error``
    key on failure.

    Example::

        info = await check_connection()
        # {"connected": True, "chain_id": 4217, "block": 1234567}
    """
    payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
    chain_payload = {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 2}
    async with httpx.AsyncClient() as client:
        try:
            r1 = await client.post(rpc_url, json=payload, timeout=10.0)
            r2 = await client.post(rpc_url, json=chain_payload, timeout=10.0)
            block = int(r1.json()["result"], 16)
            chain_id = int(r2.json()["result"], 16)
            return {"connected": True, "chain_id": chain_id, "block": block}
        except Exception as e:
            return {"connected": False, "error": str(e)}
