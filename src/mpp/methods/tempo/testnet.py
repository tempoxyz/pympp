"""Tempo testnet utilities."""
from __future__ import annotations

import httpx

from mpp.methods.tempo._defaults import CHAIN_ID, TESTNET_RPC_URL, rpc_url_for_chain


async def fund_testnet_address(
    address: str,
    rpc_url: str = TESTNET_RPC_URL,
) -> bool:
    """Fund an address via the Tempo testnet faucet RPC method.

    Uses the ``tempo_fundAddress`` JSON-RPC method available on the Moderato
    testnet. Mainnet calls will fail — this is intentional.

    Args:
        address: The EVM address to fund (e.g. ``"0xABCD...1234"``).
        rpc_url: Testnet RPC URL. Defaults to Moderato testnet.

    Returns:
        ``True`` if the faucet request was accepted, ``False`` otherwise.

    Example::

        from mpp.methods.tempo.testnet import fund_testnet_address

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


async def check_connection(chain_id: int = CHAIN_ID) -> dict:
    """Check connectivity to a Tempo RPC endpoint.

    Uses :func:`mpp.methods.tempo._defaults.rpc_url_for_chain` to resolve
    the RPC URL for known chain IDs (4217 mainnet, 42431 Moderato testnet).

    Returns a dict with ``connected`` (bool), ``chain_id`` (int), and
    ``block`` (int) on success, or ``connected=False`` with an ``error``
    key on failure.

    Example::

        from mpp.methods.tempo.testnet import check_connection
        from mpp.methods.tempo import TESTNET_CHAIN_ID

        # mainnet
        info = await check_connection()
        # {"connected": True, "chain_id": 4217, "block": 1234567}

        # testnet
        info = await check_connection(chain_id=TESTNET_CHAIN_ID)
    """
    rpc_url = rpc_url_for_chain(chain_id)
    block_payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
    chain_payload = {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 2}
    async with httpx.AsyncClient() as client:
        try:
            r1 = await client.post(rpc_url, json=block_payload, timeout=10.0)
            r2 = await client.post(rpc_url, json=chain_payload, timeout=10.0)
            block = int(r1.json()["result"], 16)
            detected_chain_id = int(r2.json()["result"], 16)
            return {"connected": True, "chain_id": detected_chain_id, "block": block}
        except Exception as e:
            return {"connected": False, "error": str(e)}
