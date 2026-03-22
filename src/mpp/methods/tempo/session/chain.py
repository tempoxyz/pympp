"""On-chain escrow reads and transaction broadcast for session payments.

Ported from mpp-rs ``session_method.rs`` on-chain helpers.
Uses ``eth_abi`` for ABI encoding/decoding and ``httpx`` for JSON-RPC
calls (same pattern as ``ChargeIntent``).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from eth_abi import decode, encode
from eth_utils import keccak

from mpp.errors import VerificationError
from mpp.methods.tempo._rpc import rpc_error_msg as _rpc_error_msg

if TYPE_CHECKING:
    import httpx

# getChannel(bytes32) selector — keccak256("getChannel(bytes32)")[:4]
_GET_CHANNEL_SELECTOR = keccak(b"getChannel(bytes32)")[:4]

# Receipt polling constants (same as ChargeIntent).
MAX_RECEIPT_RETRY_ATTEMPTS = 20
RECEIPT_RETRY_DELAY_SECONDS = 0.5


@dataclass(frozen=True, slots=True)
class OnChainChannel:
    """On-chain channel state returned by ``escrow.getChannel()``."""

    payer: str
    payee: str
    token: str
    authorized_signer: str
    deposit: int
    settled: int
    close_requested_at: int
    finalized: bool


async def get_on_chain_channel(
    client: httpx.AsyncClient,
    rpc_url: str,
    escrow_contract: str,
    channel_id: str,
) -> OnChainChannel:
    """Read channel state from the escrow contract via ``eth_call``.

    Decodes the return tuple:
    ``(bool finalized, uint64 closeRequestedAt, address payer,
    address payee, address token, address authorizedSigner,
    uint128 deposit, uint128 settled)``
    """
    try:
        channel_id_bytes = bytes.fromhex(
            channel_id[2:] if channel_id.startswith("0x") else channel_id
        )
    except ValueError as e:
        raise VerificationError(f"Invalid channel ID: {e}") from e
    calldata = "0x" + (_GET_CHANNEL_SELECTOR + encode(["bytes32"], [channel_id_bytes])).hex()

    response = await client.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": escrow_contract, "data": calldata}, "latest"],
            "id": 1,
        },
    )
    response.raise_for_status()
    result = response.json()

    if "error" in result:
        raise VerificationError(f"eth_call getChannel failed: {_rpc_error_msg(result)}")

    raw = result.get("result", "0x")
    if raw == "0x" or len(raw) < 66:
        raise VerificationError("getChannel returned empty result")

    return_bytes = bytes.fromhex(raw[2:])
    decoded = decode(
        ["bool", "uint64", "address", "address", "address", "address", "uint128", "uint128"],
        return_bytes,
    )

    return OnChainChannel(
        finalized=decoded[0],
        close_requested_at=decoded[1],
        payer=decoded[2],
        payee=decoded[3],
        token=decoded[4],
        authorized_signer=decoded[5],
        deposit=decoded[6],
        settled=decoded[7],
    )


async def broadcast_and_confirm(
    client: httpx.AsyncClient,
    rpc_url: str,
    raw_tx: str,
) -> str:
    """Broadcast a signed transaction and poll for receipt.

    Returns the transaction hash on success.
    Raises ``VerificationError`` on failure.
    """
    response = await client.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 1,
        },
    )
    response.raise_for_status()
    result = response.json()

    if "error" in result:
        raise VerificationError(f"Transaction submission failed: {_rpc_error_msg(result)}")

    tx_hash = result.get("result")
    if not tx_hash:
        raise VerificationError("No transaction hash returned")

    receipt_data = None
    for attempt in range(MAX_RECEIPT_RETRY_ATTEMPTS):
        receipt_response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1,
            },
        )
        receipt_response.raise_for_status()
        receipt_result = receipt_response.json()

        if "error" in receipt_result:
            raise VerificationError("Failed to fetch transaction receipt")

        receipt_data = receipt_result.get("result")
        if receipt_data:
            break

        if attempt < MAX_RECEIPT_RETRY_ATTEMPTS - 1:
            await asyncio.sleep(RECEIPT_RETRY_DELAY_SECONDS)

    if not receipt_data:
        raise VerificationError("Transaction receipt not found after retries")

    if receipt_data.get("status") != "0x1":
        raise VerificationError("Transaction reverted")

    return tx_hash
