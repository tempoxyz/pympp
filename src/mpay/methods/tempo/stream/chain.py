"""On-chain escrow contract interaction via JSON-RPC.

Handles reading channel state, broadcasting transactions,
and submitting settle/close operations against the
TempoStreamChannel escrow contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from eth_abi import decode, encode
from eth_utils import keccak

from mpay.methods.tempo.stream.errors import (
    StreamError,
)

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount
    from mpay.methods.tempo.stream.types import SignedVoucher

UINT128_MAX = 2**128 - 1

# ──────────────────────────────────────────────────────────────
# Function selectors (keccak256 of canonical signature, first 4 bytes)
# ──────────────────────────────────────────────────────────────

_GET_CHANNEL_SELECTOR = keccak(text="getChannel(bytes32)")[:4]
_SETTLE_SELECTOR = keccak(text="settle(bytes32,uint128,bytes)")[:4]
_CLOSE_SELECTOR = keccak(text="close(bytes32,uint128,bytes)")[:4]
_OPEN_SELECTOR = keccak(
    text="open(address,address,uint128,bytes32,address)"
)[:4]
_TOP_UP_SELECTOR = keccak(text="topUp(bytes32,uint128)")[:4]
_COMPUTE_CHANNEL_ID_SELECTOR = keccak(
    text="computeChannelId(address,address,address,uint128,bytes32,address)"
)[:4]
_APPROVE_SELECTOR = keccak(text="approve(address,uint256)")[:4]

DEFAULT_TIMEOUT = 30.0
MAX_RECEIPT_ATTEMPTS = 30
RECEIPT_RETRY_DELAY = 1.0


@dataclass
class OnChainChannel:
    """On-chain channel state from the escrow contract."""

    payer: str
    payee: str
    token: str
    authorized_signer: str
    deposit: int  # uint128
    settled: int  # uint128
    close_requested_at: int  # uint64
    finalized: bool


@dataclass
class BroadcastResult:
    """Result of broadcasting a transaction."""

    tx_hash: str | None
    on_chain: OnChainChannel


# ──────────────────────────────────────────────────────────────
# ABI encoding helpers
# ──────────────────────────────────────────────────────────────


def _encode_get_channel(channel_id: str) -> str:
    """Encode getChannel(bytes32) call data."""
    data = encode(["bytes32"], [bytes.fromhex(channel_id[2:])])
    return "0x" + _GET_CHANNEL_SELECTOR.hex() + data.hex()


def _decode_get_channel(data: bytes) -> OnChainChannel:
    """Decode getChannel return data into OnChainChannel."""
    payer, payee, token, auth_signer, deposit, settled, close_req, finalized = decode(
        ["address", "address", "address", "address", "uint128", "uint128", "uint64", "bool"],
        data,
    )
    return OnChainChannel(
        payer=payer,
        payee=payee,
        token=token,
        authorized_signer=auth_signer,
        deposit=deposit,
        settled=settled,
        close_requested_at=close_req,
        finalized=finalized,
    )


def _encode_compute_channel_id(
    payer: str,
    payee: str,
    token: str,
    deposit: int,
    salt: str,
    authorized_signer: str,
) -> str:
    """Encode computeChannelId call data."""
    data = encode(
        ["address", "address", "address", "uint128", "bytes32", "address"],
        [payer, payee, token, deposit, bytes.fromhex(salt[2:]), authorized_signer],
    )
    return "0x" + _COMPUTE_CHANNEL_ID_SELECTOR.hex() + data.hex()


def encode_settle_call(channel_id: str, cumulative_amount: int, signature: str) -> str:
    """Encode settle(bytes32,uint128,bytes) call data."""
    data = encode(
        ["bytes32", "uint128", "bytes"],
        [bytes.fromhex(channel_id[2:]), cumulative_amount, bytes.fromhex(signature[2:])],
    )
    return "0x" + _SETTLE_SELECTOR.hex() + data.hex()


def encode_close_call(channel_id: str, cumulative_amount: int, signature: str) -> str:
    """Encode close(bytes32,uint128,bytes) call data."""
    data = encode(
        ["bytes32", "uint128", "bytes"],
        [bytes.fromhex(channel_id[2:]), cumulative_amount, bytes.fromhex(signature[2:])],
    )
    return "0x" + _CLOSE_SELECTOR.hex() + data.hex()


def encode_open_call(
    payee: str,
    token: str,
    deposit: int,
    salt: str,
    authorized_signer: str,
) -> str:
    """Encode open(address,address,uint128,bytes32,address) call data."""
    data = encode(
        ["address", "address", "uint128", "bytes32", "address"],
        [payee, token, deposit, bytes.fromhex(salt[2:]), authorized_signer],
    )
    return "0x" + _OPEN_SELECTOR.hex() + data.hex()


def encode_top_up_call(channel_id: str, additional_deposit: int) -> str:
    """Encode topUp(bytes32,uint128) call data."""
    data = encode(
        ["bytes32", "uint128"],
        [bytes.fromhex(channel_id[2:]), additional_deposit],
    )
    return "0x" + _TOP_UP_SELECTOR.hex() + data.hex()


def encode_approve_call(spender: str, amount: int) -> str:
    """Encode approve(address,uint256) call data."""
    data = encode(["address", "uint256"], [spender, amount])
    return "0x" + _APPROVE_SELECTOR.hex() + data.hex()


# ──────────────────────────────────────────────────────────────
# JSON-RPC helpers
# ──────────────────────────────────────────────────────────────


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
        raise StreamError(f"RPC error: {result['error']}")
    return result["result"]


async def get_on_chain_channel(
    rpc_url: str,
    escrow_contract: str,
    channel_id: str,
    *,
    client: Any | None = None,
) -> OnChainChannel:
    """Read channel state from the escrow contract via eth_call."""
    call_data = _encode_get_channel(channel_id)
    result = await _rpc_call(
        rpc_url,
        "eth_call",
        [{"to": escrow_contract, "data": call_data}, "latest"],
        client=client,
    )
    return _decode_get_channel(bytes.fromhex(result[2:]))


async def compute_channel_id(
    rpc_url: str,
    escrow_contract: str,
    payer: str,
    payee: str,
    token: str,
    deposit: int,
    salt: str,
    authorized_signer: str,
    *,
    client: Any | None = None,
) -> str:
    """Compute channelId via the escrow contract."""
    call_data = _encode_compute_channel_id(
        payer, payee, token, deposit, salt, authorized_signer
    )
    result = await _rpc_call(
        rpc_url,
        "eth_call",
        [{"to": escrow_contract, "data": call_data}, "latest"],
        client=client,
    )
    return result  # Already 0x-prefixed bytes32 hex


def assert_uint128(amount: int) -> None:
    """Validate amount is within uint128 range."""
    if amount < 0 or amount > UINT128_MAX:
        raise StreamError("cumulativeAmount exceeds uint128 range")


async def broadcast_open_transaction(
    rpc_url: str,
    serialized_transaction: str,
    escrow_contract: str,
    channel_id: str,
    recipient: str,
    currency: str,
    *,
    fee_payer: TempoAccount | None = None,
    client: Any | None = None,
) -> BroadcastResult:
    """Broadcast an open transaction and verify on-chain state.

    Broadcasts the client's signed transaction, then reads the resulting
    channel state from the escrow contract to validate correctness.
    """
    tx_hash: str | None = None
    try:
        result = await _rpc_call(
            rpc_url,
            "eth_sendRawTransaction",
            [serialized_transaction],
            client=client,
        )
        tx_hash = result

        receipt = await _wait_for_receipt(rpc_url, tx_hash, client=client)
        if receipt.get("status") != "0x1":
            raise StreamError(f"open transaction reverted: {tx_hash}")

    except Exception as e:
        # If broadcast fails, check if channel already exists on-chain
        on_chain = await get_on_chain_channel(
            rpc_url, escrow_contract, channel_id, client=client
        )
        if on_chain.deposit > 0:
            return BroadcastResult(tx_hash=None, on_chain=on_chain)
        raise e

    on_chain = await get_on_chain_channel(
        rpc_url, escrow_contract, channel_id, client=client
    )
    return BroadcastResult(tx_hash=tx_hash, on_chain=on_chain)


async def broadcast_top_up_transaction(
    rpc_url: str,
    serialized_transaction: str,
    escrow_contract: str,
    channel_id: str,
    declared_deposit: int,
    previous_deposit: int,
    *,
    fee_payer: TempoAccount | None = None,
    client: Any | None = None,
) -> tuple[str, int]:
    """Broadcast a topUp transaction and return (txHash, newDeposit).

    Broadcasts the transaction, then verifies the deposit increased
    by reading on-chain state.
    """
    result = await _rpc_call(
        rpc_url,
        "eth_sendRawTransaction",
        [serialized_transaction],
        client=client,
    )
    tx_hash = result

    receipt = await _wait_for_receipt(rpc_url, tx_hash, client=client)
    if receipt.get("status") != "0x1":
        raise StreamError(f"topUp transaction reverted: {tx_hash}")

    on_chain = await get_on_chain_channel(
        rpc_url, escrow_contract, channel_id, client=client
    )
    if on_chain.deposit <= previous_deposit:
        raise StreamError("channel deposit did not increase after topUp")

    return tx_hash, on_chain.deposit


async def settle_on_chain(
    rpc_url: str,
    escrow_contract: str,
    voucher: SignedVoucher,
    account: TempoAccount,
    *,
    client: Any | None = None,
) -> str:
    """Submit a settle transaction on-chain.

    Builds a TempoTransaction with the settle() call and broadcasts it.

    Returns:
        Transaction hash.
    """
    from pytempo import Call, TempoTransaction

    assert_uint128(voucher.cumulative_amount)

    call_data = encode_settle_call(
        voucher.channel_id,
        voucher.cumulative_amount,
        voucher.signature,
    )

    chain_id, nonce, gas_price = await get_tx_params(rpc_url, account.address, client=client)

    tx = TempoTransaction.create(
        chain_id=chain_id,
        gas_limit=200_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        calls=(Call.create(to=escrow_contract, value=0, data=call_data),),
    )
    signed = tx.sign(account.private_key)
    raw_tx = "0x" + signed.encode().hex()

    tx_hash = await _rpc_call(
        rpc_url, "eth_sendRawTransaction", [raw_tx], client=client
    )

    receipt = await _wait_for_receipt(rpc_url, tx_hash, client=client)
    if receipt.get("status") != "0x1":
        raise StreamError(f"settle transaction reverted: {tx_hash}")

    return tx_hash


async def close_on_chain(
    rpc_url: str,
    escrow_contract: str,
    voucher: SignedVoucher,
    account: TempoAccount,
    *,
    client: Any | None = None,
) -> str:
    """Submit a close transaction on-chain.

    Returns:
        Transaction hash.
    """
    from pytempo import Call, TempoTransaction

    assert_uint128(voucher.cumulative_amount)

    call_data = encode_close_call(
        voucher.channel_id,
        voucher.cumulative_amount,
        voucher.signature,
    )

    chain_id, nonce, gas_price = await get_tx_params(rpc_url, account.address, client=client)

    tx = TempoTransaction.create(
        chain_id=chain_id,
        gas_limit=200_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        calls=(Call.create(to=escrow_contract, value=0, data=call_data),),
    )
    signed = tx.sign(account.private_key)
    raw_tx = "0x" + signed.encode().hex()

    tx_hash = await _rpc_call(
        rpc_url, "eth_sendRawTransaction", [raw_tx], client=client
    )

    receipt = await _wait_for_receipt(rpc_url, tx_hash, client=client)
    if receipt.get("status") != "0x1":
        raise StreamError(f"close transaction reverted: {tx_hash}")

    return tx_hash


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────


async def get_tx_params(
    rpc_url: str, sender: str, *, client: Any | None = None
) -> tuple[int, int, int]:
    """Fetch chain_id, nonce, and gas_price for building a transaction.

    All three RPC calls are issued concurrently via asyncio.gather.
    """
    import asyncio

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


async def _wait_for_receipt(
    rpc_url: str,
    tx_hash: str,
    *,
    client: Any | None = None,
) -> dict[str, Any]:
    """Poll for a transaction receipt."""
    import asyncio

    for _ in range(MAX_RECEIPT_ATTEMPTS):
        result = await _rpc_call(
            rpc_url,
            "eth_getTransactionReceipt",
            [tx_hash],
            client=client,
        )
        if result is not None:
            return result
        await asyncio.sleep(RECEIPT_RETRY_DELAY)

    raise StreamError(
        f"transaction receipt not found after "
        f"{MAX_RECEIPT_ATTEMPTS} attempts: {tx_hash}"
    )


