"""JSON-RPC wallet actions for paying Tempo charges with a ``JsonRpcAccount``."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from pytempo import Call

from mpp.methods.tempo.account import WalletRequest

# Seconds to wait for a sent call bundle: Tempo's block time times three, at least 5s.
SEND_CALLS_TIMEOUT = 5.0
POLLING_INTERVAL = 0.5
_STATUS_RETRY_COUNT = 4
# JSON-RPC codes for a method the wallet does not have or support.
_METHOD_UNSUPPORTED_CODES = (-32601, -32004)
# JSON-RPC and EIP-1193 codes of named errors; a wallet error with another code is unknown.
_KNOWN_RPC_CODES = frozenset(
    {-32700, -32600, -32601, -32602, -32603, -32000, -32001, -32002, -32003, -32004, -32005}
    | {-32006, 4001, 4100, 4200, 4900, 4901, 4902}
    | {5000, 5700, 5710, 5720, 5730, 5740, 5750, 5760, 7000}
)
# Error details from wallets that lack EIP-5792 without saying so with an error code.
_FALLBACK_DETAILS = (
    "does not exist / is not available",
    "missing or invalid. request()",
    "did not match any variant of untagged enum",
    "account upgraded to unsupported contract",
    "eip-7702 not supported",
    "unsupported wc_ method",
    "feature toggled misconfigured",
    "jsonrpcengine: response has no error or result for request",
)


class WaitForCallsStatusTimeoutError(TimeoutError):
    """A sent call bundle was not confirmed in time."""

    def __init__(self, bundle_id: str) -> None:
        super().__init__(
            f'Timed out while waiting for call bundle with id "{bundle_id}" to be confirmed.'
        )
        # The wallet already sent the calls: the bundle ID (or transaction hash
        # on the `eth_sendTransaction` fallback) lets the caller find the payment.
        self.id = bundle_id


def rpc_calls(calls: Sequence[Call]) -> list[dict[str, str]]:
    """Return calls as JSON-RPC call objects."""
    return [
        {
            "data": "0x" + call.data.hex(),
            "to": "0x" + call.to.hex(),
            **({"value": hex(call.value)} if call.value else {}),
        }
        for call in calls
    ]


async def send_calls_sync(
    request: WalletRequest,
    *,
    address: str,
    chain_id: int,
    calls: Sequence[Call],
    capabilities: dict[str, Any] | None = None,
    experimental_fallback: bool = False,
    force_atomic: bool = False,
    polling_interval: float = POLLING_INTERVAL,
    timeout: float = SEND_CALLS_TIMEOUT,
) -> dict[str, Any]:
    """Send calls with EIP-5792 ``wallet_sendCalls`` and wait for the bundle's final status.

    With ``experimental_fallback``, a wallet without EIP-5792 sends a single call
    with ``eth_sendTransaction`` instead. Returns the status with its ``receipts``
    once it is confirmed (``200``) or failed (``>= 300``).
    """
    params: dict[str, Any] = {
        "atomicRequired": force_atomic,
        "calls": rpc_calls(calls),
        "chainId": hex(chain_id),
        "from": address,
        "version": "2.0.0",
    }
    if capabilities is not None:
        params["capabilities"] = capabilities
    try:
        response = await request("wallet_sendCalls", [params])
    except Exception as error:
        if not (experimental_fallback and len(calls) == 1 and _supports_fallback(error)):
            raise
        # A Tempo transaction carries the fee token itself, so it survives the fallback.
        fallback_capabilities = dict(capabilities or {})
        fee_token = fallback_capabilities.pop("feeToken", None)
        if any(
            not (isinstance(value, dict) and value.get("optional"))
            for value in fallback_capabilities.values()
        ):
            raise ValueError(
                "non-optional `capabilities` are not supported on fallback to "
                "`eth_sendTransaction`."
            ) from error
        call = {**params["calls"][0], **({"feeToken": fee_token} if fee_token else {})}
        tx_hash = await _send_transaction(request, address, chain_id, call)
        return await _wait(
            lambda: _transaction_status(request, tx_hash), tx_hash, polling_interval, timeout
        )
    bundle_id = response if isinstance(response, str) else str(response["id"])
    return await _wait(
        lambda: _calls_status(request, bundle_id), bundle_id, polling_interval, timeout
    )


async def _wait(get_status: Any, bundle_id: str, polling_interval: float, timeout: float) -> Any:
    try:
        async with asyncio.timeout(timeout):
            while True:
                status = await _with_retry(get_status)
                if status["statusCode"] == 200 or status["statusCode"] >= 300:
                    return status
                await asyncio.sleep(polling_interval)
    except TimeoutError as error:
        raise WaitForCallsStatusTimeoutError(bundle_id) from error


async def _with_retry(get_status: Any) -> dict[str, Any]:
    for count in range(_STATUS_RETRY_COUNT + 1):
        try:
            return await get_status()
        except Exception:
            if count == _STATUS_RETRY_COUNT:
                raise
            await asyncio.sleep((1 << count) * 0.2)
    raise AssertionError("unreachable")


async def _calls_status(request: WalletRequest, bundle_id: str) -> dict[str, Any]:
    raw = await request("wallet_getCallsStatus", [bundle_id])
    status = {"CONFIRMED": 200, "PENDING": 100}.get(raw.get("status"), raw.get("status"))
    return {**raw, "receipts": raw.get("receipts") or [], "statusCode": int(status or 0)}


async def _transaction_status(request: WalletRequest, tx_hash: str) -> dict[str, Any]:
    receipt = await request("eth_getTransactionReceipt", [tx_hash])
    if not receipt:
        return {"receipts": [], "statusCode": 100}
    return {"receipts": [receipt], "statusCode": 200 if receipt.get("status") == "0x1" else 500}


async def _send_transaction(
    request: WalletRequest, address: str, chain_id: int, call: dict[str, str]
) -> str:
    params = [{**call, "chainId": hex(chain_id), "from": address}]
    try:
        return await request("eth_sendTransaction", params)
    except Exception as error:
        # Some wallets only serve the `wallet_` namespace.
        if getattr(error, "code", None) not in (-32000, -32602, *_METHOD_UNSUPPORTED_CODES):
            raise
        return await request("wallet_sendTransaction", params)


def _supports_fallback(error: Exception) -> bool:
    code = getattr(error, "code", None)
    details = str(getattr(error, "message", error)).lower()
    return (
        code in _METHOD_UNSUPPORTED_CODES
        or (code is not None and code not in _KNOWN_RPC_CODES)
        or details == "this request method is not supported"
        or any(fragment in details for fragment in _FALLBACK_DETAILS)
    )
