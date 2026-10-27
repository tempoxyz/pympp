"""JSON-RPC wallet actions for paying Tempo charges with a ``JsonRpcAccount``."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from mpp.methods.tempo.account import WalletRequest

if TYPE_CHECKING:
    from pytempo import Call

# Seconds to wait for a sent call bundle: Tempo's block time times three, at least 5s.
SEND_CALLS_TIMEOUT = 5.0
POLLING_INTERVAL = 0.5
_STATUS_RETRY_COUNT = 4
# JSON-RPC and EIP-1193 codes for a method the wallet does not have or support.
# Only these, which guarantee nothing was sent, let a payment be sent another way.
_METHOD_UNSUPPORTED_CODES = (-32601, -32004, 4200)
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

    def __init__(self, bundle_id: str, *, transaction_hash: str | None = None) -> None:
        super().__init__(
            f'Timed out while waiting for call bundle with id "{bundle_id}" to be confirmed.'
        )
        # The wallet already sent the calls: the bundle ID (or transaction hash
        # on the `eth_sendTransaction` fallback) lets the caller find the payment.
        self.id = bundle_id
        self.transaction_hash = transaction_hash


class CallsStatusError(RuntimeError):
    """A call bundle was sent, but reading its status failed after retries."""

    def __init__(self, bundle_id: str, *, transaction_hash: str | None = None) -> None:
        super().__init__(f'Failed to read the status of sent call bundle with id "{bundle_id}".')
        self.id = bundle_id
        self.transaction_hash = transaction_hash


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
    valid_before: int | None = None,
) -> dict[str, Any]:
    """Send calls with EIP-5792 ``wallet_sendCalls`` and wait for the bundle's final status.

    With ``experimental_fallback``, a wallet without EIP-5792 sends a single call
    with ``eth_sendTransaction`` instead, bounded by ``valid_before`` when given.
    Returns the status with its ``receipts`` once it is confirmed (``200``) or
    failed (``>= 300``), plus the bundle's ``id`` and, on the fallback, its
    ``transactionHash``.
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
        call = {
            **params["calls"][0],
            **({"feeToken": fee_token} if fee_token else {}),
            **({"validBefore": hex(valid_before)} if valid_before is not None else {}),
        }
        tx_hash = await _send_transaction(request, address, chain_id, call)
        return await wait_for_calls(
            request,
            tx_hash,
            transaction_hash=tx_hash,
            polling_interval=polling_interval,
            timeout=timeout,
        )
    bundle_id = response if isinstance(response, str) else str(response["id"])
    return await wait_for_calls(
        request, bundle_id, polling_interval=polling_interval, timeout=timeout
    )


async def wait_for_calls(
    request: WalletRequest,
    bundle_id: str,
    *,
    transaction_hash: str | None = None,
    polling_interval: float = POLLING_INTERVAL,
    timeout: float = SEND_CALLS_TIMEOUT,
) -> dict[str, Any]:
    """Wait for the final status of calls the wallet already sent, without sending again.

    ``transaction_hash`` follows a transaction sent on the ``eth_sendTransaction``
    fallback instead of a ``wallet_sendCalls`` bundle.
    """
    if transaction_hash is not None:
        status = await _wait(
            lambda: _transaction_status(request, transaction_hash),
            bundle_id,
            polling_interval,
            timeout,
            transaction_hash=transaction_hash,
        )
        return {**status, "id": bundle_id, "transactionHash": transaction_hash}
    status = await _wait(
        lambda: _calls_status(request, bundle_id), bundle_id, polling_interval, timeout
    )
    return {**status, "id": bundle_id}


async def _wait(
    get_status: Any,
    bundle_id: str,
    polling_interval: float,
    timeout: float,
    *,
    transaction_hash: str | None = None,
) -> Any:
    try:
        async with asyncio.timeout(timeout):
            while True:
                status = await _with_retry(get_status)
                if status["statusCode"] == 200 or status["statusCode"] >= 300:
                    return status
                await asyncio.sleep(polling_interval)
    except TimeoutError as error:
        raise WaitForCallsStatusTimeoutError(
            bundle_id, transaction_hash=transaction_hash
        ) from error
    except Exception as error:
        # Keep the ID of calls the wallet already sent.
        raise CallsStatusError(bundle_id, transaction_hash=transaction_hash) from error


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
        # Some wallets only serve the `wallet_` namespace. Only a definite refusal of
        # the request retries: a generic error may come after the wallet sent it.
        if getattr(error, "code", None) not in (-32602, *_METHOD_UNSUPPORTED_CODES):
            raise
        return await request("wallet_sendTransaction", params)


def _supports_fallback(error: Exception) -> bool:
    code = getattr(error, "code", None)
    details = str(getattr(error, "message", error)).lower()
    return (
        code in _METHOD_UNSUPPORTED_CODES
        or details == "this request method is not supported"
        or any(fragment in details for fragment in _FALLBACK_DETAILS)
    )
