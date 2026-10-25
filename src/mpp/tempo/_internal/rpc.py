"""A minimal async JSON-RPC client for Tempo nodes (and hosted fee payers)."""

from __future__ import annotations

import asyncio
import itertools
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, Literal, Self

import httpx
from pytempo import Call, TempoTransaction

from mpp.tempo._internal.envelope import call_target, key_authorization_to_rpc
from mpp.tempo._internal.envelope import fee_token as transaction_fee_token
from mpp.tempo._internal.envelope import sender as transaction_sender
from mpp.tempo._internal.hexutil import int_to_hex, to_hex

type BlockTag = Literal["latest", "pending", "earliest", "safe", "finalized"] | int


class RpcError(Exception):
    """A JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class RpcTransportError(Exception):
    """The node could not be reached or returned a non-JSON-RPC response."""

    def __init__(
        self, message: str, *, status: int | None = None, retry_after: str | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after
        """The response's ``Retry-After`` header, if any."""


_NO_RETRY_METHODS: Final = frozenset(
    {"eth_sendRawTransaction", "eth_sendRawTransactionSync", "eth_sendTransaction"}
)
"""Broadcasts are never retried (viem sends them with ``retryCount: 0``)."""

_RETRY_STATUSES: Final = frozenset({403, 408, 413, 429, 500, 502, 503, 504})
_RETRY_RPC_CODES: Final = frozenset({-1, -32005, -32603, 429, -32007})


def should_retry(error: BaseException) -> bool:
    """viem ``shouldRetry``: transient HTTP statuses, network errors and rate-limit codes."""
    if isinstance(error, RpcError):
        return error.code in _RETRY_RPC_CODES
    if isinstance(error, RpcTransportError) and error.status is not None:
        return error.status in _RETRY_STATUSES
    return isinstance(error, RpcTransportError | TimeoutError)


def retry_delay(count: int, error: BaseException, base: float) -> float:
    """viem backoff: ``Retry-After`` seconds when given, else ``(1 << count) * base``."""
    retry_after = getattr(error, "retry_after", None)
    if retry_after and (digits := re.match(r"[0-9]+", retry_after.strip())):
        return float(int(digits.group()))
    return (1 << count) * base


class TransactionReceiptTimeoutError(TimeoutError):
    def __init__(self, transaction_hash: str) -> None:
        super().__init__(f'Timed out while waiting for transaction with hash "{transaction_hash}".')
        self.transaction_hash = transaction_hash


@dataclass(frozen=True, slots=True, kw_only=True)
class Log:
    address: str
    topics: tuple[str, ...]
    data: str
    log_index: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TransactionReceipt:
    transaction_hash: str
    status: Literal["success", "reverted"]
    sender: str | None
    """The transaction sender (``from``)."""
    logs: tuple[Log, ...]
    block_number: int | None = None
    fee_payer: str | None = None
    fee_token: str | None = None


def parse_receipt(raw: Mapping[str, Any]) -> TransactionReceipt:
    """Parses a raw ``eth_getTransactionReceipt`` result."""
    status = raw.get("status")
    return TransactionReceipt(
        transaction_hash=raw["transactionHash"],
        status="success" if status in ("0x1", 1, "success") else "reverted",
        sender=raw.get("from"),
        logs=tuple(
            Log(
                address=log["address"],
                topics=tuple(log.get("topics", ())),
                data=log.get("data", "0x"),
                log_index=_optional_int(log.get("logIndex")),
            )
            for log in raw.get("logs", ())
        ),
        block_number=_optional_int(raw.get("blockNumber")),
        fee_payer=raw.get("feePayer"),
        fee_token=raw.get("feeToken"),
    )


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value, 16) if isinstance(value, str) else int(value)


class RpcClient:
    """Async JSON-RPC client over httpx.

    Pass ``http`` to share a connection pool (or a ``MockTransport`` in tests).
    """

    def __init__(
        self,
        url: str,
        *,
        http: httpx.AsyncClient | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        polling_interval: float = 1.0,
        retry_count: int = 3,
        retry_delay: float = 0.15,
    ) -> None:
        self.url = url
        self.polling_interval = polling_interval
        self.retry_count = retry_count
        """Retries for transient failures (viem ``http`` default: 3); broadcasts never retry."""
        self.retry_delay = retry_delay
        """Base backoff in seconds (viem default 150 ms, doubled per attempt)."""
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._headers = {**(headers or {}), "content-type": "application/json"}
        self._ids = itertools.count(1)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def request(self, method: str, params: Sequence[Any] = ()) -> Any:
        """Sends a JSON-RPC request and returns its ``result``.

        Transient failures are retried like viem's ``http`` transport (see
        :func:`should_retry`), except for transaction broadcasts.
        """
        retries = 0 if method in _NO_RETRY_METHODS else self.retry_count
        count = 0
        while True:
            try:
                return await self._request_once(method, params)
            except (RpcError, RpcTransportError, TimeoutError) as error:
                if count >= retries or not should_retry(error):
                    raise
                await asyncio.sleep(retry_delay(count, error, self.retry_delay))
                count += 1

    async def _request_once(self, method: str, params: Sequence[Any]) -> Any:
        body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": list(params)}
        try:
            response = await self._http.post(self.url, json=body, headers=self._headers)
        except httpx.HTTPError as error:
            raise RpcTransportError(f"HTTP request to {self.url} failed: {error}") from error
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if response.status_code >= 400:
            # Like viem, a valid JSON-RPC error body flows through the RPC error path even on a
            # non-2xx status; anything else is an HTTP error.
            error = payload.get("error") if isinstance(payload, dict) else None
            if not (
                isinstance(error, dict)
                and isinstance(error.get("code"), int)
                and isinstance(error.get("message"), str)
            ):
                raise RpcTransportError(
                    f"HTTP request to {self.url} failed with status {response.status_code}.",
                    status=response.status_code,
                    retry_after=response.headers.get("retry-after"),
                )
        elif payload is None:
            # viem surfaces an unparseable 2xx body as a status-less HTTP error, which it retries.
            raise RpcTransportError(f"HTTP request to {self.url} returned an invalid JSON body.")
        if not isinstance(payload, dict):
            raise RpcTransportError("Invalid JSON-RPC response.", status=response.status_code)
        if (error := payload.get("error")) is not None:
            raise RpcError(
                int(error.get("code", -32603)), str(error.get("message")), error.get("data")
            )
        return payload.get("result")

    async def chain_id(self) -> int:
        return int(await self.request("eth_chainId"), 16)

    async def call(self, request: Mapping[str, Any], block: BlockTag = "latest") -> str:
        """``eth_call`` with an RPC-formatted request (see :func:`call_request`)."""
        return await self.request("eth_call", [dict(request), _block(block)])

    async def estimate_gas(self, request: Mapping[str, Any]) -> int:
        return int(await self.request("eth_estimateGas", [dict(request)]), 16)

    async def gas_price(self) -> int:
        return int(await self.request("eth_gasPrice"), 16)

    async def max_priority_fee_per_gas(self) -> int:
        return int(await self.request("eth_maxPriorityFeePerGas"), 16)

    async def get_block(self, block: BlockTag = "latest") -> dict[str, Any] | None:
        return await self.request("eth_getBlockByNumber", [_block(block), False])

    async def get_transaction_count(self, address: str, block: BlockTag = "pending") -> int:
        return int(await self.request("eth_getTransactionCount", [address, _block(block)]), 16)

    async def get_transaction(self, transaction_hash: str) -> dict[str, Any] | None:
        return await self.request("eth_getTransactionByHash", [transaction_hash])

    async def get_transaction_receipt(self, transaction_hash: str) -> TransactionReceipt:
        """Fetches a receipt, raising :class:`TransactionReceiptNotFoundError` if absent."""
        raw = await self.request("eth_getTransactionReceipt", [transaction_hash])
        if raw is None:
            raise TransactionReceiptNotFoundError(transaction_hash)
        return parse_receipt(raw)

    async def wait_for_transaction_receipt(
        self, transaction_hash: str, *, timeout_seconds: float
    ) -> TransactionReceipt:
        """Polls for a receipt until ``timeout_seconds`` elapse."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                return await self.get_transaction_receipt(transaction_hash)
            except TransactionReceiptNotFoundError:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransactionReceiptTimeoutError(transaction_hash)
            await asyncio.sleep(min(self.polling_interval, remaining))

    async def send_raw_transaction(self, serialized: str) -> str:
        return await self.request("eth_sendRawTransaction", [serialized])

    async def send_raw_transaction_sync(
        self, serialized: str, *, timeout_ms: int | None = None
    ) -> TransactionReceipt:
        """EIP-7966 ``eth_sendRawTransactionSync``: broadcasts and returns the receipt."""
        params: list[Any] = [serialized]
        if timeout_ms is not None:
            params.append(timeout_ms)
        return parse_receipt(await self.request("eth_sendRawTransactionSync", params))

    async def fill_transaction(self, request: Mapping[str, Any]) -> Any:
        """``eth_fillTransaction`` (used by hosted Tempo fee payers)."""
        return await self.request("eth_fillTransaction", [dict(request)])


class TransactionReceiptNotFoundError(Exception):
    def __init__(self, transaction_hash: str) -> None:
        super().__init__(f'Transaction receipt with hash "{transaction_hash}" could not be found.')
        self.transaction_hash = transaction_hash


def _block(block: BlockTag) -> str:
    return int_to_hex(block) if isinstance(block, int) else block


def call_request(
    *,
    calls: Sequence[Call] = (),
    sender: str | None = None,
    to: str | None = None,
    data: str | None = None,
    transaction: TempoTransaction | None = None,
    fee_payer: str | bool | None = None,
    fee_token: str | None = None,
) -> dict[str, Any]:
    """Builds an RPC call request.

    With ``to``/``data`` it is a plain contract read. With ``calls`` or a
    ``transaction`` it is a Tempo (``0x76``) request: signatures are never
    included (``eth_call`` does not carry them).
    """
    if to is not None:
        return {
            "to": to,
            **({"data": data} if data is not None else {}),
            **({"from": sender} if sender else {}),
        }
    request: dict[str, Any] = {}
    if transaction is not None:
        calls = transaction.calls
        sender = sender or transaction_sender(transaction)
        fee_token = fee_token if fee_token is not None else transaction_fee_token(transaction)
        _put(request, "accessList", access_list_to_rpc(transaction) or None)
        _put(request, "chainId", int_to_hex(transaction.chain_id))
        # pytempo leaves unset gas and fee fields at zero; like ox, they are omitted.
        _put(request, "gas", _hex(transaction.gas_limit or None))
        _put(request, "maxFeePerGas", _hex(transaction.max_fee_per_gas or None))
        _put(request, "maxPriorityFeePerGas", _hex(transaction.max_priority_fee_per_gas or None))
        _put(request, "nonce", int_to_hex(transaction.nonce))
        _put(request, "nonceKey", int_to_hex(transaction.nonce_key))
        _put(request, "validBefore", _hex(transaction.valid_before))
        _put(request, "validAfter", _hex(transaction.valid_after))
        if transaction.key_authorization is not None:
            request["keyAuthorization"] = key_authorization_to_rpc(transaction.key_authorization)
    request["calls"] = [
        {
            "to": call_target(call),
            "value": int_to_hex(call.value) if call.value else "0x",
            "data": to_hex(call.data),
        }
        for call in calls
    ]
    # Like viem: a pending sponsorship (`feePayer: true`) leaves the fee token to the sponsor.
    _put(request, "feeToken", None if fee_payer is True else fee_token)
    request["type"] = "0x76"
    _put(request, "from", sender)
    _put(request, "feePayer", fee_payer)
    return request


def access_list_to_rpc(transaction: TempoTransaction) -> list[dict[str, Any]]:
    return [
        {
            "address": to_hex(bytes(item.address)),
            "storageKeys": [to_hex(bytes(key)) for key in item.storage_keys],
        }
        for item in transaction.access_list
    ]


def _hex(value: int | None) -> str | None:
    return None if value is None else int_to_hex(value)


def _put(request: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        request[key] = value
