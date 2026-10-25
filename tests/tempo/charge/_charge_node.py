"""An in-memory Tempo JSON-RPC node for charge tests (served through ``httpx.MockTransport``).

It executes TIP-20 ``transfer``/``transferWithMemo``/``approve`` calls, stablecoin DEX
``swapExactAmountOut`` routes against in-memory balances, signs
hosted fee-payer fills, and returns realistic receipts. Tests override any RPC method with
:meth:`FakeTempoNode.on`.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from pytempo import Call, Signature, TempoTransaction

from mpp.tempo._internal import abi
from mpp.tempo._internal.account import TempoAccount, secp256k1_account
from mpp.tempo._internal.address import is_equal
from mpp.tempo._internal.envelope import (
    EXPIRING_NONCE_KEY,
    call_target,
    deserialize,
    fee_payer_sign_payload,
    has_fee_payer,
    sender,
    serialize,
    serialize_for_fee_payer,
)
from mpp.tempo._internal.envelope import fee_token as transaction_fee_token
from mpp.tempo._internal.fee_payer import hosted_fee_payer_request  # noqa: F401  (documentation)
from mpp.tempo._internal.hexutil import int_to_hex, keccak256, to_bytes, to_hex
from mpp.tempo._internal.rpc import RpcClient, RpcError
from mpp.tempo._internal.signature import y_parity
from mpp.tempo.chains import STABLECOIN_DEX, TESTNET_CHAIN_ID

PAYER_KEY = "0x" + "01" * 32
SPONSOR_KEY = "0x" + "02" * 32
RECIPIENT_KEY = "0x" + "03" * 32
OTHER_KEY = "0x" + "04" * 32
CURRENCY = "0x20c0000000000000000000000000000000000001"
REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"
ZERO_ADDRESS = "0x" + "00" * 20

DEFAULT = object()
"""Returned by an override handler to fall through to the node's default behavior."""


class HttpStatus(Exception):
    """Raised by a handler to answer with a non-JSON HTTP status (e.g. a 502 gateway error)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


class Reverted(Exception):
    pass


def topic_address(address: str) -> str:
    return "0x" + "00" * 12 + address.lower().removeprefix("0x")


def transfer_logs(
    token: str, sender: str, recipient: str, amount: int, memo: str | None, start: int
) -> list[dict[str, Any]]:
    data = "0x" + amount.to_bytes(32, "big").hex()
    logs = [
        {
            "address": token,
            "topics": [abi.TRANSFER_EVENT_TOPIC, topic_address(sender), topic_address(recipient)],
            "data": data,
            "logIndex": int_to_hex(start),
        }
    ]
    if memo is not None:
        logs.append(
            {
                "address": token,
                "topics": [
                    abi.TRANSFER_WITH_MEMO_EVENT_TOPIC,
                    topic_address(sender),
                    topic_address(recipient),
                    memo.lower(),
                ],
                "data": data,
                "logIndex": int_to_hex(start + 1),
            }
        )
    return logs


def receipt_json(
    *,
    transaction_hash: str,
    sender: str,
    logs: list[dict[str, Any]],
    status: str = "0x1",
    fee_payer: str | None = None,
    fee_token: str | None = None,
) -> dict[str, Any]:
    return {
        "blockHash": "0x" + "ef" * 32,
        "blockNumber": "0x1",
        "transactionHash": transaction_hash,
        "transactionIndex": "0x0",
        "from": sender,
        "status": status,
        "type": "0x76",
        "gasUsed": "0x1",
        "cumulativeGasUsed": "0x1",
        "effectiveGasPrice": "0x1",
        "logs": [{**log, "transactionHash": transaction_hash} for log in logs],
        "feePayer": fee_payer,
        "feeToken": fee_token,
    }


type Handler = Callable[[list[Any]], Any | Awaitable[Any]]


@dataclass
class FakeTempoNode:
    chain_id: int = TESTNET_CHAIN_ID
    balances: dict[tuple[str, str], int] = field(default_factory=dict)
    receipts: dict[str, dict[str, Any]] = field(default_factory=dict)
    transactions: dict[str, dict[str, Any]] = field(default_factory=dict)
    methods: list[str] = field(default_factory=list)
    requests: list[tuple[str, list[Any]]] = field(default_factory=list)
    hosted_fee_payer: TempoAccount | None = None
    hosted_fee_token: str = CURRENCY
    swap_quote: Callable[[str, str, int], int] | None = None
    gas: int = 100_000
    max_fee_per_gas: int = 20_000_000_000
    max_priority_fee_per_gas: int = 1_000_000_000
    access_keys: dict[tuple[str, str], tuple[int, int, bool]] = field(default_factory=dict)
    overrides: dict[str, Handler] = field(default_factory=dict)

    # -- configuration ---------------------------------------------------------------------

    def fund(self, token: str, address: str, amount: int) -> None:
        key = (token.lower(), address.lower())
        self.balances[key] = self.balances.get(key, 0) + amount

    def balance(self, token: str, address: str) -> int:
        return self.balances.get((token.lower(), address.lower()), 0)

    def on(self, method: str, handler: Handler) -> None:
        self.overrides[method] = handler

    def authorize_access_key(self, account: str, access_key: str, *, expiry: int) -> None:
        self.access_keys[(account.lower(), access_key.lower())] = (0, expiry, False)

    def count(self, method: str) -> int:
        return self.methods.count(method)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle_http)

    def client(self, *, polling_interval: float = 0.01) -> RpcClient:
        return RpcClient(
            "https://rpc.example.com",
            http=httpx.AsyncClient(transport=self.transport()),
            polling_interval=polling_interval,
        )

    # -- JSON-RPC --------------------------------------------------------------------------

    async def _handle_http(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body.get("params", [])
        self.methods.append(method)
        self.requests.append((method, params))
        try:
            result: Any = DEFAULT
            if (override := self.overrides.get(method)) is not None:
                result = override(params)
                if hasattr(result, "__await__"):
                    result = await result
            if result is DEFAULT:
                result = self.handle(method, params)
        except HttpStatus as status:
            return httpx.Response(status.status, text="gateway error")
        except RpcError as error:
            payload = {"code": error.code, "message": error.message}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": payload})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    def handle(self, method: str, params: list[Any]) -> Any:
        match method:
            case "eth_chainId":
                return int_to_hex(self.chain_id)
            case "eth_call":
                return self._call(params[0])
            case "eth_estimateGas":
                return int_to_hex(self.gas)
            case "eth_maxPriorityFeePerGas":
                return int_to_hex(self.max_priority_fee_per_gas)
            case "eth_gasPrice":
                return int_to_hex(self.max_fee_per_gas)
            case "eth_getBlockByNumber":
                return {"number": "0x1", "baseFeePerGas": int_to_hex(self.max_fee_per_gas)}
            case "eth_fillTransaction":
                return self._fill(params[0])
            case "eth_sendRawTransactionSync":
                return self.receipts[self._send(params[0])]
            case "eth_sendRawTransaction":
                return self._send(params[0])
            case "eth_getTransactionReceipt":
                return self.receipts.get(params[0].lower())
            case "eth_getTransactionByHash":
                return self.transactions.get(params[0].lower())
        raise RpcError(-32601, f"method not found: {method}")

    def _fill(self, request: dict[str, Any]) -> dict[str, Any]:
        tx: dict[str, Any] = {
            **request,
            "gas": request.get("gas") or int_to_hex(self.gas),
            "maxFeePerGas": request.get("maxFeePerGas") or int_to_hex(self.max_fee_per_gas),
            "maxPriorityFeePerGas": request.get("maxPriorityFeePerGas")
            or int_to_hex(self.max_priority_fee_per_gas),
            "nonce": request.get("nonce") or "0x0",
        }
        if request.get("feePayer") is True and self.hosted_fee_payer is not None:
            tx["feeToken"] = self.hosted_fee_token
            transaction = TempoTransaction(
                chain_id=self.chain_id,
                calls=tuple(
                    Call(to=c.get("to"), data=c.get("data", "0x"), value=_qty(c.get("value")))
                    for c in request["calls"]
                ),
                gas_limit=_qty(tx["gas"]),
                max_fee_per_gas=_qty(tx["maxFeePerGas"]),
                max_priority_fee_per_gas=_qty(tx["maxPriorityFeePerGas"]),
                nonce=_qty(tx["nonce"]),
                nonce_key=_qty(request.get("nonceKey")),
                valid_before=_qty(request.get("validBefore")) or None,
                valid_after=_qty(request.get("validAfter")) or None,
                fee_token=self.hosted_fee_token,
            )
            signature = self.hosted_fee_payer.sign(
                fee_payer_sign_payload(transaction, sender=request["from"]), raw=True
            )
            assert isinstance(signature, Signature)
            tx["feePayerSignature"] = {
                "r": int_to_hex(signature.r),
                "s": int_to_hex(signature.s),
                "yParity": int_to_hex(y_parity(signature)),
            }
        return {"raw": "0x", "tx": tx}

    def _call(self, request: dict[str, Any]) -> str:
        if "calls" not in request:
            return self._read(request["to"], request.get("data", "0x"))
        sender = request.get("from")
        if sender is None:
            raise RpcError(-32000, "missing sender")
        calls = [
            Call(to=c.get("to") or "", data=c.get("data") or "0x", value=_qty(c.get("value")))
            for c in request["calls"]
        ]
        try:
            self._execute(sender, calls, dict(self.balances))
        except Reverted as error:
            raise RpcError(3, f"execution reverted: {error}") from None
        return "0x"

    def _read(self, to: str, data: str) -> str:
        selector = data[:10]
        if selector == abi.BALANCE_OF.selector:
            (account,) = abi.BALANCE_OF.decode_input(data)
            return "0x" + self.balance(to, account).to_bytes(32, "big").hex()
        if selector == abi.USER_TOKENS.selector:
            return "0x" + bytes(32).hex()
        if selector == abi.QUOTE_SWAP_EXACT_AMOUNT_OUT.selector:
            token_in, token_out, amount_out = abi.QUOTE_SWAP_EXACT_AMOUNT_OUT.decode_input(data)
            if self.swap_quote is None:
                raise RpcError(3, "execution reverted: no liquidity")
            return "0x" + self.swap_quote(token_in, token_out, amount_out).to_bytes(32, "big").hex()
        if selector == abi.GET_KEY.selector:
            account, access_key = abi.GET_KEY.decode_input(data)
            key_type, expiry, revoked = self.access_keys.get(
                (account.lower(), access_key.lower()), (0, 0, False)
            )
            from eth_abi.abi import encode

            known = (account.lower(), access_key.lower()) in self.access_keys
            return (
                "0x"
                + encode(
                    ["(uint8,address,uint64,bool,bool)"],
                    [(key_type, access_key if known else ZERO_ADDRESS, expiry, False, revoked)],
                ).hex()
            )
        raise RpcError(3, "execution reverted")

    # -- execution -------------------------------------------------------------------------

    def _execute(
        self, sender: str, calls: list[Call], balances: dict[tuple[str, str], int]
    ) -> list[dict[str, Any]]:
        logs: list[dict[str, Any]] = []

        def move(token: str, source: str, target: str, amount: int, memo: str | None) -> None:
            key = (token.lower(), source.lower())
            if balances.get(key, 0) < amount:
                raise Reverted("insufficient balance")
            balances[key] = balances.get(key, 0) - amount
            target_key = (token.lower(), target.lower())
            balances[target_key] = balances.get(target_key, 0) + amount
            logs.extend(transfer_logs(token, source, target, amount, memo, len(logs)))

        for call in calls:
            to = call_target(call)
            assert to is not None
            data = to_hex(call.data)
            selector = data[:10]
            if selector == abi.TRANSFER.selector:
                recipient, amount = abi.TRANSFER.decode_input(data)
                move(to, sender, recipient, amount, None)
            elif selector == abi.TRANSFER_WITH_MEMO.selector:
                recipient, amount, memo = abi.TRANSFER_WITH_MEMO.decode_input(data)
                move(to, sender, recipient, amount, to_hex(memo))
            elif selector == abi.APPROVE.selector:
                pass
            elif selector == abi.SWAP_EXACT_AMOUNT_OUT.selector and is_equal(to, STABLECOIN_DEX):
                token_in, token_out, amount_out, max_in = abi.SWAP_EXACT_AMOUNT_OUT.decode_input(
                    data
                )
                quote = self.swap_quote(token_in, token_out, amount_out) if self.swap_quote else 0
                if quote == 0 or quote > max_in:
                    raise Reverted("swap failed")
                move(token_in, sender, STABLECOIN_DEX, quote, None)
                balances[(token_out.lower(), STABLECOIN_DEX.lower())] = (
                    balances.get((token_out.lower(), STABLECOIN_DEX.lower()), 0) + amount_out
                )
                move(token_out, STABLECOIN_DEX, sender, amount_out, None)
            else:
                raise Reverted("unsupported call")
        return logs

    def _send(self, serialized: str) -> str:
        transaction = deserialize(serialized)
        payer = sender(transaction)
        if transaction.sender_signature is None or payer is None:
            raise RpcError(-32000, "invalid signature")
        if has_fee_payer(transaction) and transaction.fee_payer_signature is None:
            raise RpcError(-32000, "missing fee payer signature")
        transaction_hash = to_hex(keccak256(to_bytes(serialized)))
        if transaction_hash in self.receipts:
            raise RpcError(-32000, "already known")
        balances = dict(self.balances)
        try:
            logs = self._execute(payer, list(transaction.calls), balances)
            status = "0x1"
            self.balances = balances
        except Reverted:
            logs, status = [], "0x0"
        self.receipts[transaction_hash] = receipt_json(
            transaction_hash=transaction_hash,
            sender=payer,
            logs=logs,
            status=status,
            fee_token=transaction_fee_token(transaction),
        )
        self.transactions[transaction_hash] = {
            "hash": transaction_hash,
            "from": payer,
            "type": "0x76",
            "calls": [
                {"to": call_target(c), "data": to_hex(c.data), "value": int_to_hex(c.value)}
                for c in transaction.calls
            ],
        }
        return transaction_hash


def _qty(value: Any) -> int:
    if value in (None, "0x", ""):
        return 0
    return int(value, 16) if isinstance(value, str) else int(value)


def payer() -> TempoAccount:
    return secp256k1_account(PAYER_KEY)


def sponsor() -> TempoAccount:
    return secp256k1_account(SPONSOR_KEY)


def recipient() -> TempoAccount:
    return secp256k1_account(RECIPIENT_KEY)


def other() -> TempoAccount:
    return secp256k1_account(OTHER_KEY)


# -- HTTP harness ------------------------------------------------------------------------------


def serve(handler: Any, *, body: str = "OK") -> httpx.MockTransport:
    """Serves a configured ``mpp.server`` route handler over ``httpx.MockTransport``."""
    from mpp.server import Request, Response

    async def app(request: httpx.Request) -> httpx.Response:
        result = await handler(
            Request(
                method=request.method,
                url=str(request.url),
                headers=request.headers,
                body=request.content or None,
            )
        )
        response = (
            result.challenge if result.status == 402 else result.with_receipt(Response.text(body))
        )
        return httpx.Response(
            response.status, headers=response.headers, content=await response.read()
        )

    return httpx.MockTransport(app)


# -- transaction builders ----------------------------------------------------------------------


def transfer_call(token: str, to: str, amount: int, memo: str | None = None) -> Call:
    if memo is None:
        return Call(to=token, data=abi.TRANSFER.encode(to, amount))
    return Call(to=token, data=abi.TRANSFER_WITH_MEMO.encode(to, amount, to_bytes(memo)))


def build_transaction(
    calls: list[Call],
    *,
    chain_id: int = TESTNET_CHAIN_ID,
    valid_for: int = 25,
    fee_payer: bool = False,
    fee_token: str | None = None,
    gas: int = 100_000,
    max_fee_per_gas: int = 1_000_000_000,
    max_priority_fee_per_gas: int = 1_000_000_000,
) -> TempoTransaction:
    import time

    return TempoTransaction(
        chain_id=chain_id,
        calls=tuple(calls),
        gas_limit=gas,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        nonce=0,
        nonce_key=EXPIRING_NONCE_KEY,
        valid_before=int(time.time()) + valid_for,
        awaiting_fee_payer=fee_payer,
        fee_token=None if fee_payer else fee_token,
    )


def sign(account: TempoAccount, transaction: TempoTransaction) -> str:
    """Signs and serializes (``0x78`` sender envelope when fee-sponsored)."""
    signed = account.sign_transaction(transaction)
    return serialize_for_fee_payer(signed) if has_fee_payer(transaction) else serialize(signed)


def credential(challenge: Any, payload: dict[str, Any], source: str | None = None) -> str:
    from mpp.credential import Credential

    return Credential(challenge=challenge, payload=payload, source=source).serialize()


def memo_for(challenge: Any, client_id: str | None = None) -> str:
    from mpp.tempo import attribution

    return attribution.encode(
        challenge_id=challenge.id, server_id=challenge.realm, client_id=client_id
    )


def did(address: str, chain_id: int = TESTNET_CHAIN_ID) -> str:
    return f"did:pkh:eip155:{chain_id}:{address}"
