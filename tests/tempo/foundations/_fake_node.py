"""An in-memory Tempo JSON-RPC node for foundation tests (``httpx.MockTransport``).

Serves the ``eth_call`` reads mppx performs through viem: TIP-20
``balanceOf``, stablecoin DEX ``quoteSwapExactAmountOut`` and fee-manager
``userTokens``. Any other call is treated as a Tempo (``0x76``) simulation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from eth_abi.abi import encode

from mpp.tempo._internal import abi
from mpp.tempo._internal.rpc import RpcClient
from mpp.tempo.chains import FEE_MANAGER, STABLECOIN_DEX

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class NodeError(Exception):
    """Raise (or store) to make the node answer with a JSON-RPC error."""


type Value[T] = T | NodeError


@dataclass
class FakeNode:
    balances: dict[tuple[str, str], Value[int]] = field(default_factory=dict)
    """``(token, account)`` -> balance; missing entries read as ``0``."""
    quotes: dict[tuple[str, str], Value[int]] = field(default_factory=dict)
    """``(token_in, token_out)`` -> quoted amount in; missing entries revert."""
    user_tokens: dict[str, str] = field(default_factory=dict)
    """account -> fee-manager ``userTokens`` preference (zero address when unset)."""
    simulate_error: str | None = None
    """When set, ``0x76`` call simulations revert with this message."""
    requests: list[dict[str, Any]] = field(default_factory=list)
    """Every JSON-RPC request received."""
    quote_requests: list[tuple[str, str, int]] = field(default_factory=list)

    def set_balance(self, token: str, account: str, value: Value[int]) -> None:
        self.balances[(token.lower(), account.lower())] = value

    def set_quote(self, token_in: str, token_out: str, value: Value[int]) -> None:
        self.quotes[(token_in.lower(), token_out.lower())] = value

    @property
    def eth_calls(self) -> list[dict[str, Any]]:
        return [r["params"][0] for r in self.requests if r["method"] == "eth_call"]

    def client(self) -> RpcClient:
        return RpcClient(
            "http://tempo.invalid",
            http=httpx.AsyncClient(transport=httpx.MockTransport(self._handle)),
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        try:
            result = self._dispatch(body["method"], body["params"])
        except NodeError as error:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": 3, "message": f"execution reverted: {error}"},
                },
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    def _dispatch(self, method: str, params: list[Any]) -> Any:
        if method != "eth_call":
            raise NodeError(f"unsupported method {method}")
        call = params[0]
        if "calls" in call:
            if self.simulate_error is not None:
                raise NodeError(self.simulate_error)
            return "0x"
        to, data = call["to"].lower(), call.get("data", "0x")
        selector = data[:10]
        if selector == abi.BALANCE_OF.selector:
            (account,) = abi.BALANCE_OF.decode_input(data)
            return _uint(_value(self.balances.get((to, account.lower()), 0)))
        if selector == abi.QUOTE_SWAP_EXACT_AMOUNT_OUT.selector and to == STABLECOIN_DEX:
            token_in, token_out, amount_out = abi.QUOTE_SWAP_EXACT_AMOUNT_OUT.decode_input(data)
            self.quote_requests.append((token_in, token_out, amount_out))
            quote = self.quotes.get((token_in.lower(), token_out.lower()))
            if quote is None:
                raise NodeError("no route")
            return _uint(_value(quote))
        if selector == abi.USER_TOKENS.selector and to == FEE_MANAGER:
            (account,) = abi.USER_TOKENS.decode_input(data)
            token = self.user_tokens.get(account.lower(), ZERO_ADDRESS)
            return "0x" + encode(["address"], [token]).hex()
        raise NodeError(f"unknown call {selector} to {to}")


def _value(value: Value[int]) -> int:
    if isinstance(value, NodeError):
        raise value
    return value


def _uint(value: int) -> str:
    return "0x" + encode(["uint256"], [value]).hex()
