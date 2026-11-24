"""Typed errors when the pre-signing simulation hits a spending limit or balance revert.

Mirrors mppx ``src/tempo/internal/simulation.test.ts`` and the pre-signing simulation tests in
``src/tempo/client/Charge.test.ts`` (mppx#1293).
"""

from __future__ import annotations

import json
import pickle
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from eth_abi.abi import encode
from eth_hash.auto import keccak
from pytest_httpx import HTTPXMock

from mpp import Challenge
from mpp.errors import InsufficientBalanceError, SpendingLimitExceededError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo._rpc import RpcError
from mpp.methods.tempo._simulation import (
    INSUFFICIENT_BALANCE_SELECTOR,
    SPENDING_LIMIT_EXCEEDED_SELECTOR,
    simulation_error,
)
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS, ZERO_ADDRESS, ChannelDescriptor
from tests.test_tempo import TEST_PRIVATE_KEY, _tempo_method  # pyright: ignore[reportPrivateUsage]

TOKEN = "0x20c0000000000000000000000000000000000001"
ACCOUNT = TempoAccount.from_key("0x" + "11" * 32)
ACCESS_KEY = TempoAccount.from_key("0x" + "44" * 32)
SPENDING_LIMIT_EXCEEDED = "0x" + SPENDING_LIMIT_EXCEEDED_SELECTOR.hex()


def insufficient_balance(available: int, required: int, token: str = TOKEN) -> str:
    args = encode(["uint256", "uint256", "address"], [available, required, token])
    return "0x" + (INSUFFICIENT_BALANCE_SELECTOR + args).hex()


def revert(data: object) -> RpcError:
    return RpcError(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": 3, "message": "execution reverted", "data": data},
        }
    )


class TestSelectors:
    def test_match_the_tempo_revert_selectors(self) -> None:
        assert SPENDING_LIMIT_EXCEEDED_SELECTOR == keccak(b"SpendingLimitExceeded()")[:4]
        assert (
            INSUFFICIENT_BALANCE_SELECTOR
            == keccak(b"InsufficientBalance(uint256,uint256,address)")[:4]
        )
        assert SPENDING_LIMIT_EXCEEDED == "0x8a9e71ea"
        assert insufficient_balance(1, 2)[:10] == "0x832f98b5"


class TestSimulationError:
    def test_maps_spending_limit_exceeded(self) -> None:
        error = simulation_error(
            revert({"data": SPENDING_LIMIT_EXCEEDED}),
            account=ACCOUNT.address,
            access_key=ACCESS_KEY.address,
        )
        assert isinstance(error, SpendingLimitExceededError)
        assert error.account == ACCOUNT.address
        assert error.access_key == ACCESS_KEY.address
        assert f"key {ACCESS_KEY.address} of account {ACCOUNT.address}" in str(error)

    def test_maps_insufficient_balance(self) -> None:
        error = simulation_error(revert(insufficient_balance(487, 20_000)), account=ACCOUNT.address)
        assert isinstance(error, InsufficientBalanceError)
        assert "holds 487 of token" in str(error)
        assert "requires 20000" in str(error)
        assert error.type == "https://paymentauth.org/problems/session/insufficient-balance"

    @pytest.mark.parametrize(
        "error",
        [
            ValueError("boom"),
            revert("0xdeadbeef"),
            revert(None),
            revert("nope"),
            RpcError({"error": "execution reverted"}),
            # Too short to hold InsufficientBalance's arguments.
            revert("0x832f98b5" + "00" * 32),
        ],
    )
    def test_leaves_other_errors_unmapped(self, error: BaseException) -> None:
        assert simulation_error(error, account=ACCOUNT.address) is None

    def test_spending_limit_error_pickles(self) -> None:
        error = SpendingLimitExceededError(ACCOUNT.address, ACCESS_KEY.address)
        restored = pickle.loads(pickle.dumps(error))
        assert (restored.account, restored.access_key, str(restored)) == (
            error.account,
            error.access_key,
            str(error),
        )
        assert "key 0x" not in str(SpendingLimitExceededError(ACCOUNT.address))


def reverting_node(data: str) -> tuple[httpx.AsyncClient, list[tuple[str, list[Any]]]]:
    """A Tempo node whose eth_estimateGas reverts with ``data``; records requests."""
    requests: list[tuple[str, list[Any]]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body["params"]
        requests.append((method, params))
        answers: dict[str, Callable[[], Any]] = {
            "eth_chainId": lambda: hex(1337),
            "eth_gasPrice": lambda: hex(20_000_000_000),
        }
        if method == "eth_estimateGas":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": 3, "message": "execution reverted", "data": data},
                },
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": answers[method]()})

    return httpx.AsyncClient(transport=httpx.MockTransport(handle)), requests


class TestSessionTransactions:
    async def test_open_throws_spending_limit_exceeded_before_signing(self) -> None:
        client, requests = reverting_node(SPENDING_LIMIT_EXCEEDED)
        with pytest.raises(SpendingLimitExceededError) as raised:
            await chain.build_open_transaction(
                ACCESS_KEY,
                rpc_url="http://rpc.test",
                payee=TempoAccount.from_key("0x" + "22" * 32).address,
                token=TOKEN,
                deposit=1_000_000,
                fee_payer=True,
                root_account=ACCOUNT.address,
                client=client,
            )
        assert raised.value.account == ACCOUNT.address
        assert raised.value.access_key == ACCESS_KEY.address
        assert isinstance(raised.value.__cause__, RpcError)
        (estimate,) = [params for method, params in requests if method == "eth_estimateGas"]
        # The estimate names the access key, so the node checks its spending limits.
        assert estimate[0]["keyId"] == ACCESS_KEY.address
        assert estimate[0]["from"] == ACCOUNT.address

    async def test_top_up_throws_insufficient_balance_before_signing(self) -> None:
        client, requests = reverting_node(insufficient_balance(487, 20_000))
        descriptor = ChannelDescriptor(
            payer=ACCOUNT.address,
            payee=TempoAccount.from_key("0x" + "22" * 32).address,
            operator=ZERO_ADDRESS,
            token=TOKEN,
            salt="0x" + "11" * 32,
            authorized_signer=ACCOUNT.address,
            expiring_nonce_hash="0x" + "00" * 32,
        )
        with pytest.raises(InsufficientBalanceError, match="holds 487 of token"):
            await chain.build_top_up_transaction(
                ACCOUNT,
                rpc_url="http://rpc.test",
                escrow=ESCROW_ADDRESS,
                descriptor=descriptor,
                additional_deposit=20_000,
                fee_payer=True,
                client=client,
            )
        (estimate,) = [params for method, params in requests if method == "eth_estimateGas"]
        assert "keyId" not in estimate[0]

    async def test_other_estimate_failures_keep_the_default_gas_limit(self) -> None:
        client, _ = reverting_node("0xdeadbeef")
        raw, _, _ = await chain.build_open_transaction(
            ACCOUNT,
            rpc_url="http://rpc.test",
            payee=TempoAccount.from_key("0x" + "22" * 32).address,
            token=TOKEN,
            deposit=1_000_000,
            client=client,
        )
        assert raw.startswith("0x")


def sponsored_challenge(currency: str = "0x20c0000000000000000000000000000000000000") -> Challenge:
    return Challenge(
        id="test-sponsored-simulation",
        method="tempo",
        intent="charge",
        request={
            "amount": "1000000",
            "currency": currency,
            "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            "methodDetails": {"feePayer": True},
        },
        realm="test.example.com",
        request_b64="e30",
    )


def add_reverting_estimate(httpx_mock: HTTPXMock, data: str) -> None:
    httpx_mock.add_response(
        url="https://rpc.test", json={"jsonrpc": "2.0", "result": "0x1079", "id": 1}
    )
    httpx_mock.add_response(
        url="https://rpc.test", json={"jsonrpc": "2.0", "result": "0x1", "id": 1}
    )
    httpx_mock.add_response(
        url="https://rpc.test",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": 3, "message": "execution reverted", "data": data},
        },
    )


class TestSponsoredCharge:
    async def test_throws_spending_limit_exceeded_instead_of_signing(
        self, httpx_mock: HTTPXMock
    ) -> None:
        access_key = TempoAccount.from_key(TEST_PRIVATE_KEY)
        root = "0x975937feafc6869a260c176854dda8764a78e122"
        method = _tempo_method(account=access_key, root_account=root, rpc_url="https://rpc.test")
        add_reverting_estimate(httpx_mock, SPENDING_LIMIT_EXCEEDED)

        with pytest.raises(SpendingLimitExceededError) as raised:
            await method.create_credential(sponsored_challenge())
        assert raised.value.account == root
        assert raised.value.access_key == access_key.address
        estimates = [
            json.loads(request.content)
            for request in httpx_mock.get_requests()
            if json.loads(request.content)["method"] == "eth_estimateGas"
        ]
        assert estimates[0]["params"][0]["keyId"] == access_key.address

    async def test_throws_insufficient_balance_instead_of_signing(
        self, httpx_mock: HTTPXMock
    ) -> None:
        method = _tempo_method(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY), rpc_url="https://rpc.test"
        )
        add_reverting_estimate(httpx_mock, insufficient_balance(0, 1_000_000))

        with pytest.raises(InsufficientBalanceError, match="requires 1000000"):
            await method.create_credential(sponsored_challenge())
