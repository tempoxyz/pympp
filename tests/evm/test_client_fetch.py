"""End-to-end: one EVM route paid by the payment-aware httpx client over both protocols."""

from collections.abc import Callable, Sequence
from typing import Any

import pytest
from eth_account import Account

from mpp import Receipt
from mpp.client import ChallengeCandidate
from mpp.client import Mpp as ClientMppx
from mpp.evm import assets
from mpp.evm import client as evm_client
from mpp.evm import server as evm_server
from mpp.server import Mpp
from mpp.x402 import PAYMENT_RESPONSE_HEADER, decode_payment_response, is_x402_challenge

from ._helpers import PRIVATE_KEY, SECRET_KEY, TRANSACTION, Facilitator, mock_transport

account = Account.from_key(PRIVATE_KEY)
RECIPIENT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def prefer(
    x402: bool,
) -> Callable[[Sequence[ChallengeCandidate[Any]]], list[ChallengeCandidate[Any]]]:
    def order(candidates: Sequence[ChallengeCandidate[Any]]) -> list[ChallengeCandidate[Any]]:
        return sorted(candidates, key=lambda c: is_x402_challenge(c.challenge) != x402)

    return order


@pytest.mark.parametrize("prefer_x402", [False, True])
async def test_serves_one_route_to_mpp_and_x402_clients(prefer_x402: bool) -> None:
    facilitator = Facilitator()
    server = Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=facilitator),
            )
        ],
        secret_key=SECRET_KEY,
    )
    route = server.charge(amount="0.01")
    client = ClientMppx(
        methods=[
            evm_client.charge(
                account=account,
                authorization=None,
                currencies=[assets.BASE_SEPOLIA_USDC],
                max_atomic_amount="1000000",
            )
        ],
        inner=mock_transport(route, lambda: {"data": "premium content"}),
        order_challenges=prefer(prefer_x402),
    )
    response = await client.fetch("https://example.com/api/data")
    assert response.status_code == 200
    assert response.json() == {"data": "premium content"}
    if prefer_x402:
        settled = decode_payment_response(response.headers[PAYMENT_RESPONSE_HEADER])
        assert settled.transaction == TRANSACTION
    else:
        assert PAYMENT_RESPONSE_HEADER not in response.headers
        assert Receipt.from_headers(response.headers).reference == TRANSACTION
    assert facilitator.reached == ["verify", "settle"]


async def test_native_challenges_rank_before_x402_by_default() -> None:
    facilitator = Facilitator()
    server = Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=facilitator),
            )
        ],
        secret_key=SECRET_KEY,
    )
    client = ClientMppx(
        methods=[evm_client.charge(account=account, currencies=[assets.BASE_SEPOLIA_USDC])],
        inner=mock_transport(server.charge(amount="0.01")),
    )
    response = await client.fetch("https://example.com/api/data")
    assert response.status_code == 200
    assert PAYMENT_RESPONSE_HEADER not in response.headers
    assert "payment-receipt" in response.headers
