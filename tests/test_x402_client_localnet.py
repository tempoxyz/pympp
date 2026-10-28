"""pympp's x402 client paying x402 servers that settle on an Anvil localnet.

Port of mppx's x402 client localnet coverage: pympp's ``evm.charge`` client pays
Coinbase's official x402 FastAPI middleware, pympp's own ``evm`` server through
its x402 offer, and the MPP + x402 negotiator, with Coinbase's facilitator
settling an EIP-3009 token on Anvil behind a live HTTP server.

Requires X402_ANVIL_RPC_URL. Run with:
    anvil --port 18546 --chain-id 31337 &
    X402_ANVIL_RPC_URL=http://127.0.0.1:18546 pytest tests/test_x402_client_localnet.py -v
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware as x402_payment_middleware
from x402.http.types import PaymentOption, RouteConfig
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.schemas import AssetAmount
from x402.server import x402ResourceServer

from mpp import Receipt
from mpp.client import PaymentTransport
from mpp.methods.evm import client as evm_client
from mpp.methods.evm import evm
from mpp.server import Mpp
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_required,
    decode_payment_signature,
    payment_response,
)
from mpp.x402.fastapi import payment_middleware as negotiator_middleware
from tests.test_x402_localnet import (
    CHAIN_ID,
    RPC_URL,
    SECRET_KEY,
    Chain,
    CoinbaseFacilitator,
    paid_app,
    payer,
    poor_payer,
    recipient,
)
from tests.x402_harness import serve, serve_in_thread

NETWORK = f"eip155:{CHAIN_ID}"

pytestmark = [
    pytest.mark.x402_localnet,
    pytest.mark.skipif(not RPC_URL, reason="X402_ANVIL_RPC_URL not set (no Anvil node)"),
]


class Facilitator(CoinbaseFacilitator):
    """Coinbase's facilitator, also serving ``/supported`` for Coinbase's resource server."""

    def app(self) -> Starlette:
        app = super().app()

        async def supported(request: Request) -> JSONResponse:
            result = await asyncio.to_thread(self.facilitator.get_supported)
            return JSONResponse(result.model_dump(by_alias=True, exclude_none=True))

        app.add_route("/supported", supported, methods=["GET"])
        return app


class Tap(httpx.AsyncBaseTransport):
    """The client's inner transport: records requests and can reshape the exchange.

    ``strip_www_authenticate`` drops MPP challenges from 402 responses so only the
    x402 offer remains; ``paid_retry_delay`` holds an x402 paid retry back.
    """

    def __init__(self, *, strip_www_authenticate: bool = False, paid_retry_delay: float = 0):
        self.inner = httpx.AsyncHTTPTransport()
        self.strip_www_authenticate = strip_www_authenticate
        self.paid_retry_delay = paid_retry_delay
        self.requests: list[httpx.Request] = []
        self.responses: list[httpx.Response] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.paid_retry_delay and PAYMENT_SIGNATURE_HEADER in request.headers:
            await asyncio.sleep(self.paid_retry_delay)
        response = await self.inner.handle_async_request(request)
        if self.strip_www_authenticate and response.status_code == 402:
            headers = [
                (name, value)
                for name, value in response.headers.raw
                if name.lower() != b"www-authenticate"
            ]
            response = httpx.Response(
                402, headers=headers, stream=response.stream, extensions=response.extensions
            )
        self.responses.append(response)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()

    def signatures(self) -> list[str]:
        return [
            r.headers[PAYMENT_SIGNATURE_HEADER]
            for r in self.requests
            if PAYMENT_SIGNATURE_HEADER in r.headers
        ]


@pytest.fixture(scope="module")
def chain() -> Chain:
    assert RPC_URL is not None
    return Chain(RPC_URL)


@pytest.fixture(scope="module")
def facilitator() -> Iterator[tuple[Facilitator, str]]:
    # Its own thread and loop: Coinbase's resource server reads /supported
    # synchronously when its middleware is created on the test's loop.
    assert RPC_URL is not None
    instance = Facilitator(RPC_URL)
    with serve_in_thread(instance.app()) as url:
        yield instance, url


def pympp_client(
    chain: Chain, tap: Tap, account: Any = payer, *, max_payment_retries: int = 3
) -> httpx.AsyncClient:
    method = evm_client.charge(currency=chain.asset, account=account, max_amount="1")
    transport = PaymentTransport(
        methods=[method], inner=tap, max_payment_retries=max_payment_retries
    )
    return httpx.AsyncClient(transport=transport, timeout=30)


def refusal(response: httpx.Response) -> str:
    """The reason in the PAYMENT-REQUIRED header of a refused paid retry."""
    assert response.status_code == 402, response.text
    return decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER]).get("error", "")


def x402_routes(chain: Chain, amount: str, max_timeout_seconds: int) -> Any:
    price = AssetAmount(amount=amount, asset=chain.token, extra={"name": "USDC", "version": "2"})
    option = PaymentOption(
        scheme="exact",
        pay_to=recipient.address,
        price=price,
        network=NETWORK,
        max_timeout_seconds=max_timeout_seconds,
    )
    return {"GET /paid": RouteConfig(accepts=option, description="localnet x402 client")}


def resource_server(facilitator_url: str) -> x402ResourceServer:
    server = x402ResourceServer(HTTPFacilitatorClient(FacilitatorConfig(url=facilitator_url)))
    server.register(NETWORK, ExactEvmScheme())  # type: ignore[arg-type]
    return server


def x402_app(middleware: Any) -> FastAPI:
    app = FastAPI()
    app.state.handled = 0
    app.middleware("http")(middleware)

    @app.get("/paid")
    async def paid() -> dict[str, str]:
        app.state.handled += 1
        return {"data": "paid"}

    return app


@contextlib.asynccontextmanager
async def coinbase_server(
    chain: Chain, facilitator_url: str, *, amount: str = "10000", max_timeout_seconds: int = 300
) -> AsyncIterator[tuple[str, FastAPI]]:
    """Serve a route behind Coinbase's official x402 FastAPI middleware."""
    routes = x402_routes(chain, amount, max_timeout_seconds)
    app = x402_app(x402_payment_middleware(routes, resource_server(facilitator_url)))
    async with serve(app) as url:
        yield f"{url}/paid", app


@contextlib.asynccontextmanager
async def pympp_server(chain: Chain, facilitator_url: str) -> AsyncIterator[str]:
    """Serve a pympp ``evm`` route requiring mppx's route-bound x402 nonce."""
    server = Mpp(
        methods=evm(
            currency=chain.asset,
            recipient=recipient.address,
            facilitator=facilitator_url,
            route_binding="required",
        ),
        realm="localnet.test",
        secret_key=SECRET_KEY,
    )
    async with serve(paid_app(server, "0.01")) as url:
        yield f"{url}/paid"


def authorization(signature: str) -> dict[str, Any]:
    return decode_payment_signature(signature)["payload"]["authorization"]  # type: ignore[index]


async def test_pays_coinbase_middleware_on_chain(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    coinbase, facilitator_url = facilitator
    settles = coinbase.settle_requests
    async with coinbase_server(chain, facilitator_url) as (url, app):
        tap = Tap()
        payer_before = chain.balance(payer.address)
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap) as client:
            response = await client.get(url)

        assert response.status_code == 200, response.text
        assert response.json() == {"data": "paid"}
        settled = payment_response(response)
        assert settled is not None
        assert settled["success"] is True
        assert settled["network"] == NETWORK
        assert chain.receipt_status(settled["transaction"]) == 1
        assert chain.balance(payer.address) == payer_before - 10_000
        assert chain.balance(recipient.address) == recipient_before + 10_000
        [signature] = tap.signatures()
        signed = authorization(signature)
        assert (signed["from"], signed["to"], signed["value"]) == (
            payer.address,
            recipient.address,
            "10000",
        )
        assert chain.authorization_used(payer.address, signed["nonce"])
        assert "authorization" not in tap.requests[-1].headers
        assert app.state.handled == 1
        assert coinbase.settle_requests == settles + 1


async def test_pays_sub_cent_coinbase_prices_sequentially(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    _, facilitator_url = facilitator
    async with coinbase_server(chain, facilitator_url, amount="10") as (url, _):
        async with httpx.AsyncClient() as http:
            unpaid = await http.get(url)
        [accepted] = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])["accepts"]
        assert (accepted["amount"], accepted["asset"]) == ("10", chain.token)

        tap = Tap()
        payer_before = chain.balance(payer.address)
        recipient_before = chain.balance(recipient.address)
        transactions: list[str] = []
        async with pympp_client(chain, tap) as client:
            for _ in range(3):
                response = await client.get(url)
                assert response.status_code == 200, response.text
                settled = payment_response(response)
                assert settled is not None
                assert chain.receipt_status(settled["transaction"]) == 1
                transactions.append(settled["transaction"])

        assert len(set(transactions)) == 3
        nonces = {authorization(signature)["nonce"] for signature in tap.signatures()}
        assert len(nonces) == 3
        assert all(chain.authorization_used(payer.address, nonce) for nonce in nonces)
        assert chain.balance(payer.address) == payer_before - 30
        assert chain.balance(recipient.address) == recipient_before + 30


async def test_pays_pympp_server_through_its_route_bound_x402_offer(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    _, facilitator_url = facilitator
    async with pympp_server(chain, facilitator_url) as url:
        tap = Tap(strip_www_authenticate=True)
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap) as client:
            response = await client.get(url)

        assert response.status_code == 200, response.text
        unpaid = tap.responses[0]
        assert unpaid.status_code == 402
        assert "www-authenticate" not in unpaid.headers
        offered = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])
        assert "mppx" in offered.get("extensions", {})
        [signature] = tap.signatures()
        assert "mppx" in decode_payment_signature(signature).get("extensions", {})
        assert "authorization" not in tap.requests[-1].headers
        settled = payment_response(response)
        assert settled is not None
        assert chain.receipt_status(settled["transaction"]) == 1
        assert chain.authorization_used(payer.address, authorization(signature)["nonce"])
        assert chain.balance(recipient.address) == recipient_before + 10_000


async def test_pays_pympp_dual_offer_natively(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    _, facilitator_url = facilitator
    async with pympp_server(chain, facilitator_url) as url:
        tap = Tap()
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap) as client:
            response = await client.get(url)

        assert response.status_code == 200, response.text
        assert PAYMENT_REQUIRED_HEADER in tap.responses[0].headers
        assert "www-authenticate" in tap.responses[0].headers
        paid = tap.requests[-1]
        assert paid.headers["authorization"].startswith("Payment ")
        assert PAYMENT_SIGNATURE_HEADER not in paid.headers
        assert payment_response(response) is None
        receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
        assert receipt.method == "evm"
        assert chain.receipt_status(receipt.reference) == 1
        assert chain.balance(recipient.address) == recipient_before + 10_000


async def test_pays_negotiator_dual_offer_natively(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    _, facilitator_url = facilitator
    routes = x402_routes(chain, "10000", 300)
    middleware = negotiator_middleware(
        routes, resource_server(facilitator_url), secret_key=SECRET_KEY, realm="localnet.test"
    )
    app = x402_app(middleware)
    async with serve(app) as base:
        tap = Tap()
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap) as client:
            response = await client.get(f"{base}/paid")

        assert response.status_code == 200, response.text
        assert response.json() == {"data": "paid"}
        unpaid = tap.responses[0]
        assert PAYMENT_REQUIRED_HEADER in unpaid.headers
        assert "www-authenticate" in unpaid.headers
        paid = tap.requests[-1]
        assert paid.headers["authorization"].startswith("Payment ")
        assert PAYMENT_SIGNATURE_HEADER not in paid.headers
        receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
        assert receipt.method == "evm"
        assert chain.receipt_status(receipt.reference) == 1
        assert chain.balance(recipient.address) == recipient_before + 10_000
        assert app.state.handled == 1


async def test_unfunded_payer_is_refused_without_a_transfer(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    coinbase, facilitator_url = facilitator
    settles = coinbase.settle_requests
    async with coinbase_server(chain, facilitator_url) as (url, app):
        tap = Tap()
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap, poor_payer, max_payment_retries=1) as client:
            response = await client.get(url)

        assert refusal(response) == "invalid_exact_evm_transaction_simulation_failed"
        assert len(tap.signatures()) == 1
        assert chain.balance(poor_payer.address) == 0
        assert chain.balance(recipient.address) == recipient_before
        assert coinbase.settle_requests == settles
        assert app.state.handled == 0


async def test_replayed_payment_signature_is_refused_after_settlement(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    coinbase, facilitator_url = facilitator
    async with coinbase_server(chain, facilitator_url) as (url, app):
        tap = Tap()
        async with pympp_client(chain, tap) as client:
            paid = await client.get(url)
        assert paid.status_code == 200, paid.text
        [signature] = tap.signatures()
        assert chain.authorization_used(payer.address, authorization(signature)["nonce"])

        settles = coinbase.settle_requests
        payer_before = chain.balance(payer.address)
        recipient_before = chain.balance(recipient.address)
        async with httpx.AsyncClient(timeout=30) as http:
            replayed = await http.get(url, headers={PAYMENT_SIGNATURE_HEADER: signature})

        assert refusal(replayed) == "invalid_exact_evm_nonce_already_used"
        assert chain.balance(payer.address) == payer_before
        assert chain.balance(recipient.address) == recipient_before
        assert coinbase.settle_requests == settles
        assert app.state.handled == 1


async def test_expired_authorization_is_refused_without_a_transfer(
    chain: Chain, facilitator: tuple[Facilitator, str]
) -> None:
    coinbase, facilitator_url = facilitator
    # Coinbase's facilitator wants validBefore at least 6 seconds ahead: a
    # 10-second offer settles at once and fails once the retry waits 5 seconds.
    async with coinbase_server(chain, facilitator_url, max_timeout_seconds=10) as (url, app):
        async with pympp_client(chain, Tap()) as client:
            prompt = await client.get(url)
        assert prompt.status_code == 200, prompt.text

        settles = coinbase.settle_requests
        tap = Tap(paid_retry_delay=5)
        recipient_before = chain.balance(recipient.address)
        async with pympp_client(chain, tap, max_payment_retries=1) as client:
            late = await client.get(url)

        assert refusal(late) == "invalid_exact_evm_payload_authorization_valid_before"
        [signature] = tap.signatures()
        assert not chain.authorization_used(payer.address, authorization(signature)["nonce"])
        assert chain.balance(recipient.address) == recipient_before
        assert coinbase.settle_requests == settles
        assert app.state.handled == 1
