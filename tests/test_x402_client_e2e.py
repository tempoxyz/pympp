"""The pympp x402 client paying live x402 servers over real HTTP.

Port of mppx's client interop tests (``src/x402/Exact.e2e.test.ts``,
``src/x402/CoinbaseClient.integration.test.ts``): every server and the
facilitator run as real HTTP servers on localhost and pympp's client pays them
over real connections. The servers are Coinbase's official x402 resource
server (its FastAPI middleware), pympp's own ``evm`` server and the
MPP + x402 negotiator (``mpp.x402.fastapi``). The facilitator checks EIP-3009
signatures without a chain; ``test_x402_client_localnet.py`` settles on Anvil
and ``test_x402_client_mppx.py`` pays mppx's server.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse as FastAPIJSONResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware as x402_payment_middleware
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.server import x402ResourceServer

from mpp import Challenge, Credential, NoMethodFoundError, Receipt
from mpp.client import Mpp as Client
from mpp.methods.evm import BASE_SEPOLIA_USDC, BASE_USDC
from mpp.methods.evm import client as evm_client
from mpp.methods.evm import server as evm_server
from mpp.server import Mpp, pay
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_required,
    decode_payment_signature,
    encode_payment_signature,
    payment_response,
)
from mpp.x402.fastapi import payment_middleware
from tests.x402_harness import StubFacilitator, hd_account, serve, serve_in_thread

SECRET_KEY = "x402-client-e2e-secret-key-32-bytes"
SEPOLIA = "eip155:84532"
BASE = "eip155:8453"
payer = hd_account(0)
recipient = hd_account(1)


def accepts(*, price: str = "$0.0001", network: str = SEPOLIA, timeout: int = 60) -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": network,
        "payTo": recipient.address,
        "price": price,
        "maxTimeoutSeconds": timeout,
    }


def routes(*offers: dict[str, Any]) -> dict[str, Any]:
    return {"GET /paid": {"accepts": list(offers) or accepts(), "description": "Premium data"}}


def resource_server(facilitator_url: str) -> x402ResourceServer:
    server = x402ResourceServer(HTTPFacilitatorClient(FacilitatorConfig(url=facilitator_url)))
    for network in (SEPOLIA, BASE):
        server.register(network, ExactEvmScheme())  # type: ignore[arg-type]
    return server


def coinbase_app(facilitator_url: str, route_config: dict[str, Any], *, mpp: bool) -> FastAPI:
    """Coinbase's official x402 FastAPI middleware, alone or behind pympp's negotiator."""
    app = FastAPI()
    app.state.handled = 0
    server = resource_server(facilitator_url)
    if mpp:
        app.middleware("http")(payment_middleware(route_config, server, secret_key=SECRET_KEY))
    else:
        app.middleware("http")(x402_payment_middleware(route_config, server))

    @app.get("/paid")
    async def paid() -> FastAPIJSONResponse:
        app.state.handled += 1
        return FastAPIJSONResponse({"data": "premium"})

    return app


def pympp_app(facilitator_url: str, *, route_binding: Any = "required") -> Starlette:
    """pympp's own evm server: native MPP and x402 from one route."""
    server = Mpp(
        methods=evm_server.charge(
            currency=BASE_SEPOLIA_USDC,
            recipient=recipient.address,
            facilitator=facilitator_url,
            route_binding=route_binding,
        ),
        secret_key=SECRET_KEY,
    )

    @pay(server.charge(amount="0.0001", description="pympp x402"))
    async def paid(request: Request, credential: Credential, receipt: Receipt):
        return PlainTextResponse("paid", headers={"Payment-Receipt": receipt.to_payment_receipt()})

    return Starlette(routes=[Route("/paid", paid)])


@dataclass
class Recorder(httpx.AsyncBaseTransport):
    """Records the client's requests and lets a test rewrite or drop parts of them."""

    inner: httpx.AsyncBaseTransport = field(default_factory=httpx.AsyncHTTPTransport)
    requests: list[httpx.Request] = field(default_factory=list)
    responses: list[httpx.Response] = field(default_factory=list)
    rewrite: Callable[[httpx.Request], httpx.Request | None] | None = None
    strip_www_authenticate: bool = False
    www_authenticate: str | None = None
    delay_paid: float = 0.0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.rewrite is not None:
            request = self.rewrite(request) or request
        self.requests.append(request)
        if self.delay_paid and PAYMENT_SIGNATURE_HEADER in request.headers:
            delay, self.delay_paid = self.delay_paid, 0.0
            await asyncio.sleep(delay)
        response = await self.inner.handle_async_request(request)
        if self.strip_www_authenticate and response.status_code == 402:
            del response.headers["www-authenticate"]
        if self.www_authenticate is not None and response.status_code == 402:
            response.headers["www-authenticate"] = self.www_authenticate
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

    def authorizations(self) -> list[str]:
        return [r.headers["authorization"] for r in self.requests if "authorization" in r.headers]


@contextlib.asynccontextmanager
async def paying_client(
    recorder: Recorder | None = None, **options: Any
) -> AsyncIterator[tuple[Client, Recorder]]:
    recorder = recorder or Recorder()
    method = evm_client.charge(
        currency=options.pop("currency", BASE_SEPOLIA_USDC),
        account=options.pop("account", payer),
        max_amount=options.pop("max_amount", None),
    )
    client = Client(methods=[method], **options)
    client.payment_transport._inner = recorder  # pyright: ignore[reportPrivateUsage]
    async with client:
        yield client, recorder


@contextlib.asynccontextmanager
async def coinbase(
    *offers: dict[str, Any], mpp: bool = False, facilitator: StubFacilitator | None = None
) -> AsyncIterator[tuple[str, StubFacilitator, FastAPI]]:
    facilitator = facilitator or StubFacilitator()
    with serve_in_thread(facilitator.app()) as facilitator_url:
        app = coinbase_app(facilitator_url, routes(*offers), mpp=mpp)
        async with serve(app) as url:
            yield url + "/paid", facilitator, app


@contextlib.asynccontextmanager
async def pympp(route_binding: Any = "required") -> AsyncIterator[tuple[str, StubFacilitator]]:
    facilitator = StubFacilitator()
    with serve_in_thread(facilitator.app()) as facilitator_url:
        async with serve(pympp_app(facilitator_url, route_binding=route_binding)) as url:
            yield url + "/paid", facilitator


# -- (a) Coinbase's official x402 resource server ------------------------------


async def test_pays_the_official_x402_server() -> None:
    async with coinbase() as (url, facilitator, app), paying_client() as (client, recorder):
        response = await client.fetch(url)
    assert response.status_code == 200
    assert response.json() == {"data": "premium"}
    assert app.state.handled == 1
    [signature] = recorder.signatures()
    payment: dict[str, Any] = dict(decode_payment_signature(signature))
    assert payment["accepted"]["amount"] == "100"
    assert payment["resource"]["url"] == url
    assert recorder.authorizations() == []
    receipt = payment_response(response)
    assert receipt is not None and receipt["success"] is True
    assert receipt.get("payer") == payer.address
    [settled] = facilitator.settle_requests
    assert settled["paymentPayload"]["payload"] == payment["payload"]


async def test_pays_sub_cent_prices() -> None:
    async with coinbase(accepts(price="$0.00001")) as (url, facilitator, _):
        async with paying_client() as (client, recorder):
            responses = [await client.fetch(url) for _ in range(3)]
    assert [r.status_code for r in responses] == [200, 200, 200]
    amounts = [decode_payment_signature(s)["accepted"]["amount"] for s in recorder.signatures()]
    assert amounts == ["10", "10", "10"]
    assert len(facilitator.settle_requests) == 3


async def test_picks_the_offer_on_its_own_network() -> None:
    offers = (accepts(network=BASE), accepts(network=SEPOLIA))
    async with coinbase(*offers) as (url, _, _app), paying_client() as (client, recorder):
        response = await client.fetch(url)
    assert response.status_code == 200
    [signature] = recorder.signatures()
    assert decode_payment_signature(signature)["accepted"]["network"] == SEPOLIA


async def test_wrong_network_or_asset_is_not_paid() -> None:
    failures: list[dict[str, Any]] = []
    async with coinbase() as (url, facilitator, app):
        async with paying_client(currency=BASE_USDC) as (client, recorder):
            client.on_payment_failed(failures.append)
            with pytest.raises(NoMethodFoundError):
                await client.fetch(url)
    assert recorder.signatures() == []
    assert facilitator.verify_requests == [] and app.state.handled == 0
    assert "No method found for challenges" in str(failures[0]["error"])


async def test_amount_above_policy_is_not_paid() -> None:
    async with coinbase(accepts(price="$0.01")) as (url, facilitator, app):
        async with paying_client(max_amount="0.001") as (client, recorder):
            with pytest.raises(NoMethodFoundError):
                await client.fetch(url)
    assert recorder.signatures() == []
    assert facilitator.verify_requests == [] and app.state.handled == 0


async def test_tampered_payment_is_rejected() -> None:
    def tamper(request: httpx.Request) -> httpx.Request | None:
        if PAYMENT_SIGNATURE_HEADER not in request.headers:
            return None
        signature = request.headers[PAYMENT_SIGNATURE_HEADER]
        payment: dict[str, Any] = dict(decode_payment_signature(signature))
        payment["payload"]["authorization"]["to"] = hd_account(4).address
        request.headers[PAYMENT_SIGNATURE_HEADER] = encode_payment_signature(payment)  # type: ignore[arg-type]
        return request

    async with coinbase() as (url, facilitator, app):
        async with paying_client(Recorder(rewrite=tamper), max_payment_retries=1) as (client, _):
            response = await client.fetch(url)
    assert response.status_code == 402
    assert facilitator.settle_requests == [] and app.state.handled == 0


async def test_replayed_payment_is_rejected() -> None:
    async with coinbase() as (url, facilitator, app), paying_client() as (client, recorder):
        assert (await client.fetch(url)).status_code == 200
        [signature] = recorder.signatures()
        async with httpx.AsyncClient() as http:
            replay = await http.get(url, headers={PAYMENT_SIGNATURE_HEADER: signature})
    assert replay.status_code == 402
    assert app.state.handled == 1
    assert len(facilitator.settle_requests) == 1
    assert facilitator.check(facilitator.verify_requests[-1])["invalidReason"] == "nonce_used"


async def test_expired_payment_is_rejected_then_paid_afresh() -> None:
    async with coinbase(accepts(timeout=1)) as (url, facilitator, app):
        async with paying_client(Recorder(delay_paid=2.2)) as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code == 200
    first, second = recorder.signatures()
    assert first != second
    assert facilitator.check({**facilitator.verify_requests[0]})["invalidReason"] in {
        "authorization_window",
        "nonce_used",
    }
    assert len(facilitator.settle_requests) == 1 and app.state.handled == 1


async def test_facilitator_rejection_is_not_paid() -> None:
    facilitator = StubFacilitator(
        verify_result=lambda body: {"isValid": False, "invalidReason": "insufficient_funds"}
    )
    async with coinbase(facilitator=facilitator) as (url, _, app):
        async with paying_client(max_payment_retries=2) as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code == 402
    assert len(recorder.signatures()) == 2
    assert facilitator.settle_requests == [] and app.state.handled == 0
    error = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER]).get("error")
    assert error


async def test_failed_settlement_is_not_retried_into_a_double_payment() -> None:
    facilitator = StubFacilitator(
        settle_result=lambda body: {
            "success": False,
            "errorReason": "transaction_failed",
            "network": SEPOLIA,
            "transaction": "",
        }
    )
    async with coinbase(facilitator=facilitator) as (url, _, _app):
        async with paying_client(max_payment_retries=1) as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code != 200
    assert len(recorder.signatures()) == 1
    assert len(facilitator.settle_requests) == 1


async def test_facilitator_outage_is_reported_without_paying() -> None:
    async with serve(coinbase_app("http://127.0.0.1:9", routes(), mpp=False)) as base:
        async with paying_client() as (client, recorder):
            response = await client.fetch(base + "/paid")
    assert response.status_code != 200
    assert len(recorder.signatures()) <= 1


# -- (b) pympp's own evm server and the MPP + x402 negotiator -------------------


async def test_dual_offer_pays_native_mpp_on_a_pympp_server() -> None:
    async with pympp() as (url, facilitator), paying_client() as (client, recorder):
        response = await client.fetch(url)
    assert response.status_code == 200
    assert recorder.signatures() == []
    [authorization] = recorder.authorizations()
    assert authorization.startswith("Payment ")
    assert Receipt.from_payment_receipt(response.headers["payment-receipt"]).method == "evm"
    assert len(facilitator.settle_requests) == 1


@pytest.mark.parametrize("route_binding", ["required", "resource"])
async def test_x402_path_pays_a_pympp_server(route_binding: str) -> None:
    async with pympp(route_binding) as (url, facilitator):
        async with paying_client(Recorder(strip_www_authenticate=True)) as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code == 200
    [signature] = recorder.signatures()
    payment: dict[str, Any] = dict(decode_payment_signature(signature))
    # pympp advertises mppx's route binding in both modes, so the client binds.
    assert "nonce" in payment["extensions"]["mppx"]["info"]
    receipt = payment_response(response)
    assert receipt is not None and receipt["success"] is True
    assert len(facilitator.settle_requests) == 1


async def test_x402_replay_is_rejected_by_a_pympp_server() -> None:
    async with pympp() as (url, facilitator):
        async with paying_client(Recorder(strip_www_authenticate=True)) as (client, recorder):
            assert (await client.fetch(url)).status_code == 200
        [signature] = recorder.signatures()
        async with httpx.AsyncClient() as http:
            replay = await http.get(url, headers={PAYMENT_SIGNATURE_HEADER: signature})
    assert replay.status_code in (402, 403)  # pympp refuses a replayed credential
    assert len(facilitator.settle_requests) == 1


async def test_negotiator_dual_offer_pays_native_mpp() -> None:
    async with coinbase(mpp=True) as (url, facilitator, app):
        async with paying_client() as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code == 200
    assert recorder.signatures() == []
    assert recorder.authorizations()[0].startswith("Payment ")
    assert app.state.handled == 1
    assert len(facilitator.settle_requests) == 1


async def test_negotiator_x402_path_pays_through_the_official_middleware() -> None:
    async with coinbase(mpp=True) as (url, facilitator, app):
        async with paying_client(Recorder(strip_www_authenticate=True)) as (client, recorder):
            response = await client.fetch(url)
    assert response.status_code == 200
    assert len(recorder.signatures()) == 1 and recorder.authorizations() == []
    assert payment_response(response) is not None
    assert app.state.handled == 1 and len(facilitator.settle_requests) == 1


async def test_unpayable_mpp_offer_falls_back_to_x402() -> None:
    """MPP offered only in a method the client lacks, plus x402: the client pays x402."""
    tempo = Challenge.create(
        secret_key=SECRET_KEY,
        realm="127.0.0.1",
        method="tempo",
        intent="charge",
        request={"amount": "100", "currency": "0x" + "20" * 20, "recipient": recipient.address},
    )
    recorder = Recorder(www_authenticate=tempo.to_www_authenticate(tempo.realm))
    async with coinbase(mpp=True) as (url, facilitator, app):
        async with paying_client(recorder) as (client, _):
            response = await client.fetch(url)
    assert response.status_code == 200
    assert len(recorder.signatures()) == 1 and recorder.authorizations() == []
    assert app.state.handled == 1 and len(facilitator.settle_requests) == 1
