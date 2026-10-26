"""MPP and x402 clients paying one route behind the official x402 FastAPI middleware."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.schemas import SettleResponse, SupportedKind, SupportedResponse, VerifyResponse
from x402.schemas.hooks import SkipHandlerDirective, SkipHandlerResult
from x402.server import x402ResourceServer

from mpp import Challenge, Receipt
from mpp.methods.evm import BASE_SEPOLIA_USDC
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    decode_payment_required,
)
from mpp.x402.fastapi import payment_middleware
from tests.x402_harness import hd_account, sign_native, sign_x402_payment

SECRET_KEY = "x402-fastapi-secret-key-32-bytes-long"
NETWORK = "eip155:84532"
TRANSACTION = "0x" + "1" * 64
payer = hd_account(0)
recipient = hd_account(1)
ROUTES: Any = {
    "GET /paid": {
        "accepts": {
            "maxTimeoutSeconds": 15,
            "network": NETWORK,
            "payTo": recipient.address,
            "price": "$0.01",
            "scheme": "exact",
        },
        "description": "Premium data",
    },
}


class Facilitator:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[str] = []
        self.payloads: list[Any] = []
        self.supported_calls = 0

    def get_supported(self) -> SupportedResponse:
        self.supported_calls += 1
        kind = SupportedKind(x402_version=2, scheme="exact", network=NETWORK)
        return SupportedResponse(kinds=[kind], extensions=[], signers={})

    async def verify(self, payload: Any, requirements: Any) -> VerifyResponse:
        self.calls.append("verify")
        self.payloads.append(payload)
        if not self.valid:
            return VerifyResponse(is_valid=False, invalid_reason="invalid_signature")
        return VerifyResponse(is_valid=True, payer=payer.address)

    async def settle(self, payload: Any, requirements: Any) -> SettleResponse:
        self.calls.append("settle")
        return SettleResponse(
            success=True, transaction=TRANSACTION, network=NETWORK, payer=payer.address
        )


def create_app(facilitator: Facilitator, server: x402ResourceServer | None = None) -> FastAPI:
    server = server or x402ResourceServer(facilitator)  # type: ignore[arg-type]
    server.register(NETWORK, ExactEvmScheme())  # type: ignore[arg-type]
    app = FastAPI()
    app.state.handled = 0
    app.middleware("http")(payment_middleware(ROUTES, server, secret_key=SECRET_KEY))

    @app.get("/paid")
    async def paid() -> JSONResponse:
        app.state.handled += 1
        return JSONResponse({"data": "premium"}, headers={"Cache-Control": "max-age=5"})

    @app.get("/free")
    async def free() -> dict[str, bool]:
        return {"free": True}

    return app


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://api.test")


async def pay_mpp(http: httpx.AsyncClient) -> httpx.Response:
    unpaid = await http.get("/paid")
    challenge = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
    credential = await sign_native(payer, challenge, BASE_SEPOLIA_USDC)
    return await http.get("/paid", headers={"Authorization": credential.to_authorization()})


async def test_unprotected_routes_pass_through() -> None:
    facilitator = Facilitator()
    async with client(create_app(facilitator)) as http:
        response = await http.get("/free")
    assert response.json() == {"free": True}
    assert facilitator.supported_calls == 0


async def test_unpaid_response_offers_x402_and_mpp() -> None:
    async with client(create_app(Facilitator())) as http:
        response = await http.get("/paid")
    assert response.status_code == 402
    assert response.headers["cache-control"] == "no-store"
    [accepted] = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])["accepts"]
    [header] = response.headers.get_list("www-authenticate")
    challenge = Challenge.from_www_authenticate(header)
    assert (challenge.method, challenge.intent) == ("evm", "charge")
    assert challenge.description == "Premium data"
    assert challenge.request["amount"] == accepted["amount"] == "10000"
    assert challenge.request["currency"] == BASE_SEPOLIA_USDC.address
    assert challenge.request["recipient"] == recipient.address
    remaining = datetime.fromisoformat(challenge.expires or "") - datetime.now(UTC)
    assert 10 < remaining.total_seconds() <= 15


async def test_mpp_credential_settles_through_the_x402_server() -> None:
    facilitator = Facilitator()
    app = create_app(facilitator)
    async with client(app) as http:
        response = await pay_mpp(http)
    assert response.status_code == 200
    assert response.json() == {"data": "premium"}
    assert Receipt.from_payment_receipt(response.headers["payment-receipt"]).reference == (
        TRANSACTION
    )
    assert response.headers["cache-control"] == "private, max-age=5"
    assert facilitator.calls == ["verify", "settle"]
    authorization = facilitator.payloads[0].payload["authorization"]
    assert authorization["from"] == payer.address
    assert app.state.handled == 1


async def test_mpp_credential_is_not_accepted_twice() -> None:
    facilitator = Facilitator()
    async with client(create_app(facilitator)) as http:
        unpaid = await http.get("/paid")
        challenge = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
        credential = await sign_native(payer, challenge, BASE_SEPOLIA_USDC)
        headers = {"Authorization": credential.to_authorization()}
        assert (await http.get("/paid", headers=headers)).status_code == 200
        assert (await http.get("/paid", headers=headers)).status_code != 200
    assert facilitator.calls.count("settle") == 1


async def test_x402_credential_goes_to_the_official_middleware() -> None:
    facilitator = Facilitator()
    app = create_app(facilitator)
    async with client(app) as http:
        unpaid = await http.get("/paid")
        required = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])
        signature = sign_x402_payment(payer, dict(required["accepts"][0]), "https://api.test/paid")
        response = await http.get("/paid", headers={"PAYMENT-SIGNATURE": signature})
    assert response.status_code == 200
    assert response.headers[PAYMENT_RESPONSE_HEADER]
    assert "payment-receipt" not in response.headers
    assert facilitator.calls == ["verify", "settle"]
    assert facilitator.supported_calls == 1


async def test_rejects_mpp_and_x402_credentials_together() -> None:
    async with client(create_app(Facilitator())) as http:
        response = await http.get(
            "/paid", headers={"Authorization": "Payment abc", "X-PAYMENT": "abc"}
        )
    assert response.status_code == 400
    assert response.json() == {
        "error": "Send either an MPP credential or an x402 payment signature, not both."
    }


async def test_failed_verification_answers_both_challenges() -> None:
    facilitator = Facilitator(valid=False)
    app = create_app(facilitator)
    async with client(app) as http:
        response = await pay_mpp(http)
    assert response.status_code == 402
    assert response.headers[PAYMENT_REQUIRED_HEADER]
    assert Challenge.from_www_authenticate(response.headers["www-authenticate"]).method == "evm"
    assert facilitator.calls == ["verify"]
    assert app.state.handled == 0


async def test_skip_handler_hooks_apply_to_mpp_credentials() -> None:
    facilitator = Facilitator()
    server = x402ResourceServer(facilitator)  # type: ignore[arg-type]
    directive = SkipHandlerDirective(body={"acknowledged": True})
    server.on_after_verify(lambda _: SkipHandlerResult(response=directive))
    app = create_app(facilitator, server)
    async with client(app) as http:
        response = await pay_mpp(http)
    assert response.status_code == 200
    assert response.content == b'{"acknowledged":true}'
    assert "payment-receipt" in response.headers
    assert app.state.handled == 0
    assert facilitator.calls == ["verify", "settle"]


def test_requires_a_strong_secret_key() -> None:
    server = x402ResourceServer(Facilitator())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="32 bytes"):
        payment_middleware(ROUTES, server, secret_key="short")
