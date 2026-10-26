"""MPP and x402 clients paying one route behind the official x402 FastAPI middleware."""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
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
from mpp.errors import InternalPaymentError
from mpp.methods.evm import BASE_SEPOLIA_USDC
from mpp.methods.evm.intents import _ClaimCache
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    decode_payment_required,
)
from mpp.x402._negotiator import Negotiator
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


def create_app(
    facilitator: Facilitator, server: x402ResourceServer | None = None, routes: Any = ROUTES
) -> FastAPI:
    server = server or x402ResourceServer(facilitator)  # type: ignore[arg-type]
    server.register(NETWORK, ExactEvmScheme())  # type: ignore[arg-type]
    app = FastAPI()
    app.state.handled = 0
    app.middleware("http")(payment_middleware(routes, server, secret_key=SECRET_KEY))

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


class PaywallProvider:
    def generate_html(self, payment_required: Any, config: Any = None) -> str:
        return "<html>custom paywall</html>"


async def test_paywall_provider_serves_unpaid_browser_requests() -> None:
    facilitator = Facilitator()
    server = x402ResourceServer(facilitator)  # type: ignore[arg-type]
    server.register(NETWORK, ExactEvmScheme())  # type: ignore[arg-type]
    app = FastAPI()
    app.middleware("http")(
        payment_middleware(
            ROUTES,
            server,
            secret_key=SECRET_KEY,
            paywall_provider=PaywallProvider(),  # type: ignore[arg-type]
        )
    )
    headers = {"Accept": "text/html", "User-Agent": "Mozilla/5.0"}
    async with client(app) as http:
        response = await http.get("/paid", headers=headers)
    assert response.status_code == 402
    assert response.text == "<html>custom paywall</html>"


async def test_missing_raw_path_falls_back_to_the_url_path() -> None:
    app = create_app(Facilitator())

    async def without_raw_path(scope: Any, receive: Any, send: Any) -> None:
        await app(dict(scope, raw_path=None), receive, send)

    async with client(without_raw_path) as http:  # type: ignore[arg-type]
        assert (await http.get("/free")).json() == {"free": True}
        assert (await http.get("/paid")).status_code == 402


async def test_encoded_path_delimiters_keep_distinct_challenge_scopes() -> None:
    facilitator = Facilitator()
    routes = {"GET /files/*": ROUTES["GET /paid"]}
    app = create_app(facilitator, routes=routes)

    @app.get("/files/{name:path}")
    async def files(name: str) -> dict[str, str]:
        return {"name": name}

    async with client(app) as http:
        unpaid = await http.get("/files/x%2Fy")
        challenge = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
        credential = await sign_native(payer, challenge, BASE_SEPOLIA_USDC)
        headers = {"Authorization": credential.to_authorization()}
        assert (await http.get("/files/x/y", headers=headers)).status_code == 402
        paid = await http.get("/files/x%2Fy", headers=headers)
    assert paid.json() == {"name": "x/y"}
    assert facilitator.calls.count("settle") == 1


def test_x402_extra_installs_the_evm_scheme_dependencies() -> None:
    with open(Path(__file__).parents[1] / "pyproject.toml", "rb") as file:
        extra = tomllib.load(file)["project"]["optional-dependencies"]["x402"]
    [x402] = [requirement for requirement in extra if re.match(r"x402\b", requirement)]
    extras = re.search(r"\[(.*)\]", x402)
    assert extras is not None
    assert {"evm", "httpx"} <= {name.strip() for name in extras.group(1).split(",")}


async def test_failed_verify_call_releases_the_authorization() -> None:
    facilitator = Facilitator()
    verify = facilitator.verify
    failures = [RuntimeError("facilitator timed out")]

    async def flaky_verify(payload: Any, requirements: Any) -> VerifyResponse:
        if failures:
            facilitator.calls.append("verify")
            raise failures.pop()
        return await verify(payload, requirements)

    facilitator.verify = flaky_verify  # type: ignore[method-assign]
    app = create_app(facilitator)
    async with client(app) as http:
        unpaid = await http.get("/paid")
        challenge = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
        credential = await sign_native(payer, challenge, BASE_SEPOLIA_USDC)
        headers = {"Authorization": credential.to_authorization()}
        assert (await http.get("/paid", headers=headers)).status_code == 402
        response = await http.get("/paid", headers=headers)
    assert response.status_code == 200
    assert facilitator.calls == ["verify", "verify", "settle"]


async def test_pending_settlement_keeps_the_claim_without_a_retry_challenge() -> None:
    facilitator = Facilitator()

    async def pending(payload: Any, requirements: Any) -> SettleResponse:
        facilitator.calls.append("settle")
        return SettleResponse(
            success=False,
            error_reason="settlement_pending",
            transaction=TRANSACTION,
            network=NETWORK,
            payer=payer.address,
        )

    facilitator.settle = pending  # type: ignore[method-assign]
    app = create_app(facilitator)
    async with client(app) as http:
        unpaid = await http.get("/paid")
        challenge = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
        credential = await sign_native(payer, challenge, BASE_SEPOLIA_USDC)
        headers = {"Authorization": credential.to_authorization()}
        # Raised like the native facilitator path: a 500, never a retryable 402.
        with pytest.raises(InternalPaymentError):
            await http.get("/paid", headers=headers)
        calls = list(facilitator.calls)
        replayed = await http.get("/paid", headers=headers)
    assert replayed.status_code == 403
    assert "settle" in calls
    assert facilitator.calls == calls
    assert app.state.handled == 0


def test_default_store_expires_claims() -> None:
    server = x402ResourceServer(Facilitator())  # type: ignore[arg-type]
    assert isinstance(Negotiator(ROUTES, server, secret_key=SECRET_KEY).store, _ClaimCache)
