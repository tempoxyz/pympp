from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mpay import Challenge
from mpay.client import PaymentTransport
from mpay.methods.tempo import tempo
from mpay.methods.tempo.intents import ChargeIntent
from mpay.server.verify import verify_or_challenge
from tests.conftest import INTEGRATION

pytestmark = [pytest.mark.integration, INTEGRATION]


class RealVerifyTransport(httpx.AsyncBaseTransport):
    def __init__(self, intent, request_params, realm, secret_key):
        self.intent = intent
        self.request_params = request_params
        self.realm = realm
        self.secret_key = secret_key

    async def handle_async_request(self, request):
        if request.url.path == "/free":
            return httpx.Response(200, json={"free": True})

        auth = request.headers.get("authorization")
        result = await verify_or_challenge(
            authorization=auth,
            intent=self.intent,
            request=self.request_params,
            realm=self.realm,
            secret_key=self.secret_key,
        )

        if isinstance(result, Challenge):
            headers = {"www-authenticate": result.to_www_authenticate(self.realm)}
            return httpx.Response(402, headers=headers)

        credential, receipt = result
        return httpx.Response(
            200,
            json={"paid": True, "payer": credential.source},
            headers={"payment-receipt": receipt.to_payment_receipt()},
        )

    async def aclose(self) -> None:
        pass


@pytest.fixture
def server_transport(rpc_url, funded_recipient, currency, chain_id):
    intent = ChargeIntent(rpc_url=rpc_url)
    request_params = {
        "amount": "1000000",
        "currency": currency,
        "recipient": funded_recipient.address,
        "expires": (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "methodDetails": {
            "feePayer": False,
            "chainId": chain_id,
        },
    }
    return RealVerifyTransport(
        intent=intent,
        request_params=request_params,
        realm="test.local",
        secret_key="test-secret-key",
    )


class TestClientServerIntegration:
    async def test_free_endpoint_no_payment(self, server_transport):
        async with httpx.AsyncClient(
            transport=server_transport, base_url="http://test"
        ) as client:
            response = await client.get("/free")
            assert response.status_code == 200
            assert response.json() == {"free": True}

    async def test_paid_endpoint_returns_402_without_auth(self, server_transport):
        async with httpx.AsyncClient(
            transport=server_transport, base_url="http://test"
        ) as client:
            response = await client.get("/paid")
            assert response.status_code == 402
            assert response.headers["www-authenticate"].startswith("Payment ")

    async def test_full_payment_roundtrip(self, rpc_url, funded_payer, server_transport):
        method = tempo(account=funded_payer, rpc_url=rpc_url)
        payment_transport = PaymentTransport(methods=[method], inner=server_transport)

        async with httpx.AsyncClient(
            transport=payment_transport, base_url="http://test"
        ) as client:
            response = await client.get("/paid")
            assert response.status_code == 200
            data = response.json()
            assert data["paid"] is True
            assert funded_payer.address.lower() in data["payer"].lower()

    async def test_payment_roundtrip_no_matching_method(self, server_transport):
        payment_transport = PaymentTransport(methods=[], inner=server_transport)

        async with httpx.AsyncClient(
            transport=payment_transport, base_url="http://test"
        ) as client:
            response = await client.get("/paid")
            assert response.status_code == 402
