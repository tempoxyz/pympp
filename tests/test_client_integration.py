"""Integration tests for client→server payment roundtrip against a real node.

Requires TEMPO_RPC_URL to be set. Run with:
    TEMPO_RPC_URL=http://localhost:8545 pytest -m integration -v
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mpp import Challenge, Receipt
from mpp.client import PaymentTransport
from mpp.methods.tempo import TempoAccount, tempo
from mpp.methods.tempo.intents import ChargeIntent
from mpp.server.verify import verify_or_challenge
from tests import INTEGRATION, TEST_SECRET
from tests.conftest import _fund_account, _tip20_balance

pytestmark = [pytest.mark.integration, INTEGRATION]


class RealVerifyTransport(httpx.AsyncBaseTransport):
    def __init__(self, intent, request_params, realm, secret_key=TEST_SECRET):
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


def _make_transport(rpc_url, recipient_address, currency, chain_id, *, fee_payer=None):
    intent = ChargeIntent(rpc_url=rpc_url)
    if fee_payer is not None:
        tempo(
            rpc_url=rpc_url,
            fee_payer=fee_payer,
            intents={"charge": intent},
        )
    request_params = {
        "amount": "1000000",
        "currency": currency,
        "recipient": recipient_address,
        "expires": (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "methodDetails": {
            "feePayer": fee_payer is not None,
            "chainId": chain_id,
        },
    }
    return RealVerifyTransport(
        intent=intent,
        request_params=request_params,
        realm="test.local",
    )


@pytest.fixture
def server_transport(rpc_url, funded_recipient, currency, chain_id):
    return _make_transport(rpc_url, funded_recipient.address, currency, chain_id)


@pytest.fixture
def fee_payer_transport(rpc_url, funded_recipient, currency, chain_id):
    fee_payer = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, fee_payer.address, currency)
    return _make_transport(
        rpc_url, funded_recipient.address, currency, chain_id, fee_payer=fee_payer
    )


class TestClientServerIntegration:
    async def test_free_endpoint_no_payment(self, server_transport):
        async with httpx.AsyncClient(transport=server_transport, base_url="http://test") as client:
            response = await client.get("/free")
            assert response.status_code == 200
            assert response.json() == {"free": True}

    async def test_paid_endpoint_returns_402_without_auth(self, server_transport):
        async with httpx.AsyncClient(transport=server_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 402
            assert response.headers["www-authenticate"].startswith("Payment ")

    async def test_full_payment_roundtrip(self, rpc_url, funded_payer, server_transport):
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        payment_transport = PaymentTransport(methods=[method], inner=server_transport)

        async with httpx.AsyncClient(transport=payment_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 200
            data = response.json()
            assert data["paid"] is True
            assert funded_payer.address.lower() in data["payer"].lower()

            receipt_header = response.headers.get("payment-receipt")
            assert receipt_header is not None
            receipt = Receipt.from_payment_receipt(receipt_header)
            assert receipt.status == "success"
            assert receipt.method == "tempo"
            assert receipt.reference.startswith("0x")
            assert len(receipt.reference) >= 66

    async def test_payment_roundtrip_no_matching_method(self, server_transport):
        payment_transport = PaymentTransport(methods=[], inner=server_transport)

        async with httpx.AsyncClient(transport=payment_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 402

    async def test_wrong_auth_scheme_returns_402(self, server_transport):
        async with httpx.AsyncClient(transport=server_transport, base_url="http://test") as client:
            response = await client.get("/paid", headers={"authorization": "Bearer some-jwt-token"})
            assert response.status_code == 402
            assert response.headers["www-authenticate"].startswith("Payment ")

    async def test_malformed_credential_returns_402(self, server_transport):
        async with httpx.AsyncClient(transport=server_transport, base_url="http://test") as client:
            response = await client.get(
                "/paid", headers={"authorization": "Payment !!not-valid-base64!!"}
            )
            assert response.status_code == 402
            assert response.headers["www-authenticate"].startswith("Payment ")

    async def test_multiple_sequential_payments(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        transport = _make_transport(rpc_url, funded_recipient.address, currency, chain_id)

        payer_a = funded_payer
        payer_b = TempoAccount.from_key("0x" + os.urandom(32).hex())
        _fund_account(rpc_url, payer_b.address, currency)

        references = []
        for payer in [payer_a, payer_b]:
            method = tempo(
                account=payer,
                rpc_url=rpc_url,
                intents={"charge": ChargeIntent()},
            )
            payment_transport = PaymentTransport(methods=[method], inner=transport)
            async with httpx.AsyncClient(
                transport=payment_transport, base_url="http://test"
            ) as client:
                response = await client.get("/paid")
                assert response.status_code == 200
                receipt = Receipt.from_payment_receipt(response.headers["payment-receipt"])
                assert receipt.status == "success"
                references.append(receipt.reference)

        assert references[0] != references[1]

    async def test_client_balance_decreases_after_payment(
        self, rpc_url, funded_payer, server_transport, currency
    ):
        with httpx.Client(timeout=30) as c:
            balance_before = _tip20_balance(rpc_url, currency, funded_payer.address, c)

        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        payment_transport = PaymentTransport(methods=[method], inner=server_transport)

        async with httpx.AsyncClient(transport=payment_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 200

        with httpx.Client(timeout=30) as c:
            balance_after = _tip20_balance(rpc_url, currency, funded_payer.address, c)

        assert balance_after < balance_before
        assert balance_before - balance_after >= 1_000_000

    async def test_e2e_charge_with_fee_payer(self, rpc_url, funded_payer, fee_payer_transport):
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        payment_transport = PaymentTransport(methods=[method], inner=fee_payer_transport)

        async with httpx.AsyncClient(transport=payment_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 200
            data = response.json()
            assert data["paid"] is True

            receipt = Receipt.from_payment_receipt(response.headers["payment-receipt"])
            assert receipt.status == "success"
            assert receipt.method == "tempo"
            assert receipt.reference.startswith("0x")
            assert len(receipt.reference) >= 66

    async def test_fee_payer_no_signer_fails_verification(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        intent = ChargeIntent(rpc_url=rpc_url)
        request_params = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "methodDetails": {
                "feePayer": True,
                "chainId": chain_id,
                "feePayerUrl": "http://127.0.0.1:1/nonexistent",
            },
        }

        client_method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="integ-no-signer",
            method="tempo",
            intent="charge",
            request=request_params,
        )
        credential = await client_method.create_credential(challenge)

        with pytest.raises(httpx.ConnectError):
            await intent.verify(credential, request_params)

    async def test_fee_payer_balance_accounting(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        fee_payer_account = TempoAccount.from_key("0x" + os.urandom(32).hex())
        _fund_account(rpc_url, fee_payer_account.address, currency)

        transport = _make_transport(
            rpc_url,
            funded_recipient.address,
            currency,
            chain_id,
            fee_payer=fee_payer_account,
        )

        with httpx.Client(timeout=30) as c:
            payer_before = _tip20_balance(rpc_url, currency, funded_payer.address, c)
            recipient_before = _tip20_balance(rpc_url, currency, funded_recipient.address, c)

        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        payment_transport = PaymentTransport(methods=[method], inner=transport)

        async with httpx.AsyncClient(transport=payment_transport, base_url="http://test") as client:
            response = await client.get("/paid")
            assert response.status_code == 200

        with httpx.Client(timeout=30) as c:
            payer_after = _tip20_balance(rpc_url, currency, funded_payer.address, c)
            recipient_after = _tip20_balance(rpc_url, currency, funded_recipient.address, c)

        assert payer_before - payer_after == 1_000_000
        assert recipient_after - recipient_before == 1_000_000
