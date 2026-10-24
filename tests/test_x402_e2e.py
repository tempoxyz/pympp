"""x402 and MPP clients paying a live pympp server over real HTTP.

Port of mppx's ``src/x402/Exact.e2e.test.ts``: the paid server and the
facilitator run as real HTTP servers on localhost, and clients pay over real
connections. Coinbase's official x402 client (the ``x402`` package) pays with
``PAYMENT-SIGNATURE``; pympp's client pays the same endpoint with a native
``evm/charge`` credential. The facilitator checks EIP-3009 signatures without
a chain; ``tests/test_x402_localnet.py`` settles on Anvil.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from x402 import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm.exact import register_exact_evm_client

from mpp import Challenge, Credential, Receipt
from mpp.client import Client
from mpp.events import PAYMENT_FAILED, PAYMENT_SUCCESS
from mpp.methods.evm import BASE_SEPOLIA_USDC, evm
from mpp.methods.tempo import ChargeIntent as TempoChargeIntent
from mpp.methods.tempo import tempo
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_required,
    decode_payment_response,
    is_x402_credential,
)
from tests.x402_harness import StubFacilitator, hd_account, serve, sign_x402_payment

SECRET_KEY = "x402-e2e-secret-key-32-bytes-long"
REALM = "x402.e2e.test"
payer = hd_account(0)
recipient = hd_account(1)
other = hd_account(4)


def coinbase_client(account: Any = payer) -> x402HttpxClient:
    """Coinbase's x402 client, with its default Base Sepolia USDC allowlist."""
    client = x402Client()
    register_exact_evm_client(client, account)
    return x402HttpxClient(client, timeout=30)


def receipt_response(body: str, receipt: Receipt) -> PlainTextResponse:
    return PlainTextResponse(body, headers={"Payment-Receipt": receipt.to_payment_receipt()})


@dataclass
class Live:
    url: str
    facilitator: StubFacilitator
    server: Mpp
    events: list[tuple[str, dict[str, Any]]]

    async def unpaid(self, path: str = "/paid") -> httpx.Response:
        async with httpx.AsyncClient() as http:
            return await http.get(self.url + path)

    async def accepted(self, path: str = "/paid") -> dict[str, Any]:
        response = await self.unpaid(path)
        required = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])
        return dict(required["accepts"][0])

    async def get(self, path: str = "/paid", **headers: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=30) as http:
            return await http.get(self.url + path, headers=headers)


def build_app(server: Mpp) -> Starlette:
    @server.pay(amount="0.01", description="x402 e2e")
    async def paid(request: Request, credential: Credential, receipt: Receipt):
        return receipt_response("paid", receipt)

    @server.pay(amount="0.00001")
    async def sub_cent(request: Request, credential: Credential, receipt: Receipt):
        return receipt_response("sub-cent", receipt)

    @server.pay(amount="0.01")
    async def public(request: Request, credential: Credential, receipt: Receipt):
        return PlainTextResponse(
            "public", headers={"Cache-Control": "public, max-age=60, s-maxage=600"}
        )

    @server.pay(amount="0.01", body=lambda request: request.query_params.get("order", ""))
    async def body_bound(request: Request, credential: Credential, receipt: Receipt):
        return receipt_response("body", receipt)

    two_prices = server.compose(("evm", {"amount": "0.01"}), ("evm", {"amount": "0.02"}))

    @two_prices
    async def composed(request: Request, credential: Credential, receipt: Receipt):
        return receipt_response(request.app.state.last_amount(credential), receipt)

    async def direct(request: Request):
        result = await server.charge(
            request.headers.get("Authorization"),
            "0.01",
            payment_signature=request.headers.get(PAYMENT_SIGNATURE_HEADER),
            resource_url=str(request.url),
        )
        if isinstance(result, tuple):
            credential, receipt = result
            return JSONResponse({"x402": is_x402_credential(credential), "ref": receipt.reference})
        header = server.x402_payment_required(result, str(request.url))
        assert header is not None
        return JSONResponse({}, status_code=402, headers={PAYMENT_REQUIRED_HEADER: header})

    app = Starlette(
        routes=[
            Route("/paid", paid),
            Route("/sub-cent", sub_cent),
            Route("/public", public),
            Route("/body-bound", body_bound),
            Route("/composed", composed),
            Route("/direct", direct),
        ]
    )

    def last_amount(credential: Credential) -> str:
        request = json.loads(base64.urlsafe_b64decode(credential.challenge.request + "==").decode())
        return request["amount"]

    app.state.last_amount = last_amount
    return app


@pytest.fixture
async def live() -> AsyncIterator[Live]:
    facilitator = StubFacilitator()
    async with serve(facilitator.app()) as facilitator_url:
        server = Mpp.create(
            method=evm(
                currency=BASE_SEPOLIA_USDC,
                recipient=recipient.address,
                facilitator=facilitator_url,
            ),
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        events: list[tuple[str, dict[str, Any]]] = []
        server.on_payment_success(lambda payload: events.append((PAYMENT_SUCCESS, payload)))
        server.on_payment_failed(lambda payload: events.append((PAYMENT_FAILED, payload)))
        async with serve(build_app(server)) as url:
            yield Live(url, facilitator, server, events)


class TestUnpaid:
    async def test_offers_mpp_and_x402_in_one_402(self, live: Live) -> None:
        response = await live.unpaid()

        assert response.status_code == 402
        assert response.headers["content-type"] == "application/problem+json"
        challenge = Challenge.from_www_authenticate(response.headers["WWW-Authenticate"])
        assert (challenge.method, challenge.intent, challenge.realm) == ("evm", "charge", REALM)
        assert challenge.request["amount"] == "10000"
        assert challenge.request["currency"] == BASE_SEPOLIA_USDC.address
        assert challenge.request["recipient"] == recipient.address
        assert challenge.request["methodDetails"] == {
            "chainId": 84532,
            "credentialTypes": ["authorization"],
            "decimals": 6,
        }

        required = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])
        assert required == {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:84532",
                    "amount": "10000",
                    "asset": BASE_SEPOLIA_USDC.address,
                    "payTo": recipient.address,
                    "maxTimeoutSeconds": 300,
                    "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
                }
            ],
            "resource": {"url": f"{live.url}/paid"},
            "error": "PAYMENT-SIGNATURE header is required",
        }

    async def test_resource_url_keeps_the_query_string(self, live: Live) -> None:
        response = await live.unpaid("/paid?q=1")
        required = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])
        assert required["resource"] == {"url": f"{live.url}/paid?q=1"}

    async def test_composed_offers_list_every_x402_requirement(self, live: Live) -> None:
        response = await live.unpaid("/composed")

        assert len(response.headers.get_list("WWW-Authenticate")) == 2
        required = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])
        assert [accepted["amount"] for accepted in required["accepts"]] == ["10000", "20000"]


class TestCoinbaseClient:
    async def test_pays_with_payment_signature(self, live: Live) -> None:
        async with coinbase_client() as client:
            response = await client.get(f"{live.url}/paid")

        assert response.status_code == 200, response.text
        assert response.text == "paid"
        settled = decode_payment_response(response.headers[PAYMENT_RESPONSE_HEADER])
        assert settled["success"] is True
        assert settled["network"] == "eip155:84532"
        assert settled.get("payer") == payer.address
        assert settled["transaction"].startswith("0x")
        receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
        assert receipt.reference == settled["transaction"]
        assert receipt.method == "evm"
        assert len(live.facilitator.verify_requests) == 1
        assert len(live.facilitator.settle_requests) == 1

    async def test_facilitator_gets_the_x402_payment(self, live: Live) -> None:
        async with coinbase_client() as client:
            await client.get(f"{live.url}/paid")

        body = live.facilitator.settle_requests[0]
        assert body["x402Version"] == 2
        assert body["paymentRequirements"] == body["paymentPayload"]["accepted"]
        assert body["paymentRequirements"]["amount"] == "10000"
        authorization = body["paymentPayload"]["payload"]["authorization"]
        assert authorization["from"] == payer.address
        assert authorization["to"] == recipient.address

    async def test_paid_responses_stay_out_of_shared_caches(self, live: Live) -> None:
        async with coinbase_client() as client:
            paid = await client.get(f"{live.url}/paid")
            public = await client.get(f"{live.url}/public")
        assert paid.headers["cache-control"] == "private"
        assert public.headers["cache-control"] == "private, max-age=60"

    async def test_body_bound_routes_are_not_offered_to_x402(self, live: Live) -> None:
        unpaid = await live.unpaid("/body-bound?order=1")
        assert unpaid.status_code == 402
        assert unpaid.headers.get("WWW-Authenticate")
        assert PAYMENT_REQUIRED_HEADER not in unpaid.headers

        # A payment carried over from an unbound route can't pay it either.
        accepted = await live.accepted()
        signature = sign_x402_payment(payer, accepted, f"{live.url}/body-bound?order=1")
        response = await live.get("/body-bound?order=1", **{PAYMENT_SIGNATURE_HEADER: signature})
        assert response.status_code == 402
        assert "bound to a request body" in response.json()["detail"]
        assert live.facilitator.settle_requests == []

    async def test_pays_a_sub_cent_price(self, live: Live) -> None:
        async with coinbase_client() as client:
            response = await client.get(f"{live.url}/sub-cent")
        assert response.status_code == 200, response.text
        assert live.facilitator.settle_requests[0]["paymentRequirements"]["amount"] == "10"

    async def test_pays_the_first_composed_offer(self, live: Live) -> None:
        async with coinbase_client() as client:
            response = await client.get(f"{live.url}/composed")
        assert response.status_code == 200, response.text
        assert response.text == "10000"

    async def test_pays_a_server_built_from_charge(self, live: Live) -> None:
        async with coinbase_client() as client:
            response = await client.get(f"{live.url}/direct")
        assert response.status_code == 200, response.text
        assert response.json()["x402"] is True

    async def test_emits_payment_success(self, live: Live) -> None:
        async with coinbase_client() as client:
            await client.get(f"{live.url}/paid")

        [(name, payload)] = live.events
        assert name == PAYMENT_SUCCESS
        assert payload["method"] == "evm"
        assert is_x402_credential(payload["credential"])
        assert payload["receipt"].payer == payer.address


class TestMppClient:
    async def test_pays_the_same_endpoint_natively(self, live: Live) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, account=payer, max_amount="0.05")
        async with Client(methods=[method]) as client:
            response = await client.get(f"{live.url}/paid")

        assert response.status_code == 200, response.text
        assert PAYMENT_RESPONSE_HEADER not in response.headers
        receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
        assert receipt.method == "evm"
        assert len(live.facilitator.settle_requests) == 1

    async def test_refuses_more_than_max_amount(self, live: Live) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, account=payer, max_amount="0.001")
        async with Client(methods=[method]) as client:
            try:
                response = await client.get(f"{live.url}/paid")
            except ValueError as error:
                assert "No compatible payment method" in str(error)
            else:
                assert response.status_code == 402
        assert live.facilitator.settle_requests == []

    async def test_payment_credential_wins_over_payment_signature(self, live: Live) -> None:
        unpaid = await live.unpaid()
        challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
        credential = await evm(currency=BASE_SEPOLIA_USDC, account=payer).create_credential(
            challenge
        )
        accepted = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])["accepts"][0]
        signature = sign_x402_payment(other, dict(accepted), f"{live.url}/paid")

        response = await live.get(
            Authorization=credential.to_authorization(), **{PAYMENT_SIGNATURE_HEADER: signature}
        )

        assert response.status_code == 200, response.text
        assert PAYMENT_RESPONSE_HEADER not in response.headers
        [settled] = live.facilitator.settle_requests
        assert settled["paymentPayload"]["payload"]["authorization"]["from"] == payer.address


class TestRejectedX402Payments:
    async def rejected(self, response: httpx.Response) -> str:
        assert response.status_code == 402
        assert response.headers.get("WWW-Authenticate")
        return decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER]).get("error", "")

    async def test_payment_for_a_different_amount(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(
            payer, {**accepted, "amount": "1"}, f"{live.url}/paid", value="1"
        )

        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))

        assert "does not match route requirements" in error
        assert live.facilitator.verify_requests == []
        assert live.facilitator.settle_requests == []
        [(name, payload)] = live.events
        assert name == PAYMENT_FAILED
        assert "does not match route requirements" in str(payload["error"])

    async def test_payment_for_a_different_recipient(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(
            payer, {**accepted, "payTo": other.address}, f"{live.url}/paid", to=other.address
        )
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "does not match route requirements" in error

    async def test_authorization_that_differs_from_its_accepted_terms(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(payer, accepted, f"{live.url}/paid", value="1")
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "amount mismatch" in error
        assert live.facilitator.settle_requests == []

    async def test_payment_for_another_resource(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(payer, accepted, f"{live.url}/sub-cent")
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "resource does not match" in error

    async def test_payment_without_a_resource(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(payer, accepted, None)
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "resource does not match" in error

    async def test_malformed_payment_signature(self, live: Live) -> None:
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: "not-base64!"}))
        assert "invalid PAYMENT-SIGNATURE header" in error

    async def test_x402_v1_payload(self, live: Live) -> None:
        accepted = await live.accepted()
        payload = json.loads(
            base64.b64decode(sign_x402_payment(payer, accepted, f"{live.url}/paid"))
        )
        payload["x402Version"] = 1
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: header}))
        assert "x402Version must be 2" in error

    async def test_permit2_payload(self, live: Live) -> None:
        accepted = await live.accepted()
        payload = json.loads(
            base64.b64decode(sign_x402_payment(payer, accepted, f"{live.url}/paid"))
        )
        payload["payload"] = {"permit2Authorization": {}, "signature": "0x00"}
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: header}))
        assert "only supports x402 EIP-3009" in error

    async def test_signature_from_another_account(self, live: Live) -> None:
        accepted = await live.accepted()
        payload = json.loads(
            base64.b64decode(sign_x402_payment(other, accepted, f"{live.url}/paid"))
        )
        payload["payload"]["authorization"]["from"] = payer.address
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: header}))
        assert "signature mismatch" in error
        assert live.facilitator.verify_requests == []

    async def test_expired_authorization(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(
            payer, accepted, f"{live.url}/paid", valid_before=int(time.time()) - 1
        )
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "has expired" in error

    async def test_not_yet_valid_authorization(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(
            payer, accepted, f"{live.url}/paid", valid_after=int(time.time()) + 600
        )
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: signature}))
        assert "not valid yet" in error

    async def test_replayed_payment(self, live: Live) -> None:
        accepted = await live.accepted()
        signature = sign_x402_payment(payer, accepted, f"{live.url}/paid")

        first = await live.get(**{PAYMENT_SIGNATURE_HEADER: signature})
        second = await live.get(**{PAYMENT_SIGNATURE_HEADER: signature})

        assert first.status_code == 200
        error = await self.rejected(second)
        assert "authorization nonce already used" in error
        assert len(live.facilitator.settle_requests) == 1

    async def test_composed_payment_matching_no_offer(self, live: Live) -> None:
        accepted = await live.accepted("/composed")
        signature = sign_x402_payment(
            payer, {**accepted, "amount": "30000"}, f"{live.url}/composed", value="30000"
        )
        response = await live.get("/composed", **{PAYMENT_SIGNATURE_HEADER: signature})
        error = await self.rejected(response)
        assert "does not match route requirements" in error
        assert len(response.headers.get_list("WWW-Authenticate")) == 2
        [(name, payload)] = live.events
        assert name == PAYMENT_FAILED
        assert "does not match route requirements" in str(payload["error"])

    async def test_value_too_long_to_parse_is_a_402(self, live: Live) -> None:
        accepted = await live.accepted()
        payload = json.loads(
            base64.b64decode(sign_x402_payment(payer, accepted, f"{live.url}/paid"))
        )
        payload["payload"]["authorization"]["validBefore"] = "9" * 5000
        header = base64.b64encode(json.dumps(payload).encode()).decode()
        error = await self.rejected(await live.get(**{PAYMENT_SIGNATURE_HEADER: header}))
        assert "malformed" in error

    async def test_composed_payment_for_the_second_offer(self, live: Live) -> None:
        response = await live.unpaid("/composed")
        second = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])["accepts"][1]
        signature = sign_x402_payment(payer, dict(second), f"{live.url}/composed")
        paid = await live.get("/composed", **{PAYMENT_SIGNATURE_HEADER: signature})
        assert paid.status_code == 200, paid.text
        assert paid.text == "20000"


class TestFacilitatorFailures:
    async def test_settlement_failure_offers_a_new_challenge(self) -> None:
        facilitator = StubFacilitator(
            settle_result=lambda body: {
                "success": False,
                "errorReason": "insufficient_funds",
                "network": body["paymentRequirements"]["network"],
                "transaction": "",
            }
        )
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                method=evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=recipient.address,
                    facilitator=facilitator_url,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
            )
            async with serve(build_app(server)) as url, coinbase_client() as client:
                response = await client.get(f"{url}/paid")

        assert response.status_code == 402
        error = decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER]).get("error")
        assert error == "Payment verification failed: insufficient_funds."

    async def test_pending_settlement_is_a_server_error_without_a_challenge(self) -> None:
        facilitator = StubFacilitator(
            settle_result=lambda body: {
                "success": False,
                "errorReason": "settlement_pending",
                "network": body["paymentRequirements"]["network"],
                "transaction": "0x" + "ee" * 32,
            }
        )
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                method=evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=recipient.address,
                    facilitator=facilitator_url,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
            )
            async with serve(build_app(server)) as url, httpx.AsyncClient() as http:
                unpaid = await http.get(f"{url}/paid")
                accepted = dict(
                    decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])["accepts"][0]
                )
                signature = sign_x402_payment(payer, accepted, f"{url}/paid")
                response = await http.get(
                    f"{url}/paid", headers={PAYMENT_SIGNATURE_HEADER: signature}
                )

        assert response.status_code == 500
        assert PAYMENT_REQUIRED_HEADER not in response.headers

    async def test_unreadable_settlement_is_a_server_error(self) -> None:
        facilitator = StubFacilitator(settle_result=lambda body: {"oops": True})
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                method=evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=recipient.address,
                    facilitator=facilitator_url,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
            )
            app = build_app(server)
            async with serve(app) as url:
                accepted = dict(
                    decode_payment_required(
                        (await httpx.AsyncClient().get(f"{url}/paid")).headers[
                            PAYMENT_REQUIRED_HEADER
                        ]
                    )["accepts"][0]
                )
                signature = sign_x402_payment(payer, accepted, f"{url}/paid")
                async with httpx.AsyncClient() as http:
                    response = await http.get(
                        f"{url}/paid", headers={PAYMENT_SIGNATURE_HEADER: signature}
                    )

        # The transfer may have landed, so no retryable 402 invites a second payment.
        assert response.status_code == 500
        assert PAYMENT_REQUIRED_HEADER not in response.headers


class TestReplayStore:
    async def test_replay_with_a_store_is_a_403_without_a_challenge(self) -> None:
        facilitator = StubFacilitator()
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                method=evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=recipient.address,
                    facilitator=facilitator_url,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
                store=MemoryStore(),
            )
            async with serve(build_app(server)) as url:
                async with httpx.AsyncClient() as http:
                    unpaid = await http.get(f"{url}/paid")
                    accepted = dict(
                        decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])["accepts"][
                            0
                        ]
                    )
                    headers = {
                        PAYMENT_SIGNATURE_HEADER: sign_x402_payment(payer, accepted, f"{url}/paid")
                    }
                    first = await http.get(f"{url}/paid", headers=headers)
                    second = await http.get(f"{url}/paid", headers=headers)

        assert first.status_code == 200
        assert second.status_code == 403
        assert PAYMENT_REQUIRED_HEADER not in second.headers
        assert "WWW-Authenticate" not in second.headers
        assert len(facilitator.verify_requests) == 1


class TestOtherServers:
    async def test_tempo_and_x402_offers_share_one_endpoint(self) -> None:
        facilitator = StubFacilitator()
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                methods=[
                    tempo(
                        intents={"charge": TempoChargeIntent()},
                        recipient=recipient.address,
                        chain_id=42431,
                    ),
                    evm(
                        currency=BASE_SEPOLIA_USDC,
                        recipient=recipient.address,
                        facilitator=facilitator_url,
                    ),
                ],
                realm=REALM,
                secret_key=SECRET_KEY,
            )

            @server.pay(amount="0.01")
            async def paid(request: Request, credential: Credential, receipt: Receipt):
                return receipt_response("paid", receipt)

            async with serve(Starlette(routes=[Route("/paid", paid)])) as url:
                async with httpx.AsyncClient() as http:
                    unpaid = await http.get(f"{url}/paid")
                async with coinbase_client() as client:
                    response = await client.get(f"{url}/paid")

        methods = [
            Challenge.from_www_authenticate(value).method
            for value in unpaid.headers.get_list("WWW-Authenticate")
        ]
        # Tempo offers each of its default Moderato currencies; evm offers one.
        assert methods.count("evm") == 1
        assert methods.count("tempo") >= 1
        required = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])
        assert [accepted["network"] for accepted in required["accepts"]] == ["eip155:84532"]
        assert response.status_code == 200, response.text
        assert PAYMENT_RESPONSE_HEADER in response.headers

    async def test_tempo_only_routes_ignore_payment_signature(self) -> None:
        server = Mpp.create(
            method=tempo(
                intents={"charge": TempoChargeIntent()},
                recipient=recipient.address,
                chain_id=42431,
            ),
            realm=REALM,
            secret_key=SECRET_KEY,
        )

        @server.pay(amount="0.01")
        async def paid(request: Request, credential: Credential, receipt: Receipt):
            return receipt_response("paid", receipt)

        async with serve(Starlette(routes=[Route("/paid", paid)])) as url:
            async with httpx.AsyncClient() as http:
                response = await http.get(
                    f"{url}/paid", headers={PAYMENT_SIGNATURE_HEADER: "anything"}
                )

        assert response.status_code == 402
        assert PAYMENT_REQUIRED_HEADER not in response.headers

    async def test_standalone_pay_decorator_serves_x402(self) -> None:
        facilitator = StubFacilitator()
        async with serve(facilitator.app()) as facilitator_url:
            method = evm(
                currency=BASE_SEPOLIA_USDC,
                recipient=recipient.address,
                facilitator=facilitator_url,
            )

            @pay(
                intent=method.intents["charge"],
                request=lambda request: method.transform_request(
                    {
                        "amount": "10000",
                        "currency": method.currency,
                        "recipient": recipient.address,
                    },
                    None,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
                method="evm",
            )
            async def paid(request: Request, credential: Credential, receipt: Receipt):
                return receipt_response("paid", receipt)

            async with serve(Starlette(routes=[Route("/paid", paid)])) as url:
                async with coinbase_client() as client:
                    response = await client.get(f"{url}/paid")

        assert response.status_code == 200, response.text
        assert PAYMENT_RESPONSE_HEADER in response.headers

    async def test_requires_auth_servers_still_serve_x402(self) -> None:
        facilitator = StubFacilitator()
        async with serve(facilitator.app()) as facilitator_url:
            server = Mpp.create(
                method=evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=recipient.address,
                    facilitator=facilitator_url,
                ),
                realm=REALM,
                secret_key=SECRET_KEY,
                requires_auth=True,
            )
            async with serve(build_app(server)) as url, coinbase_client() as client:
                response = await client.get(
                    f"{url}/paid", headers={"Authorization": "Bearer app-key"}
                )

        assert response.status_code == 200, response.text
