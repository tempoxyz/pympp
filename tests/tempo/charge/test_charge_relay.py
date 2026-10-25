"""Port of mppx ``tempo/server/Relay.test.ts`` (Tempo API relay delegation)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import store as _store
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import PaymentExpiredError, VerificationFailedError
from mpp.method import ValidateContext, VerifyContext, broadcast_credential
from mpp.receipt import Receipt
from mpp.server import Mpp, Request, Response
from mpp.tempo import methods
from mpp.tempo.server import RelayOptions
from mpp.tempo.server._charge import charge

API_BASE_URL = "https://relay.example"
REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"
SOURCE = "did:pkh:eip155:42431:0x123"
PUSHED = {
    "hash": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
    "type": "hash",
}

type Respond = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]


def challenge(**changes: Any) -> Challenge:
    return Challenge(
        id="challenge_123",
        intent="charge",
        method="tempo",
        realm=REALM,
        request={"amount": "100", "currency": "0x123", "recipient": "0x456"},
        **changes,
    )


def credential(
    payload: dict[str, Any] | None = None, *, source: str | None = SOURCE, **changes: Any
) -> Credential[Any]:
    return Credential(
        challenge=challenge(**changes),
        payload=methods.ChargePayload.model_validate(
            payload or {"signature": "0x1234", "type": "transaction"}
        ),
        source=source,
    )


class Relay:
    def __init__(self, respond: Respond) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        result = self.respond(request)
        if isinstance(result, Awaitable):
            result = await result
        return result

    @property
    def paths(self) -> list[str]:
        return [request.url.path for request in self.requests]

    def options(self, url: str | None = API_BASE_URL) -> RelayOptions:
        http = httpx.AsyncClient(transport=httpx.MockTransport(self))
        if url is None:
            return RelayOptions(api_key="tempo_api_key", http=http)
        return RelayOptions(api_key="tempo_api_key", api_base_url=url, http=http)


def ok(_: httpx.Request | None = None) -> httpx.Response:
    return httpx.Response(200, json={"success": True})


def success_receipt(_: httpx.Request | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "receipt": {
                "externalId": "order_123",
                "method": "tempo",
                "reference": "0xabc",
                "timestamp": "2026-07-22T00:00:00.000Z",
            },
            "success": True,
        },
    )


def validate_then_receipt(request: httpx.Request) -> httpx.Response:
    return ok() if request.url.path.endswith("/validate") else success_receipt()


def method(relay: Relay, url: str | None = API_BASE_URL, **parameters: Any):
    return charge(
        currency="0x123",
        recipient="0x456",
        relay=relay.options(url),
        testnet=True,
        store=_store.memory(),
        **parameters,
    )


def wire_body(credential: Credential[Any]) -> dict[str, Any]:
    body: dict[str, Any] = {
        "challenge": credential.challenge.to_dict(),
        "payload": credential.payload.model_dump(mode="json"),
    }
    if credential.source:
        body["source"] = credential.source
    return body


async def validate(server_method: Any, value: Credential[Any]) -> Any:
    return await server_method.validate(
        ValidateContext(credential=value, request=value.challenge.request)
    )


async def broadcast(server_method: Any, value: Credential[Any]) -> Receipt:
    return await server_method.broadcast(
        VerifyContext(credential=value, request=value.challenge.request)
    )


async def verify(server_method: Any, value: Credential[Any]) -> Receipt:
    receipt, _ = await server_method.settle(
        VerifyContext(credential=value, request=value.challenge.request)
    )
    return receipt


def assert_generic_failure(error: BaseException) -> None:
    assert isinstance(error, VerificationFailedError)
    assert type(error) is VerificationFailedError
    assert error.message == "Payment verification failed."
    assert error.details is None


class TestRelayBoundary:
    async def test_sends_complete_credential_to_validation_endpoint(self) -> None:
        relay = Relay(ok)
        server_method = method(relay)
        value = credential()
        result = await server_method.validate(
            ValidateContext(
                credential=value,
                request={"amount": "1", "currency": "0x123", "decimals": 6, "recipient": "0x456"},
            )
        )
        assert result.challenge == value.challenge
        assert result.credential is value
        assert result.details == {}
        assert (result.intent, result.method) == ("charge", "tempo")
        assert result.request == value.challenge.request
        assert result.source == SOURCE
        (request,) = relay.requests
        assert request.method == "POST"
        assert str(request.url) == f"{API_BASE_URL}/v1/mpp/validate"
        assert request.headers["accept"] == "application/json"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["tempo-api-key"] == "tempo_api_key"
        body = json.loads(request.content)
        assert body == wire_body(value)
        assert list(body) == ["challenge", "payload", "source"]

    async def test_uses_default_base_url_and_omits_absent_source(self) -> None:
        relay = Relay(ok)
        value = credential(source=None)
        await validate(method(relay, url=None), value)
        (request,) = relay.requests
        assert str(request.url) == "https://api.tempo.xyz/v1/mpp/validate"
        assert json.loads(request.content) == {
            "challenge": value.challenge.to_dict(),
            "payload": {"signature": "0x1234", "type": "transaction"},
        }

    async def test_preserves_configured_base_path(self) -> None:
        relay = Relay(ok)
        await validate(method(relay, url="https://relay.example/mpp"), credential())
        assert str(relay.requests[0].url) == "https://relay.example/mpp/v1/mpp/validate"

    async def test_broadcasts_receipt_and_forwards_external_id(self) -> None:
        relay = Relay(success_receipt)
        value = credential()
        receipt = await broadcast(method(relay), value)
        assert receipt.to_dict() == {
            "externalId": "order_123",
            "method": "tempo",
            "reference": "0xabc",
            "status": "success",
            "timestamp": "2026-07-22T00:00:00.000Z",
        }
        (request,) = relay.requests
        assert str(request.url) == f"{API_BASE_URL}/v1/mpp/broadcast"
        assert json.loads(request.content) == wire_body(value)
        assert request.headers["tempo-api-key"] == "tempo_api_key"
        assert "idempotency-key" not in request.headers

    async def test_delegates_pushed_transaction_finalization(self) -> None:
        relay = Relay(validate_then_receipt)
        value = credential(PUSHED)
        receipt = await verify(method(relay), value)
        assert (receipt.method, receipt.reference, receipt.status) == ("tempo", "0xabc", "success")
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]
        assert json.loads(relay.requests[1].content) == wire_body(value)

    async def test_validates_pushed_transaction_before_returning_receipt(self) -> None:
        relay = Relay(validate_then_receipt)
        expires = (datetime.now(UTC) + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        value = credential(PUSHED, expires=expires)
        receipt = await broadcast_credential([method(relay)], value)
        assert (receipt.method, receipt.reference) == ("tempo", "0xabc")
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]

    @pytest.mark.parametrize("payload_type", ["transaction", "hash", "proof"])
    async def test_consumes_credentials_once(self, payload_type: str) -> None:
        consumed = False

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal consumed
            if request.url.path.endswith("/validate"):
                return ok()
            if consumed and "idempotency-key" not in request.headers:
                return httpx.Response(
                    200,
                    json={"success": False, "error": {"code": "already_used", "message": "Used"}},
                )
            consumed = True
            return success_receipt()

        payload = (
            PUSHED if payload_type == "hash" else {"signature": "0x1234", "type": payload_type}
        )
        server_method = method(Relay(respond))
        value = credential(payload)
        results = await asyncio.gather(
            verify(server_method, value), verify(server_method, value), return_exceptions=True
        )
        assert sum(isinstance(r, Receipt) for r in results) == 1
        assert sum(isinstance(r, BaseException) for r in results) == 1

    async def test_preserves_combined_settle(self) -> None:
        relay = Relay(validate_then_receipt)
        receipt = await verify(method(relay), credential())
        assert (receipt.method, receipt.status) == ("tempo", "success")
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]

    @staticmethod
    def _dns_failure(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("relay DNS failure", request=request)

    @pytest.mark.parametrize(
        ("operation", "respond"),
        [
            ("validate", _dns_failure),
            (
                "validate",
                lambda _: httpx.Response(
                    403, json={"error": {"code": "policy_denied", "message": "private detail"}}
                ),
            ),
            ("validate", lambda _: httpx.Response(200, text="not JSON")),
            (
                "validate",
                lambda _: httpx.Response(
                    200,
                    json={
                        "error": {"code": "policy_denied", "message": "private detail"},
                        "success": False,
                    },
                ),
            ),
            ("broadcast", _dns_failure),
            (
                "broadcast",
                lambda _: httpx.Response(
                    500, json={"error": {"code": "settlement_failed", "message": "private detail"}}
                ),
            ),
            ("broadcast", lambda _: httpx.Response(200, text="not JSON")),
            (
                "broadcast",
                lambda _: httpx.Response(
                    200,
                    json={
                        "error": {"code": "settlement_failed", "message": "private detail"},
                        "success": False,
                    },
                ),
            ),
            (
                "broadcast",
                lambda _: httpx.Response(
                    200, json={"receipt": {"method": "tempo"}, "success": True}
                ),
            ),
            (
                "broadcast",
                lambda _: httpx.Response(
                    200,
                    json={
                        "receipt": {
                            "method": "stripe",
                            "reference": "0xabc",
                            "timestamp": "2026-07-22T00:00:00.000Z",
                        },
                        "success": True,
                    },
                ),
            ),
            (
                "broadcast",
                lambda _: httpx.Response(
                    200,
                    json={
                        "receipt": {
                            "method": "tempo",
                            "reference": "0xabc",
                            "timestamp": "not a timestamp",
                        },
                        "success": True,
                    },
                ),
            ),
        ],
    )
    async def test_maps_boundary_failure_to_generic_error(
        self, operation: str, respond: Respond
    ) -> None:
        server_method = method(Relay(respond))
        call = validate if operation == "validate" else broadcast
        with pytest.raises(VerificationFailedError) as caught:
            await call(server_method, credential())
        assert_generic_failure(caught.value)

    @pytest.mark.parametrize(
        ("code", "details"),
        [
            ("already_used", {"code": "already_used"}),
            ("broadcast_failed", {"code": "broadcast_failed"}),
            ("invalid_payment", {"code": "invalid_payment"}),
            ("insufficient_funds", {"code": "insufficient_funds"}),
            ("simulation_failed", {"code": "simulation_failed"}),
            ("unsupported", {"code": "unsupported"}),
            (
                "temporarily_unavailable",
                {"code": "temporarily_unavailable", "retry": "same_credential"},
            ),
        ],
    )
    async def test_exposes_safe_codes(self, code: str, details: dict[str, str]) -> None:
        server_method = method(
            Relay(
                lambda _: httpx.Response(
                    200,
                    json={
                        "error": {"code": code, "message": "Tempo API private message."},
                        "success": False,
                    },
                )
            )
        )
        with pytest.raises(VerificationFailedError) as caught:
            await validate(server_method, credential())
        assert caught.value.details == details
        assert caught.value.message == "Payment verification failed."
        assert "private message" not in caught.value.message

    async def test_maps_expired_to_payment_expired(self) -> None:
        server_method = method(
            Relay(
                lambda _: httpx.Response(
                    200,
                    json={
                        "error": {"code": "expired", "message": "Tempo API private message."},
                        "success": False,
                    },
                )
            )
        )
        with pytest.raises(PaymentExpiredError) as caught:
            await validate(server_method, credential())
        assert caught.value.details is None
        assert caught.value.message == "Payment has expired."
        assert caught.value.type == "https://paymentauth.org/problems/payment-expired"

    @pytest.mark.parametrize("code", ["policy_denied", "screen_rejected", "unknown"])
    async def test_keeps_sensitive_codes_opaque(self, code: str) -> None:
        server_method = method(
            Relay(
                lambda _: httpx.Response(
                    200,
                    json={
                        "error": {"code": code, "message": "Tempo API private message."},
                        "success": False,
                    },
                )
            )
        )
        with pytest.raises(VerificationFailedError) as caught:
            await validate(server_method, credential())
        assert_generic_failure(caught.value)

    async def test_keeps_non_2xx_responses_opaque(self) -> None:
        server_method = method(
            Relay(
                lambda _: httpx.Response(
                    403,
                    json={
                        "error": {
                            "code": "insufficient_funds",
                            "message": "Tempo API private message.",
                        }
                    },
                )
            )
        )
        with pytest.raises(VerificationFailedError) as caught:
            await validate(server_method, credential())
        assert_generic_failure(caught.value)


# -- HTTP flow ---------------------------------------------------------------------------------


class PaymentServer:
    def __init__(self, relay: Relay) -> None:
        self.mppx = Mpp(methods=[method(relay)], realm=REALM, secret_key=SECRET_KEY)
        self.handler = self.mppx.tempo.charge(amount="1", decimals=6)

    async def challenge(self) -> Challenge:
        result = await self.handler(Request(method="GET", url="https://api.example.com/paid"))
        assert result.status == 402
        return Challenge.deserialize(result.challenge.headers["www-authenticate"])

    async def pay(self, payload: dict[str, Any] | None = None) -> Response:
        value = Credential(
            challenge=await self.challenge(),
            payload=payload or {"signature": "0x1234", "type": "transaction"},
            source=SOURCE,
        )
        result = await self.handler(
            Request(
                method="GET",
                url="https://api.example.com/paid",
                headers={"Authorization": value.serialize()},
            )
        )
        if result.status == 402:
            return result.challenge
        return result.with_receipt(Response.text("OK"))


class TestRelayHttpFlow:
    async def test_validates_broadcasts_and_returns_receipt(self) -> None:
        relay = Relay(validate_then_receipt)
        server = PaymentServer(relay)
        await server.challenge()
        response = await server.pay()
        assert response.status == 200
        assert response.headers.get("payment-receipt")
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]

    async def test_delegates_pushed_transaction_finalization(self) -> None:
        relay = Relay(validate_then_receipt)
        response = await PaymentServer(relay).pay(PUSHED)
        assert response.status == 200
        receipt = Receipt.from_headers(response.headers)
        assert (receipt.method, receipt.reference, receipt.status) == ("tempo", "0xabc", "success")
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]

    async def test_no_receipt_when_validation_rejects_pushed_transaction(self) -> None:
        relay = Relay(
            lambda _: httpx.Response(
                200,
                json={
                    "error": {"code": "policy_denied", "message": "private detail"},
                    "success": False,
                },
            )
        )
        response = await PaymentServer(relay).pay(PUSHED)
        body = json.loads(await response.read())
        assert response.status == 402
        assert "payment-receipt" not in response.headers
        assert body["detail"] == "Payment verification failed."
        assert body["type"] == "https://paymentauth.org/problems/verification-failed"
        assert "policy_denied" not in json.dumps(body)
        assert "private detail" not in json.dumps(body)
        assert relay.paths == ["/v1/mpp/validate"]

    async def test_no_receipt_when_finalization_rejects_pushed_transaction(self) -> None:
        relay = Relay(
            lambda request: (
                ok()
                if request.url.path.endswith("/validate")
                else httpx.Response(
                    200,
                    json={
                        "error": {"code": "already_used", "message": "private detail"},
                        "success": False,
                    },
                )
            )
        )
        response = await PaymentServer(relay).pay(PUSHED)
        body = json.loads(await response.read())
        assert response.status == 402
        assert "payment-receipt" not in response.headers
        assert body["detail"] == "Payment verification failed."
        assert body["details"] == {"code": "already_used"}
        assert "private detail" not in json.dumps(body)
        assert relay.paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]

    @pytest.mark.parametrize(
        ("failure", "expected_calls"),
        [
            ("network", 1),
            ("rejection", 1),
            ("network", 2),
            ("settlement", 2),
            ("malformed", 2),
        ],
    )
    async def test_returns_opaque_402(self, failure: str, expected_calls: int) -> None:
        calls = 0

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls != expected_calls:
                return ok()
            match failure:
                case "network":
                    raise httpx.ConnectError("tempo api unavailable", request=request)
                case "rejection":
                    code = "policy_denied"
                case "settlement":
                    code = "settlement_failed"
                case _:
                    return httpx.Response(
                        200, json={"receipt": {"method": "tempo"}, "success": True}
                    )
            return httpx.Response(
                200,
                json={"error": {"code": code, "message": "private detail"}, "success": False},
            )

        response = await PaymentServer(Relay(respond)).pay()
        text = (await response.read()).decode()
        body = json.loads(text)
        assert response.status == 402
        assert "Payment" in response.headers["www-authenticate"]
        assert "payment-receipt" not in response.headers
        assert "application/problem+json" in response.headers["content-type"]
        assert isinstance(body["challengeId"], str)
        assert body["detail"] == "Payment verification failed."
        assert body["status"] == 402
        assert body["title"] == "Verification Failed"
        assert body["type"] == "https://paymentauth.org/problems/verification-failed"
        for secret in (
            "tempo api unavailable",
            "policy_denied",
            "settlement_failed",
            "private detail",
            API_BASE_URL,
            "tempo_api_key",
        ):
            assert secret not in text
        assert calls == expected_calls

    async def test_includes_safe_relay_code_in_problem_details(self) -> None:
        relay = Relay(
            lambda _: httpx.Response(
                200,
                json={
                    "error": {
                        "code": "temporarily_unavailable",
                        "message": "Tempo API private message.",
                    },
                    "success": False,
                },
            )
        )
        response = await PaymentServer(relay).pay()
        text = (await response.read()).decode()
        body = json.loads(text)
        assert response.status == 402
        assert body["detail"] == "Payment verification failed."
        assert body["details"] == {"code": "temporarily_unavailable", "retry": "same_credential"}
        assert "Tempo API private message." not in text
        assert API_BASE_URL not in text
