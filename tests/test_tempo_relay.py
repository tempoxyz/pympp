"""Tests for the Tempo API relay adapter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from eth_hash.auto import keccak

from mpp.errors import PaymentExpiredError, VerificationFailedError
from mpp.methods.tempo import ChargeIntent, Relay, tempo
from mpp.server import broadcast_credential
from tests import make_credential

API_BASE_URL = "https://relay.example/mpp"
API_KEY = "tempo_api_key"


def _credential(
    *,
    payload: dict[str, Any] | None = None,
    source: str | None = "did:pkh:eip155:42431:0x123",
):
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    return make_credential(
        payload=payload or {"type": "transaction", "signature": "0x1234"},
        challenge_id="challenge_123",
        request="eyJhbW91bnQiOiIxMDAifQ",
        source=source,
        expires=expires,
    )


def _success_receipt() -> dict[str, Any]:
    return {
        "success": True,
        "receipt": {
            "externalId": "order_123",
            "method": "tempo",
            "reference": "0xabc",
            "timestamp": "2026-07-22T00:00:00.000Z",
        },
    }


def _relay(handler: Any) -> tuple[Relay, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Relay(API_KEY, API_BASE_URL, http_client=client), client


async def test_validates_then_broadcasts_complete_credential() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/validate"):
            return httpx.Response(200, json={"success": True})
        return httpx.Response(200, json=_success_receipt())

    relay, client = _relay(handler)
    try:
        receipt = await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()

    assert [request.url.path for request in requests] == [
        "/mpp/v1/mpp/validate",
        "/mpp/v1/mpp/broadcast",
    ]
    body = json.loads(requests[0].content)
    assert body["challenge"]["id"] == "challenge_123"
    assert body["challenge"]["request"] == {"amount": "100"}
    assert body["payload"] == {"type": "transaction", "signature": "0x1234"}
    assert body["source"] == "did:pkh:eip155:42431:0x123"
    assert requests[0].headers["tempo-api-key"] == API_KEY
    assert requests[0].headers["accept"] == "application/json"
    assert (
        requests[1].headers["idempotency-key"] == f"pympp_0x{keccak(bytes.fromhex('1234')).hex()}"
    )
    assert receipt.reference == "0xabc"
    assert receipt.external_id == "order_123"
    assert receipt.timestamp == datetime(2026, 7, 22, tzinfo=UTC)


async def test_split_validate_does_not_broadcast() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    relay, client = _relay(handler)
    try:
        validation = await relay.configure(ChargeIntent()).validate(_credential(), {})
    finally:
        await client.aclose()

    assert validation.details == {}
    assert [request.url.path for request in requests] == ["/mpp/v1/mpp/validate"]


async def test_split_broadcast_calls_terminal_endpoint_only() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=_success_receipt())

    relay, client = _relay(handler)
    try:
        receipt = await relay.configure(ChargeIntent()).broadcast(_credential(), {})
    finally:
        await client.aclose()

    assert receipt.reference == "0xabc"
    assert [request.url.path for request in requests] == ["/mpp/v1/mpp/broadcast"]


async def test_lifecycle_helper_revalidates_relay_before_broadcast() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        result = {"success": True} if request.url.path.endswith("/validate") else _success_receipt()
        return httpx.Response(200, json=result)

    relay, client = _relay(handler)
    try:
        receipt = await broadcast_credential(
            intent=relay.configure(ChargeIntent()),
            credential=_credential(),
            request={},
        )
    finally:
        await client.aclose()

    assert receipt.reference == "0xabc"
    assert [request.url.path for request in requests] == [
        "/mpp/v1/mpp/validate",
        "/mpp/v1/mpp/broadcast",
    ]


async def test_default_url_omits_absent_source() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        result = {"success": True} if request.url.path.endswith("/validate") else _success_receipt()
        return httpx.Response(200, json=result)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    relay = Relay(API_KEY, http_client=client)
    try:
        await relay.configure(ChargeIntent()).verify(_credential(source=None), {})
    finally:
        await client.aclose()

    assert str(requests[0].url) == "https://api.tempo.xyz/v1/mpp/validate"
    assert "source" not in json.loads(requests[0].content)


async def test_non_transaction_idempotency_key_uses_canonical_input() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        result = {"success": True} if request.url.path.endswith("/validate") else _success_receipt()
        return httpx.Response(200, json=result)

    relay, client = _relay(handler)
    try:
        await relay.configure(ChargeIntent()).verify(
            _credential(payload={"type": "proof", "proof": "proof_123"}),
            {},
        )
    finally:
        await client.aclose()

    relay_input = json.loads(requests[1].content)
    canonical = json.dumps(
        relay_input, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    assert requests[1].headers["idempotency-key"] == (
        f"pympp_0x{hashlib.sha256(canonical).hexdigest()}"
    )


async def test_invalid_transaction_hex_uses_canonical_idempotency_key() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        result = {"success": True} if request.url.path.endswith("/validate") else _success_receipt()
        return httpx.Response(200, json=result)

    relay, client = _relay(handler)
    try:
        await relay.configure(ChargeIntent()).verify(
            _credential(payload={"type": "transaction", "signature": "not-hex"}),
            {},
        )
    finally:
        await client.aclose()

    assert requests[1].headers["idempotency-key"].startswith("pympp_0x")


async def test_network_failure_is_opaque() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private relay hostname")

    relay, client = _relay(handler)
    try:
        with pytest.raises(VerificationFailedError) as exc_info:
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()

    assert str(exc_info.value) == "Payment verification failed."
    assert "hostname" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("operation", "response"),
    [
        ("validate", httpx.Response(500, json={"error": {"code": "invalid_payment"}})),
        ("validate", httpx.Response(200, text="not JSON")),
        ("validate", httpx.Response(200, json={"success": False})),
        ("broadcast", httpx.Response(200, text="not JSON")),
        ("broadcast", httpx.Response(200, json={"success": False})),
        ("broadcast", httpx.Response(200, json={"success": True, "receipt": {}})),
        (
            "broadcast",
            httpx.Response(
                200,
                json={
                    "success": True,
                    "receipt": {
                        "method": "stripe",
                        "reference": "0xabc",
                        "timestamp": "2026-07-22T00:00:00Z",
                    },
                },
            ),
        ),
    ],
)
async def test_boundary_failures_are_opaque(operation: str, response: httpx.Response) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if operation == "validate" or request.url.path.endswith("/broadcast"):
            return response
        return httpx.Response(200, json={"success": True})

    relay, client = _relay(handler)
    try:
        with pytest.raises(VerificationFailedError) as exc_info:
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()

    assert str(exc_info.value) == "Payment verification failed."
    assert exc_info.value.details is None


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
async def test_exposes_safe_relay_error_codes(code: str, details: dict[str, str]) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": False,
                "error": {"code": code, "message": "private relay detail"},
            },
        )

    relay, client = _relay(handler)
    try:
        with pytest.raises(VerificationFailedError) as exc_info:
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()

    assert exc_info.value.details == details
    assert "private relay detail" not in str(exc_info.value)


@pytest.mark.parametrize("code", ["policy_denied", "screen_rejected", "unknown"])
async def test_keeps_sensitive_relay_codes_opaque(code: str) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": False, "error": {"code": code}})

    relay, client = _relay(handler)
    try:
        with pytest.raises(VerificationFailedError) as exc_info:
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()

    assert exc_info.value.details is None


async def test_maps_expired_to_payment_expired() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": False, "error": {"code": "expired"}})

    relay, client = _relay(handler)
    try:
        with pytest.raises(PaymentExpiredError):
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {"method": "tempo", "reference": "0xabc", "timestamp": "not-a-date"},
        {"method": "tempo", "reference": "0xabc", "timestamp": "2026-07-22T00:00:00"},
        {
            "method": "tempo",
            "reference": "0xabc",
            "timestamp": "2026-07-22T00:00:00Z",
            "externalId": 123,
        },
    ],
)
async def test_rejects_invalid_receipts(receipt: Any) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        result = {"success": True}
        if request.url.path.endswith("/broadcast"):
            result["receipt"] = receipt
        return httpx.Response(200, json=result)

    relay, client = _relay(handler)
    try:
        with pytest.raises(VerificationFailedError):
            await relay.configure(ChargeIntent()).verify(_credential(), {})
    finally:
        await client.aclose()


async def test_rejects_malformed_challenge_request() -> None:
    relay = Relay(API_KEY)
    with pytest.raises(VerificationFailedError):
        await relay.configure(ChargeIntent()).verify(
            make_credential(payload={}, request="not-base64"),
            {},
        )


async def test_context_manager_closes_owned_client() -> None:
    relay = Relay(API_KEY)
    async with relay:
        client = relay._http_client
        assert client is not None

    assert client.is_closed
    assert relay._http_client is None


async def test_wrapped_intent_context_manager_closes_owned_client() -> None:
    relay = Relay(API_KEY)
    intent: Any = relay.configure(ChargeIntent())

    async with intent:
        client = relay._http_client
        assert client is not None

    assert client.is_closed
    assert relay._http_client is None


async def test_forwards_optional_challenge_fields() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    credential = _credential()
    credential = replace(
        credential,
        challenge=replace(
            credential.challenge,
            digest="sha-256=:digest:",
            opaque="eyJrIjoidiJ9",
        ),
    )
    relay, client = _relay(handler)
    try:
        await relay.configure(ChargeIntent()).validate(credential, {})
    finally:
        await client.aclose()

    challenge = json.loads(requests[0].content)["challenge"]
    assert challenge["digest"] == "sha-256=:digest:"
    assert challenge["opaque"] == "eyJrIjoidiJ9"


def test_relay_validates_configuration() -> None:
    with pytest.raises(ValueError, match="api_key is required"):
        Relay("")
    with pytest.raises(ValueError, match="api_base_url is required"):
        Relay(API_KEY, "")

    class SessionIntent:
        name = "session"

    with pytest.raises(ValueError, match="charge intent"):
        Relay(API_KEY).configure(SessionIntent())  # type: ignore[arg-type]


def test_tempo_factory_configures_charge_intent() -> None:
    relay = Relay(API_KEY)
    original = ChargeIntent()
    method = tempo(intents={"charge": original}, relay=relay)

    assert method.intents["charge"].name == "charge"
    assert method.intents["charge"] is not original


def test_tempo_factory_requires_charge_intent_for_relay() -> None:
    with pytest.raises(ValueError, match="relay requires a charge intent"):
        tempo(intents={}, relay=Relay(API_KEY))
