"""Tests for the Tempo API relay adapter."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from eth_hash.auto import keccak

from mpp import Credential, Receipt
from mpp.errors import PaymentExpiredError, VerificationFailedError
from mpp.methods.tempo import ChargeIntent, Relay, tempo
from mpp.server import broadcast_credential
from mpp.store import MemoryStore
from tests import make_bound_credential, make_credential


def credential(payload: dict | None = None) -> Credential:
    return make_bound_credential(
        payload=payload or {"type": "transaction", "signature": "0x1234"},
        request={"amount": "1000"},
        source="did:pkh:eip155:42431:0x1234567890123456789012345678901234567890",
    )


def response(body: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


@pytest.mark.asyncio
async def test_relay_validates_then_broadcasts_with_idempotency() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response(
            {
                "success": True,
                "receipt": {
                    "method": "tempo",
                    "reference": "0xabc",
                    "timestamp": "2026-08-05T12:00:00Z",
                },
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(
                api_key="tempo:sk:test",
                api_base_url="https://relay.example/mpp",
                http_client=client,
            ),
        )
        result = await broadcast_credential(
            intent=method.intents["charge"],
            credential=credential(),
            request={"amount": "1000"},
        )

    assert result.reference == "0xabc"
    assert [call.url.path for call in calls] == [
        "/mpp/v1/mpp/validate",
        "/mpp/v1/mpp/broadcast",
    ]
    assert calls[0].headers["tempo-api-key"] == "tempo:sk:test"
    expected_key = "pympp_0x" + keccak(bytes.fromhex("1234")).hex()
    assert calls[1].headers["idempotency-key"] == expected_key
    body = json.loads(calls[0].content)
    assert body["challenge"]["request"] == {"amount": "1000"}
    assert body["payload"] == {"type": "transaction", "signature": "0x1234"}


@pytest.mark.asyncio
async def test_relay_finalizes_pushed_hash_credential() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response(
            {
                "success": True,
                "receipt": {
                    "method": "tempo",
                    "reference": "0xpushed",
                    "timestamp": "2026-08-05T12:00:00+00:00",
                },
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key="key", http_client=client),
        )
        result = await broadcast_credential(
            intent=method.intents["charge"],
            credential=credential({"type": "hash", "hash": "0xpushed"}),
            request={"amount": "1000"},
        )

    assert result.reference == "0xpushed"
    assert paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "details"),
    [
        ("already_used", {"code": "already_used"}),
        (
            "temporarily_unavailable",
            {"code": "temporarily_unavailable", "retry": "same_credential"},
        ),
    ],
)
async def test_relay_exposes_only_safe_error_details(code: str, details: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response({"success": False, "error": {"code": code, "message": "private"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key="key", http_client=client),
        )
        with pytest.raises(VerificationFailedError) as raised:
            await method.intents["charge"].validate(credential(), {"amount": "1000"})  # type: ignore[attr-defined]

    assert raised.value.details == details
    assert raised.value.to_problem_details()["details"] == details
    assert "private" not in str(raised.value)


@pytest.mark.asyncio
async def test_relay_hides_policy_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response(
            {
                "success": False,
                "error": {"code": "policy_denied", "message": "private policy detail"},
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key="key", http_client=client),
        )
        with pytest.raises(VerificationFailedError) as raised:
            await method.intents["charge"].validate(credential(), {})  # type: ignore[attr-defined]

    assert raised.value.details is None
    assert "policy" not in str(raised.value)


@pytest.mark.asyncio
async def test_relay_maps_expired_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response({"success": False, "error": {"code": "expired"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key="key", http_client=client),
        )
        with pytest.raises(PaymentExpiredError):
            await method.intents["charge"].validate(credential(), {})  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_relay_rejects_invalid_receipt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response({"success": True, "receipt": {"method": "stripe"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key="key", http_client=client),
        )
        with pytest.raises(VerificationFailedError):
            await broadcast_credential(
                intent=method.intents["charge"],
                credential=credential(),
                request={},
            )


def test_relay_requires_charge_intent() -> None:
    with pytest.raises(ValueError, match="charge intent"):
        tempo(intents={}, relay=Relay(api_key="key"))


@pytest.mark.asyncio
async def test_charge_validation_does_not_consume_hash() -> None:
    store = MemoryStore()
    intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
    payment = make_credential(
        payload={"type": "hash", "hash": "0xabc"},
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )

    with patch.object(
        intent,
        "_validate_hash",
        AsyncMock(return_value=Receipt.success("0xabc")),
    ):
        result = await intent.validate(
            payment,
            {
                "amount": "1000",
                "currency": "0x1234567890123456789012345678901234567890",
                "recipient": "0x4567890123456789012345678901234567890123",
            },
        )

    assert result.details == {"mode": "push"}
    assert await store.get("mpp:charge:0xabc") is None
