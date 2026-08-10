"""Tests for the Tempo API relay adapter."""

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from eth_hash.auto import keccak

from mpp import Challenge, Credential, Receipt
from mpp.errors import (
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    VerificationError,
    VerificationFailedError,
)
from mpp.methods.tempo import ChargeIntent, Relay, TempoMethod, tempo
from mpp.server import broadcast_credential, pay
from mpp.store import MemoryStore
from tests import MockRequest, challenge_from_402, make_bound_credential, make_credential


def credential(payload: dict | None = None) -> Credential:
    return make_bound_credential(
        payload=payload or {"type": "transaction", "signature": "0x1234"},
        request={"amount": "1000"},
        source="did:pkh:eip155:42431:0x1234567890123456789012345678901234567890",
    )


def response(body: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


@asynccontextmanager
async def relay_method(
    handler: Callable[[httpx.Request], httpx.Response],
    **relay_kwargs: Any,
) -> AsyncIterator[TempoMethod]:
    """Yield a tempo method whose charge intent is served by a mock relay."""
    relay_kwargs.setdefault("api_key", "key")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        yield tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(http_client=client, **relay_kwargs),
        )


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

    async with relay_method(
        handler,
        api_key="tempo:sk:test",
        api_base_url="https://relay.example/mpp",
    ) as method:
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
                    "reference": "0xpushed",
                    "timestamp": "2026-08-05T12:00:00+00:00",
                },
            }
        )

    async with relay_method(handler) as method:
        result = await broadcast_credential(
            intent=method.intents["charge"],
            credential=credential({"type": "hash", "hash": "0xpushed"}),
            request={"amount": "1000"},
        )

    assert result.reference == "0xpushed"
    assert [call.url.path for call in calls] == [
        "/v1/mpp/validate",
        "/v1/mpp/broadcast",
    ]
    assert calls[1].headers["idempotency-key"].startswith("pympp_0x")


@pytest.mark.asyncio
async def test_relay_validate_posts_to_validate_endpoint() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return response({"success": True})

    async with relay_method(handler) as method:
        validation = await method.intents["charge"].validate(  # type: ignore[attr-defined]
            credential(), {"amount": "1000"}
        )

    assert paths == ["/v1/mpp/validate"]
    assert validation.request == {"amount": "1000"}


@pytest.mark.asyncio
@pytest.mark.parametrize("hook_name", ["validate", "broadcast"])
async def test_relay_rejects_mismatched_request(hook_name: str) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return response({"success": True})

    async with relay_method(handler) as method:
        hook = getattr(method.intents["charge"], hook_name)
        with pytest.raises(VerificationFailedError):
            await hook(credential(), {"amount": "2000"})

    assert calls == []


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

    async with relay_method(handler) as method:
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

    async with relay_method(handler) as method:
        with pytest.raises(VerificationFailedError) as raised:
            await method.intents["charge"].validate(  # type: ignore[attr-defined]
                credential(), {"amount": "1000"}
            )

    assert raised.value.details is None
    assert "policy" not in str(raised.value)


@pytest.mark.asyncio
async def test_relay_rejection_returns_retryable_http_challenge() -> None:
    def relay_handler(request: httpx.Request) -> httpx.Response:
        return response(
            {
                "success": False,
                "error": {"code": "insufficient_funds", "message": "private balance"},
            }
        )

    async with relay_method(relay_handler) as method:

        @pay(
            intent=method.intents["charge"],
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(
            request: MockRequest,
            credential: Credential,
            receipt: Receipt,
        ) -> dict[str, bool]:
            return {"paid": True}

        initial: Any = await handler(MockRequest())
        challenge = challenge_from_402(initial)
        rejected: Any = await handler(
            MockRequest(
                Credential(
                    challenge=challenge.to_echo(),
                    payload={"type": "transaction", "signature": "0x1234"},
                ).to_authorization()
            )
        )

    if hasattr(rejected, "status_code"):
        status = rejected.status_code
        headers = rejected.headers
        body = json.loads(rejected.body)
    else:
        status = rejected["status"]
        headers = rejected["headers"]
        body = json.loads(rejected["body"])

    retry = Challenge.from_www_authenticate(headers["WWW-Authenticate"])
    assert status == 402
    assert headers["Content-Type"] == "application/problem+json"
    assert retry.id != challenge.id
    assert body["type"].endswith("/verification-failed")
    assert body["status"] == 402
    assert body["challengeId"] == retry.id
    assert body["details"] == {"code": "insufficient_funds"}
    assert "private balance" not in json.dumps(body)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["transport", "json"])
async def test_ambiguous_broadcast_does_not_issue_fresh_challenge(failure: str) -> None:
    paths: list[str] = []

    def relay_handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        if failure == "transport":
            raise httpx.ReadError("response lost", request=request)
        return httpx.Response(200, content=b"not-json")

    async with relay_method(relay_handler) as method:

        @pay(
            intent=method.intents["charge"],
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(
            request: MockRequest,
            credential: Credential,
            receipt: Receipt,
        ) -> dict[str, bool]:
            return {"paid": True}

        initial: Any = await handler(MockRequest())
        challenge = challenge_from_402(initial)
        payment = Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": "0x1234"},
        )
        with pytest.raises(PaymentOutcomeUnknownError) as raised:
            await handler(MockRequest(payment.to_authorization()))

    assert paths == ["/v1/mpp/validate", "/v1/mpp/broadcast"]
    assert raised.value.challenge.id == challenge.id
    assert raised.value.credential == payment
    assert raised.value.request == {"amount": "1000"}
    assert raised.value.retry_challenge is None


@pytest.mark.asyncio
async def test_relay_maps_expired_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response({"success": False, "error": {"code": "expired"}})

    async with relay_method(handler) as method:
        with pytest.raises(PaymentExpiredError):
            await method.intents["charge"].validate(  # type: ignore[attr-defined]
                credential(), {"amount": "1000"}
            )


@pytest.mark.asyncio
async def test_relay_rejects_invalid_receipt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response({"success": True, "receipt": {"method": "stripe"}})

    async with relay_method(handler) as method:
        with pytest.raises(VerificationFailedError):
            await broadcast_credential(
                intent=method.intents["charge"],
                credential=credential(),
                request={"amount": "1000"},
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


@pytest.mark.asyncio
async def test_charge_validation_rejects_consumed_hash() -> None:
    store = MemoryStore()
    await store.put("mpp:charge:0xabc", "0xabc")
    intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
    payment = make_credential(
        payload={"type": "hash", "hash": "0xabc"},
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )

    with (
        patch.object(intent, "_validate_hash", AsyncMock()) as validate_hash,
        pytest.raises(VerificationError, match="Transaction hash already used"),
    ):
        await intent.validate(
            payment,
            {
                "amount": "1000",
                "currency": "0x1234567890123456789012345678901234567890",
                "recipient": "0x4567890123456789012345678901234567890123",
            },
        )

    validate_hash.assert_not_awaited()


@pytest.mark.asyncio
async def test_charge_validation_uses_python_field_names() -> None:
    intent = ChargeIntent(rpc_url="https://rpc.test")
    payment = make_credential(
        payload={"type": "transaction", "signature": "0x1234"},
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    request = {
        "amount": "1000",
        "currency": "0x1234567890123456789012345678901234567890",
        "recipient": "0x4567890123456789012345678901234567890123",
    }

    with patch.object(intent, "_validate_transaction_payload"):
        result = await intent.validate(payment, request)

    assert result.details == {
        "mode": "pull",
        "serialized_transaction": "0x1234",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("signature", ["0x1234", "0x76ff"])
async def test_charge_validation_rejects_undecodable_transactions(signature: str) -> None:
    intent = ChargeIntent(rpc_url="https://rpc.test")
    payment = make_credential(
        payload={"type": "transaction", "signature": signature},
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )

    with pytest.raises(VerificationError):
        await intent.validate(
            payment,
            {
                "amount": "1000",
                "currency": "0x1234567890123456789012345678901234567890",
                "recipient": "0x4567890123456789012345678901234567890123",
            },
        )
