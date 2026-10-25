"""Tests for the Tempo API relay adapter."""

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mpp import Challenge, Credential, Receipt
from mpp.errors import (
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    VerificationError,
    VerificationFailedError,
)
from mpp.methods.tempo import ChargeIntent, Relay
from mpp.methods.tempo import server as tempo_server
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from tests import (
    MockRequest,
    challenge_from_402,
    make_bound_credential,
    make_credential,
)


def credential(payload: dict | None = None) -> Credential:
    return make_bound_credential(
        payload=payload or {"type": "transaction", "signature": "0x1234"},
        request={"amount": "1000"},
        source="did:pkh:eip155:42431:0x1234567890123456789012345678901234567890",
    )


async def _broadcast(*, intent: Any, credential: Credential, request: dict) -> Receipt:
    """Validate then broadcast, copying the validated payer onto the receipt."""
    validation = await intent.validate(credential, request)
    receipt = await intent.broadcast(credential, request)
    if validation.payer is not None and receipt.payer is None:
        receipt = replace(receipt, payer=validation.payer)
    return receipt


def response(body: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


@asynccontextmanager
async def mock_relay(
    handler: Callable[[httpx.Request], httpx.Response],
    client_headers: dict[str, str] | None = None,
    **relay_kwargs: Any,
) -> AsyncIterator[Relay]:
    """Yield a relay served by a mock Tempo API."""
    relay_kwargs.setdefault("api_key", "key")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers=client_headers
    ) as client:
        yield Relay(http_client=client, **relay_kwargs)


@pytest.mark.asyncio
async def test_relay_validates_then_broadcasts_without_receipt_caching() -> None:
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

    async with mock_relay(
        handler,
        client_headers={"Idempotency-Key": "inherited-key"},
        api_key="tempo:sk:test",
        api_base_url="https://relay.example/mpp",
    ) as relay:
        result = await _broadcast(
            intent=relay.configure(ChargeIntent()),
            credential=credential(),
            request={"amount": "1000"},
        )

    assert result.reference == "0xabc"
    assert [call.url.path for call in calls] == [
        "/mpp/v1/mpp/validate",
        "/mpp/v1/mpp/broadcast",
    ]
    assert calls[0].headers["tempo-api-key"] == "tempo:sk:test"
    assert calls[0].headers["idempotency-key"] == "inherited-key"
    assert "idempotency-key" not in calls[1].headers
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

    async with mock_relay(handler) as relay:
        result = await _broadcast(
            intent=relay.configure(ChargeIntent()),
            credential=credential({"type": "hash", "hash": "0xpushed"}),
            request={"amount": "1000"},
        )

    assert result.reference == "0xpushed"
    assert [call.url.path for call in calls] == [
        "/v1/mpp/validate",
        "/v1/mpp/broadcast",
    ]
    assert "idempotency-key" not in calls[1].headers


@pytest.mark.asyncio
async def test_relay_validate_posts_to_validate_endpoint() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return response({"success": True})

    async with mock_relay(handler) as relay:
        validation = await relay.configure(ChargeIntent()).validate(  # type: ignore[attr-defined]
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

    async with mock_relay(handler) as relay:
        hook = getattr(relay.configure(ChargeIntent()), hook_name)
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

    async with mock_relay(handler) as relay:
        with pytest.raises(VerificationFailedError) as raised:
            await relay.configure(ChargeIntent()).validate(credential(), {"amount": "1000"})  # type: ignore[attr-defined]

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

    async with mock_relay(handler) as relay:
        with pytest.raises(VerificationFailedError) as raised:
            await relay.configure(ChargeIntent()).validate(  # type: ignore[attr-defined]
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

    async with mock_relay(relay_handler) as relay:

        @pay(
            Mpp(
                methods=tempo_server.charge(relay=relay, recipient="0x" + "11" * 20),
                realm="api.example.com",
                secret_key="test-secret",
            ).charge(amount="0.001")
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
    assert retry.id == challenge.id
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

    async with mock_relay(relay_handler) as relay:

        @pay(
            Mpp(
                methods=tempo_server.charge(relay=relay, recipient="0x" + "11" * 20),
                realm="api.example.com",
                secret_key="test-secret",
            ).charge(amount="0.001")
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
    assert raised.value.request == challenge.request
    assert raised.value.retry_challenge is None


@pytest.mark.asyncio
async def test_relay_maps_expired_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response({"success": False, "error": {"code": "expired"}})

    async with mock_relay(handler) as relay:
        with pytest.raises(PaymentExpiredError):
            await relay.configure(ChargeIntent()).validate(  # type: ignore[attr-defined]
                credential(), {"amount": "1000"}
            )


@pytest.mark.asyncio
async def test_relay_rejects_invalid_receipt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response({"success": True, "receipt": {"method": "stripe"}})

    async with mock_relay(handler) as relay:
        with pytest.raises(VerificationFailedError):
            await _broadcast(
                intent=relay.configure(ChargeIntent()),
                credential=credential(),
                request={"amount": "1000"},
            )


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

    with patch.object(intent, "_validate_transaction_payload", return_value=None):
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


@pytest.mark.asyncio
async def test_relay_does_not_authorize_cached_receipts_for_concurrent_credentials() -> None:
    import asyncio

    consumed = False
    receipt = {
        "success": True,
        "receipt": {"method": "tempo", "reference": "0xabc", "timestamp": "2026-08-05T12:00:00Z"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal consumed
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        # Model the relay contract: an idempotency key permits cached success.
        if consumed and "idempotency-key" not in request.headers:
            return response(
                {"success": False, "error": {"code": "already_used", "message": "Used"}}
            )
        consumed = True
        return response(receipt)

    async with mock_relay(handler, client_headers={"Idempotency-Key": "inherited-key"}) as relay:
        results = await asyncio.gather(
            *(
                _broadcast(
                    intent=relay.configure(ChargeIntent()),
                    credential=credential(),
                    request={"amount": "1000"},
                )
                for _ in range(2)
            ),
            return_exceptions=True,
        )
    assert sum(isinstance(result, Receipt) for result in results) == 1
    assert sum(isinstance(result, VerificationFailedError) for result in results) == 1


@pytest.mark.asyncio
async def test_relay_receipt_preserves_funding_currency() -> None:
    token = "0x20c0000000000000000000000000000000000001"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/validate"):
            return response({"success": True})
        return response(
            {
                "success": True,
                "receipt": {
                    "method": "tempo",
                    "reference": "0xabc",
                    "timestamp": "2026-08-05T12:00:00Z",
                    "fundingCurrency": token,
                },
            }
        )

    async with mock_relay(handler) as relay:
        result = await _broadcast(
            intent=relay.configure(ChargeIntent()),
            credential=credential(),
            request={"amount": "1000"},
        )

    assert result.funding_currency == token
