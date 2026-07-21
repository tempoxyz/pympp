"""HTTP transport coverage for Tempo session SSE payments."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mpp import Challenge, Credential, Receipt
from mpp.client import PaymentTransport, SyncPaymentTransport
from mpp.methods.tempo import TempoAccount, tempo_session

PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TOKEN = "0x20c0000000000000000000000000000000000000"
PAYEE = "0x2222222222222222222222222222222222222222"
URL = "https://api.example.test/stream?topic=weather"


@pytest.fixture(autouse=True)
def mock_session_transactions() -> Iterator[None]:
    with (
        patch(
            "mpp.methods.tempo.session.get_tx_params",
            new=AsyncMock(return_value=(4217, 1, 1)),
        ),
        patch(
            "mpp.methods.tempo.session.TempoSessionMethod._lane_nonce",
            new=AsyncMock(return_value=0),
        ),
    ):
        yield


def _challenge() -> Challenge:
    return Challenge(
        id="session-challenge",
        method="tempo",
        intent="session",
        realm="api.example.test",
        request={
            "amount": "2",
            "currency": TOKEN,
            "recipient": PAYEE,
            "suggestedDeposit": "5",
            "methodDetails": {
                "sessionProtocol": "v2",
                "chainId": 4217,
                "escrowContract": "0x4d50500000000000000000000000000000000000",
            },
        },
    )


def _receipt(channel_id: str, accepted: int, spent: int) -> dict[str, object]:
    return {
        "method": "tempo",
        "intent": "session",
        "status": "success",
        "timestamp": "2026-07-20T00:00:00Z",
        "reference": channel_id,
        "challengeId": "session-challenge",
        "channelId": channel_id,
        "acceptedCumulative": str(accepted),
        "spent": str(spent),
    }


def _receipt_header(value: dict[str, object]) -> str:
    extensions = dict(value)
    for field in ("method", "status", "timestamp", "reference"):
        extensions.pop(field)
    return Receipt(
        method="tempo",
        status="success",
        timestamp=datetime(2026, 7, 20, tzinfo=UTC),
        reference=str(value["reference"]),
        extensions=extensions,
    ).to_payment_receipt()


class SessionServer:
    def __init__(self) -> None:
        self.challenge = _challenge()
        self.actions: list[str] = []
        self.management_urls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization")
        if authorization is None:
            return httpx.Response(
                402,
                headers={
                    "WWW-Authenticate": self.challenge.to_www_authenticate("api.example.test")
                },
            )

        payload = Credential.from_authorization(authorization).payload
        action = str(payload["action"])
        self.actions.append(action)
        channel_id = str(payload["channelId"])

        if action == "open":
            need = {
                "channelId": channel_id,
                "requiredCumulative": "8",
                "acceptedCumulative": "2",
                "deposit": "5",
            }
            body = (
                b"data: first\n\n"
                + f"event: payment-need-voucher\ndata: {json.dumps(need)}\n\n".encode()
                + b"data: second\n\n"
                + (
                    "event: payment-receipt\ndata: "
                    + json.dumps(_receipt(channel_id, 8, 8))
                    + "\n\n"
                ).encode()
            )
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/event-stream",
                    "content-length": str(len(body)),
                    "payment-receipt": _receipt_header(_receipt(channel_id, 2, 0)),
                },
                stream=httpx.ByteStream(body),
            )

        self.management_urls.append(str(request.url))
        accepted = 2 if action == "topUp" else 8
        return httpx.Response(
            204,
            headers={"payment-receipt": _receipt_header(_receipt(channel_id, accepted, 0))},
        )


class ErrorSseServer:
    def __init__(self) -> None:
        self.challenge = _challenge()
        self.payloads: list[dict[str, object]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization")
        if authorization is None:
            return httpx.Response(
                402,
                headers={
                    "WWW-Authenticate": self.challenge.to_www_authenticate("api.example.test")
                },
            )
        payload = Credential.from_authorization(authorization).payload
        self.payloads.append(payload)
        channel_id = str(payload["channelId"])
        need = {
            "channelId": channel_id,
            "requiredCumulative": "8",
            "acceptedCumulative": "2",
            "deposit": "5",
        }
        body = f"event: payment-need-voucher\ndata: {json.dumps(need)}\n\n".encode()
        return httpx.Response(
            500,
            headers={
                "content-type": "text/event-stream",
                "payment-receipt": _receipt_header(_receipt(channel_id, 2, 0)),
            },
            stream=httpx.ByteStream(body),
        )


@pytest.mark.asyncio
async def test_async_transport_drives_session_sse_top_up_and_voucher() -> None:
    server = SessionServer()
    method = tempo_session(
        account=TempoAccount.from_key(PRIVATE_KEY),
        max_deposit=10,
        rpc_url="https://rpc.test",
    )
    transport = PaymentTransport(methods=[method], inner=httpx.MockTransport(server))

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get(URL, headers={"Accept": "text/event-stream"})
        assert b"".join([chunk async for chunk in response.aiter_bytes()]) == (
            b"data: first\n\ndata: second\n\n"
        )

    assert server.actions == ["open", "topUp", "voucher"]
    assert server.management_urls == [URL, URL]
    assert "content-length" not in response.headers


def test_sync_transport_drives_session_sse_top_up_and_voucher() -> None:
    server = SessionServer()
    method = tempo_session(
        account=TempoAccount.from_key(PRIVATE_KEY),
        max_deposit=10,
        rpc_url="https://rpc.test",
    )
    transport = SyncPaymentTransport(methods=[method], inner=httpx.MockTransport(server))

    with httpx.Client(transport=transport) as client:
        response = client.get(URL, headers={"Accept": "text/event-stream"})
        assert b"".join(response.iter_bytes()) == b"data: first\n\ndata: second\n\n"

    assert server.actions == ["open", "topUp", "voucher"]
    assert server.management_urls == [URL, URL]
    assert "content-length" not in response.headers


@pytest.mark.asyncio
async def test_async_error_sse_cannot_advance_session() -> None:
    server = ErrorSseServer()
    transport = PaymentTransport(
        methods=[
            tempo_session(
                account=TempoAccount.from_key(PRIVATE_KEY),
                max_deposit=10,
                rpc_url="https://rpc.test",
            )
        ],
        inner=httpx.MockTransport(server),
    )

    async with httpx.AsyncClient(transport=transport) as client:
        assert (await client.get(URL)).status_code == 500
        assert (await client.get(URL)).status_code == 500

    assert [payload["action"] for payload in server.payloads] == ["open", "open"]
    assert server.payloads[0]["transaction"] == server.payloads[1]["transaction"]


def test_sync_error_sse_cannot_advance_session() -> None:
    server = ErrorSseServer()
    transport = SyncPaymentTransport(
        methods=[
            tempo_session(
                account=TempoAccount.from_key(PRIVATE_KEY),
                max_deposit=10,
                rpc_url="https://rpc.test",
            )
        ],
        inner=httpx.MockTransport(server),
    )

    with httpx.Client(transport=transport) as client:
        assert client.get(URL).status_code == 500
        assert client.get(URL).status_code == 500

    assert [payload["action"] for payload in server.payloads] == ["open", "open"]
    assert server.payloads[0]["transaction"] == server.payloads[1]["transaction"]
