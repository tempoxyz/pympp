import json

import httpx
import pytest

from mpp.x402 import PaymentPayload, PaymentRequirements, facilitator

REQUIREMENTS = PaymentRequirements.model_validate(
    {
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        "maxTimeoutSeconds": 60,
        "network": "eip155:84532",
        "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "scheme": "exact",
    }
)
PAYLOAD = PaymentPayload.model_validate(
    {
        "accepted": REQUIREMENTS.to_dict(),
        "payload": {
            "authorization": {
                "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
                "to": REQUIREMENTS.pay_to,
                "validAfter": "1740672089",
                "validBefore": "1740672154",
                "value": REQUIREMENTS.amount,
            },
            "signature": "0x" + "2d" * 65,
        },
        "x402Version": 2,
    }
)


def client(responder: dict[str, object], calls: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=responder)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_sends_v2_verify_envelopes() -> None:
    calls: list[httpx.Request] = []
    async with client({"isValid": True}, calls) as http:
        result = await facilitator.http("https://facilitator.example", client=http).verify(
            PAYLOAD, REQUIREMENTS
        )
    assert result.is_valid
    assert len(calls) == 1
    assert str(calls[0].url) == "https://facilitator.example/verify"
    assert calls[0].method == "POST"
    assert calls[0].headers["content-type"] == "application/json"
    assert json.loads(calls[0].content) == {
        "paymentPayload": PAYLOAD.to_dict(),
        "paymentRequirements": REQUIREMENTS.to_dict(),
        "x402Version": 2,
    }


async def test_sends_v2_settle_envelopes() -> None:
    calls: list[httpx.Request] = []
    body = {"network": "eip155:84532", "success": True, "transaction": "0x" + "1" * 64}
    async with client(body, calls) as http:
        result = await facilitator.http("https://facilitator.example/", client=http).settle(
            PAYLOAD, REQUIREMENTS
        )
    assert result.transaction == "0x" + "1" * 64
    assert str(calls[0].url) == "https://facilitator.example/settle"
    assert json.loads(calls[0].content) == {
        "paymentPayload": PAYLOAD.to_dict(),
        "paymentRequirements": REQUIREMENTS.to_dict(),
        "x402Version": 2,
    }


async def test_rejects_malformed_facilitator_responses() -> None:
    async with client({"success": "yes"}, []) as http:
        with pytest.raises(facilitator.FacilitatorError, match="unreadable SettleResponse"):
            await facilitator.http("https://f.example", client=http).settle(PAYLOAD, REQUIREMENTS)


def test_resolves_urls_and_clients() -> None:
    resolved = facilitator.resolve("https://f.example")
    assert isinstance(resolved, facilitator.HttpFacilitator)
    assert resolved.url == "https://f.example"
    custom = facilitator.HttpFacilitator("https://other.example")
    assert facilitator.resolve(custom) is custom
    with pytest.raises(ValueError, match="requires `facilitator`"):
        facilitator.resolve("")


def recording(status: int, body: bytes, calls: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, content=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_sends_static_headers() -> None:
    calls: list[httpx.Request] = []
    async with client({"isValid": True}, calls) as http:
        await facilitator.http(
            "https://f.example", client=http, headers={"Authorization": "Bearer static"}
        ).verify(PAYLOAD, REQUIREMENTS)
    assert calls[0].headers["authorization"] == "Bearer static"
    assert calls[0].headers["content-type"] == "application/json"


async def test_resolves_async_headers_per_request() -> None:
    tokens = iter(["one", "two"])

    async def headers() -> dict[str, str]:
        return {"Authorization": f"Bearer {next(tokens)}"}

    calls: list[httpx.Request] = []
    async with client({"isValid": True}, calls) as http:
        remote = facilitator.HttpFacilitator("https://f.example", client=http, headers=headers)
        await remote.verify(PAYLOAD, REQUIREMENTS)
        await remote.verify(PAYLOAD, REQUIREMENTS)
    assert [call.headers["authorization"] for call in calls] == ["Bearer one", "Bearer two"]


async def test_reads_json_error_bodies() -> None:
    body = json.dumps({"invalidReason": "insufficient_funds", "isValid": False}).encode()
    async with recording(400, body, []) as http:
        result = await facilitator.http("https://f.example", client=http).verify(
            PAYLOAD, REQUIREMENTS
        )
    assert (result.is_valid, result.invalid_reason) == (False, "insufficient_funds")


async def test_rejects_non_json_bodies() -> None:
    async with recording(502, b"<html>bad gateway</html>", []) as http:
        with pytest.raises(facilitator.FacilitatorError, match="HTTP 502 without a JSON body"):
            await facilitator.http("https://f.example", client=http).settle(PAYLOAD, REQUIREMENTS)


async def test_network_errors_raise_facilitator_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(facilitator.FacilitatorError, match="request failed"):
            await facilitator.http("https://f.example", client=http).verify(PAYLOAD, REQUIREMENTS)
