"""Tests for the shared payment runtime."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge, ChallengeEcho, Credential
from mpp.extensions.mcp import (
    META_CREDENTIAL,
    META_PAYMENT_REQUIRED,
    McpClient,
    PaymentOutcomeUnknownError,
)
from mpp.runtime import PaymentRuntime


class MockMethod:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.create_credential = AsyncMock(
            return_value=Credential(
                challenge=ChallengeEcho(
                    id="test-id",
                    realm="example.com",
                    method="tempo",
                    intent="charge",
                    request="e30",
                ),
                payload={"hash": "0xabc"},
                source="0x1234",
            )
        )


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)


class FakeCallToolResult:
    def __init__(self, text: str = "ok", meta: dict[str, Any] | None = None) -> None:
        self.content = [{"type": "text", "text": text}]
        self.isError = False
        self.meta = meta


class FakeMcpError(Exception):
    def __init__(self, code: int, data: Any = None) -> None:
        super().__init__("mcp error")
        self.code = code
        self.data = data


class FakeClientSession:
    def __init__(self, side_effects: list[Any]) -> None:
        self.side_effects = side_effects
        self.calls: list[tuple[str, dict[str, Any] | None, tuple[Any, ...], dict[str, Any]]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        self.calls.append((name, arguments, args, kwargs))
        item = self.side_effects.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def payment_challenge_header() -> str:
    challenge = Challenge(id="test-id", method="tempo", intent="charge", request={})
    return challenge.to_www_authenticate("example.com")


def mcp_payment_error() -> FakeMcpError:
    return FakeMcpError(
        -32042,
        data={
            "challenges": [
                {
                    "id": "test-id",
                    "realm": "example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": {"amount": "1000"},
                }
            ]
        },
    )


def mcp_payment_result() -> FakeCallToolResult:
    return FakeCallToolResult(
        "payment required",
        meta={
            META_PAYMENT_REQUIRED: {
                "httpStatus": 402,
                "challenges": mcp_payment_error().data["challenges"],
            }
        },
    )


class TestHttpxRuntime:
    @pytest.mark.asyncio
    async def test_runtime_wrap_async_client_without_global_hook(self) -> None:
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": payment_challenge_header()}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        runtime = PaymentRuntime([MockMethod()])
        client = runtime.wrap_async_client(httpx.AsyncClient(transport=inner))
        try:
            response = await client.get("https://example.com/paid")
        finally:
            await client.aclose()

        assert response.status_code == 200
        assert len(inner.requests) == 2
        assert inner.requests[1].headers["authorization"].startswith("Payment ")

    @pytest.mark.asyncio
    async def test_disallowed_http_origin_does_not_retry_payment(self) -> None:
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": payment_challenge_header()}),
            ]
        )
        method = MockMethod()
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["https://other.example"],
        )
        client = runtime.wrap_async_client(httpx.AsyncClient(transport=inner))
        try:
            response = await client.get("https://example.com/paid")
        finally:
            await client.aclose()

        assert response.status_code == 402
        assert len(inner.requests) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_redirected_402_uses_challenged_origin_policy(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.host == "allowed.example":
                return httpx.Response(302, headers={"location": "https://evil.example/paid"})
            return httpx.Response(
                402,
                headers={"www-authenticate": payment_challenge_header()},
            )

        method = MockMethod()
        runtime = PaymentRuntime([method], allowed_origins=["https://allowed.example"])
        client = runtime.wrap_async_client(
            httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        )
        try:
            response = await client.get("https://allowed.example/start")
        finally:
            await client.aclose()

        assert response.status_code == 402
        assert [request.url.host for request in requests] == ["allowed.example", "evil.example"]
        method.create_credential.assert_not_called()


class TestMcpRuntime:
    @pytest.mark.asyncio
    async def test_mcp_client_accepts_runtime_without_methods(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])

        client = McpClient(session, runtime=runtime)
        result = await client.call_tool("premium_tool")

        assert client._runtime is runtime
        assert result.result.content[0]["text"] == "paid"

    def test_mcp_client_rejects_runtime_with_methods(self) -> None:
        runtime = PaymentRuntime([])

        with pytest.raises(ValueError, match="either methods or runtime"):
            McpClient(FakeClientSession([]), methods=[], runtime=runtime)

    @pytest.mark.asyncio
    async def test_payment_runtime_call_mcp_tool_pays_and_preserves_raw_result(self) -> None:
        raw_result = FakeCallToolResult("paid")
        session = FakeClientSession([mcp_payment_error(), raw_result])
        runtime = PaymentRuntime([MockMethod()])

        result = await runtime.call_mcp_tool(
            session.call_tool,
            "premium_tool",
            {"query": "test"},
            progress_callback="callback",
            meta={"trace_id": "abc"},
        )

        assert result is raw_result
        assert len(session.calls) == 2
        retry_kwargs = session.calls[1][3]
        assert retry_kwargs["progress_callback"] == "callback"
        assert retry_kwargs["meta"]["trace_id"] == "abc"
        assert META_CREDENTIAL in retry_kwargs["meta"]

    @pytest.mark.asyncio
    async def test_disallowed_mcp_realm_does_not_retry_payment(self) -> None:
        method = MockMethod()
        session = FakeClientSession([mcp_payment_error()])
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["other.example"],
        )

        with pytest.raises(ValueError, match="disallowed"):
            await runtime.call_mcp_tool(session.call_tool, "premium_tool", {"query": "test"})

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_result_metadata_payment_preserves_raw_result_and_meta(self) -> None:
        raw_result = FakeCallToolResult("paid")
        session = FakeClientSession([mcp_payment_result(), raw_result])
        runtime = PaymentRuntime([MockMethod()])

        result = await runtime.call_mcp_tool(
            session.call_tool,
            "premium_tool",
            meta={"trace_id": "abc"},
        )

        assert result is raw_result
        assert len(session.calls) == 2
        retry_meta = session.calls[1][3]["meta"]
        assert retry_meta["trace_id"] == "abc"
        assert META_CREDENTIAL in retry_meta

    @pytest.mark.asyncio
    async def test_shared_runtime_emits_mcp_payment_events(self) -> None:
        events: list[Any] = []
        runtime = PaymentRuntime([MockMethod()])
        runtime.events.on("*", events.append)
        session = FakeClientSession([mcp_payment_result(), FakeCallToolResult("paid")])

        await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        assert [event.name for event in events] == [
            "challenge.received",
            "credential.created",
            "payment.response",
        ]
        assert all(event.payload["protocol"] == "mcp" for event in events)

    @pytest.mark.asyncio
    async def test_mcp_challenge_handler_can_supply_credential(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        credential = Credential(
            challenge=ChallengeEcho(
                id="event-id",
                realm="example.com",
                method="tempo",
                intent="charge",
                request="e30",
            ),
            payload={"hash": "0xevent"},
        )
        runtime.events.on("challenge.received", lambda _: credential)
        session = FakeClientSession([mcp_payment_result(), FakeCallToolResult("paid")])

        await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_mcp_retry_failure_emits_payment_failed(self) -> None:
        events: list[Any] = []
        runtime = PaymentRuntime([MockMethod()])
        runtime.events.on("*", events.append)
        session = FakeClientSession([mcp_payment_result(), TimeoutError("timed out")])

        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        assert events[-1].name == "payment.failed"
        assert isinstance(events[-1].payload["error"], PaymentOutcomeUnknownError)
