"""Tests for the shared payment runtime."""

from __future__ import annotations

import asyncio
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


def mcp_payment_error(
    *,
    realm: str = "example.com",
    expires: str | None = None,
) -> FakeMcpError:
    error = FakeMcpError(
        -32042,
        data={
            "challenges": [
                {
                    "id": "test-id",
                    "realm": realm,
                    "method": "tempo",
                    "intent": "charge",
                    "request": {"amount": "1000"},
                }
            ]
        },
    )
    if expires is not None:
        error.data["challenges"][0]["expires"] = expires
    return error


def mcp_payment_result(*, expires: str | None = None) -> FakeCallToolResult:
    return FakeCallToolResult(
        "payment required",
        meta={
            META_PAYMENT_REQUIRED: {
                "httpStatus": 402,
                "challenges": mcp_payment_error(expires=expires).data["challenges"],
            }
        },
    )


class TestHttpxRuntime:
    @pytest.mark.parametrize(
        ("allowed", "url"),
        [
            ("HTTPS://EXAMPLE.COM:443/path", "https://example.com/resource"),
            ("https://[2001:DB8::1]:443/path", "https://[2001:db8::1]/resource"),
            ("https://bücher.example", "https://xn--bcher-kva.example/resource"),
            ("https://xn--bcher-kva.example", "https://bücher.example/resource"),
        ],
    )
    def test_allowed_origins_are_normalized(self, allowed: str, url: str) -> None:
        runtime = PaymentRuntime([], allowed_origins=[allowed])

        assert runtime.allows_http_payment(httpx.URL(url))

    def test_mcp_url_realm_uses_normalized_origin(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["HTTPS://EXAMPLE.COM:443/path"])

        assert runtime._allowed.mcp_realm("https://example.com/tool")

    def test_http_url_allowlist_accepts_matching_hostname_mcp_realm(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["https://api.example.com"])

        assert runtime._allowed.mcp_realm("api.example.com")
        assert not runtime._allowed.mcp_realm("http://api.example.com:9999")

    @pytest.mark.parametrize(
        ("allowed", "realm"),
        [
            ("https://bücher.example", "xn--bcher-kva.example"),
            ("https://xn--bcher-kva.example", "bücher.example"),
            ("bücher.example", "https://xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "https://bücher.example"),
        ],
    )
    def test_mcp_realms_use_idna_normalized_hosts(self, allowed: str, realm: str) -> None:
        runtime = PaymentRuntime([], allowed_origins=[allowed])

        assert runtime._allowed.mcp_realm(realm)

    def test_bare_mcp_realm_does_not_authorize_http(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["api.example.com"])

        assert runtime._allowed.mcp_realm("api.example.com")
        assert not runtime.allows_http_payment(httpx.URL("https://api.example.com"))

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
    async def test_runtime_wrappers_pay_before_httpx_response_hooks(self) -> None:
        sync_calls = 0
        async_calls = 0
        seen: list[tuple[str, int]] = []

        def sync_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal sync_calls
            sync_calls += 1
            if sync_calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": payment_challenge_header()},
                )
            return httpx.Response(200)

        async def async_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal async_calls
            async_calls += 1
            if async_calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": payment_challenge_header()},
                )
            return httpx.Response(200)

        def sync_hook(response: httpx.Response) -> None:
            seen.append(("sync", response.status_code))
            response.raise_for_status()

        async def async_hook(response: httpx.Response) -> None:
            seen.append(("async", response.status_code))
            response.raise_for_status()

        runtime = PaymentRuntime([MockMethod()])
        sync_client = runtime.wrap_client(
            httpx.Client(
                transport=httpx.MockTransport(sync_handler),
                event_hooks={"response": [sync_hook]},
            )
        )
        async_client = runtime.wrap_async_client(
            httpx.AsyncClient(
                transport=httpx.MockTransport(async_handler),
                event_hooks={"response": [async_hook]},
            )
        )
        try:
            sync_response = sync_client.get("https://example.com/sync")
            async_response = await async_client.get("https://example.com/async")
        finally:
            sync_client.close()
            await async_client.aclose()
            runtime.close()

        assert sync_response.status_code == async_response.status_code == 200
        assert seen == [("sync", 200), ("async", 200)]

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
    def test_mcp_does_not_use_legacy_name_only_matching(self) -> None:
        class NameOnlyMethod:
            name = "tempo"

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        runtime = PaymentRuntime([NameOnlyMethod()])
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="subscription",
            request={},
        )

        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([challenge])

    @pytest.mark.asyncio
    async def test_mcp_client_accepts_runtime_without_methods(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])

        client = McpClient(session, runtime=runtime)
        result = await client.call_tool("premium_tool")

        assert client._runtime is runtime
        assert result.result.content[0]["text"] == "paid"

    @pytest.mark.asyncio
    async def test_mcp_client_implicit_runtime_stays_on_caller_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        caller_future: asyncio.Future[None] = caller_loop.create_future()
        method = MockMethod()

        async def create_credential(challenge: Challenge) -> Credential:
            await caller_future
            return Credential(
                challenge=challenge.to_echo(),
                payload={"hash": "0xabc"},
            )

        method.create_credential.side_effect = create_credential
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])
        caller_loop.call_later(0.01, caller_future.set_result, None)

        async with McpClient(session, methods=[method]) as client:
            await client.call_tool("premium_tool")
            assert client._runtime._bridge._thread is None

        assert client._runtime._bridge._closed

    @pytest.mark.asyncio
    async def test_mcp_client_does_not_close_injected_runtime(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])
        client = McpClient(session, runtime=runtime)
        await client.call_tool("premium_tool")
        thread = runtime._bridge._thread
        assert thread is not None and thread.is_alive()

        await client.aclose()
        assert thread.is_alive()
        await runtime.aclose()
        assert thread.is_alive() is False

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
    async def test_close_waits_for_committed_mcp_retry(self) -> None:
        retry_started = asyncio.Event()
        retry_release = asyncio.Event()
        raw_result = FakeCallToolResult("paid")
        calls = 0

        async def call_tool(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise mcp_payment_error()
            retry_started.set()
            await retry_release.wait()
            return raw_result

        runtime = PaymentRuntime([MockMethod()])
        request = asyncio.create_task(runtime.call_mcp_tool(call_tool, "premium_tool"))
        await asyncio.wait_for(retry_started.wait(), 1)
        close = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.05)
        assert not close.done()

        retry_release.set()
        assert await request is raw_result
        await asyncio.wait_for(close, 1)

    @pytest.mark.asyncio
    async def test_inherited_paid_lease_expires_with_its_owner(self) -> None:
        runtime = PaymentRuntime([], _async_inline=True)
        release = asyncio.Event()
        ran = False

        async def delayed() -> None:
            nonlocal ran
            await release.wait()

            async def mark_ran() -> None:
                nonlocal ran
                ran = True

            await runtime.run_async(mark_ran())

        with runtime._paid_operation():
            task = asyncio.create_task(delayed())
        runtime.close()
        release.set()

        with pytest.raises(RuntimeError, match="closed"):
            await task
        assert not ran

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

    @pytest.mark.parametrize("shape", ["error", "result"])
    @pytest.mark.asyncio
    async def test_expired_mcp_challenge_emits_failure_without_paying(
        self,
        shape: str,
    ) -> None:
        method = MockMethod()
        expires = "2020-01-01T00:00:00Z"
        challenge = (
            mcp_payment_error(expires=expires)
            if shape == "error"
            else mcp_payment_result(expires=expires)
        )
        session = FakeClientSession([challenge])
        runtime = PaymentRuntime([method])
        events: list[Any] = []
        runtime.events.on("*", events.append)
        try:
            with pytest.raises(ValueError, match="Challenge expired"):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()
        assert [event.name for event in events] == ["payment.failed"]
        assert events[-1].payload["challenge"].expires == expires
        assert events[-1].payload["credential"] is None

    @pytest.mark.asyncio
    async def test_malformed_mcp_url_realm_fails_closed(self) -> None:
        method = MockMethod()
        session = FakeClientSession([mcp_payment_error(realm="https://[malformed")])
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["https://example.com"],
        )
        events: list[Any] = []
        runtime.events.on("*", events.append)
        try:
            with pytest.raises(ValueError, match="malformed.*disallowed"):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()
        assert events[-1].name == "payment.failed"
        assert events[-1].payload["credential"] is None

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

    @pytest.mark.asyncio
    async def test_repeated_result_payment_challenge_fails_without_retrying_again(self) -> None:
        events: list[Any] = []
        first = mcp_payment_result()
        second = mcp_payment_result()
        runtime = PaymentRuntime([MockMethod()])
        runtime.events.on("*", events.append)
        session = FakeClientSession([first, second])
        try:
            with pytest.raises(PaymentOutcomeUnknownError):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 2
        assert [event.name for event in events] == [
            "challenge.received",
            "credential.created",
            "payment.failed",
        ]
        assert events[-1].payload["response"] is second
