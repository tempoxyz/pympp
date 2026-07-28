"""Tests for per-client HTTPX payment adapters."""

from __future__ import annotations

import inspect
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

import mpp._httpx as httpx_compat
from mpp import Challenge, Credential
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.runtime import (
    HTTPX_ADAPTER_VERSIONS,
    HttpxCompatibilityError,
    PaymentRuntime,
)


class Method:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.create_credential = AsyncMock(side_effect=self._create_credential)

    async def _create_credential(self, challenge: Challenge):
        return Credential(challenge=challenge.to_echo(), payload={"hash": "0xabc"})


def payment_required(challenge_id: str = "challenge") -> httpx.Response:
    challenge = Challenge(
        id=challenge_id,
        method="tempo",
        intent="charge",
        request={},
    )
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
    )


@pytest.mark.asyncio
async def test_wrap_clients_are_idempotent_and_preserve_auth_and_hooks() -> None:
    method = Method()
    runtime = PaymentRuntime([method])
    sync_requests: list[httpx.Request] = []
    async_requests: list[httpx.Request] = []
    hooks: list[tuple[str, int]] = []

    def handler(requests: list[httpx.Request], request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b"paid") if len(requests) == 2 else payment_required()

    def sync_hook(response: httpx.Response) -> None:
        hooks.append(("sync", response.status_code))

    async def async_hook(response: httpx.Response) -> None:
        hooks.append(("async", response.status_code))

    sync_client = httpx.Client(
        auth=("user", "password"),
        event_hooks={"response": [sync_hook]},
        transport=httpx.MockTransport(lambda request: handler(sync_requests, request)),
    )
    async_client = httpx.AsyncClient(
        auth=("user", "password"),
        event_hooks={"response": [async_hook]},
        transport=httpx.MockTransport(lambda request: handler(async_requests, request)),
    )
    try:
        assert runtime.wrap_client(sync_client) is sync_client
        assert runtime.wrap_client(sync_client) is sync_client
        assert runtime.wrap_async_client(async_client) is async_client
        assert runtime.wrap_async_client(async_client) is async_client
        sync_response = sync_client.get("https://example.com/sync")
        async_response = await async_client.get("https://example.com/async")
    finally:
        sync_client.close()
        await async_client.aclose()
        runtime.close()

    assert sync_response.status_code == async_response.status_code == 200
    assert sync_requests[0].headers["authorization"].startswith("Basic ")
    assert async_requests[0].headers["authorization"].startswith("Basic ")
    assert sync_requests[1].headers["authorization"].startswith("Payment ")
    assert async_requests[1].headers["authorization"].startswith("Payment ")
    assert hooks == [("sync", 200), ("async", 200)]
    assert method.create_credential.await_count == 2


@pytest.mark.asyncio
async def test_runtime_send_httpx_helpers_handle_sync_and_async_challenges() -> None:
    method = Method()
    runtime = PaymentRuntime([method])
    sync_requests: list[httpx.Request] = []
    async_requests: list[httpx.Request] = []

    def sync_send(request: httpx.Request) -> httpx.Response:
        sync_requests.append(request)
        return (
            httpx.Response(200, content=b"sync")
            if "authorization" in request.headers
            else payment_required("sync")
        )

    async def async_send(request: httpx.Request) -> httpx.Response:
        async_requests.append(request)
        return (
            httpx.Response(200, content=b"async")
            if "authorization" in request.headers
            else payment_required("async")
        )

    try:
        sync_response = runtime.send_httpx_sync(
            sync_send,
            httpx.Request("GET", "https://example.com/sync"),
        )
        async_response = await runtime.send_httpx(
            async_send,
            httpx.Request("GET", "https://example.com/async"),
        )
    finally:
        runtime.close()

    assert sync_response.content == b"sync"
    assert async_response.content == b"async"
    assert all(
        "authorization" in requests[1].headers for requests in (sync_requests, async_requests)
    )


@pytest.mark.asyncio
async def test_wrappers_send_free_one_shot_uploads_once() -> None:
    sync_bodies: list[bytes] = []
    async_bodies: list[bytes] = []
    runtime = PaymentRuntime([])

    def sync_handler(request: httpx.Request) -> httpx.Response:
        sync_bodies.append(b"".join(cast(httpx.SyncByteStream, request.stream)))
        return httpx.Response(200)

    async def async_handler(request: httpx.Request) -> httpx.Response:
        stream = cast(httpx.AsyncByteStream, request.stream)
        async_bodies.append(b"".join([chunk async for chunk in stream]))
        return httpx.Response(200)

    def sync_body():
        yield b"one-"
        yield b"shot"

    async def async_body():
        yield b"one-"
        yield b"shot"

    sync_client = runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(sync_handler)))
    async_client = runtime.wrap_async_client(
        httpx.AsyncClient(transport=httpx.MockTransport(async_handler))
    )
    try:
        sync_response = sync_client.post("https://example.com", content=sync_body())
        async_response = await async_client.post(
            "https://example.com",
            content=async_body(),
        )
    finally:
        sync_client.close()
        await async_client.aclose()
        runtime.close()

    assert sync_response.status_code == async_response.status_code == 200
    assert sync_bodies == async_bodies == [b"one-shot"]


@pytest.mark.asyncio
async def test_redirect_policy_uses_the_challenged_origin() -> None:
    requests: list[httpx.Request] = []
    method = Method()
    runtime = PaymentRuntime([method], allowed_origins=["https://allowed.example"])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "allowed.example":
            return httpx.Response(302, headers={"location": "https://other.example/paid"})
        return payment_required()

    client = runtime.wrap_async_client(
        httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
        )
    )
    try:
        response = await client.get("https://allowed.example/start")
    finally:
        await client.aclose()
        runtime.close()

    assert response.status_code == 402
    assert [request.url.host for request in requests] == ["allowed.example", "other.example"]
    method.create_credential.assert_not_awaited()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_repeated_challenge_never_pays_twice(asynchronous: bool) -> None:
    requests: list[httpx.Request] = []
    method = Method()
    runtime = PaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return payment_required(f"challenge-{len(requests)}")

    client: httpx.Client | httpx.AsyncClient
    client = (
        runtime.wrap_async_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        if asynchronous
        else runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(handler)))
    )
    try:
        with pytest.raises(PaymentOutcomeUnknownError):
            if asynchronous:
                await cast(httpx.AsyncClient, client).get("https://example.com/paid")
            else:
                cast(httpx.Client, client).get("https://example.com/paid")
    finally:
        if asynchronous:
            await cast(httpx.AsyncClient, client).aclose()
        else:
            cast(httpx.Client, client).close()
        runtime.close()

    assert len(requests) == 2
    method.create_credential.assert_awaited_once()


def test_paid_send_failure_blocks_a_second_payment() -> None:
    requests: list[httpx.Request] = []
    method = Method()
    runtime = PaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "authorization" in request.headers:
            raise httpx.ReadTimeout("paid response lost", request=request)
        return payment_required()

    client = runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(handler)))
    headers = {"Idempotency-Key": "operation"}
    try:
        with pytest.raises(PaymentOutcomeUnknownError, match="outcome is unknown"):
            client.get("https://example.com/paid", headers=headers)
        with pytest.raises(PaymentOutcomeUnknownError):
            client.get("https://example.com/paid", headers=headers)
    finally:
        client.close()
        runtime.close()

    assert len(requests) == 3
    method.create_credential.assert_awaited_once()


def test_response_hook_failure_keeps_nested_transport_attempt_unknown() -> None:
    method = Method()
    runtime = PaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        return payment_required()

    hook_calls = 0

    def hook(response: httpx.Response) -> None:
        nonlocal hook_calls
        hook_calls += 1
        response.read()
        raise RuntimeError("consumer failed")

    transport = runtime.sync_payment_transport(inner=httpx.MockTransport(handler))
    client = runtime.wrap_client(
        httpx.Client(transport=transport, event_hooks={"response": [hook]})
    )
    try:
        with pytest.raises(RuntimeError, match="consumer failed"):
            client.get("https://example.com/paid")
        with pytest.raises(PaymentOutcomeUnknownError):
            client.get("https://example.com/paid")
    finally:
        client.close()
        runtime.close()

    assert hook_calls == 1
    method.create_credential.assert_awaited_once()


class BrokenStream(httpx.SyncByteStream):
    def __iter__(self):
        raise httpx.ReadError("body lost")
        yield b""  # pragma: no cover


def test_paid_stream_failure_blocks_a_second_payment() -> None:
    method = Method()
    runtime = PaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, stream=BrokenStream())
        return payment_required()

    client = runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(handler)))
    try:
        request = client.build_request("GET", "https://example.com/paid")
        response = client.send(request, stream=True)
        with pytest.raises(httpx.ReadError, match="body lost"):
            response.read()
        response.close()
        with pytest.raises(PaymentOutcomeUnknownError):
            client.get("https://example.com/paid")
    finally:
        client.close()
        runtime.close()

    method.create_credential.assert_awaited_once()


def test_paid_one_shot_upload_fails_before_sending_a_credential() -> None:
    bodies: list[bytes] = []
    method = Method()
    runtime = PaymentRuntime([method])

    class ConsumingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            bodies.append(b"".join(cast(httpx.SyncByteStream, request.stream)))
            return payment_required()

    def body():
        yield b"one-shot"

    client = runtime.wrap_client(httpx.Client(transport=ConsumingTransport()))
    try:
        with pytest.raises(PaymentError, match="cannot be replayed"):
            client.post("https://example.com/paid", content=body())
    finally:
        client.close()
        runtime.close()

    assert bodies == [b"one-shot"]
    method.create_credential.assert_not_awaited()


def test_unsupported_version_fails_without_mutating_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = httpx.Client()
    runtime = PaymentRuntime([])
    send = inspect.getattr_static(client, "send")
    send_single = inspect.getattr_static(client, "_send_single_request")
    monkeypatch.setattr(httpx_compat, "version", lambda _: "0.29.0")
    try:
        with pytest.raises(HttpxCompatibilityError, match=r"supported: >=0.27,<0.29"):
            runtime.wrap_client(client)
    finally:
        client.close()
        runtime.close()

    assert HTTPX_ADAPTER_VERSIONS == ">=0.27,<0.29"
    assert inspect.getattr_static(client, "send") is send
    assert inspect.getattr_static(client, "_send_single_request") is send_single
    assert not hasattr(client, "_mpp_payment_runtime")
    assert not hasattr(client, "_mpp_payment_wrapped")


def test_changed_send_signature_fails_without_mutating_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = httpx.Client()
    runtime = PaymentRuntime([])
    wrapped = runtime.wrap_client(httpx.Client())
    send_single = inspect.getattr_static(client, "_send_single_request")

    def incompatible(
        self: httpx.Client,
        request: httpx.Request,
        extra: object,
    ) -> httpx.Response:
        raise AssertionError

    monkeypatch.setattr(httpx.Client, "send", incompatible)
    try:
        assert runtime.wrap_client(wrapped) is wrapped
        with pytest.raises(HttpxCompatibilityError, match="Client.send.*unsupported signature"):
            runtime.wrap_client(client)
    finally:
        client.close()
        wrapped.close()
        runtime.close()

    assert inspect.getattr_static(client, "_send_single_request") is send_single
    assert inspect.getattr_static(client, "send") is incompatible
    assert not hasattr(client, "_mpp_payment_runtime")
    assert not hasattr(client, "_mpp_payment_wrapped")


def test_sync_wrap_ignores_an_incompatible_async_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def incompatible(
        self: httpx.AsyncClient,
        request: httpx.Request,
        extra: object,
    ) -> httpx.Response:
        raise AssertionError

    monkeypatch.setattr(httpx.AsyncClient, "send", incompatible)
    runtime = PaymentRuntime([])
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    try:
        assert runtime.wrap_client(client).get("https://example.com").status_code == 200
    finally:
        client.close()
        runtime.close()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.asyncio
async def test_instance_seams_fail_before_mutation(asynchronous: bool) -> None:
    client: httpx.Client | httpx.AsyncClient = (
        httpx.AsyncClient() if asynchronous else httpx.Client()
    )
    runtime = PaymentRuntime([])
    send_single = inspect.getattr_static(client, "_send_single_request")
    if asynchronous:

        async def incompatible_async(
            request: httpx.Request,
            required: object,
        ) -> httpx.Response:
            raise AssertionError

        incompatible = incompatible_async
    else:

        def incompatible_sync(
            request: httpx.Request,
            required: object,
        ) -> httpx.Response:
            raise AssertionError

        incompatible = incompatible_sync

    client.send = incompatible  # type: ignore[method-assign, assignment]
    try:
        with pytest.raises(HttpxCompatibilityError, match="instance.send.*unsupported signature"):
            if asynchronous:
                runtime.wrap_async_client(cast(httpx.AsyncClient, client))
            else:
                runtime.wrap_client(cast(httpx.Client, client))
    finally:
        if asynchronous:
            await cast(httpx.AsyncClient, client).aclose()
        else:
            cast(httpx.Client, client).close()
        runtime.close()

    assert inspect.getattr_static(client, "send") is incompatible
    assert inspect.getattr_static(client, "_send_single_request") is send_single
    assert not hasattr(client, "_mpp_payment_runtime")
    assert not hasattr(client, "_mpp_payment_wrapped")


def test_adapter_mutation_rolls_back_on_assignment_failure() -> None:
    class RejectingClient(httpx.Client):
        def __setattr__(self, name: str, value: object) -> None:
            if name == "_mpp_payment_wrapped":
                raise RuntimeError("assignment rejected")
            super().__setattr__(name, value)

    client = RejectingClient()
    runtime = PaymentRuntime([])
    send = inspect.getattr_static(client, "send")
    send_single = inspect.getattr_static(client, "_send_single_request")
    try:
        with pytest.raises(RuntimeError, match="assignment rejected"):
            runtime.wrap_client(client)
    finally:
        client.close()
        runtime.close()

    assert inspect.getattr_static(client, "send") is send
    assert inspect.getattr_static(client, "_send_single_request") is send_single
    assert not hasattr(client, "_mpp_payment_runtime")
    assert not hasattr(client, "_mpp_payment_wrapped")


@pytest.mark.asyncio
async def test_wrap_entry_points_reject_the_wrong_client_kind() -> None:
    sync_client = httpx.Client()
    async_client = httpx.AsyncClient()
    runtime = PaymentRuntime([])
    try:
        with pytest.raises(TypeError, match="httpx.Client"):
            runtime.wrap_client(cast(Any, async_client))
        with pytest.raises(TypeError, match="httpx.AsyncClient"):
            runtime.wrap_async_client(cast(Any, sync_client))
    finally:
        sync_client.close()
        await async_client.aclose()
        runtime.close()

    assert not hasattr(sync_client, "_mpp_payment_wrapped")
    assert not hasattr(async_client, "_mpp_payment_wrapped")
