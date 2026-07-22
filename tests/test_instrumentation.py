"""Tests for scoped HTTP and MCP instrumentation."""

from __future__ import annotations

import asyncio
import builtins
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge
from mpp.extensions.mcp import META_CREDENTIAL, McpClient
from mpp.instrumentation import _bindings, _state, instrument
from mpp.runtime import PaymentRuntime
from tests import make_credential


class MockMethod:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self, label: str) -> None:
        self.label = label
        self.create_credential = AsyncMock(side_effect=self._create)

    async def _create(self, challenge: Challenge):
        return make_credential({"runtime": self.label}, challenge_id=challenge.id)


def payment_required() -> httpx.Response:
    challenge = Challenge(id="test-id", method="tempo", intent="charge", request={})
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
    )


def paid_transport(requests: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return payment_required() if len(requests) == 1 else httpx.Response(200, content=b"paid")

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def clean_instrumentation_state():
    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send
    thread_start = threading.Thread.start
    _bindings.set(None)
    yield
    with _state.lock:
        for binding in _state.bindings:
            binding.active = False
        _state.bindings.clear()
        if _state.mcp_client_session is not None and _state.original_mcp_call_tool is not None:
            _state.mcp_client_session.call_tool = _state.original_mcp_call_tool
        _state.original_sync_send = None
        _state.sync_send_patch = None
        _state.original_async_send = None
        _state.async_send_patch = None
        _state.original_thread_start = None
        _state.thread_start_patch = None
        _state.original_mcp_call_tool = None
        _state.mcp_call_tool_patch = None
        _state.mcp_client_session = None
    httpx.Client.send = sync_send
    httpx.AsyncClient.send = async_send
    threading.Thread.start = thread_start
    _bindings.set(None)


@pytest.mark.asyncio
async def test_instruments_existing_sync_and_async_clients() -> None:
    sync_requests: list[httpx.Request] = []
    async_requests: list[httpx.Request] = []
    sync_client = httpx.Client(transport=paid_transport(sync_requests))
    async_client = httpx.AsyncClient(transport=paid_transport(async_requests))
    method = MockMethod("one")
    runtime = PaymentRuntime([method])
    handle = instrument(runtime, mcp=False)
    try:
        sync_response = sync_client.get("https://example.com/sync")
        async_response = await async_client.get("https://example.com/async")
    finally:
        handle.disable()
        sync_client.close()
        await async_client.aclose()
        runtime.close()

    assert sync_response.status_code == async_response.status_code == 200
    assert len(sync_requests) == len(async_requests) == 2
    assert method.create_credential.call_count == 2


@pytest.mark.asyncio
async def test_concurrent_contexts_select_their_own_runtime() -> None:
    methods = [MockMethod("a"), MockMethod("b")]
    runtimes = [PaymentRuntime([method]) for method in methods]

    async def call(runtime: PaymentRuntime) -> None:
        requests: list[httpx.Request] = []
        async with httpx.AsyncClient(transport=paid_transport(requests)) as client:
            with instrument(runtime, mcp=False):
                assert (await client.get("https://example.com/paid")).status_code == 200

    try:
        await asyncio.gather(*(call(runtime) for runtime in runtimes))
    finally:
        for runtime in runtimes:
            runtime.close()

    assert [method.create_credential.call_count for method in methods] == [1, 1]


@pytest.mark.asyncio
async def test_active_payment_does_not_block_another_local_context() -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingMethod(MockMethod):
        async def _create(self, challenge: Challenge):
            started.set()
            while not release.is_set():
                await asyncio.sleep(0.01)
            return await super()._create(challenge)

    methods = [BlockingMethod("a"), MockMethod("b")]
    runtimes = [PaymentRuntime([method]) for method in methods]

    async def first_call() -> int:
        requests: list[httpx.Request] = []
        async with httpx.AsyncClient(transport=paid_transport(requests)) as client:
            with instrument(runtimes[0], mcp=False):
                return (await client.get("https://example.com/first")).status_code

    task = asyncio.create_task(first_call())
    assert await asyncio.to_thread(started.wait, 1)
    second_requests: list[httpx.Request] = []
    try:
        async with httpx.AsyncClient(transport=paid_transport(second_requests)) as client:
            with instrument(runtimes[1], mcp=False):
                second_status = (await client.get("https://example.com/second")).status_code
    finally:
        release.set()
        first_status = await task
        for runtime in runtimes:
            runtime.close()

    assert first_status == second_status == 200
    assert len(second_requests) == 2
    assert [method.create_credential.call_count for method in methods] == [1, 1]


@pytest.mark.asyncio
async def test_disabled_context_does_not_fall_back_to_another_runtime() -> None:
    other_method = MockMethod("other")
    other_runtime = PaymentRuntime([other_method])
    local_runtime = PaymentRuntime([MockMethod("local")])
    ready = asyncio.Event()
    release = asyncio.Event()

    async def hold_other_context() -> None:
        with instrument(other_runtime, mcp=False):
            ready.set()
            await release.wait()

    task = asyncio.create_task(hold_other_context())
    await ready.wait()
    handle = instrument(local_runtime, mcp=False)
    handle.disable()
    requests: list[httpx.Request] = []
    try:
        async with httpx.AsyncClient(transport=paid_transport(requests)) as client:
            assert (await client.get("https://example.com/paid")).status_code == 402
    finally:
        release.set()
        await task
        local_runtime.close()
        other_runtime.close()

    assert len(requests) == 1
    other_method.create_credential.assert_not_called()


@pytest.mark.asyncio
async def test_preexisting_async_context_does_not_use_process_fallback() -> None:
    method = MockMethod("one")
    runtime = PaymentRuntime([method])
    ready = asyncio.Event()
    release = asyncio.Event()
    requests: list[httpx.Request] = []

    async def call() -> int:
        ready.set()
        await release.wait()
        async with httpx.AsyncClient(transport=paid_transport(requests)) as client:
            return (await client.get("https://example.com/paid")).status_code

    task = asyncio.create_task(call())
    await ready.wait()
    handle = instrument(runtime, mcp=False)
    try:
        release.set()
        status = await task
    finally:
        handle.disable()
        runtime.close()

    assert status == 402
    assert len(requests) == 1
    method.create_credential.assert_not_called()


def test_bare_thread_uses_only_unambiguous_process_runtime() -> None:
    method = MockMethod("one")
    runtime = PaymentRuntime([method])
    requests: list[httpx.Request] = []
    client = httpx.Client(transport=paid_transport(requests))
    handle = instrument(runtime, mcp=False)
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(client.get("https://example.com/paid").status_code)
    )
    try:
        thread.start()
        thread.join(timeout=2)
    finally:
        handle.disable()
        client.close()
        runtime.close()

    assert thread.is_alive() is False
    assert result == [200]
    assert method.create_credential.call_count == 1


def test_background_event_loop_uses_unambiguous_http_runtime() -> None:
    method = MockMethod("one")
    runtime = PaymentRuntime([method])
    requests: list[httpx.Request] = []
    result: dict[str, Any] = {}
    handle = instrument(runtime, mcp=False)

    async def call() -> None:
        async with httpx.AsyncClient(transport=paid_transport(requests)) as client:
            result["status"] = (await client.get("https://example.com/paid")).status_code

    thread = threading.Thread(target=lambda: asyncio.run(call()))
    try:
        thread.start()
        thread.join(timeout=2)
    finally:
        handle.disable()
        runtime.close()

    assert thread.is_alive() is False
    assert result == {"status": 200}
    assert len(requests) == 2


def test_background_event_loop_uses_unambiguous_mcp_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp

    monkeypatch.setattr(mcp, "ClientSession", FakeSession)
    method = MockMethod("one")
    runtime = PaymentRuntime([method])
    paid_result = object()
    session = FakeSession([FakeMcpError(), paid_result])
    result: list[Any] = []
    handle = instrument(runtime, httpx=False, mcp=True)
    thread = threading.Thread(target=lambda: result.append(asyncio.run(session.call_tool("paid"))))
    try:
        thread.start()
        thread.join(timeout=2)
    finally:
        handle.disable()
        runtime.close()

    assert thread.is_alive() is False
    assert result == [paid_result]
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_free_async_generator_upload_is_not_buffered() -> None:
    consumed: list[bytes] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        consumed.append(await request.aread())
        return httpx.Response(200, content=b"ok")

    async def body():
        yield b"one-"
        yield b"shot"

    runtime = PaymentRuntime([MockMethod("one")])
    handle = instrument(runtime, mcp=False)
    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            response = await client.post("https://example.com/upload", content=body())
    finally:
        handle.disable()
        runtime.close()

    assert response.status_code == 200
    assert consumed == [b"one-shot"]


def test_concurrent_bare_threads_share_the_process_runtime() -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingFirstMethod(MockMethod):
        async def _create(self, challenge: Challenge):
            if self.create_credential.call_count == 1:
                started.set()
                while not release.is_set():
                    await asyncio.sleep(0.01)
            return await super()._create(challenge)

    method = BlockingFirstMethod("one")
    runtime = PaymentRuntime([method])
    request_sets: list[list[httpx.Request]] = [[], []]
    clients = [
        httpx.Client(transport=paid_transport(request_sets[0])),
        httpx.Client(transport=paid_transport(request_sets[1])),
    ]
    handle = instrument(runtime, mcp=False)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(clients[0].get, "https://example.com/paid")
            try:
                assert started.wait(1)
                second = pool.submit(clients[1].get, "https://example.com/paid")
                assert second.result(timeout=2).status_code == 200
            finally:
                release.set()
            assert first.result(timeout=2).status_code == 200
    finally:
        release.set()
        handle.disable()
        for client in clients:
            client.close()
        runtime.close()

    assert [len(requests) for requests in request_sets] == [2, 2]
    assert method.create_credential.call_count == 2


def test_bare_thread_fails_closed_with_multiple_runtimes() -> None:
    methods = [MockMethod("a"), MockMethod("b")]
    runtimes = [PaymentRuntime([method]) for method in methods]
    handles = [instrument(runtime, mcp=False) for runtime in runtimes]
    requests: list[httpx.Request] = []
    client = httpx.Client(transport=paid_transport(requests))
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(client.get("https://example.com/paid").status_code)
    )
    try:
        thread.start()
        thread.join(timeout=2)
    finally:
        for handle in handles:
            handle.disable()
        client.close()
        for runtime in runtimes:
            runtime.close()

    assert result == [402]
    assert len(requests) == 1
    assert all(method.create_credential.call_count == 0 for method in methods)


def test_out_of_order_disable_restores_exact_originals() -> None:
    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send
    thread_start = threading.Thread.start
    runtimes = [PaymentRuntime([MockMethod("a")]), PaymentRuntime([MockMethod("b")])]
    first = instrument(runtimes[0], mcp=False)
    second = instrument(runtimes[1], mcp=False)

    first.disable()
    assert httpx.Client.send is not sync_send
    second.disable()

    assert httpx.Client.send is sync_send
    assert httpx.AsyncClient.send is async_send
    assert threading.Thread.start is thread_start
    for runtime in runtimes:
        runtime.close()


def test_disable_does_not_overwrite_a_later_patch() -> None:
    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send
    runtime = PaymentRuntime([MockMethod("one")])
    handle = instrument(runtime, mcp=False)

    def replacement(self: httpx.Client, request: httpx.Request, **kwargs: Any):
        return sync_send(self, request, **kwargs)

    httpx.Client.send = replacement
    try:
        handle.disable()
        assert httpx.Client.send is replacement
        assert httpx.AsyncClient.send is async_send
    finally:
        httpx.Client.send = sync_send
        runtime.close()


@pytest.mark.asyncio
async def test_explicit_sync_and_async_wrappers_take_precedence() -> None:
    explicit_method = MockMethod("explicit")
    global_method = MockMethod("global")
    explicit_runtime = PaymentRuntime([explicit_method])
    global_runtime = PaymentRuntime([global_method])
    sync_requests: list[httpx.Request] = []
    async_requests: list[httpx.Request] = []
    handle = instrument(global_runtime, mcp=False)
    sync_client = explicit_runtime.wrap_client(
        httpx.Client(transport=paid_transport(sync_requests))
    )
    async_client = explicit_runtime.wrap_async_client(
        httpx.AsyncClient(transport=paid_transport(async_requests))
    )
    try:
        assert sync_client.get("https://example.com/sync").status_code == 200
        assert (await async_client.get("https://example.com/async")).status_code == 200
    finally:
        handle.disable()
        sync_client.close()
        await async_client.aclose()
        explicit_runtime.close()
        global_runtime.close()

    assert explicit_method.create_credential.call_count == 2
    global_method.create_credential.assert_not_called()
    assert len(sync_requests) == len(async_requests) == 2


def test_credential_http_is_not_recursively_instrumented() -> None:
    internal_requests: list[httpx.Request] = []
    internal_statuses: list[int] = []

    def internal_handler(request: httpx.Request) -> httpx.Response:
        internal_requests.append(request)
        return payment_required()

    class HttpMethod(MockMethod):
        async def _create(self, challenge: Challenge):
            if self.create_credential.call_count == 1:

                def request() -> None:
                    with httpx.Client(transport=httpx.MockTransport(internal_handler)) as client:
                        internal_statuses.append(client.get("https://rpc.example.com").status_code)

                thread = threading.Thread(target=request)
                thread.start()
                thread.join(timeout=2)
                assert thread.is_alive() is False
            return await super()._create(challenge)

    method = HttpMethod("one")
    runtime = PaymentRuntime([method])
    requests: list[httpx.Request] = []
    client = runtime.wrap_client(httpx.Client(transport=paid_transport(requests)))
    handle = instrument(runtime, mcp=False)
    try:
        assert client.get("https://example.com/paid").status_code == 200
    finally:
        handle.disable()
        client.close()
        runtime.close()

    assert len(internal_requests) == 1
    assert internal_statuses == [402]
    assert method.create_credential.call_count == 1


class FakeMcpError(Exception):
    def __init__(self) -> None:
        self.code = -32042
        self.data = {
            "challenges": [
                {
                    "id": "test-id",
                    "realm": "example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": {},
                }
            ]
        }


class FakeSession:
    def __init__(self, results: list[Any]) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        self.calls.append(kwargs)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.asyncio
async def test_credential_thread_is_not_recursively_instrumented_for_mcp_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp

    monkeypatch.setattr(mcp, "ClientSession", FakeSession)
    internal = FakeSession([FakeMcpError()])
    internal_results: list[str] = []

    class ThreadedMethod(MockMethod):
        async def _create(self, challenge: Challenge):
            def call() -> None:
                try:
                    asyncio.run(internal.call_tool("internal"))
                except FakeMcpError:
                    internal_results.append("unpaid")

            thread = threading.Thread(target=call)
            thread.start()
            thread.join(timeout=2)
            assert thread.is_alive() is False
            return await super()._create(challenge)

    method = ThreadedMethod("one")
    runtime = PaymentRuntime([method])
    paid_result = object()
    session = FakeSession([FakeMcpError(), paid_result])
    handle = instrument(runtime, httpx=False, mcp=True)
    try:
        result = await session.call_tool("paid")
    finally:
        handle.disable()
        runtime.close()

    assert result is paid_result
    assert internal_results == ["unpaid"]
    assert len(internal.calls) == 1


@pytest.mark.asyncio
async def test_mcp_instrumentation_preserves_shape_and_explicit_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp

    monkeypatch.setattr(mcp, "ClientSession", FakeSession)
    global_method = MockMethod("global")
    explicit_method = MockMethod("explicit")
    global_runtime = PaymentRuntime([global_method])
    explicit_runtime = PaymentRuntime([explicit_method])
    handle = instrument(global_runtime, httpx=False, mcp=True)
    raw_result = object()
    raw_session = FakeSession([FakeMcpError(), raw_result])
    explicit_result = object()
    explicit_session = FakeSession([FakeMcpError(), explicit_result])
    try:
        result = await raw_session.call_tool("paid", meta={"trace": "abc"})
        wrapped = await McpClient(explicit_session, runtime=explicit_runtime).call_tool("paid")
    finally:
        handle.disable()
        global_runtime.close()
        explicit_runtime.close()

    assert result is raw_result
    assert raw_session.calls[1]["meta"]["trace"] == "abc"
    assert META_CREDENTIAL in raw_session.calls[1]["meta"]
    assert wrapped.result is explicit_result
    assert global_method.create_credential.call_count == 1
    assert explicit_method.create_credential.call_count == 1


def test_required_mcp_failure_is_transactional(monkeypatch: pytest.MonkeyPatch) -> None:
    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send
    real_import = builtins.__import__

    def missing_mcp(name: str, *args: Any, **kwargs: Any):
        if name == "mcp":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_mcp)
    runtime = PaymentRuntime([])
    try:
        with pytest.raises(ImportError, match="Cannot instrument MCP"):
            instrument(runtime, mcp=True)
    finally:
        runtime.close()

    assert httpx.Client.send is sync_send
    assert httpx.AsyncClient.send is async_send


def test_mcp_patch_failure_is_transactional(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp

    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send

    class FrozenSessionMeta(type):
        def __setattr__(cls, name: str, value: Any) -> None:
            if name == "call_tool":
                raise RuntimeError("frozen")
            super().__setattr__(name, value)

    class FrozenSession(metaclass=FrozenSessionMeta):
        async def call_tool(self, name: str) -> Any:
            return name

    monkeypatch.setattr(mcp, "ClientSession", FrozenSession)
    runtime = PaymentRuntime([])
    try:
        with pytest.raises(RuntimeError, match="frozen"):
            instrument(runtime, mcp=True)
    finally:
        runtime.close()

    assert httpx.Client.send is sync_send
    assert httpx.AsyncClient.send is async_send
