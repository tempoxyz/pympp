"""Tests for scoped HTTPX payment instrumentation."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from typing import Any

import httpx
import pytest

import mpp.instrumentation as instrumentation
from mpp import Challenge, Credential
from mpp.instrumentation import HttpxCompatibilityError, instrument
from mpp.runtime import PaymentRuntime


class Method:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.calls = 0
        self.on_create: Any | None = None

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.calls += 1
        if self.on_create is not None:
            result = self.on_create()
            if asyncio.iscoroutine(result):
                await result
        return Credential(challenge=challenge.to_echo(), payload={"call": self.calls})


def payment_required(challenge_id: str = "test-id") -> httpx.Response:
    challenge = Challenge(
        id=challenge_id,
        method="tempo",
        intent="charge",
        request={"amount": "1000"},
    )
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
    )


def paid_handler(request: httpx.Request) -> httpx.Response:
    if "authorization" in request.headers:
        return httpx.Response(200, content=b"paid")
    return payment_required(request.url.path)


@pytest.fixture(autouse=True)
def restore_instrumentation():
    originals = (
        httpx.Client._send_single_request,
        httpx.AsyncClient._send_single_request,
        httpx.Client.send,
        httpx.AsyncClient.send,
        threading.Thread.start,
        ThreadPoolExecutor.submit,
    )
    bindings_token = instrumentation._bindings.set(None)
    active_token = instrumentation._httpx_active.set(False)
    internal_token = instrumentation._payment_internal_work.set(None)
    instrumentation._payment_worker_state.internal = None
    yield
    (
        httpx.Client._send_single_request,
        httpx.AsyncClient._send_single_request,
        httpx.Client.send,
        httpx.AsyncClient.send,
        threading.Thread.start,
        ThreadPoolExecutor.submit,
    ) = originals
    instrumentation._bindings.reset(bindings_token)
    instrumentation._httpx_active.reset(active_token)
    instrumentation._payment_internal_work.reset(internal_token)
    instrumentation._payment_worker_state.internal = None
    instrumentation._state.bindings = []
    instrumentation._state.httpx_patches = ()
    instrumentation._state.worker_patches = ()


def test_sync_instrumentation_covers_existing_and_future_clients() -> None:
    method = Method()
    runtime = PaymentRuntime([method])
    existing = httpx.Client(transport=httpx.MockTransport(paid_handler))
    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit
    try:
        with instrument(runtime, allow_unrestricted=True):
            assert threading.Thread.start is original_thread_start
            assert ThreadPoolExecutor.submit is original_executor_submit
            assert existing.get("https://example.com/existing").status_code == 200
            with httpx.Client(transport=httpx.MockTransport(paid_handler)) as future:
                assert future.get("https://example.com/future").status_code == 200
    finally:
        existing.close()
        runtime.close()

    assert method.calls == 2


@pytest.mark.asyncio
async def test_async_instrumentation_preserves_response_hooks() -> None:
    seen: list[int] = []

    async def hook(response: httpx.Response) -> None:
        seen.append(response.status_code)
        response.raise_for_status()

    runtime = PaymentRuntime([Method()])
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(paid_handler),
        event_hooks={"response": [hook]},
    )
    try:
        with instrument(runtime, allow_unrestricted=True):
            response = await client.get("https://example.com/paid")
    finally:
        await client.aclose()
        await runtime.aclose()

    assert response.content == b"paid"
    assert seen == [200]


def test_process_scope_reaches_workers_but_context_scope_does_not() -> None:
    method = Method()
    runtime = PaymentRuntime([method])

    def run(result: list[int]) -> None:
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            result.append(client.get("https://example.com/paid").status_code)

    context_result: list[int] = []
    with instrument(runtime, allow_unrestricted=True):
        thread = threading.Thread(target=run, args=(context_result,))
        thread.start()
        thread.join()

    process_result: list[int] = []
    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit
    with instrument(runtime, scope="process", allow_unrestricted=True):
        assert threading.Thread.start is not original_thread_start
        assert ThreadPoolExecutor.submit is not original_executor_submit
        thread = threading.Thread(target=run, args=(process_result,))
        thread.start()
        thread.join()
    runtime.close()

    assert context_result == [402]
    assert process_result == [200]
    assert method.calls == 1


def test_ambiguous_process_bindings_fail_closed() -> None:
    methods = [Method(), Method()]
    runtimes = [PaymentRuntime([method]) for method in methods]
    handles = [
        instrument(runtime, scope="process", allow_unrestricted=True) for runtime in runtimes
    ]
    result: list[int] = []
    copied = copy_context()

    assert instrumentation._select_runtime() is None
    assert copied.run(instrumentation._select_runtime) is None

    def run() -> None:
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            result.append(client.get("https://example.com/paid").status_code)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    for handle in handles:
        handle.disable()
    for runtime in runtimes:
        runtime.close()

    assert result == [402]
    assert [method.calls for method in methods] == [0, 0]


def test_nested_bindings_choose_innermost_and_restore_patches() -> None:
    originals = (
        httpx.Client._send_single_request,
        httpx.AsyncClient._send_single_request,
        httpx.Client.send,
        httpx.AsyncClient.send,
        threading.Thread.start,
        ThreadPoolExecutor.submit,
    )
    methods = [Method(), Method()]
    runtimes = [PaymentRuntime([method]) for method in methods]
    outer = instrument(runtimes[0], allow_unrestricted=True)
    patched = httpx.Client._send_single_request
    inner = instrument(runtimes[1], scope="process", allow_unrestricted=True)
    try:
        assert threading.Thread.start is not originals[4]
        assert ThreadPoolExecutor.submit is not originals[5]
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            assert client.get("https://example.com/inner").status_code == 200
        inner.disable()
        assert threading.Thread.start is originals[4]
        assert ThreadPoolExecutor.submit is originals[5]
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            assert client.get("https://example.com/outer").status_code == 200
        assert httpx.Client._send_single_request is patched
    finally:
        outer.disable()
        for runtime in runtimes:
            runtime.close()

    assert [method.calls for method in methods] == [1, 1]
    assert (
        httpx.Client._send_single_request,
        httpx.AsyncClient._send_single_request,
        httpx.Client.send,
        httpx.AsyncClient.send,
        threading.Thread.start,
        ThreadPoolExecutor.submit,
    ) == originals


def test_disable_does_not_overwrite_later_patch() -> None:
    runtime = PaymentRuntime([])
    handle = instrument(runtime, allow_unrestricted=True)

    def replacement(self: httpx.Client, request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, request=request)

    httpx.Client._send_single_request = replacement
    handle.disable()
    runtime.close()

    assert httpx.Client._send_single_request is replacement


def test_method_http_is_not_recursively_instrumented() -> None:
    paths: list[str] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path in {"/event", "/method"}:
            return httpx.Response(204)
        return paid_handler(request)

    def send_internal(path: str) -> None:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            assert client.get(f"https://example.com/{path}").status_code == 204

    method.on_create = lambda: send_internal("method")
    runtime = PaymentRuntime([method])
    runtime.events.on("challenge.received", lambda _payload: send_internal("event"))
    try:
        with instrument(runtime, allow_unrestricted=True):
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                assert client.get("https://example.com/paid").status_code == 200
    finally:
        runtime.close()

    assert paths == ["/paid", "/event", "/method", "/paid"]


def test_runtime_callbacks_are_not_recursively_instrumented() -> None:
    statuses: list[int] = []

    def send(path: str) -> None:
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            statuses.append(client.get(f"https://example.com/{path}").status_code)

    class ManagedMethod(Method):
        async def __aenter__(self) -> ManagedMethod:
            send("enter")
            return self

        async def __aexit__(self, *_args: Any) -> None:
            send("exit")

    runtime = PaymentRuntime(method_factories=[ManagedMethod])
    runtime.events.on("test", lambda _payload: send("event"))
    with instrument(runtime, scope="process", allow_unrestricted=True):
        try:
            runtime.start()
            runtime.emit_event_sync("test", {})
        finally:
            runtime.close()

    assert statuses == [402, 402, 402]


def test_response_hook_nested_send_has_an_independent_payment_budget() -> None:
    method = Method()
    runtime = PaymentRuntime([method])
    inner = httpx.Client(transport=httpx.MockTransport(paid_handler))

    def hook(_response: httpx.Response) -> None:
        assert inner.get("https://example.com/inner").status_code == 200

    outer = httpx.Client(
        transport=httpx.MockTransport(paid_handler),
        event_hooks={"response": [hook]},
    )
    try:
        with instrument(runtime, allow_unrestricted=True):
            response = outer.get("https://example.com/outer")
    finally:
        outer.close()
        inner.close()
        runtime.close()

    assert response.content == b"paid"
    assert method.calls == 2


def test_process_scope_suppresses_raw_method_threads() -> None:
    method = Method()
    internal_statuses: list[int] = []

    def on_create() -> None:
        def request() -> None:
            with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
                internal_statuses.append(client.get("https://example.com/internal").status_code)

        thread = threading.Thread(target=request)
        thread.start()
        thread.join()

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
                assert client.get("https://example.com/outer").status_code == 200
    finally:
        runtime.close()

    assert internal_statuses == [402]
    assert method.calls == 1


def test_executor_suppression_ends_with_payment_flow() -> None:
    method = Method()
    internal_statuses: list[int] = []

    def send(path: str) -> int:
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            return client.get(f"https://example.com/{path}").status_code

    async def on_create() -> None:
        if method.calls == 1:
            internal_statuses.append(
                await asyncio.get_running_loop().run_in_executor(executor, send, "internal")
            )

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(lambda: None).result()
        try:
            with instrument(runtime, scope="process", allow_unrestricted=True):
                assert send("outer") == 200
                assert executor.submit(send, "unrelated").result() == 200
        finally:
            runtime.close()

    assert internal_statuses == [402]
    assert method.calls == 2


def test_to_thread_worker_is_not_permanently_internal() -> None:
    method = Method()
    executor: ThreadPoolExecutor | None = None
    internal_statuses: list[int] = []

    def send(path: str) -> int:
        with httpx.Client(transport=httpx.MockTransport(paid_handler)) as client:
            return client.get(f"https://example.com/{path}").status_code

    async def on_create() -> None:
        nonlocal executor
        if method.calls == 1:
            executor = ThreadPoolExecutor(max_workers=1)
            asyncio.get_running_loop().set_default_executor(executor)
            internal_statuses.append(await asyncio.to_thread(send, "internal"))

    async def send_from_copied_context() -> int:
        assert executor is not None
        asyncio.get_running_loop().set_default_executor(executor)
        return await asyncio.to_thread(send, "unrelated")

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            assert send("outer") == 200
            assert asyncio.run(send_from_copied_context()) == 200
    finally:
        runtime.close()
        if executor is not None:
            executor.shutdown()

    assert internal_statuses == [402]
    assert method.calls == 2


def test_executor_patch_accepts_opaque_callables() -> None:
    class OpaqueCallable:
        __slots__ = ()

        def __call__(self) -> int:
            return 42

    runtime = PaymentRuntime([])
    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            with ThreadPoolExecutor(max_workers=1) as executor:
                assert executor.submit(OpaqueCallable()).result() == 42
    finally:
        runtime.close()


def test_stale_context_falls_back_to_active_process_binding() -> None:
    stale_runtime = PaymentRuntime([])
    stale_handle = instrument(stale_runtime, allow_unrestricted=True)
    stale_context = copy_context()
    stale_handle.disable()

    method = Method()
    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(paid_handler))
    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            response = stale_context.run(client.get, "https://example.com/paid")
    finally:
        client.close()
        runtime.close()
        stale_runtime.close()

    assert response.status_code == 200
    assert method.calls == 1


@pytest.mark.parametrize("scope", ["invalid", "", "PROCESS"])
def test_invalid_scope_fails_without_patching(scope: str) -> None:
    original = httpx.Client._send_single_request
    runtime = PaymentRuntime([])
    with pytest.raises(ValueError, match="scope"):
        instrument(runtime, scope=scope)  # type: ignore[arg-type]
    runtime.close()
    assert httpx.Client._send_single_request is original


def test_unrestricted_runtime_requires_explicit_opt_in() -> None:
    original = httpx.Client._send_single_request
    runtime = PaymentRuntime([])
    with pytest.raises(ValueError, match="allow_unrestricted=True"):
        instrument(runtime)
    assert httpx.Client._send_single_request is original

    with instrument(runtime, allow_unrestricted=True):
        assert httpx.Client._send_single_request is not original
    runtime.close()
    assert httpx.Client._send_single_request is original


def test_reinstrument_fails_if_active_patch_was_replaced() -> None:
    runtime = PaymentRuntime([])
    handle = instrument(runtime, allow_unrestricted=True)
    installed_send = httpx.Client.send

    def replacement(
        self: httpx.Client,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        return installed_send(self, request, *args, **kwargs)

    httpx.Client.send = replacement  # type: ignore[method-assign]
    try:
        with pytest.raises(HttpxCompatibilityError, match="was replaced"):
            instrument(runtime, allow_unrestricted=True)
    finally:
        httpx.Client.send = installed_send  # type: ignore[method-assign]
        handle.disable()
        runtime.close()
