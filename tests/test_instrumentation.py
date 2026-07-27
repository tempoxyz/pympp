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
from mpp.client import PaymentTransport
from mpp.errors import PaymentOutcomeUnknownError
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


@pytest.fixture(autouse=True)
def restore_instrumentation():
    sync_send_single = httpx.Client._send_single_request
    async_send_single = httpx.AsyncClient._send_single_request
    sync_send = httpx.Client.send
    async_send = httpx.AsyncClient.send
    thread_start = threading.Thread.start
    executor_submit = ThreadPoolExecutor.submit
    token = instrumentation._bindings.set(None)
    active_token = instrumentation._httpx_active.set(False)
    internal_token = instrumentation._payment_internal_work.set(None)
    instrumentation._payment_worker_state.internal = None
    yield
    httpx.Client._send_single_request = sync_send_single
    httpx.AsyncClient._send_single_request = async_send_single
    httpx.Client.send = sync_send
    httpx.AsyncClient.send = async_send
    threading.Thread.start = thread_start
    ThreadPoolExecutor.submit = executor_submit
    instrumentation._bindings.reset(token)
    instrumentation._httpx_active.reset(active_token)
    instrumentation._payment_internal_work.reset(internal_token)
    instrumentation._payment_worker_state.internal = None
    instrumentation._state.bindings = []
    instrumentation._state.patches = ()
    assert threading.Thread.start is thread_start
    assert ThreadPoolExecutor.submit is executor_submit


def test_global_sync_instrumentation_covers_existing_and_future_clients() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required(f"challenge-{len(requests)}")

    method = Method()
    runtime = PaymentRuntime([method])
    existing = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            first = existing.get("https://example.com/paid")
            assert first.read() == b"paid"
            first.close()
            with httpx.Client(transport=httpx.MockTransport(handler)) as future:
                assert future.get("https://example.com/paid").status_code == 200
    finally:
        existing.close()
        runtime.close()

    assert method.calls == 2
    assert [request.headers.get("authorization") is not None for request in requests] == [
        False,
        True,
        False,
        True,
    ]


@pytest.mark.asyncio
async def test_global_async_instrumentation_and_response_hooks() -> None:
    requests: list[httpx.Request] = []
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required()

    async def hook(response: httpx.Response) -> None:
        seen.append(response.status_code)
        response.raise_for_status()

    runtime = PaymentRuntime([Method()])
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"response": [hook]},
    )
    try:
        with instrument(runtime, allow_unrestricted=True):
            response = await client.get("https://example.com/paid")
    finally:
        await client.aclose()
        await runtime.aclose()

    assert response.content == b"paid"
    assert len(requests) == 2
    assert seen == [200]


def test_process_scope_reaches_workers_but_context_scope_does_not() -> None:
    method = Method()
    runtime = PaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required()

    def run(result: list[int]) -> None:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result.append(client.get("https://example.com/paid").status_code)

    context_result: list[int] = []
    with instrument(runtime, allow_unrestricted=True):
        thread = threading.Thread(target=run, args=(context_result,))
        thread.start()
        thread.join()
    assert context_result == [402]

    process_result: list[int] = []
    with instrument(runtime, scope="process", allow_unrestricted=True):
        thread = threading.Thread(target=run, args=(process_result,))
        thread.start()
        thread.join()
    runtime.close()

    assert process_result == [200]
    assert method.calls == 1


def test_ambiguous_process_bindings_fail_closed() -> None:
    methods = [Method(), Method()]
    runtimes = [PaymentRuntime([method]) for method in methods]
    handles = [
        instrument(runtime, scope="process", allow_unrestricted=True) for runtime in runtimes
    ]
    result: list[int] = []

    def run() -> None:
        with httpx.Client(transport=httpx.MockTransport(lambda _: payment_required())) as client:
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


def test_nested_bindings_choose_innermost_and_restore_exactly() -> None:
    original_sync = httpx.Client._send_single_request
    original_async = httpx.AsyncClient._send_single_request
    original_sync_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send
    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit
    methods = [Method(), Method()]
    runtimes = [PaymentRuntime([method]) for method in methods]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required(f"challenge-{request.url.path}")

    first = instrument(runtimes[0], allow_unrestricted=True)
    patched_sync = httpx.Client._send_single_request
    second = instrument(runtimes[1], allow_unrestricted=True)
    try:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            assert client.get("https://example.com/inner").status_code == 200
        second.disable()
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            assert client.get("https://example.com/outer").status_code == 200
        assert httpx.Client._send_single_request is patched_sync
    finally:
        first.disable()
        for runtime in runtimes:
            runtime.close()

    assert [method.calls for method in methods] == [1, 1]
    assert httpx.Client._send_single_request is original_sync
    assert httpx.AsyncClient._send_single_request is original_async
    assert httpx.Client.send is original_sync_send
    assert httpx.AsyncClient.send is original_async_send
    assert threading.Thread.start is original_thread_start
    assert ThreadPoolExecutor.submit is original_executor_submit


def test_disabling_does_not_overwrite_a_later_third_party_patch() -> None:
    original_async = httpx.AsyncClient._send_single_request
    runtime = PaymentRuntime([])
    handle = instrument(runtime, allow_unrestricted=True)

    def replacement(self: httpx.Client, request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, request=request)

    httpx.Client._send_single_request = replacement
    handle.disable()
    runtime.close()

    assert httpx.Client._send_single_request is replacement
    assert httpx.AsyncClient._send_single_request is original_async


def test_method_http_is_not_recursively_instrumented() -> None:
    requests: list[str] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.path == "/method":
            return httpx.Response(204)
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required()

    def on_create() -> None:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            assert client.get("https://example.com/method").status_code == 204

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    try:
        with instrument(runtime, allow_unrestricted=True):
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                assert client.get("https://example.com/paid").status_code == 200
    finally:
        runtime.close()

    assert requests == [
        "https://example.com/paid",
        "https://example.com/method",
        "https://example.com/paid",
    ]


def test_raw_method_thread_is_marked_internal_for_process_scope() -> None:
    method = Method()
    internal_requests: list[httpx.Request] = []
    internal_statuses: list[int] = []

    def internal_handler(request: httpx.Request) -> httpx.Response:
        internal_requests.append(request)
        return payment_required("internal")

    def on_create() -> None:
        def request() -> None:
            with httpx.Client(transport=httpx.MockTransport(internal_handler)) as client:
                internal_statuses.append(client.get("https://example.com/internal").status_code)

        thread = threading.Thread(target=request)
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()

    method.on_create = on_create

    def outer_handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required("outer")

    runtime = PaymentRuntime([method])
    with httpx.Client(transport=httpx.MockTransport(outer_handler)) as client:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            assert client.get("https://example.com/paid").status_code == 200
    runtime.close()

    assert len(internal_requests) == 1
    assert internal_statuses == [402]
    assert method.calls == 1


def test_prestarted_executor_work_is_suppressed_only_during_payment_flow() -> None:
    method = Method()
    internal_statuses: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required(request.url.path)

    def send(path: str) -> int:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.get(f"https://example.com/{path}").status_code

    async def on_create() -> None:
        if method.calls == 1:
            loop = asyncio.get_running_loop()
            internal_statuses.append(await loop.run_in_executor(executor, send, "internal"))

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    with ThreadPoolExecutor(max_workers=1) as executor:
        # Ensure payment handling cannot rely on marking a newly-created worker.
        executor.submit(lambda: None).result()
        try:
            with instrument(runtime, scope="process", allow_unrestricted=True):
                assert send("outer") == 200
                # The same worker must become payment-aware again after the
                # internal unit of work returns.
                assert executor.submit(send, "unrelated").result() == 200
        finally:
            runtime.close()

    assert internal_statuses == [402]
    assert method.calls == 2


def test_executor_started_during_payment_flow_is_not_permanently_internal() -> None:
    method = Method()
    executor: ThreadPoolExecutor | None = None
    internal_statuses: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required(request.url.path)

    def send(path: str) -> int:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.get(f"https://example.com/{path}").status_code

    async def on_create() -> None:
        nonlocal executor
        if method.calls == 1:
            executor = ThreadPoolExecutor(max_workers=1)
            loop = asyncio.get_running_loop()
            internal_statuses.append(await loop.run_in_executor(executor, send, "internal"))

    method.on_create = on_create
    runtime = PaymentRuntime([method])
    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            assert send("outer") == 200
            assert executor is not None
            assert executor.submit(send, "unrelated").result() == 200
    finally:
        if executor is not None:
            executor.shutdown()
        runtime.close()

    assert internal_statuses == [402]
    assert method.calls == 2


def test_marked_executor_worker_allows_later_normal_to_thread_work() -> None:
    method = Method()
    executor: ThreadPoolExecutor | None = None
    internal_statuses: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return payment_required(request.url.path)

    def send(path: str) -> int:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
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


def test_executor_patch_accepts_opaque_callable_objects() -> None:
    class OpaqueCallable:
        __slots__ = ()

        def __getattribute__(self, name: str) -> Any:
            if name == "__dict__":
                return None
            return super().__getattribute__(name)

        def __call__(self) -> int:
            return 42

    runtime = PaymentRuntime([])
    try:
        with instrument(runtime, allow_unrestricted=True):
            with ThreadPoolExecutor(max_workers=1) as executor:
                assert executor.submit(OpaqueCallable()).result() == 42
    finally:
        runtime.close()


def test_paid_send_loss_blocks_outer_retry_from_minting_again() -> None:
    requests: list[httpx.Request] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return payment_required("first")
        if len(requests) == 2:
            raise httpx.ReadTimeout("paid response lost", request=request)
        return payment_required("outer-retry")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(PaymentOutcomeUnknownError) as first:
                client.get("https://example.com/paid")
            with pytest.raises(PaymentOutcomeUnknownError) as second:
                client.get("https://example.com/paid")
    finally:
        client.close()
        runtime.close()

    assert isinstance(first.value.__cause__, httpx.ReadTimeout)
    assert isinstance(second.value.cause, httpx.ReadTimeout)
    assert len(requests) == 3
    assert method.calls == 1


class BrokenStream(httpx.SyncByteStream):
    def __iter__(self):
        raise httpx.ReadError("body lost")
        yield b""  # pragma: no cover


def test_paid_stream_failure_blocks_outer_retry() -> None:
    requests: list[httpx.Request] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return payment_required("first")
        if len(requests) == 2:
            return httpx.Response(200, stream=BrokenStream())
        return payment_required("outer-retry")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(httpx.ReadError, match="body lost"):
                client.get("https://example.com/paid")
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get("https://example.com/paid")
    finally:
        client.close()
        runtime.close()

    assert len(requests) == 3
    assert method.calls == 1


def test_paid_server_error_blocks_outer_retry() -> None:
    requests: list[httpx.Request] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return payment_required("first")
        if len(requests) == 2:
            return httpx.Response(503, content=b"unknown")
        return payment_required("outer-retry")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            assert client.get("https://example.com/paid").status_code == 503
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get("https://example.com/paid")
    finally:
        client.close()
        runtime.close()

    assert len(requests) == 3
    assert method.calls == 1


def test_paid_redirect_to_another_402_does_not_mint_again() -> None:
    requests: list[httpx.Request] = []
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/start":
            if "authorization" not in request.headers:
                return payment_required("first")
            return httpx.Response(302, headers={"location": "/next"})
        return payment_required("second")

    runtime = PaymentRuntime([method])
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get("https://example.com/start")
    finally:
        client.close()
        runtime.close()

    assert method.calls == 1
    assert [(request.url.path, "authorization" in request.headers) for request in requests] == [
        ("/start", False),
        ("/start", True),
        ("/next", False),
    ]


def test_response_hook_failure_after_read_blocks_idempotent_retry() -> None:
    requests: list[httpx.Request] = []
    method = Method()
    hook_calls = 0
    challenge_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number
        requests.append(request)
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        challenge_number += 1
        return payment_required(f"challenge-{challenge_number}")

    def hook(response: httpx.Response) -> None:
        nonlocal hook_calls
        hook_calls += 1
        response.read()
        if hook_calls == 1:
            raise RuntimeError("consumer failed after reading paid response")

    runtime = PaymentRuntime([method])
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        event_hooks={"response": [hook]},
    )
    headers = {"Idempotency-Key": "hook-operation"}
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(RuntimeError, match="consumer failed"):
                client.get("https://example.com/paid", headers=headers)
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get("https://example.com/paid", headers=headers)
    finally:
        client.close()
        runtime.close()

    assert hook_calls == 1
    assert method.calls == 1
    assert len(requests) == 3


def test_response_hook_nested_send_has_an_independent_payment_budget() -> None:
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, content=request.url.path.encode())
        return payment_required(f"challenge-{request.url.path}")

    runtime = PaymentRuntime([method])
    inner = httpx.Client(transport=httpx.MockTransport(handler))

    def hook(_response: httpx.Response) -> None:
        assert inner.get("https://example.com/inner").status_code == 200

    outer = httpx.Client(
        transport=httpx.MockTransport(handler),
        event_hooks={"response": [hook]},
    )
    try:
        with instrument(runtime, allow_unrestricted=True):
            response = outer.get("https://example.com/outer")
    finally:
        outer.close()
        inner.close()
        runtime.close()

    assert response.content == b"/outer"
    assert method.calls == 2


@pytest.mark.asyncio
async def test_concurrent_identical_requests_with_distinct_challenges_both_pay() -> None:
    requests: list[httpx.Request] = []
    method = Method()
    challenge_number = 0

    async def delay_credential() -> None:
        await asyncio.sleep(0.05)

    method.on_create = delay_credential

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number
        requests.append(request)
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        challenge_number += 1
        return payment_required(f"challenge-{challenge_number}")

    runtime = PaymentRuntime([method])
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            first, second = await asyncio.gather(
                client.get("https://example.com/identical"),
                client.get("https://example.com/identical"),
            )
    finally:
        await client.aclose()
        await runtime.aclose()

    assert first.status_code == second.status_code == 200
    assert challenge_number == method.calls == 2
    assert len(requests) == 4


@pytest.mark.asyncio
async def test_direct_transport_nested_calls_use_independent_operations() -> None:
    release = asyncio.Event()
    background: asyncio.Task[httpx.Response] | None = None
    nested_response: httpx.Response | None = None
    method = Method()

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, content=request.url.path.encode())
        return payment_required(f"challenge-{request.url.path}")

    runtime = PaymentRuntime([method])
    inner = httpx.AsyncClient(
        transport=PaymentTransport(
            inner=httpx.MockTransport(handler),
            runtime=runtime,
        )
    )

    async def hook(_response: httpx.Response) -> None:
        nonlocal background, nested_response

        nested_response = await inner.get("https://example.com/inner")

        async def send_later() -> httpx.Response:
            await release.wait()
            return await inner.get("https://example.com/background")

        background = asyncio.create_task(send_later())

    outer = runtime.wrap_async_client(
        httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            event_hooks={"response": [hook]},
        )
    )
    try:
        response = await outer.get("https://example.com/outer")
        assert nested_response is not None
        assert background is not None
        release.set()
        background_response = await background
    finally:
        await outer.aclose()
        await inner.aclose()
        await runtime.aclose()

    assert response.content == b"/outer"
    assert nested_response.content == b"/inner"
    assert background_response.content == b"/background"
    assert method.calls == 3


def test_concurrent_requests_with_same_idempotency_key_pay_once() -> None:
    barrier = threading.Barrier(2)
    first_request_finished = threading.Event()
    counter_lock = threading.Lock()
    challenge_number = 0
    paid_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number, paid_requests
        if "authorization" in request.headers:
            with counter_lock:
                paid_requests += 1
            return httpx.Response(200, content=b"paid")
        with counter_lock:
            challenge_number += 1
            challenge_id = f"challenge-{challenge_number}"
        barrier.wait(timeout=1)
        if challenge_id == "challenge-2":
            assert first_request_finished.wait(timeout=5)
        return payment_required(challenge_id)

    method = Method()
    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))

    def send() -> httpx.Response:
        response = client.post(
            "https://example.com/paid",
            content=b"same",
            headers={"Idempotency-Key": "same-operation"},
        )
        first_request_finished.set()
        return response

    try:
        with instrument(runtime, scope="process", allow_unrestricted=True):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(send) for _ in range(2)]
                outcomes: list[httpx.Response | PaymentOutcomeUnknownError] = []
                for future in futures:
                    try:
                        outcomes.append(future.result())
                    except PaymentOutcomeUnknownError as error:
                        outcomes.append(error)
            assert not runtime._http_active_idempotent_operations
            assert not runtime._http_idempotent_operations
    finally:
        client.close()
        runtime.close()

    assert sum(isinstance(item, httpx.Response) for item in outcomes) == 1
    assert sum(isinstance(item, PaymentOutcomeUnknownError) for item in outcomes) == 1
    assert method.calls == paid_requests == 1


@pytest.mark.asyncio
async def test_cancellation_before_credential_send_does_not_poison_retry() -> None:
    requests: list[httpx.Request] = []
    started = threading.Event()
    cancelled = threading.Event()
    method = Method()

    async def block_credential() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    method.on_create = block_credential

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        return payment_required("same-challenge")

    runtime = PaymentRuntime([method])
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            task = asyncio.create_task(client.get("https://example.com/cancel"))
            assert await asyncio.to_thread(started.wait, 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await asyncio.to_thread(cancelled.wait, 1)

            method.on_create = None
            response = await client.get("https://example.com/cancel")
    finally:
        await client.aclose()
        await runtime.aclose()

    assert response.status_code == 200
    assert method.calls == 2
    assert ["authorization" in request.headers for request in requests] == [
        False,
        False,
        True,
    ]


def test_unknown_attempt_is_not_evicted_after_256_others() -> None:
    method = Method()
    challenge_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number
        if "authorization" in request.headers:
            raise httpx.ReadTimeout("paid response lost", request=request)
        challenge_number += 1
        return payment_required(f"challenge-{challenge_number}")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))

    def lose_response(key: str) -> None:
        with pytest.raises(PaymentOutcomeUnknownError):
            client.get(
                "https://example.com/paid",
                headers={"Idempotency-Key": key},
            )

    try:
        with instrument(runtime, allow_unrestricted=True):
            lose_response("victim")
            for index in range(256):
                lose_response(f"filler-{index}")
            calls_before_retry = method.calls
            lose_response("victim")
    finally:
        client.close()
        runtime.close()

    assert calls_before_retry == 257
    assert method.calls == calls_before_retry


def test_idempotency_key_scopes_unknown_outcome_protection() -> None:
    method = Method()
    challenge_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number
        if "authorization" in request.headers:
            if request.headers["idempotency-key"] == "operation-a":
                raise httpx.ReadTimeout("paid response lost", request=request)
            return httpx.Response(200, content=b"paid")
        challenge_number += 1
        return payment_required(f"challenge-{challenge_number}")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(PaymentOutcomeUnknownError):
                client.post(
                    "https://example.com/paid",
                    content=b"first body",
                    headers={"Idempotency-Key": "operation-a"},
                )
            with pytest.raises(PaymentOutcomeUnknownError) as repeated:
                client.post(
                    "https://example.com/paid",
                    content=b"different body",
                    headers={"Idempotency-Key": "operation-a"},
                )
            response = client.post(
                "https://example.com/paid",
                content=b"first body",
                headers={"Idempotency-Key": "operation-b"},
            )
    finally:
        client.close()
        runtime.close()

    assert isinstance(repeated.value.cause, httpx.ReadTimeout)
    assert response.status_code == 200
    assert method.calls == 2
    assert challenge_number == 3


def test_url_fragment_does_not_bypass_idempotency_protection() -> None:
    method = Method()
    challenge_number = 0
    paid_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal challenge_number, paid_requests
        if "authorization" in request.headers:
            paid_requests += 1
            if paid_requests == 1:
                raise httpx.ReadTimeout("paid response lost", request=request)
            return httpx.Response(200, content=b"paid")
        challenge_number += 1
        return payment_required(f"challenge-{challenge_number}")

    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with instrument(runtime, allow_unrestricted=True):
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get(
                    "https://example.com/paid#first",
                    headers={"Idempotency-Key": "same-operation"},
                )
            with pytest.raises(PaymentOutcomeUnknownError):
                client.get(
                    "https://example.com/paid#second",
                    headers={"Idempotency-Key": "same-operation"},
                )
    finally:
        client.close()
        runtime.close()

    assert method.calls == paid_requests == 1


def test_stale_context_falls_back_to_active_process_binding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        return payment_required()

    stale_runtime = PaymentRuntime([])
    stale_handle = instrument(stale_runtime, allow_unrestricted=True)
    stale_context = copy_context()
    stale_handle.disable()

    method = Method()
    runtime = PaymentRuntime([method])
    client = httpx.Client(transport=httpx.MockTransport(handler))
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
    original_sync_single = httpx.Client._send_single_request
    original_async_single = httpx.AsyncClient._send_single_request
    original_sync_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send
    original_thread_start = threading.Thread.start
    original_executor_submit = ThreadPoolExecutor.submit
    runtime = PaymentRuntime([])

    with pytest.raises(ValueError, match="allow_unrestricted=True"):
        instrument(runtime)

    assert httpx.Client._send_single_request is original_sync_single
    assert httpx.AsyncClient._send_single_request is original_async_single
    assert httpx.Client.send is original_sync_send
    assert httpx.AsyncClient.send is original_async_send
    assert threading.Thread.start is original_thread_start
    assert ThreadPoolExecutor.submit is original_executor_submit

    with instrument(runtime, allow_unrestricted=True):
        assert httpx.Client._send_single_request is not original_sync_single

    runtime.close()
    assert httpx.Client._send_single_request is original_sync_single
    assert httpx.AsyncClient._send_single_request is original_async_single
    assert httpx.Client.send is original_sync_send
    assert httpx.AsyncClient.send is original_async_send
    assert threading.Thread.start is original_thread_start
    assert ThreadPoolExecutor.submit is original_executor_submit


def test_unsupported_httpx_version_fails_before_patching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_sync = httpx.Client._send_single_request
    original_async = httpx.AsyncClient._send_single_request
    monkeypatch.setattr(instrumentation, "version", lambda _: "0.29.0")
    runtime = PaymentRuntime([])

    with pytest.raises(HttpxCompatibilityError, match=r"supported: >=0.27,<0.29"):
        instrument(runtime, allow_unrestricted=True)
    runtime.close()

    assert httpx.Client._send_single_request is original_sync
    assert httpx.AsyncClient._send_single_request is original_async


def test_changed_httpx_signature_fails_before_patching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_async = httpx.AsyncClient._send_single_request

    def incompatible(self: httpx.Client, request: httpx.Request, extra: object) -> httpx.Response:
        raise AssertionError

    monkeypatch.setattr(httpx.Client, "_send_single_request", incompatible)
    runtime = PaymentRuntime([])
    with pytest.raises(HttpxCompatibilityError, match="unsupported signature"):
        instrument(runtime, allow_unrestricted=True)
    runtime.close()

    assert httpx.Client._send_single_request is incompatible
    assert httpx.AsyncClient._send_single_request is original_async


def test_wrong_async_shape_fails_before_patching(monkeypatch: pytest.MonkeyPatch) -> None:
    original_sync = httpx.Client._send_single_request

    def incompatible(self: httpx.AsyncClient, request: httpx.Request) -> httpx.Response:
        raise AssertionError

    monkeypatch.setattr(httpx.AsyncClient, "_send_single_request", incompatible)
    runtime = PaymentRuntime([])
    with pytest.raises(HttpxCompatibilityError, match="is not async"):
        instrument(runtime, allow_unrestricted=True)
    runtime.close()

    assert httpx.Client._send_single_request is original_sync
    assert httpx.AsyncClient._send_single_request is incompatible


def test_missing_httpx_seam_fails_before_patching(monkeypatch: pytest.MonkeyPatch) -> None:
    original_async = httpx.AsyncClient._send_single_request
    monkeypatch.delattr(httpx.Client, "_send_single_request")
    runtime = PaymentRuntime([])
    with pytest.raises(HttpxCompatibilityError, match="is missing"):
        instrument(runtime, allow_unrestricted=True)
    runtime.close()
    assert httpx.AsyncClient._send_single_request is original_async


def test_changed_public_send_signature_fails_before_patching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_sync_single = httpx.Client._send_single_request
    original_async_single = httpx.AsyncClient._send_single_request

    def incompatible(
        self: httpx.Client,
        request: httpx.Request,
        extra: object,
    ) -> httpx.Response:
        raise AssertionError

    monkeypatch.setattr(httpx.Client, "send", incompatible)
    runtime = PaymentRuntime([])
    with pytest.raises(HttpxCompatibilityError, match="Client.send.*unsupported signature"):
        instrument(runtime, allow_unrestricted=True)
    runtime.close()

    assert httpx.Client._send_single_request is original_sync_single
    assert httpx.AsyncClient._send_single_request is original_async_single


def test_reinstrument_fails_if_an_active_patch_was_replaced() -> None:
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
