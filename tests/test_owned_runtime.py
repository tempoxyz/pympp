"""Tests for the explicit owned-loop payment runtime."""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import Any, cast

import httpx
import pytest

import mpp.runtime as runtime_module
from mpp import Challenge, Credential
from mpp.client import PaymentTransport
from mpp.runtime import OwnedPaymentRuntime


def challenge(identifier: str = "test") -> Challenge:
    return Challenge(id=identifier, method="tempo", intent="charge", request={})


class MockMethod:
    name = "tempo"
    intents = MappingProxyType({"charge": object()})

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.loops.append(asyncio.get_running_loop())
        return Credential(challenge=challenge.to_echo(), payload={"ok": True})


async def test_factory_sync_async_events_and_exit_share_owned_loop() -> None:
    caller_loop = asyncio.get_running_loop()
    loops: list[asyncio.AbstractEventLoop] = []
    events: list[str] = []

    @asynccontextmanager
    async def factory():
        events.append("enter")
        loops.append(asyncio.get_running_loop())
        method = MockMethod()
        try:
            yield method
        finally:
            loops.append(asyncio.get_running_loop())
            events.append("exit")

    async with OwnedPaymentRuntime(method_factories=[factory]) as runtime:
        method = cast(MockMethod, runtime.methods[0])
        runtime.events.on("*", lambda _event: loops.append(asyncio.get_running_loop()))
        await runtime.create_credential(challenge("async"), method)
        await asyncio.to_thread(runtime.create_credential_sync, challenge("sync"), method)

    assert events == ["enter", "exit"]
    assert len(method.loops) == 2
    assert len({*loops, *method.loops}) == 1
    assert loops[0] is not caller_loop


async def test_borrowed_method_is_not_entered_or_closed() -> None:
    events: list[str] = []

    class BorrowedMethod(MockMethod):
        async def __aenter__(self):
            events.append("enter")
            return self

        async def __aexit__(self, *_args: Any) -> None:
            events.append("exit")

    method = BorrowedMethod()
    async with OwnedPaymentRuntime([method]) as runtime:
        await runtime.create_credential(challenge(), method)

    assert events == []


async def test_name_only_credential_creation() -> None:
    method = MockMethod()
    value = Challenge(id="legacy", method="tempo", intent="subscription", request={})
    async with OwnedPaymentRuntime([method]) as runtime:
        matched = runtime.match_challenge([value], allow_name_only=True)
        created = await runtime.create_credential(*matched, allow_name_only=True)
        created_sync = await asyncio.to_thread(
            runtime.create_credential_sync, *matched, allow_name_only=True
        )
    assert created.payload == created_sync.payload == {"ok": True}


def test_factory_failure_unwinds_and_closes_runtime() -> None:
    events: list[str] = []

    @asynccontextmanager
    async def entered():
        events.append("enter")
        try:
            yield MockMethod()
        finally:
            events.append("exit")

    @asynccontextmanager
    async def failed():
        raise ValueError("factory failed")
        yield MockMethod()  # pragma: no cover

    runtime = OwnedPaymentRuntime(method_factories=[entered, failed])
    with pytest.raises(ValueError, match="factory failed"):
        runtime.start()

    assert events == ["enter", "exit"]
    with pytest.raises(RuntimeError, match="closed"):
        runtime.start()


def test_failed_start_is_closed_after_portal_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runtime_module.start_blocking_portal
    exiting = threading.Event()
    release = threading.Event()

    def delayed_portal(**kwargs: Any):
        inner = original(**kwargs)

        class Context:
            def __enter__(self):
                return inner.__enter__()

            def __exit__(self, *args: Any):
                exiting.set()
                assert release.wait(1)
                return inner.__exit__(*args)

        return Context()

    monkeypatch.setattr(runtime_module, "start_blocking_portal", delayed_portal)

    @asynccontextmanager
    async def failed():
        raise ValueError("factory failed")
        yield MockMethod()  # pragma: no cover

    runtime = OwnedPaymentRuntime(method_factories=[failed])
    errors: list[BaseException] = []

    def start() -> None:
        try:
            runtime.start()
        except BaseException as error:
            errors.append(error)

    starter = threading.Thread(target=start)
    starter.start()
    assert exiting.wait(1)
    closed = threading.Event()
    closer = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    closer.start()
    assert not closed.wait(0.05)
    release.set()
    starter.join(timeout=1)
    closer.join(timeout=1)

    assert not starter.is_alive() and not closer.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], ValueError)
    assert runtime._state == "closed"


def test_factory_contract_is_strict() -> None:
    runtime = OwnedPaymentRuntime(
        method_factories=[lambda: MockMethod()],  # type: ignore[list-item]
    )
    with pytest.raises(TypeError, match="asynchronous context manager"):
        runtime.start()


def test_factory_runtime_reentry_fails_fast() -> None:
    runtimes: list[OwnedPaymentRuntime] = []

    @asynccontextmanager
    async def factory():
        runtime = runtimes[0]
        assert runtime._owner_thread_id == threading.get_ident()
        with pytest.raises(RuntimeError, match="owned event loop"):
            runtime.start()
        with pytest.raises(RuntimeError, match="owned event loop"):
            await runtime.astart()
        with pytest.raises(RuntimeError, match="owned event loop"):
            runtime.close()
        with pytest.raises(RuntimeError, match="owned event loop"):
            await runtime.emit_event("nested", {})
        yield MockMethod()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    runtimes.append(runtime)
    with runtime:
        assert runtime.methods


def test_concurrent_first_start_is_shared() -> None:
    entered = threading.Event()
    release = threading.Event()
    started: list[OwnedPaymentRuntime] = []

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        yield MockMethod()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    thread = threading.Thread(target=lambda: started.append(runtime.start()))
    thread.start()
    assert entered.wait(1)
    waiter = threading.Thread(target=lambda: started.append(runtime.start()))
    waiter.start()
    try:
        assert waiter.is_alive()
    finally:
        release.set()
        thread.join(timeout=1)
        waiter.join(timeout=1)
        runtime.close()
    assert not thread.is_alive() and not waiter.is_alive()
    assert started == [runtime, runtime]


def test_close_during_start_and_concurrent_close_are_idempotent() -> None:
    entered = threading.Event()
    release = threading.Event()

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        yield MockMethod()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    starter = threading.Thread(target=runtime.start)
    closers = [threading.Thread(target=runtime.close) for _ in range(2)]
    starter.start()
    assert entered.wait(1)
    for closer in closers:
        closer.start()
    release.set()
    starter.join(timeout=1)
    for closer in closers:
        closer.join(timeout=1)

    assert not starter.is_alive()
    assert all(not closer.is_alive() for closer in closers)
    assert runtime._state == "closed"


def test_close_waits_for_operation_and_active_close_fails_fast() -> None:
    runtime = OwnedPaymentRuntime().start()
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def operation() -> None:
        with runtime._paid_operation():
            entered.set()
            assert release.wait(1)

    worker = threading.Thread(target=operation)
    worker.start()
    assert entered.wait(1)
    closer = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    closer.start()
    assert not closed.wait(0.05)

    release.set()
    worker.join(timeout=1)
    closer.join(timeout=1)
    assert not worker.is_alive() and not closer.is_alive()
    assert closed.is_set()

    active = OwnedPaymentRuntime().start()
    with active._paid_operation():
        with pytest.raises(RuntimeError, match="active operation"):
            active.close()
    active.close()


async def test_child_task_inherits_scope_but_acquires_its_own_lease() -> None:
    runtime = OwnedPaymentRuntime().start()
    child_started = asyncio.Event()
    child_release = asyncio.Event()
    closed = threading.Event()

    async def child() -> None:
        with runtime._paid_operation():
            child_started.set()
            await child_release.wait()

    with runtime._paid_operation():
        task = asyncio.create_task(child())
        await child_started.wait()

    closer = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    closer.start()
    assert not await asyncio.to_thread(closed.wait, 0.05)
    child_release.set()
    await task
    closer.join(timeout=1)

    assert not closer.is_alive()
    assert closed.is_set()


async def test_inherited_scope_expires_with_parent_operation() -> None:
    runtime = OwnedPaymentRuntime().start()
    release = asyncio.Event()

    async def close_after_parent() -> None:
        await release.wait()
        await asyncio.to_thread(runtime.close)

    with runtime._paid_operation():
        task = asyncio.create_task(close_after_parent())

    release.set()
    await asyncio.wait_for(task, 1)


def test_sync_call_from_owner_loop_fails_fast() -> None:
    runtime: OwnedPaymentRuntime

    class ReentrantMethod(MockMethod):
        async def create_credential(self, challenge: Challenge) -> Credential:
            runtime.emit_event_sync("nested", {})
            return await super().create_credential(challenge)

    method = ReentrantMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    try:
        with pytest.raises(RuntimeError, match="owned event loop"):
            runtime.create_credential_sync(challenge(), method)
    finally:
        runtime.close()


async def test_async_close_from_owner_loop_fails_fast() -> None:
    runtime: OwnedPaymentRuntime

    class ReentrantMethod(MockMethod):
        async def create_credential(self, challenge: Challenge) -> Credential:
            await runtime.aclose()
            return await super().create_credential(challenge)

    method = ReentrantMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    try:
        with pytest.raises(RuntimeError, match="active operation"):
            await runtime.create_credential(challenge(), method)
    finally:
        runtime.close()


async def test_close_from_inherited_to_thread_scope_fails_fast() -> None:
    runtime: OwnedPaymentRuntime

    class ReentrantMethod(MockMethod):
        async def create_credential(self, challenge: Challenge) -> Credential:
            await asyncio.to_thread(runtime.close)
            return await super().create_credential(challenge)

    method = ReentrantMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    try:
        with pytest.raises(RuntimeError, match="active operation"):
            await asyncio.wait_for(runtime.create_credential(challenge(), method), 1)
    finally:
        runtime.close()


async def test_lazy_async_http_start_does_not_block_caller_loop() -> None:
    release = threading.Event()
    caller_ran = threading.Event()
    remained_responsive: list[bool] = []

    @asynccontextmanager
    async def factory():
        await asyncio.to_thread(release.wait)
        yield MockMethod()

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            return httpx.Response(
                402,
                headers={
                    "www-authenticate": challenge().to_www_authenticate("example.com"),
                },
            )
        return httpx.Response(200, content=b"paid")

    def watchdog() -> None:
        remained_responsive.append(caller_ran.wait(0.5))
        release.set()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    transport = PaymentTransport(runtime=runtime, inner=httpx.MockTransport(handler))
    thread = threading.Thread(target=watchdog)
    thread.start()
    caller_loop_turn = asyncio.create_task(asyncio.sleep(0, result=caller_ran.set()))
    try:
        response = await transport.handle_async_request(
            httpx.Request("GET", "https://example.com"),
        )
        await caller_loop_turn
    finally:
        release.set()
        thread.join()
        await transport.aclose()
        await runtime.aclose()

    assert response.status_code == 200
    assert remained_responsive == [True]


@pytest.mark.parametrize("operation", ["event", "credential"])
async def test_lazy_async_runtime_start_does_not_block_caller_loop(operation: str) -> None:
    release = threading.Event()
    caller_ran = threading.Event()
    remained_responsive: list[bool] = []
    method = MockMethod()

    @asynccontextmanager
    async def factory():
        await asyncio.to_thread(release.wait)
        yield method

    def watchdog() -> None:
        remained_responsive.append(caller_ran.wait(0.5))
        release.set()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    thread = threading.Thread(target=watchdog)
    thread.start()
    caller_loop_turn = asyncio.create_task(asyncio.sleep(0, result=caller_ran.set()))
    try:
        if operation == "event":
            await runtime.emit_event("test", {})
        else:
            await runtime.create_credential(challenge(), method)
        await caller_loop_turn
    finally:
        release.set()
        thread.join()
        await runtime.aclose()

    assert remained_responsive == [True]


async def test_repeatedly_cancelled_start_closes_initialized_resources() -> None:
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        try:
            yield MockMethod()
        finally:
            exited.set()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    task = asyncio.create_task(runtime.astart())
    assert await asyncio.to_thread(entered.wait, 1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert runtime._state == "closed"
    assert exited.is_set()


async def test_cancelled_shared_start_does_not_close_other_caller() -> None:
    entered = threading.Event()
    release = threading.Event()

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        yield MockMethod()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    cancelled = asyncio.create_task(runtime.astart())
    waiting = asyncio.create_task(runtime.astart())
    assert await asyncio.to_thread(entered.wait, 1)
    cancelled.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await cancelled
    assert await waiting is runtime
    assert runtime._state == "open"
    runtime.close()


async def test_cancelled_async_start_preserves_waiting_sync_start() -> None:
    entered = threading.Event()
    release = threading.Event()
    started: list[OwnedPaymentRuntime] = []

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        yield MockMethod()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    cancelled = asyncio.create_task(runtime.astart())
    assert await asyncio.to_thread(entered.wait, 1)
    waiter = threading.Thread(target=lambda: started.append(runtime.start()))
    waiter.start()
    while not runtime._start_claimed:
        await asyncio.sleep(0)
    cancelled.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await cancelled
    waiter.join(timeout=1)
    assert not waiter.is_alive()
    assert started == [runtime]
    assert runtime._state == "open"
    runtime.close()


async def test_all_cancelled_starters_close_initialized_resources() -> None:
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    @asynccontextmanager
    async def factory():
        entered.set()
        await asyncio.to_thread(release.wait)
        try:
            yield MockMethod()
        finally:
            exited.set()

    runtime = OwnedPaymentRuntime(method_factories=[factory])
    tasks = [asyncio.create_task(runtime.astart()) for _ in range(2)]
    assert await asyncio.to_thread(entered.wait, 1)
    for task in tasks:
        task.cancel()
    release.set()

    for task in tasks:
        with pytest.raises(asyncio.CancelledError):
            await task
    assert runtime._state == "closed"
    assert exited.is_set()


async def test_close_waits_while_async_payment_finishes() -> None:
    started = threading.Event()
    release = threading.Event()
    events: list[str] = []

    class BlockingMethod(MockMethod):
        async def create_credential(self, challenge: Challenge) -> Credential:
            started.set()
            await asyncio.to_thread(release.wait)
            return await super().create_credential(challenge)

    method = BlockingMethod()

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            return httpx.Response(
                402,
                headers={
                    "www-authenticate": challenge().to_www_authenticate("example.com"),
                },
            )
        return httpx.Response(200, content=b"paid")

    runtime = OwnedPaymentRuntime([method])
    runtime.events.on("payment.response", lambda _payload: events.append("response"))

    async def reject_nested_operation(_payload: dict[str, Any]) -> None:
        with pytest.raises(RuntimeError, match="closing"):
            await runtime.emit_event("nested", {})

    runtime.events.on("credential.created", reject_nested_operation)
    transport = PaymentTransport(runtime=runtime, inner=httpx.MockTransport(handler))
    request = asyncio.create_task(
        transport.handle_async_request(httpx.Request("GET", "https://example.com"))
    )
    assert await asyncio.to_thread(started.wait, 1)
    close = asyncio.create_task(asyncio.to_thread(runtime.close))
    while runtime._state != "closing":
        await asyncio.sleep(0)
    release.set()

    assert (await request).status_code == 200
    assert events == ["response"]
    await close
    await transport.aclose()


async def test_operation_started_during_close_fails_fast() -> None:
    runtime = OwnedPaymentRuntime().start()
    closer = threading.Thread(target=runtime.close)

    with runtime._paid_operation():
        closer.start()
        while runtime._state != "closing":
            await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="closing"):
            await asyncio.wait_for(asyncio.create_task(runtime.emit_event("late", {})), 1)
        with pytest.raises(RuntimeError, match="closing"), runtime._paid_operation():
            pass

    closer.join(timeout=1)
    assert not closer.is_alive()


def test_same_thread_operation_started_during_close_fails_fast() -> None:
    runtime = OwnedPaymentRuntime().start()
    closer = threading.Thread(target=runtime.close)

    with runtime._paid_operation():
        closer.start()
        while runtime._state != "closing":
            threading.Event().wait(0.001)
        with pytest.raises(RuntimeError, match="closing"):
            runtime.emit_event_sync("late", {})

    closer.join(timeout=1)
    assert not closer.is_alive()


def test_non_exception_base_exception_does_not_kill_portal() -> None:
    class Abort(BaseException):
        pass

    class AbortOnceMethod(MockMethod):
        calls = 0

        async def create_credential(self, challenge: Challenge) -> Credential:
            self.calls += 1
            if self.calls == 1:
                raise Abort
            return await super().create_credential(challenge)

    method = AbortOnceMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    try:
        with pytest.raises(Abort):
            runtime.create_credential_sync(challenge("abort"), method)
        assert runtime.create_credential_sync(challenge("ok"), method).payload == {"ok": True}
    finally:
        runtime.close()


async def test_cancelled_async_call_finishes_method_cleanup_before_close() -> None:
    started = threading.Event()
    cleaned = threading.Event()

    class BlockingMethod(MockMethod):
        async def create_credential(self, challenge: Challenge) -> Credential:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()
            raise AssertionError(challenge.id)

    method = BlockingMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    task = asyncio.create_task(runtime.create_credential(challenge(), method))
    assert await asyncio.to_thread(started.wait, 1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.to_thread(runtime.close)
    assert cleaned.is_set()


def test_method_exit_base_exception_still_stops_runtime() -> None:
    class Abort(BaseException):
        pass

    @asynccontextmanager
    async def factory():
        try:
            yield MockMethod()
        finally:
            raise Abort

    runtime = OwnedPaymentRuntime(method_factories=[factory]).start()
    with pytest.raises(Abort):
        runtime.close()
    runtime.close()
