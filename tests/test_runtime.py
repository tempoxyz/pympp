"""Tests for the shared payment runtime."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from types import MappingProxyType
from typing import Any

import pytest

from mpp import Challenge, Credential
from mpp.runtime import Method, PaymentRuntime


def challenge(identifier: str = "test-id", *, intent: str = "charge") -> Challenge:
    return Challenge(
        id=identifier,
        method="tempo",
        intent=intent,
        request={},
    )


class MockMethod:
    name = "tempo"
    intents = MappingProxyType({"charge": object()})

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []

    async def create_credential(self, value: Challenge) -> Credential:
        self.loops.append(asyncio.get_running_loop())
        return Credential(challenge=value.to_echo(), payload={"ok": True})


class TestRuntimeLifecycle:
    @pytest.mark.asyncio
    async def test_factory_lifecycle_uses_one_owned_loop_for_sync_and_async(self) -> None:
        loops: list[asyncio.AbstractEventLoop] = []
        events: list[str] = []

        class LoopBoundMethod(MockMethod):
            def __init__(self) -> None:
                super().__init__()
                self.loop = asyncio.get_running_loop()
                self.ready = self.loop.create_future()
                self.loop.call_soon(self.ready.set_result, None)

            async def create_credential(self, value: Challenge) -> Credential:
                loops.append(asyncio.get_running_loop())
                await self.ready
                return await super().create_credential(value)

        @asynccontextmanager
        async def managed() -> AsyncIterator[Method]:
            events.append("enter")
            method = LoopBoundMethod()
            loops.append(method.loop)
            try:
                yield method
            finally:
                loops.append(asyncio.get_running_loop())
                events.append("exit")

        async def factory() -> AbstractAsyncContextManager[Method]:
            return managed()

        caller_loop = asyncio.get_running_loop()
        async with PaymentRuntime(method_factories=[factory]) as runtime:
            method = runtime.methods[0]
            await runtime.create_credential(challenge("async"), method)
            await asyncio.to_thread(
                runtime.create_credential_sync,
                challenge("sync"),
                method,
            )
            thread = runtime._bridge._thread

        assert events == ["enter", "exit"]
        assert len(set(loops)) == 1
        assert loops[0] is not caller_loop
        assert thread is not None and not thread.is_alive()
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()

    def test_borrowed_methods_are_not_entered_or_closed(self) -> None:
        events: list[str] = []

        class BorrowedMethod(MockMethod):
            async def __aenter__(self) -> BorrowedMethod:
                events.append("enter")
                return self

            async def __aexit__(self, *_args: Any) -> None:
                events.append("exit")

        method = BorrowedMethod()
        with PaymentRuntime([method]) as runtime:
            runtime.create_credential_sync(challenge(), method)

        assert events == []

    @pytest.mark.asyncio
    async def test_concurrent_start_is_single_flight_and_cancellation_safe(self) -> None:
        calls = 0

        async def factory() -> MockMethod:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.05)
            return MockMethod()

        runtime = PaymentRuntime(method_factories=[factory])
        first = asyncio.create_task(runtime.astart())
        second = asyncio.create_task(runtime.astart())
        await asyncio.sleep(0.01)
        first.cancel()

        with pytest.raises(asyncio.CancelledError):
            await first
        assert await second is runtime
        assert calls == 1
        await runtime.aclose()

    @pytest.mark.asyncio
    async def test_cancelled_async_context_entry_closes_started_runtime(self) -> None:
        events: list[str] = []
        entered = threading.Event()

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            entered.set()
            await asyncio.sleep(0.05)
            try:
                yield MockMethod()
            finally:
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[factory])

        async def use_runtime() -> None:
            async with runtime:
                raise AssertionError("cancelled entry reached the context body")

        task = asyncio.create_task(use_runtime())
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert events == ["enter", "exit"]
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    @pytest.mark.asyncio
    async def test_cancelled_async_context_exit_finishes_close(self) -> None:
        events: list[str] = []
        exit_started = threading.Event()

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield MockMethod()
            finally:
                exit_started.set()
                await asyncio.sleep(0.05)
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[factory])

        async def use_runtime() -> None:
            async with runtime:
                pass

        task = asyncio.create_task(use_runtime())
        assert await asyncio.to_thread(exit_started.wait, 1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert events == ["enter", "exit"]
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    @pytest.mark.asyncio
    async def test_cancelled_aclose_finishes_close(self) -> None:
        exit_started = threading.Event()

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            try:
                yield MockMethod()
            finally:
                exit_started.set()
                await asyncio.sleep(0.05)

        runtime = await PaymentRuntime(method_factories=[factory]).astart()
        close = asyncio.create_task(runtime.aclose())
        assert await asyncio.to_thread(exit_started.wait, 1)
        close.cancel()

        with pytest.raises(asyncio.CancelledError):
            await close
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_sync_context_manager_and_close_before_start(self) -> None:
        calls = 0

        def factory() -> MockMethod:
            nonlocal calls
            calls += 1
            return MockMethod()

        unused = PaymentRuntime(method_factories=[factory])
        unused.close()
        assert calls == 0

        with PaymentRuntime(method_factories=[factory]) as runtime:
            assert runtime.methods
        assert calls == 1
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_factory_failure_unwinds_entered_methods_and_stops_loop(self) -> None:
        events: list[str] = []

        @asynccontextmanager
        async def managed() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield MockMethod()
            finally:
                events.append("exit")

        async def fail() -> MockMethod:
            raise ValueError("factory failed")

        runtime = PaymentRuntime(method_factories=[managed, fail])
        with pytest.raises(ValueError, match="factory failed"):
            runtime.start()

        assert events == ["enter", "exit"]
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()
        with pytest.raises(RuntimeError, match="failed to start"):
            runtime.start()

    def test_factory_reentry_through_worker_fails_without_deadlock(self) -> None:
        runtime_holder: dict[str, PaymentRuntime] = {}

        async def factory() -> MockMethod:
            runtime = runtime_holder["runtime"]
            with pytest.raises(RuntimeError, match="while method factories start"):
                await asyncio.wait_for(asyncio.to_thread(runtime.start), 1)
            with pytest.raises(RuntimeError, match="while method factories start"):
                await asyncio.wait_for(asyncio.to_thread(runtime.close), 1)
            return MockMethod()

        runtime = PaymentRuntime(method_factories=[factory])
        runtime_holder["runtime"] = runtime
        with runtime:
            pass

    def test_invalid_factory_result_unwinds_and_stops_loop(self) -> None:
        runtime = PaymentRuntime(method_factories=[lambda: object()])  # type: ignore[list-item]

        with pytest.raises(TypeError, match="payment Method"):
            runtime.start()
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_methods_and_factories_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValueError, match="either methods or method_factories"):
            PaymentRuntime([], method_factories=[MockMethod])

    def test_invalid_borrowed_method_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="payment Methods"):
            PaymentRuntime([object()])  # type: ignore[list-item]

    @pytest.mark.parametrize("async_close", [False, True])
    @pytest.mark.asyncio
    async def test_close_from_owned_loop_event_is_deferred(self, async_close: bool) -> None:
        events: list[str] = []

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield MockMethod()
            finally:
                events.append("exit")

        runtime = await PaymentRuntime(method_factories=[factory]).astart()

        if async_close:

            async def async_close_from_event(_payload: Any) -> None:
                events.append("close")
                await runtime.aclose()
                events.append("closed-callback")

            close_from_event = async_close_from_event
        else:

            def sync_close_from_event(_payload: Any) -> None:
                events.append("close")
                runtime.close()
                events.append("closed-callback")

            close_from_event = sync_close_from_event

        runtime.events.on("challenge.received", close_from_event)
        credential = await asyncio.wait_for(
            runtime.create_credential(challenge("close"), runtime.methods[0]),
            1,
        )

        assert credential.payload == {"ok": True}
        assert events == ["enter", "close", "closed-callback", "exit"]
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_external_close_cancels_method_before_lifecycle_exit(self) -> None:
        events: list[str] = []
        started = threading.Event()

        class BlockingMethod(MockMethod):
            async def create_credential(self, value: Challenge) -> Credential:
                events.append("credential-start")
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    events.append("credential-finally")
                raise AssertionError(f"unexpected release for {value.id}")

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield BlockingMethod()
            finally:
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[factory]).start()
        errors: list[BaseException] = []

        def create() -> None:
            try:
                runtime.create_credential_sync(challenge("cancel"), runtime.methods[0])
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=create)
        worker.start()
        assert started.wait(1)
        runtime.close()
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert len(errors) == 1
        assert type(errors[0]).__name__ == "CancelledError"
        assert events == ["enter", "credential-start", "credential-finally", "exit"]

    @pytest.mark.parametrize("threaded_close", [False, True])
    def test_close_during_method_exit_does_not_deadlock(self, threaded_close: bool) -> None:
        events: list[str] = []
        runtime_holder: dict[str, PaymentRuntime] = {}

        class ManagedMethod(MockMethod):
            async def __aenter__(self) -> ManagedMethod:
                events.append("enter")
                return self

            async def __aexit__(self, *_args: Any) -> None:
                events.append("exit-start")
                runtime = runtime_holder["runtime"]
                if threaded_close:
                    await asyncio.to_thread(runtime.close)
                else:
                    runtime.close()
                events.append("exit-end")

        runtime = PaymentRuntime(method_factories=[ManagedMethod])
        runtime_holder["runtime"] = runtime
        runtime.start()
        errors: list[BaseException] = []

        def close() -> None:
            try:
                runtime.close()
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=close, daemon=True)
        worker.start()
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert not errors
        assert events == ["enter", "exit-start", "exit-end"]
        assert runtime._state == "closed"

    def test_concurrent_close_waits_for_method_exit(self) -> None:
        exit_started = threading.Event()
        release_exit = threading.Event()
        second_done = threading.Event()
        errors: list[BaseException] = []
        exits = 0

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            nonlocal exits
            try:
                yield MockMethod()
            finally:
                exit_started.set()
                await asyncio.to_thread(release_exit.wait)
                exits += 1

        runtime = PaymentRuntime(method_factories=[factory]).start()

        def close(*, done: threading.Event | None = None) -> None:
            try:
                runtime.close()
            except BaseException as error:
                errors.append(error)
            finally:
                if done is not None:
                    done.set()

        first = threading.Thread(target=close)
        second = threading.Thread(target=close, kwargs={"done": second_done})
        first.start()
        assert exit_started.wait(1)
        second.start()
        assert not second_done.wait(0.05)
        release_exit.set()
        first.join(timeout=1)
        second.join(timeout=1)

        assert not errors
        assert not first.is_alive() and not second.is_alive()
        assert exits == 1

    @pytest.mark.asyncio
    async def test_async_finalizer_yields_to_in_progress_close(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([])
        runtime._state = "closing"
        runtime._deferred_close = True
        runtime._finalizing = True
        called = False

        async def cancel_pending() -> None:
            nonlocal called
            called = True

        monkeypatch.setattr(runtime._bridge, "_cancel_pending", cancel_pending)
        await runtime._finish_close_async()

        assert not called

    def test_method_exit_failure_still_stops_runtime(self) -> None:
        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            try:
                yield MockMethod()
            finally:
                raise ValueError("method exit failed")

        runtime = PaymentRuntime(method_factories=[factory]).start()
        with pytest.raises(ValueError, match="method exit failed"):
            runtime.close()

        assert runtime._state == "closed"
        assert runtime._method_stack is None
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    @pytest.mark.asyncio
    async def test_deferred_close_waits_for_inherited_runtime_lease_child(self) -> None:
        runtime = PaymentRuntime([])
        entered = asyncio.Event()
        release = asyncio.Event()

        async def child() -> None:
            with runtime._runtime_operation():
                entered.set()
                await release.wait()

        with runtime._runtime_operation():
            task = asyncio.create_task(child())
            await asyncio.wait_for(entered.wait(), 1)
            runtime.close()

        assert runtime._state == "closing"
        assert runtime._active_operations == 1
        release.set()
        await asyncio.wait_for(task, 1)
        assert runtime._state == "closed"

    def test_detached_owned_loop_close_finishes_cleanly(self) -> None:
        runtime_holder: dict[str, PaymentRuntime] = {}
        release: asyncio.Event | None = None
        done = threading.Event()
        errors: list[BaseException] = []
        lifecycle: list[str] = []

        class SpawningMethod(MockMethod):
            async def create_credential(self, value: Challenge) -> Credential:
                nonlocal release
                release = asyncio.Event()

                async def detached() -> None:
                    assert release is not None
                    await release.wait()

                    async def close_inside_operation() -> None:
                        runtime_holder["runtime"].close()

                    try:
                        await runtime_holder["runtime"].run_async(close_inside_operation())
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        done.set()

                asyncio.create_task(detached())
                return await super().create_credential(value)

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            lifecycle.append("enter")
            try:
                yield SpawningMethod()
            finally:
                lifecycle.append("exit")

        runtime = PaymentRuntime(method_factories=[factory]).start()
        runtime_holder["runtime"] = runtime
        runtime.create_credential_sync(challenge(), runtime.methods[0])

        async def wake_detached() -> None:
            assert release is not None
            release.set()

        runtime.run_sync(wake_detached())
        assert done.wait(1)
        assert runtime._bridge._thread is not None
        runtime.close()
        assert errors == []
        assert lifecycle == ["enter", "exit"]
        assert runtime._method_stack is None
        assert not runtime._bridge._thread.is_alive()


class TestRuntimeBridge:
    def test_concurrent_sync_calls_share_one_method_loop(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(
                    pool.map(
                        lambda _: runtime.create_credential_sync(challenge(), method),
                        range(4),
                    )
                )
        finally:
            runtime.close()

        assert len(method.loops) == 4
        assert len({id(loop) for loop in method.loops}) == 1

    @pytest.mark.asyncio
    async def test_sync_async_and_events_share_runtime_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        method = MockMethod()
        runtime = PaymentRuntime([method])
        event_loops: list[asyncio.AbstractEventLoop] = []
        runtime.events.on("*", lambda _: event_loops.append(asyncio.get_running_loop()))
        try:
            await runtime.create_credential(challenge("async"), method)
            await asyncio.to_thread(
                runtime.create_credential_sync,
                challenge("sync"),
                method,
            )
        finally:
            runtime.close()

        assert len(method.loops) == 2
        assert method.loops[0] is method.loops[1]
        assert method.loops[0] is not caller_loop
        assert len(event_loops) == 4
        assert set(event_loops) == {method.loops[0]}

    def test_bridge_rejects_same_thread_blocking(self) -> None:
        runtime = PaymentRuntime([])

        async def block_bridge() -> None:
            with pytest.raises(RuntimeError, match="Cannot block"):
                runtime._bridge.run(asyncio.sleep(0))

        try:
            runtime._bridge.run(block_bridge())
        finally:
            runtime.close()

    def test_thread_start_failure_closes_runtime_without_waiting(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([])

        def fail_start(_thread: threading.Thread) -> None:
            raise OSError("thread unavailable")

        monkeypatch.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(RuntimeError, match="background loop failed") as exc_info:
            runtime.start()

        assert isinstance(exc_info.value.__cause__, OSError)
        assert runtime._state == "closed"
        assert runtime._bridge._ready.is_set()
        assert runtime._bridge._stopped.is_set()

    def test_shutdown_runs_all_cleanup_and_reraises_first_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([]).start()
        original_close = runtime._bridge.close
        closed = False

        def fail_cancel() -> None:
            raise ValueError("first cleanup failure")

        def close_then_fail() -> None:
            nonlocal closed
            original_close()
            closed = True
            raise RuntimeError("later cleanup failure")

        monkeypatch.setattr(runtime._bridge, "cancel_pending", fail_cancel)
        monkeypatch.setattr(runtime._bridge, "close", close_then_fail)

        with pytest.raises(ValueError, match="first cleanup failure"):
            runtime.close()

        assert closed
        assert runtime._state == "closed"
        assert runtime._bridge._stopped.is_set()
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_loop_cleanup_failure_is_published_after_thread_stops(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([]).start()
        runtime.run_sync(asyncio.to_thread(lambda: None))
        loop = runtime._bridge._loop
        assert loop is not None
        shutdown_default_executor = loop.shutdown_default_executor
        executor_shutdowns = 0

        async def fail_shutdown(_loop: Any) -> None:
            raise OSError("async generator cleanup failed")

        async def record_executor_shutdown(_loop: Any) -> None:
            nonlocal executor_shutdowns
            executor_shutdowns += 1
            await shutdown_default_executor()

        monkeypatch.setattr(type(loop), "shutdown_asyncgens", fail_shutdown)
        monkeypatch.setattr(type(loop), "shutdown_default_executor", record_executor_shutdown)
        with pytest.raises(OSError, match="async generator cleanup failed"):
            runtime.close()

        assert executor_shutdowns == 1
        assert runtime._state == "closed"
        assert runtime._bridge._stopped.is_set()
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_close_is_idempotent(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        runtime.create_credential_sync(challenge(), method)

        runtime.close()
        runtime.close()

        with pytest.raises(RuntimeError, match="closed"):
            runtime.create_credential_sync(challenge(), method)


class TestRuntimeMethods:
    @pytest.mark.asyncio
    async def test_challenge_handler_can_supply_credential(self) -> None:
        method = MockMethod()
        supplied = Credential(challenge=challenge("supplied").to_echo(), payload={"event": True})
        created: list[dict[str, Any]] = []
        runtime = PaymentRuntime([method])
        runtime.events.on("challenge.received", lambda _payload: supplied)
        runtime.events.on("credential.created", created.append)

        try:
            result = await runtime.create_credential(
                challenge("requested"),
                method,
                event_payload={"challenge": "cannot override", "source": "adapter"},
            )
        finally:
            await runtime.aclose()

        assert result is supplied
        assert method.loops == []
        assert created[0]["credential"] is supplied
        assert created[0]["challenge"].id == "requested"
        assert created[0]["source"] == "adapter"

    def test_matching_uses_public_intents_mapping(self) -> None:
        class SubscriptionMethod(MockMethod):
            intents = MappingProxyType({"subscription": object()})

        method = SubscriptionMethod()
        runtime = PaymentRuntime([method])
        subscription = challenge("subscription", intent="subscription")

        assert runtime.match_challenge([subscription]) == (subscription, method)
        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([challenge("charge")])
        runtime.close()

    def test_legacy_method_defaults_to_charge(self) -> None:
        class LegacyMethod:
            name = "tempo"

            async def create_credential(self, value: Challenge) -> Credential:
                return Credential(challenge=value.to_echo(), payload={})

        method = LegacyMethod()
        runtime = PaymentRuntime([method])

        assert runtime.match_challenge([challenge()]) == (challenge(), method)
        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([challenge(intent="subscription")])
        assert (
            runtime.match_challenge(
                [challenge(intent="subscription")],
                allow_name_only=True,
            )[1]
            is method
        )
        runtime.close()

    def test_invalid_intents_capability_is_rejected(self) -> None:
        class InvalidMethod(MockMethod):
            intents: Any = ["charge"]

        with pytest.raises(TypeError, match="payment Methods"):
            PaymentRuntime([InvalidMethod()])

    def test_matching_order_is_explicit(self) -> None:
        class StripeMethod(MockMethod):
            name = "stripe"

        stripe = StripeMethod()
        tempo = MockMethod()
        stripe_challenge = Challenge(
            id="stripe",
            method="stripe",
            intent="charge",
            request={},
        )
        tempo_challenge = challenge("tempo")
        runtime = PaymentRuntime([stripe, tempo])

        assert runtime.match_challenge([tempo_challenge, stripe_challenge])[1] is stripe
        assert (
            runtime.match_challenge(
                [tempo_challenge, stripe_challenge],
                prefer_method_order=False,
            )[1]
            is tempo
        )
        runtime.close()
