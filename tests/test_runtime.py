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

        assert events == ["enter", "exit"]
        assert len(set(loops)) == 1
        assert loops[0] is not caller_loop
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
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()

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

    def test_factory_lifecycle_is_scoped_per_runtime(self) -> None:
        b_entered = threading.Event()
        release_b = threading.Event()
        a_called_b = threading.Event()

        def b_factory() -> MockMethod:
            b_entered.set()
            release_b.wait()
            return MockMethod()

        b = PaymentRuntime(method_factories=[b_factory])
        a: PaymentRuntime | None = None
        pool = ThreadPoolExecutor(max_workers=2)
        try:
            b_started = pool.submit(b.start)
            assert b_entered.wait(1)

            def a_factory() -> MockMethod:
                a_called_b.set()
                b.start()
                return MockMethod()

            a = PaymentRuntime(method_factories=[a_factory])
            a_started = pool.submit(a.start)
            assert a_called_b.wait(1)
            assert not a_started.done()

            release_b.set()
            assert b_started.result(1) is b
            assert a_started.result(1) is a
        finally:
            release_b.set()
            pool.shutdown(wait=True, cancel_futures=True)
            if a is not None:
                a.close()
            b.close()

    def test_invalid_factory_result_unwinds_and_stops_loop(self) -> None:
        runtime = PaymentRuntime(method_factories=[lambda: object()])  # type: ignore[list-item]

        with pytest.raises(TypeError, match="payment Method"):
            runtime.start()

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

        async def close_from_event(_payload: Any) -> None:
            events.append("close")
            if async_close:
                await runtime.aclose()
            else:
                runtime.close()
            events.append("closed-callback")

        runtime.events.on("challenge.received", close_from_event)
        credential = await asyncio.wait_for(
            runtime.create_credential(challenge("close"), runtime.methods[0]),
            1,
        )

        assert credential.payload == {"ok": True}
        assert events == ["enter", "close", "closed-callback", "exit"]
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()

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

        runtime.close()


class TestRuntimeExecution:
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
