"""Tests for shared client-side payment primitives."""

from __future__ import annotations

import asyncio
import gc
import weakref
from types import MappingProxyType
from typing import Any

import pytest

from mpp import Challenge, Credential
from mpp.runtime import PaymentRuntime


def challenge(
    identifier: str = "test",
    *,
    method: str = "tempo",
    intent: str = "charge",
) -> Challenge:
    return Challenge(id=identifier, method=method, intent=intent, request={})


class MockMethod:
    name = "tempo"
    intents = MappingProxyType({"charge": object()})

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.loops.append(asyncio.get_running_loop())
        return Credential(challenge=challenge.to_echo(), payload={"ok": True})


async def test_credential_creation_and_events_use_caller_loop() -> None:
    caller_loop = asyncio.get_running_loop()
    method = MockMethod()
    runtime = PaymentRuntime([method])
    event_loops: list[asyncio.AbstractEventLoop] = []
    runtime.events.on("*", lambda _event: event_loops.append(asyncio.get_running_loop()))

    credential = await runtime.create_credential(challenge(), method)

    assert credential.payload == {"ok": True}
    assert method.loops == [caller_loop]
    assert event_loops == [caller_loop, caller_loop]


async def test_challenge_handler_can_supply_credential() -> None:
    method = MockMethod()
    supplied = Credential(challenge=challenge("supplied").to_echo(), payload={"event": True})
    created: list[dict[str, Any]] = []
    runtime = PaymentRuntime([method])
    runtime.events.on("challenge.received", lambda _payload: supplied)
    runtime.events.on("credential.created", created.append)

    result = await runtime.create_credential(
        challenge("requested"),
        method,
        event_payload={
            "challenge": "cannot override",
            "challenges": [challenge("offered")],
            "source": "adapter",
        },
    )

    assert result is supplied
    assert method.loops == []
    assert created[0]["challenge"].id == "requested"
    assert created[0]["challenges"][0].id == "offered"
    assert created[0]["source"] == "adapter"


async def test_credential_creation_requires_installed_method_identity() -> None:
    class EqualMethod(MockMethod):
        def __eq__(self, other: object) -> bool:
            return isinstance(other, EqualMethod)

    installed = EqualMethod()
    uninstalled = EqualMethod()
    events: list[Any] = []
    runtime = PaymentRuntime([installed])
    runtime.events.on("*", events.append)

    with pytest.raises(ValueError, match="not installed"):
        await runtime.create_credential(challenge(), uninstalled)

    assert uninstalled == installed
    assert uninstalled.loops == []
    assert events == []


@pytest.mark.parametrize(
    "incompatible",
    [
        challenge(method="stripe"),
        challenge(intent="subscription"),
    ],
)
async def test_credential_creation_requires_compatible_method(
    incompatible: Challenge,
) -> None:
    method = MockMethod()
    events: list[Any] = []
    runtime = PaymentRuntime([method])
    runtime.events.on("*", events.append)

    with pytest.raises(ValueError, match="does not support"):
        await runtime.create_credential(incompatible, method)

    assert method.loops == []
    assert events == []


def test_sync_context_and_close_are_idempotent() -> None:
    runtime = PaymentRuntime()

    with runtime as entered:
        assert entered is runtime

    runtime.close()
    with pytest.raises(RuntimeError, match="closed"):
        runtime.start()
    with pytest.raises(RuntimeError, match="closed"):
        runtime.match_challenge([])


async def test_async_context_closes_runtime() -> None:
    runtime = PaymentRuntime()

    async with runtime as entered:
        assert entered is runtime

    with pytest.raises(RuntimeError, match="closed"):
        await runtime.emit_event("test", {})


async def test_async_lifecycle_aliases() -> None:
    runtime = PaymentRuntime()

    assert await runtime.astart() is runtime
    await runtime.aclose()

    with pytest.raises(RuntimeError, match="closed"):
        await runtime.astart()


async def test_borrowed_methods_are_not_entered_or_closed() -> None:
    events: list[str] = []

    class ManagedMethod(MockMethod):
        async def __aenter__(self) -> ManagedMethod:
            events.append("enter")
            return self

        async def __aexit__(self, *_args: Any) -> None:
            events.append("exit")

    method = ManagedMethod()
    async with PaymentRuntime([method]) as runtime:
        await runtime.create_credential(challenge(), method)

    assert events == []


async def test_child_scope_does_not_retain_completed_parent_task() -> None:
    runtime = PaymentRuntime()
    release = asyncio.Event()
    parent_ref: weakref.ReferenceType[asyncio.Task[Any]] | None = None

    async def parent() -> asyncio.Task[bool]:
        nonlocal parent_ref
        with runtime._paid_operation():
            child = asyncio.create_task(release.wait())
            task = asyncio.current_task()
            assert task is not None
            parent_ref = weakref.ref(task)
            return child

    parent_task = asyncio.create_task(parent())
    child = await parent_task
    del parent_task
    await asyncio.sleep(0)
    gc.collect()

    assert parent_ref is not None
    assert parent_ref() is None
    release.set()
    await child


def test_matching_prefers_method_order_by_default() -> None:
    class StripeMethod(MockMethod):
        name = "stripe"

    stripe = StripeMethod()
    tempo = MockMethod()
    offered = [challenge("tempo"), challenge("stripe", method="stripe")]
    runtime = PaymentRuntime([stripe, tempo])

    assert runtime.match_challenge(offered)[1] is stripe
    assert runtime.match_challenge(offered, prefer_method_order=False)[1] is tempo


def test_matching_uses_intent_capabilities() -> None:
    class SubscriptionMethod(MockMethod):
        intents = MappingProxyType({"subscription": object()})

    method = SubscriptionMethod()
    runtime = PaymentRuntime([method])
    subscription = challenge(intent="subscription")

    assert runtime.match_challenge([subscription]) == (subscription, method)
    with pytest.raises(ValueError, match="No compatible payment method"):
        runtime.match_challenge([challenge()])


async def test_legacy_methods_default_to_charge() -> None:
    class LegacyMethod:
        name = "tempo"

        async def create_credential(self, challenge: Challenge) -> Credential:
            return Credential(challenge=challenge.to_echo(), payload={})

    method = LegacyMethod()
    runtime = PaymentRuntime([method])

    assert runtime.match_challenge([challenge()]) == (challenge(), method)
    with pytest.raises(ValueError, match="No compatible payment method"):
        runtime.match_challenge([challenge(intent="subscription")])
    matched = runtime.match_challenge(
        [challenge(intent="subscription")],
        allow_name_only=True,
    )
    assert matched[1] is method
    assert (await runtime.create_credential(*matched, allow_name_only=True)).payload == {}


@pytest.mark.parametrize(
    "method, message",
    [
        (object(), "payment Methods"),
        (
            type(
                "InvalidIntentsMethod",
                (),
                {
                    "name": "tempo",
                    "intents": ["charge"],
                    "create_credential": lambda self, value: None,
                },
            )(),
            "intents must be a Mapping",
        ),
    ],
)
def test_invalid_methods_are_rejected(method: object, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        PaymentRuntime([method])  # type: ignore[list-item]
