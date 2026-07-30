"""Tests for transport-neutral client payment handling."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mpp import Challenge, Credential, InvalidChallengeError, PaymentExpiredError
from mpp.events import EventDispatcher
from mpp.runtime import PaymentRuntime


def challenge(
    identifier: str = "test",
    *,
    method: str = "tempo",
    intent: str = "charge",
    expires: str | None = None,
) -> Challenge:
    return Challenge(
        id=identifier,
        method=method,
        intent=intent,
        request={},
        expires=expires,
    )


class MockMethod:
    name = "tempo"

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.loops.append(asyncio.get_running_loop())
        return Credential(challenge=challenge.to_echo(), payload={"ok": True})


def test_matching_preserves_transport_selection() -> None:
    class StripeMethod(MockMethod):
        name = "stripe"

    first_tempo = MockMethod()
    last_tempo = MockMethod()
    stripe = StripeMethod()
    runtime = PaymentRuntime([first_tempo, stripe, last_tempo])
    offered = [
        challenge("stripe", method="stripe", intent="subscription"),
        challenge("tempo", intent="unsupported"),
    ]

    assert runtime.match_challenge(offered) == (offered[0], stripe)
    assert runtime.match_challenge([offered[1]]) == (offered[1], last_tempo)
    with pytest.raises(ValueError, match="No compatible payment method"):
        runtime.match_challenge([challenge(method="other")])


def test_preserves_falsey_event_dispatcher() -> None:
    class FalseyEvents(EventDispatcher):
        def __bool__(self) -> bool:
            return False

    events = FalseyEvents()

    assert PaymentRuntime(events=events).events is events


async def test_credential_creation_and_events_use_caller_loop() -> None:
    loop = asyncio.get_running_loop()
    method = MockMethod()
    runtime = PaymentRuntime([method])
    event_loops: list[asyncio.AbstractEventLoop] = []
    runtime.events.on("*", lambda _event: event_loops.append(asyncio.get_running_loop()))

    credential = await runtime.create_credential(challenge(), method)

    assert credential.payload == {"ok": True}
    assert method.loops == [loop]
    assert event_loops == [loop, loop]


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


async def test_credential_creation_validates_method() -> None:
    method = MockMethod()
    runtime = PaymentRuntime([method])

    with pytest.raises(ValueError, match="not installed"):
        await runtime.create_credential(challenge(), MockMethod())
    with pytest.raises(ValueError, match="does not support"):
        await runtime.create_credential(challenge(method="stripe"), method)

    assert method.loops == []


@pytest.mark.parametrize(
    ("expires", "error"),
    [
        ("not-a-date", InvalidChallengeError),
        ("2020-01-01T00:00:00", InvalidChallengeError),
        ("2020-01-01T00:00:00Z", PaymentExpiredError),
    ],
)
async def test_credential_creation_rejects_invalid_expiry(
    expires: str,
    error: type[Exception],
) -> None:
    method = MockMethod()
    runtime = PaymentRuntime([method])

    with pytest.raises(error):
        await runtime.create_credential(challenge(expires=expires), method)

    assert method.loops == []
