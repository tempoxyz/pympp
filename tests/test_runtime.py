"""Tests for transport-neutral client payment handling."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

import pytest

from mpp import (
    Challenge,
    Credential,
    InvalidChallengeError,
    NoMethodFoundError,
    PaymentExpiredError,
)
from mpp.events import EventDispatcher
from mpp.methods import Method
from mpp.runtime import ChallengeCandidate, ClientMethod, CredentialParams, PaymentRuntime


def challenge(
    identifier: str = "test",
    *,
    method: str = "tempo",
    intent: str = "charge",
    expires: str | None = None,
    currency: str | None = None,
) -> Challenge:
    return Challenge(
        id=identifier,
        method=method,
        intent=intent,
        request={} if currency is None else {"currency": currency},
        expires=expires,
    )


class MockMethod:
    """Records the event loops its client method creates credentials on."""

    def __init__(self, intent: str = "charge", *, name: str = "tempo") -> None:
        self.currency: str | None = None
        self.loops: list[asyncio.AbstractEventLoop] = []
        self.client = ClientMethod(
            method=Method(name=name, intent=intent, request_model=dict, payload_model=dict),
            create_credential=self._create_credential,
            can_handle_challenge=self._can_handle_challenge,
        )

    def _can_handle_challenge(self, challenge: Challenge) -> bool:
        offered = challenge.request.get("currency")
        return self.currency is None or (
            isinstance(offered, str) and offered.lower() == self.currency.lower()
        )

    async def _create_credential(self, params: CredentialParams) -> str:
        self.loops.append(asyncio.get_running_loop())
        return Credential(
            challenge=params.challenge.to_echo(), payload={"ok": True}
        ).to_authorization()


def test_matching_preserves_transport_selection() -> None:
    first_tempo = MockMethod()
    last_tempo = MockMethod()
    stripe = MockMethod("subscription", name="stripe")
    runtime = PaymentRuntime([first_tempo.client, stripe.client, last_tempo.client])
    offered = [
        challenge("stripe", method="stripe", intent="subscription"),
        challenge("tempo", intent="unsupported"),
    ]

    assert runtime.match_challenge(offered) == (offered[0], runtime.methods[1])
    with pytest.raises(NoMethodFoundError, match="No method found for challenges"):
        runtime.match_challenge([offered[1]])
    with pytest.raises(NoMethodFoundError, match="No method found for challenges"):
        runtime.match_challenge([challenge(method="other")])


def test_no_method_found_mirrors_mppx_message() -> None:
    runtime = PaymentRuntime([MockMethod().client])
    offered = [challenge(method="stripe"), challenge(intent="session")]

    with pytest.raises(NoMethodFoundError) as raised:
        runtime.match_challenge(offered)

    assert str(raised.value) == (
        "No method found for challenges: stripe.charge, tempo.session. Available: tempo.charge"
    )
    assert raised.value.challenges == tuple(offered)
    assert isinstance(raised.value, ValueError)


async def test_order_challenges_hook_reorders_and_filters_candidates() -> None:
    first, second = MockMethod(), MockMethod()
    runtime = PaymentRuntime([first.client, second.client])
    offered = [challenge("a"), challenge("b", method="other"), challenge("c")]

    candidates = runtime.challenge_candidates(offered)
    assert [(c.challenge.id, c.method, c.index) for c in candidates] == [
        ("a", first.client, 0),
        ("a", second.client, 0),
        ("c", first.client, 2),
        ("c", second.client, 2),
    ]

    def last_first(found: Sequence[ChallengeCandidate]) -> list[ChallengeCandidate]:
        return list(reversed(found))

    async def none(found: Sequence[ChallengeCandidate]) -> list[ChallengeCandidate]:
        return []

    assert await runtime.order_challenges(offered) == candidates
    assert await runtime.order_challenges(offered, last_first) == candidates[::-1]
    assert await runtime.order_challenges(offered, none) == []


def test_matching_skips_unsupported_intent_before_supported_challenge() -> None:
    method = MockMethod("charge")
    runtime = PaymentRuntime([method.client])
    offered = [
        challenge("unsupported", intent="session"),
        challenge("supported", intent="charge"),
    ]

    assert runtime.match_challenge(offered) == (offered[1], runtime.methods[0])


def test_matching_skips_currency_rejected_by_configured_method() -> None:
    method = MockMethod("charge")
    method.currency = "0xUsdc"
    runtime = PaymentRuntime([method.client])
    offered = [
        challenge("machine-usd", currency="0xMachineUsd"),
        challenge("usdc", currency="0xUSDC"),
    ]

    assert runtime.match_challenge(offered) == (offered[1], runtime.methods[0])
    with pytest.raises(NoMethodFoundError, match="No method found for challenges"):
        runtime.match_challenge(offered[:1])


def test_matching_considers_each_same_key_method_currency_constraint() -> None:
    usdc_method = MockMethod("charge")
    usdc_method.currency = "0xUsdc"
    machine_usd_method = MockMethod("charge")
    machine_usd_method.currency = "0xMachineUsd"
    runtime = PaymentRuntime([usdc_method.client, machine_usd_method.client])

    usdc_challenge = challenge("usdc", currency="0xUSDC")
    machine_usd_challenge = challenge("machine-usd", currency="0xMACHINEUSD")

    assert runtime.match_challenge([usdc_challenge]) == (usdc_challenge, runtime.methods[0])
    assert runtime.match_challenge([machine_usd_challenge]) == (
        machine_usd_challenge,
        runtime.methods[1],
    )


def test_matching_accepts_any_currency_without_currency_pin() -> None:
    method = MockMethod("charge")
    runtime = PaymentRuntime([method.client])
    offered = challenge("machine-usd", currency="0xMachineUsd")

    assert runtime.match_challenge([offered]) == (offered, runtime.methods[0])


def test_preserves_falsey_event_dispatcher() -> None:
    class FalseyEvents(EventDispatcher):
        def __bool__(self) -> bool:
            return False

    events = FalseyEvents()

    assert PaymentRuntime(events=events).events is events


async def test_credential_creation_and_events_use_caller_loop() -> None:
    loop = asyncio.get_running_loop()
    method = MockMethod()
    runtime = PaymentRuntime([method.client])
    event_loops: list[asyncio.AbstractEventLoop] = []
    runtime.events.on("*", lambda _event: event_loops.append(asyncio.get_running_loop()))

    credential = await runtime.create_credential(challenge(), method.client)

    assert credential.payload == {"ok": True}
    assert method.loops == [loop]
    assert event_loops == [loop, loop]


async def test_challenge_handler_can_supply_credential() -> None:
    method = MockMethod()
    supplied = Credential(challenge=challenge("supplied").to_echo(), payload={"event": True})
    created: list[dict[str, Any]] = []
    runtime = PaymentRuntime([method.client])
    runtime.events.on("challenge.received", lambda _payload: supplied)
    runtime.events.on("credential.created", created.append)

    result = await runtime.create_credential(
        challenge("requested"),
        method.client,
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
    runtime = PaymentRuntime([method.client])

    with pytest.raises(ValueError, match="not installed"):
        await runtime.create_credential(challenge(), MockMethod().client)
    with pytest.raises(ValueError, match="does not support"):
        await runtime.create_credential(challenge(method="stripe"), method.client)

    assert method.loops == []


async def test_credential_creation_rejects_mismatched_currency() -> None:
    method = MockMethod()
    method.currency = "0xUsdc"
    runtime = PaymentRuntime([method.client])

    with pytest.raises(ValueError, match="does not accept this challenge"):
        await runtime.create_credential(challenge(currency="0xMachineUsd"), method.client)

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
    runtime = PaymentRuntime([method.client])

    with pytest.raises(error):
        await runtime.create_credential(challenge(expires=expires), method.client)

    assert method.loops == []
