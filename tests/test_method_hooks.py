"""Coverage for per-method offer and payment-success hooks."""

from __future__ import annotations

from typing import Any, cast

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods.stripe import stripe
from mpp.methods.tempo import tempo
from mpp.server import ComposedChallenges, Mpp, compose, intent
from tests import MockRequest


class ThirdPartyMethod:
    def __init__(
        self,
        name: str,
        *,
        can_offer: CanOfferFn | None = None,
        on_payment_success: PaymentSuccessHandler | None = None,
    ) -> None:
        self.name = name
        self.can_offer = can_offer
        self.on_payment_success = on_payment_success
        self.currency = f"{name}-currency"
        self.recipient = f"{name}-recipient"
        self.decimals = 2

        @intent(name="charge")
        async def verify(_credential: Credential, _request: dict[str, Any]) -> Receipt:
            return Receipt.success(name)

        self.intents = {"charge": verify}

    def transform_request(
        self, request: dict[str, Any], _credential: Credential | None
    ) -> dict[str, Any]:
        return {**request, "transformedBy": self.name}

    async def create_credential(self, challenge: Challenge) -> Credential:  # pragma: no cover
        del challenge
        raise NotImplementedError


def create_server(*methods: ThirdPartyMethod) -> Mpp:
    return Mpp.create(
        methods=methods,
        realm="api.example.com",
        secret_key="secret",
    )


def credential(challenge: Challenge) -> Credential:
    return Credential(challenge=challenge.to_echo(), payload={})


@pytest.mark.asyncio
async def test_can_offer_filters_normalized_composed_offers_before_challenge_events() -> None:
    seen: list[tuple[str, dict[str, Any]]] = []

    def reject_first(request: dict[str, Any]) -> bool:
        seen.append(("first", request))
        return False

    async def offer_second(request: dict[str, Any]) -> bool:
        seen.append(("second", request))
        request["amount"] = "999"
        request["_mppx_scope"]["resource"] = "/tampered"
        return True

    first = ThirdPartyMethod("first", can_offer=reject_first)
    second = ThirdPartyMethod("second", can_offer=offer_second)
    server = create_server(first, second)
    challenged: list[str] = []
    server.on_challenge_created(lambda payload: challenged.append(payload["method"]))

    result = await server.compose(
        (first, {"amount": "1.50"}),
        (second, {"amount": "1.50"}),
    ).verify(None, MockRequest(path="/paid", route="/paid"))

    assert isinstance(result, ComposedChallenges)
    assert [challenge.method for challenge in result.challenges] == ["second"]
    assert result.challenges[0].request["amount"] == "150"
    assert result.challenges[0].request["_mppx_scope"]["resource"] == "/paid"
    assert challenged == ["second"]
    assert [name for name, _request in seen] == ["first", "second"]
    assert seen[0][1] == {
        "amount": "150",
        "currency": "first-currency",
        "recipient": "first-recipient",
        "transformedBy": "first",
        "_mppx_scope": {"resource": "/paid", "route": "/paid"},
    }


@pytest.mark.asyncio
async def test_can_offer_checks_repeated_offers_but_not_direct_handlers_or_redemption() -> None:
    amounts: list[str] = []

    def can_offer(request: dict[str, Any]) -> bool:
        amounts.append(request["amount"])
        return request["amount"] == "200"

    method = ThirdPartyMethod("only", can_offer=can_offer)
    server = create_server(method)

    direct = await server.charge(None, "1.00")
    assert isinstance(direct, Challenge)
    assert amounts == []

    configured = server.compose(
        (method, {"amount": "1.00"}),
        (method, {"amount": "2.00"}),
    )
    result = await configured.verify(None)
    assert isinstance(result, ComposedChallenges)
    assert [challenge.request["amount"] for challenge in result.challenges] == ["200"]
    assert amounts == ["100", "200"]

    paid = await configured.verify(credential(result.challenges[0]).to_authorization())
    assert not isinstance(paid, ComposedChallenges)
    assert paid[1].reference == "only"
    assert amounts == ["100", "200"]


@pytest.mark.asyncio
async def test_can_offer_rejects_invalid_results_and_propagates_errors() -> None:
    non_callable = ThirdPartyMethod("non-callable", can_offer=cast(CanOfferFn, object()))
    with pytest.raises(ValueError, match="can_offer must be callable"):
        await create_server(non_callable).compose((non_callable, {"amount": "1.00"})).verify(None)

    invalid = ThirdPartyMethod("invalid", can_offer=lambda _request: cast(Any, "yes"))
    with pytest.raises(ValueError, match="can_offer must return bool"):
        await create_server(invalid).compose((invalid, {"amount": "1.00"})).verify(None)

    def fail(_request: dict[str, Any]) -> bool:
        raise RuntimeError("offer hook failure")

    failing = ThirdPartyMethod("failing", can_offer=fail)
    with pytest.raises(RuntimeError, match="offer hook failure"):
        await create_server(failing).compose((failing, {"amount": "1.00"})).verify(None)

    unavailable = ThirdPartyMethod("unavailable", can_offer=lambda _request: False)
    with pytest.raises(ValueError, match="No payment offers"):
        await create_server(unavailable).compose((unavailable, {"amount": "1.00"})).verify(None)


@pytest.mark.asyncio
async def test_success_hook_runs_only_for_the_settled_method() -> None:
    first_calls: list[ServerPaymentSuccessPayload] = []
    second_calls: list[ServerPaymentSuccessPayload] = []

    async def record_second(payload: ServerPaymentSuccessPayload) -> None:
        second_calls.append(payload)

    first = ThirdPartyMethod("first", on_payment_success=first_calls.append)
    second = ThirdPartyMethod("second", on_payment_success=record_second)
    server = create_server(first, second)
    global_calls: list[ServerPaymentSuccessPayload] = []
    server.on_payment_success(global_calls.append)
    configured = server.compose(
        (first, {"amount": "1.00"}),
        (second, {"amount": "2.00"}),
    )
    offered = await configured.verify(None)
    assert isinstance(offered, ComposedChallenges)

    paid = await configured.verify(credential(offered.challenges[1]).to_authorization())

    assert not isinstance(paid, ComposedChallenges)
    assert first_calls == []
    assert second_calls == global_calls
    assert second_calls[0]["method"] == "second"
    assert second_calls[0]["intent"] == "charge"
    assert second_calls[0]["request"]["amount"] == "200"
    assert second_calls[0]["receipt"].reference == "second"


@pytest.mark.asyncio
async def test_static_composition_uses_only_the_owning_method_success_hook() -> None:
    first_calls: list[ServerPaymentSuccessPayload] = []
    second_calls: list[ServerPaymentSuccessPayload] = []
    first_method = ThirdPartyMethod("shared", on_payment_success=first_calls.append)
    second_method = ThirdPartyMethod("shared", on_payment_success=second_calls.append)
    first = Mpp.create(
        method=first_method,
        realm="api.example.com",
        secret_key="first-secret",
    )
    second = Mpp.create(
        method=second_method,
        realm="api.example.com",
        secret_key="second-secret",
    )
    configured = compose(
        first.compose((first_method, {"amount": "1.00"})),
        second.compose((second_method, {"amount": "1.00"})),
    )
    offered = await configured.verify(None)
    assert isinstance(offered, ComposedChallenges)

    paid = await configured.verify(credential(offered.challenges[1]).to_authorization())

    assert not isinstance(paid, ComposedChallenges)
    assert first_calls == []
    assert [payload["receipt"].reference for payload in second_calls] == ["shared"]


@pytest.mark.asyncio
async def test_success_hook_errors_do_not_interrupt_bound_broadcast() -> None:
    calls: list[str] = []

    def fail(payload: ServerPaymentSuccessPayload) -> None:
        calls.append(payload["receipt"].reference or "")
        raise RuntimeError("hook failure")

    method = ThirdPartyMethod("only", on_payment_success=fail)
    server = create_server(method)
    challenge = await server.charge(None, "1.00")
    assert isinstance(challenge, Challenge)

    receipt = await server.broadcast_credential(credential(challenge))

    assert receipt.reference == "only"
    assert calls == ["only"]


def test_method_factories_preserve_hooks() -> None:
    def can_offer(_request: dict[str, Any]) -> bool:
        return True

    def on_payment_success(_payload: ServerPaymentSuccessPayload) -> None:
        pass

    stripe_method = stripe(
        intents={},
        currency="usd",
        recipient="acct_123",
        can_offer=can_offer,
        on_payment_success=on_payment_success,
    )
    tempo_method = tempo(
        intents={},
        currency="0xcurrency",
        recipient="0xrecipient",
        can_offer=can_offer,
        on_payment_success=on_payment_success,
    )

    assert stripe_method.can_offer is tempo_method.can_offer is can_offer
    assert stripe_method.on_payment_success is tempo_method.on_payment_success is on_payment_success


def test_non_callable_success_hook_is_rejected_at_configuration_time() -> None:
    method = ThirdPartyMethod("only", on_payment_success=cast(PaymentSuccessHandler, object()))
    with pytest.raises(ValueError, match="on_payment_success must be callable"):
        create_server(method)
