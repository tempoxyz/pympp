"""Coverage for per-method offer and payment-success hooks."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mpp import Challenge, Credential, Receipt
from mpp._units import parse_units
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn, Method, PaymentSuccessHandler
from mpp.methods.stripe import server as stripe_server
from mpp.methods.tempo import server as tempo_server
from mpp.server import (
    Mpp,
    OfferSelectionContext,
    PaymentVerified,
    RequestContext,
    ServerMethod,
    ServerOffer,
    VerifyContext,
    compose,
)
from tests import challenge, challenges, http_request


class Wire(BaseModel):
    model_config = ConfigDict(extra="allow")


def third_party_method(
    name: str,
    *,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
    request_model: type[BaseModel] = Wire,
    verify: Any = None,
) -> ServerMethod:
    async def settle(_context: VerifyContext) -> Receipt:
        return Receipt.success(name)

    def resolve_request(context: RequestContext) -> dict[str, Any]:
        request = {**context.request, "transformedBy": name}
        if "amount" in request:
            request["amount"] = str(parse_units(request["amount"], 2))
        return request

    return ServerMethod(
        method=Method(name=name, intent="charge", request_model=request_model, payload_model=Wire),
        verify=verify or settle,
        resolve_request=resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        defaults={"currency": f"{name}-currency", "recipient": f"{name}-recipient"},
    )


def create_server(*methods: ServerMethod) -> Mpp:
    return Mpp(
        methods=list(methods),
        realm="api.example.com",
        secret_key="secret",
    )


def credential(challenge: Challenge) -> Credential:
    return Credential(challenge=challenge.to_echo(), payload={})


async def test_generic_preparation_consumes_private_input_without_changing_protocol():
    seen = []

    class PrivateInput(BaseModel):
        model_config = ConfigDict(extra="forbid", populate_by_name=True)

        amount: str
        currency: str
        recipient: str
        transformed_by: str = Field(alias="transformedBy")
        private_value: str | None = Field(default=None, exclude=True)

    async def verify(context: VerifyContext) -> Receipt:
        seen.append(context.request.get("private_value"))
        return Receipt.success("custom")

    method = third_party_method("custom", request_model=PrivateInput, verify=verify)
    server = create_server(method)
    events = []
    server.on_payment_success(events.append)
    for private_value in ("first", "second"):
        handler = server.charge(amount="1.50", private_value=private_value)
        unpaid = challenge(await handler(http_request()))
        assert "private_value" not in unpaid.request
        assert unpaid.request["transformedBy"] == "custom"
        assert unpaid.request["amount"] == "150"
        paid = await handler(http_request(credential(unpaid).to_authorization()))
        assert isinstance(paid, PaymentVerified)
    assert seen == ["first", "second"]
    assert all("private_value" not in event["request"] for event in events)
    with pytest.raises(ValidationError, match="typo"):
        server.compose(("custom/charge", cast(Any, {"amount": "1.50", "typo": "bad"})))


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

    first = third_party_method("first", can_offer=reject_first)
    second = third_party_method("second", can_offer=offer_second)
    server = create_server(first, second)
    challenged: list[str] = []
    server.on_challenge_created(lambda payload: challenged.append(payload["method"]))

    result = challenges(
        await server.compose(
            ("first/charge", {"amount": "1.50"}),
            ("second/charge", {"amount": "1.50"}),
        )(http_request(url="https://test.example.com/paid", route="/paid"))
    )

    assert [issued.method for issued in result] == ["second"]
    assert result[0].request["amount"] == "150"
    assert result[0].request["_mppx_scope"]["resource"] == "/paid"
    assert challenged == ["second"]
    assert [name for name, _request in seen] == ["first", "second"]
    assert seen[0][1] == {
        "amount": "150",
        "currency": "first-currency",
        "recipient": "first-recipient",
        "transformedBy": "first",
        "_mppx_scope": {
            "http_method": "GET",
            "resource": "/paid",
            "route": "/paid",
        },
    }


@pytest.mark.asyncio
async def test_can_offer_checks_repeated_offers_but_not_direct_handlers_or_redemption() -> None:
    amounts: list[str] = []

    def can_offer(request: dict[str, Any]) -> bool:
        amounts.append(request["amount"])
        return request["amount"] == "200"

    method = third_party_method("only", can_offer=can_offer)
    server = Mpp(methods=method, realm="api.example.com", secret_key="secret")

    challenge(await server.charge(amount="1.00")(http_request()))
    assert amounts == []

    configured = server.compose(
        ("only/charge", {"amount": "1.00"}),
        ("only/charge", {"amount": "2.00"}),
    )
    result = challenges(await configured(http_request()))
    assert [issued.request["amount"] for issued in result] == ["200"]
    assert amounts == ["100", "200"]

    paid = await configured(http_request(credential(result[0]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "only"
    assert amounts == ["100", "200"]


@pytest.mark.asyncio
async def test_implicit_charge_keeps_composed_result_when_one_method_is_filtered() -> None:
    first = third_party_method("first", can_offer=lambda _request: False)
    second = third_party_method("second", can_offer=lambda _request: True)

    result = challenges(await create_server(first, second).charge(amount="1.00")(http_request()))

    assert [issued.method for issued in result] == ["second"]


@pytest.mark.asyncio
async def test_can_offer_rejects_invalid_results_and_propagates_errors() -> None:
    with pytest.raises(ValueError, match="can_offer must be callable"):
        third_party_method("non-callable", can_offer=cast(CanOfferFn, object()))

    invalid = third_party_method("invalid", can_offer=lambda _request: cast(Any, "yes"))
    with pytest.raises(ValueError, match="can_offer must return bool"):
        await create_server(invalid).compose(("invalid/charge", {"amount": "1.00"}))(http_request())

    def fail(_request: dict[str, Any]) -> bool:
        raise RuntimeError("offer hook failure")

    failing = third_party_method("failing", can_offer=fail)
    with pytest.raises(RuntimeError, match="offer hook failure"):
        await create_server(failing).compose(("failing/charge", {"amount": "1.00"}))(http_request())

    unavailable = third_party_method("unavailable", can_offer=lambda _request: False)
    with pytest.raises(ValueError, match="No payment offers"):
        await create_server(unavailable).compose(("unavailable/charge", {"amount": "1.00"}))(
            http_request()
        )


@pytest.mark.asyncio
async def test_success_hook_runs_only_for_the_settled_method() -> None:
    first_calls: list[ServerPaymentSuccessPayload] = []
    second_calls: list[ServerPaymentSuccessPayload] = []

    async def record_second(payload: ServerPaymentSuccessPayload) -> None:
        second_calls.append(payload)

    first = third_party_method("first", on_payment_success=first_calls.append)
    second = third_party_method("second", on_payment_success=record_second)
    server = create_server(first, second)
    global_calls: list[ServerPaymentSuccessPayload] = []
    server.on_payment_success(global_calls.append)
    configured = server.compose(
        ("first/charge", {"amount": "1.00"}),
        ("second/charge", {"amount": "2.00"}),
    )
    offered = challenges(await configured(http_request()))

    paid = await configured(http_request(credential(offered[1]).to_authorization()))

    assert isinstance(paid, PaymentVerified)
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
    first_method = third_party_method("shared", on_payment_success=first_calls.append)
    second_method = third_party_method("shared", on_payment_success=second_calls.append)
    first = Mpp(
        methods=first_method,
        realm="api.example.com",
        secret_key="first-secret",
    )
    second = Mpp(
        methods=second_method,
        realm="api.example.com",
        secret_key="second-secret",
    )
    configured = compose(
        first.compose(("shared/charge", {"amount": "1.00"})),
        second.compose(("shared/charge", {"amount": "1.00"})),
    )
    offered = challenges(await configured(http_request()))

    paid = await configured(http_request(credential(offered[1]).to_authorization()))

    assert isinstance(paid, PaymentVerified)
    assert first_calls == []
    assert [payload["receipt"].reference for payload in second_calls] == ["shared"]


@pytest.mark.asyncio
async def test_success_hook_errors_do_not_interrupt_bound_broadcast() -> None:
    calls: list[str] = []

    def fail(payload: ServerPaymentSuccessPayload) -> None:
        calls.append(payload["receipt"].reference or "")
        raise RuntimeError("hook failure")

    method = third_party_method("only", on_payment_success=fail)
    server = create_server(method)
    issued = challenge(await server.charge(amount="1.00")(http_request()))

    receipt = await server.broadcast_credential(credential(issued))

    assert receipt.reference == "only"
    assert calls == ["only"]


def test_method_factories_preserve_hooks() -> None:
    def can_offer(_request: dict[str, Any]) -> bool:
        return True

    def on_payment_success(_payload: ServerPaymentSuccessPayload) -> None:
        pass

    stripe_method = stripe_server.charge(
        network_id="profile_123",
        secret_key="sk_test_123",
        currency="usd",
        recipient="acct_123",
        can_offer=can_offer,
        on_payment_success=on_payment_success,
    )
    [tempo_method] = tempo_server.charge(
        currency="0x20c0000000000000000000000000000000000000",
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        can_offer=can_offer,
        on_payment_success=on_payment_success,
    )

    assert stripe_method.can_offer is tempo_method.can_offer is can_offer
    assert stripe_method.on_payment_success is tempo_method.on_payment_success is on_payment_success


def test_non_callable_success_hook_is_rejected_at_configuration_time() -> None:
    with pytest.raises(ValueError, match="on_payment_success must be callable"):
        third_party_method("only", on_payment_success=cast(PaymentSuccessHandler, object()))


@pytest.mark.asyncio
async def test_select_offers_narrows_composed_offers_in_order() -> None:
    seen: list[tuple[tuple[ServerOffer, ...], OfferSelectionContext]] = []

    async def select(
        offers: tuple[ServerOffer, ...], context: OfferSelectionContext
    ) -> list[ServerOffer]:
        seen.append((offers, context))
        return [offer for offer in offers if offer.method.name != "second"]

    first = third_party_method("first")
    second = third_party_method("second", can_offer=lambda _request: True)
    third = third_party_method("third")
    unavailable = third_party_method("unavailable", can_offer=lambda _request: False)
    server = Mpp(
        methods=[first, second, third, unavailable],
        realm="api.example.com",
        secret_key="secret",
        select_offers=select,
    )
    challenged: list[str] = []
    server.on_challenge_created(lambda payload: challenged.append(payload["method"]))
    configured = server.compose(
        ("first/charge", {"amount": "1.00"}),
        ("second/charge", {"amount": "1.00"}),
        ("unavailable/charge", {"amount": "1.00"}),
        ("third/charge", {"amount": "1.00"}),
    )
    request = http_request(url="https://test.example.com/paid", route="/paid")

    result = challenges(await configured(request))

    assert [issued.method for issued in result] == ["first", "third"]
    assert challenged == ["first", "third"]
    offers, context = seen[0]
    assert context.request is request
    assert [offer.key for offer in offers] == ["first/charge", "second/charge", "third/charge"]
    assert offers[1].method is second
    assert offers[0].request["amount"] == "100"
    assert offers[0].request["_mppx_scope"]["resource"] == "/paid"
    with pytest.raises(TypeError):
        cast(Any, offers[0].request)["amount"] = "999"

    # A credential for an offer the selector drops still pays: selection only shapes challenges.
    unselected = third_party_method("second")
    issuer = Mpp(methods=[first, unselected], realm="api.example.com", secret_key="secret")
    offered = challenges(await issuer.charge(amount="1.00")(http_request()))
    paid = await server.charge(amount="1.00")(
        http_request(credential(offered[1]).to_authorization())
    )
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "second"


@pytest.mark.asyncio
async def test_select_offers_skips_direct_handlers_and_keeps_nested_groups() -> None:
    calls: list[list[str]] = []

    def select(
        offers: tuple[ServerOffer, ...], _context: OfferSelectionContext
    ) -> tuple[ServerOffer, ...]:
        calls.append([offer.key for offer in offers])
        return offers[-1:]

    single = Mpp(
        methods=third_party_method("only"),
        realm="api.example.com",
        secret_key="secret",
        select_offers=select,
    )
    challenge(await single.charge(amount="1.00")(http_request()))
    assert calls == []

    server = create_server(third_party_method("first"), third_party_method("second"))
    selecting = Mpp(
        methods=[third_party_method("third"), third_party_method("fourth")],
        realm="api.example.com",
        secret_key="secret",
        select_offers=select,
    )
    configured = compose(
        server.compose(("first/charge", {"amount": "1.00"})),
        selecting.charge(amount="1.00"),
        server.compose(("second/charge", {"amount": "1.00"})),
    )

    result = challenges(await configured(http_request()))

    assert [issued.method for issued in result] == ["first", "fourth", "second"]
    assert calls == [["third/charge", "fourth/charge"]]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("choose", "error", "match"),
    [
        (lambda offers: [], ValueError, "at least one offer"),
        (lambda offers: offers[0], TypeError, "sequence of offers"),
        (lambda offers: [replace(offers[0])], ValueError, "only offers from its input"),
        (lambda offers: [offers[1], offers[0]], ValueError, "preserve offer order"),
        (lambda offers: [offers[0], offers[0]], ValueError, "preserve offer order"),
    ],
)
async def test_select_offers_rejects_invalid_selections(
    choose: Any, error: type, match: str
) -> None:
    server = Mpp(
        methods=[third_party_method("first"), third_party_method("second")],
        realm="api.example.com",
        secret_key="secret",
        select_offers=lambda offers, _context: choose(offers),
    )
    with pytest.raises(error, match=match):
        await server.charge(amount="1.00")(http_request())


def test_select_offers_must_be_callable() -> None:
    with pytest.raises(ValueError, match="select_offers must be callable"):
        Mpp(
            methods=third_party_method("only"),
            realm="api.example.com",
            secret_key="secret",
            select_offers=cast(Any, object()),
        )
