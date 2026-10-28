"""Externally meaningful guarantees for composed server payments."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, field_validator, model_serializer

from mpp import Challenge, Credential, Receipt
from mpp._units import parse_units
from mpp.methods import Method
from mpp.server import (
    Mpp,
    PaymentRequired,
    PaymentVerified,
    RequestContext,
    ServerMethod,
    VerifyContext,
    compose,
    pay,
)
from tests import MockRequest, challenge, challenges, http_request


class MockInput(BaseModel):
    """Route input whose decimal amount is sent in base units of a 2-decimal currency."""

    model_config = ConfigDict(extra="forbid")

    amount: str
    currency: str
    recipient: str
    transformedBy: str | None = None

    @field_validator("amount")
    @classmethod
    def _check_amount(cls, amount: str) -> str:
        parse_units(amount, 18)
        return amount.strip()

    def wire_amount(self) -> str:
        return str(parse_units(self.amount, 2))

    @model_serializer
    def _wire(self) -> dict[str, Any]:
        wire = {
            "amount": self.wire_amount(),
            "currency": self.currency,
            "recipient": self.recipient,
        }
        if self.transformedBy is not None:
            wire["transformedBy"] = self.transformedBy
        return wire


class MockPayload(BaseModel):
    model_config = ConfigDict(extra="allow")


class MockMethod:
    request_model: type[MockInput] = MockInput

    def __init__(self, name: str, intent: str = "charge", reference: str | None = None) -> None:
        self.name = name
        self.reference = reference or name
        self.settlements = 0
        self.server = ServerMethod(
            method=Method(
                name=name,
                intent=intent,
                request_model=self.request_model,
                payload_model=MockPayload,
            ),
            verify=self.verify,
            resolve_request=self.resolve_request,
            defaults={"currency": f"{name}-currency", "recipient": f"{name}-recipient"},
        )

    def resolve_request(self, context: RequestContext) -> dict[str, Any]:
        return {**context.request, "transformedBy": self.name}

    async def verify(self, context: VerifyContext) -> Receipt:
        del context
        self.settlements += 1
        return Receipt.success(self.reference)


def response_challenges(response: Any) -> list[Challenge]:
    if hasattr(response, "raw_headers"):
        values = [
            value.decode()
            for name, value in response.raw_headers
            if name.lower() == b"www-authenticate"
        ]
    else:
        raw = response["headers"]["WWW-Authenticate"]
        values = [raw] if isinstance(raw, str) else raw
    return [Challenge.from_www_authenticate(value) for value in values]


def credential(challenge: Challenge) -> Credential:
    return Credential(challenge=challenge.to_echo(), payload={})


def test_multi_method_creation_validates_configuration() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="secret",
    )

    assert [method.key for method in server.methods] == ["first/charge", "second/charge"]

    with pytest.raises(ValueError, match="methods is required"):
        Mpp(methods=[], realm="api.example.com", secret_key="secret")


def test_compose_validates_public_entries_at_configuration_time() -> None:
    method = MockMethod("first")
    server = Mpp(methods=method.server, realm="api.example.com", secret_key="secret")
    [configured] = server.methods

    with pytest.raises(ValueError, match="at least one entry"):
        server.compose()
    with pytest.raises(ValueError, match="amount"):
        server.compose((configured, {}))
    with pytest.raises(ValueError, match="ammount"):
        server.compose((configured, {"amount": "1", "ammount": "1"}))
    with pytest.raises(ValueError, match=r"meta must be a dict\[str, str\]"):
        server.compose((configured, {"amount": "1", "meta": {"plan": 1}}))
    with pytest.raises(ValueError, match="not registered"):
        server.compose(("first/refund", {"amount": "1"}))
    with pytest.raises(ValueError, match="not registered"):
        server.compose(("other", {"amount": "1"}))


@pytest.mark.asyncio
async def test_explicit_compose_renders_all_offers_and_dispatches_one_payment() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="secret",
    )
    successes: list[dict[str, Any]] = []
    server.on_payment_success(successes.append)
    configured = server.compose(
        (server.methods[0], {"amount": "1.50"}),
        ("second/charge", {"amount": "2.00"}),
    )

    @pay(configured)
    async def endpoint(
        _request: MockRequest,
        credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    request = MockRequest(path="/paid", route="/paid")
    issued = response_challenges(await endpoint(request))
    assert [item.request["amount"] for item in issued] == ["150", "200"]

    paid_request = MockRequest(
        authorization=credential(issued[1]).to_authorization(),
        path="/paid",
        route="/paid",
    )
    assert await endpoint(paid_request) == "second"
    assert second.settlements == 1
    assert [event["method"] for event in successes] == ["second"]


class DecimalInput(MockInput):
    def wire_amount(self) -> str:
        return self.amount


class DecimalAmountMethod(MockMethod):
    """A custom method whose wire amount is a decimal string, not base units."""

    request_model = DecimalInput


@pytest.mark.asyncio
async def test_method_request_model_controls_wire_amount() -> None:
    decimal = DecimalAmountMethod("decimal")
    units = MockMethod("units")
    server = Mpp(
        methods=[decimal.server, units.server], realm="api.example.com", secret_key="secret"
    )
    configured = server.compose(
        ("decimal/charge", {"amount": "0.50"}), ("units/charge", {"amount": "0.50"})
    )

    @pay(configured)
    async def endpoint(
        _request: MockRequest,
        credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    issued = response_challenges(await endpoint(MockRequest(path="/paid", route="/paid")))
    assert [item.request["amount"] for item in issued] == ["0.50", "50"]
    paid_request = MockRequest(
        authorization=credential(issued[0]).to_authorization(),
        path="/paid",
        route="/paid",
    )
    assert await endpoint(paid_request) == "decimal"

    single = Mpp(methods=decimal.server, realm="api.example.com", secret_key="secret")
    unpaid = challenge(await single.charge(amount="0.50")(http_request()))
    assert unpaid.request["amount"] == "0.50"


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", ["", " ", "-1", "NaN", "Infinity", "abc", None, 5])
@pytest.mark.parametrize("entry", ["compose", "charge", "pay"])
async def test_request_model_validates_route_input(amount: Any, entry: str) -> None:
    method = DecimalAmountMethod("decimal")
    server = Mpp(methods=method.server, realm="api.example.com", secret_key="secret")
    with pytest.raises(ValueError):
        if entry == "compose":
            server.compose(("decimal/charge", {"amount": amount}))
        elif entry == "charge":
            await server.charge(amount=amount)(http_request())
        else:

            @pay(server.charge(amount=amount))
            async def endpoint(_request: MockRequest, credential: Credential, receipt: Receipt):
                return receipt.reference

            await endpoint(MockRequest(path="/paid", route="/paid"))


@pytest.mark.asyncio
async def test_implicit_charge_and_pay_are_composition_conveniences() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="secret",
    )

    handler = server.charge(amount="1.50")
    unpaid = challenges(await handler(http_request()))
    assert [item.method for item in unpaid] == ["first", "second"]
    paid = await handler(http_request(credential(unpaid[1]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "second"

    @pay(server.charge(amount="2.00"))
    async def endpoint(
        _request: MockRequest,
        credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    issued = response_challenges(await endpoint(MockRequest(path="/paid")))
    assert [item.method for item in issued] == ["first", "second"]
    assert (
        await endpoint(
            MockRequest(
                authorization=credential(issued[0]).to_authorization(),
                path="/paid",
            )
        )
        == "first"
    )

    only_charge = Mpp(
        methods=[MockMethod("charge").server, MockMethod("session", intent="session").server],
        realm="api.example.com",
        secret_key="secret",
    )
    challenge(await only_charge.charge(amount="1.00")(http_request()))


@pytest.mark.asyncio
async def test_implicit_pay_supports_shared_non_charge_intents() -> None:
    first = MockMethod("first", intent="session")
    second = MockMethod("second", intent="session")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="secret",
    )

    @pay(server.session(amount="1.00"))
    async def endpoint(
        _request: MockRequest,
        credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    issued = response_challenges(await endpoint(MockRequest(path="/session")))
    assert [item.intent for item in issued] == ["session", "session"]
    assert (
        await endpoint(
            MockRequest(
                authorization=credential(issued[1]).to_authorization(),
                path="/session",
            )
        )
        == "second"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_realm", "second_realm", "second_secret", "second_body"),
    [
        ("first.example.com", "second.example.com", "first-secret", b"first"),
        ("shared.example.com", "shared.example.com", "second-secret", b"first"),
        ("shared.example.com", "shared.example.com", "first-secret", b"second"),
    ],
)
async def test_static_nested_compose_preserves_cross_instance_ownership(
    first_realm: str,
    second_realm: str,
    second_secret: str,
    second_body: bytes,
) -> None:
    first_method = MockMethod("shared", reference="first")
    second_method = MockMethod("shared", reference="second")
    first = Mpp(
        methods=first_method.server,
        realm=first_realm,
        secret_key="first-secret",
    )
    second = Mpp(
        methods=second_method.server,
        realm=second_realm,
        secret_key=second_secret,
    )
    first_events: list[dict[str, Any]] = []
    second_events: list[dict[str, Any]] = []
    first.on_payment_success(first_events.append)
    second.on_payment_success(second_events.append)
    first_offer = first.compose(("shared/charge", {"amount": "1.00", "body": b"first"}))
    second_offer = second.compose(("shared/charge", {"amount": "1.00", "body": second_body}))
    configured = compose(first_offer, compose(second_offer))

    issued = challenges(await configured(http_request()))
    assert [item.realm for item in issued] == [first_realm, second_realm]
    assert issued[0].request == issued[1].request

    paid = await configured(http_request(credential(issued[1]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "second"
    assert first_method.settlements == 0
    assert first_events == []
    assert len(second_events) == 1


@pytest.mark.asyncio
async def test_meta_disambiguates_wire_identical_cross_instance_offers() -> None:
    first_method = MockMethod("shared", reference="first")
    second_method = MockMethod("shared", reference="second")
    first = Mpp(
        methods=first_method.server,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    second = Mpp(
        methods=second_method.server,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    configured = compose(
        first.compose(("shared/charge", {"amount": "1.00", "meta": {"plan": "first"}})),
        second.compose(("shared/charge", {"amount": "1.00", "meta": {"plan": "second"}})),
    )

    unpaid = challenges(await configured(http_request()))
    assert [
        {k: v for k, v in (item.opaque or {}).items() if k != "_mpp_nonce"} for item in unpaid
    ] == [
        {"plan": "first"},
        {"plan": "second"},
    ]

    paid = await configured(http_request(credential(unpaid[1]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "second"
    assert first_method.settlements == 0
    assert second_method.settlements == 1


@pytest.mark.asyncio
async def test_wire_identical_cross_instance_offers_fail_closed() -> None:
    first_method = MockMethod("shared", reference="first")
    second_method = MockMethod("shared", reference="second")
    first = Mpp(
        methods=first_method.server,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    second = Mpp(
        methods=second_method.server,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    configured = compose(
        first.compose(("shared/charge", {"amount": "1.00"})),
        second.compose(("shared/charge", {"amount": "1.00"})),
    )

    unpaid = challenges(await configured(http_request()))
    rejected = await configured(http_request(credential(unpaid[1]).to_authorization()))

    assert len(challenges(rejected)) == 2
    assert first_method.settlements == 0
    assert second_method.settlements == 0


@pytest.mark.asyncio
async def test_stable_binding_offers_prefer_the_signed_offer_then_the_first() -> None:
    method = MockMethod("session", intent="session")
    verified: list[dict[str, Any]] = []

    async def verify(context: VerifyContext) -> Receipt:
        verified.append(dict(context.request))
        return Receipt.success("session")

    server = Mpp(
        methods=replace(
            method.server,
            verify=verify,
            stable_binding=lambda request: {
                "currency": request.get("currency"),
                "recipient": request.get("recipient"),
            },
        ),
        realm="api.example.com",
        secret_key="shared-secret",
    )
    configured = server.compose(
        ("session/session", {"amount": "1.00"}),
        ("session/session", {"amount": "2.00"}),
    )

    unpaid = challenges(await configured(http_request()))
    assert len(unpaid) == 2
    # The offer whose challenge the client paid verifies at its own price.
    paid = await configured(http_request(credential(unpaid[1]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert [request["amount"] for request in verified] == ["2.00"]

    # A reusable challenge quoting a price no offer has now is paid by the first offer.
    stale = challenges(
        await server.compose(("session/session", {"amount": "5.00"}))(http_request())
    )
    paid = await configured(http_request(credential(stale[0]).to_authorization()))
    assert isinstance(paid, PaymentVerified)
    assert [request["amount"] for request in verified] == ["2.00", "1.00"]


@pytest.mark.asyncio
async def test_composed_offer_rejects_tampered_opaque() -> None:
    method = MockMethod("first")
    server = Mpp(
        methods=method.server,
        realm="api.example.com",
        secret_key="shared-secret",
    )
    configured = server.compose(
        ("first/charge", {"amount": "1.00", "meta": {"plan": "original"}}),
    )
    issued = challenge(await configured(http_request()))
    tampered_opaque = (
        Challenge.create(
            secret_key="shared-secret",
            realm=issued.realm,
            method=issued.method,
            intent=issued.intent,
            request=issued.request,
            expires=issued.expires,
            digest=issued.digest,
            meta={"plan": "tampered"},
        )
        .to_echo()
        .opaque
    )
    tampered = Credential(
        challenge=replace(issued.to_echo(), opaque=tampered_opaque),
        payload={},
    )

    rejected = await configured(http_request(tampered.to_authorization()))
    assert isinstance(rejected, PaymentRequired)
    assert method.settlements == 0


@pytest.mark.asyncio
async def test_compose_rejects_unusable_authorization_without_settlement() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="shared-secret",
    )
    configured = server.compose(
        ("first/charge", {"amount": "1.00"}),
        ("second/charge", {"amount": "2.00"}),
    )
    first_challenge = challenges(await configured(http_request()))[0]
    unusable = [
        "Bearer token",
        "Payment not-base64!!",
        credential(
            Challenge.create(
                secret_key="shared-secret",
                realm=first_challenge.realm,
                method="unknown",
                intent="charge",
                request=first_challenge.request,
                expires=first_challenge.expires,
            )
        ).to_authorization(),
        credential(
            Challenge.create(
                secret_key="shared-secret",
                realm=first_challenge.realm,
                method="first",
                intent="refund",
                request=first_challenge.request,
                expires=first_challenge.expires,
            )
        ).to_authorization(),
    ]

    for authorization in unusable:
        rejected = await configured(http_request(authorization))
        assert len(challenges(rejected)) == 2

    assert first.settlements == 0
    assert second.settlements == 0


@pytest.mark.asyncio
async def test_repeated_offers_keep_body_hmac_and_route_scope_bindings() -> None:
    method = MockMethod("first")
    server = Mpp(methods=method.server, realm="api.example.com", secret_key="secret")
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)
    body_calls = 0

    def body(request: Any) -> bytes:
        nonlocal body_calls
        body_calls += 1
        assert request.body is not None
        return request.body

    configured = server.compose(
        ("first/charge", {"amount": "1.00", "body": body}),
        ("first/charge", {"amount": "2.00", "body": body}),
    )
    url = "https://api.example.com/paid"
    request = http_request(url=url, route="/paid", body=b"bound body")
    unpaid = challenges(await configured(request))
    assert [item.request["amount"] for item in unpaid] == ["100", "200"]
    assert body_calls == 1
    selected = credential(unpaid[1])

    forged = Credential(
        challenge=Challenge.create(
            secret_key="wrong-secret",
            realm="api.example.com",
            method="first",
            intent="charge",
            request=unpaid[1].request,
            expires=unpaid[1].expires,
            digest=unpaid[1].digest,
        ).to_echo(),
        payload={},
    )
    rejected = [
        (forged, url, "/paid", b"bound body"),
        (selected, url, "/paid", b"wrong body"),
        (selected, "https://api.example.com/other", "/other", b"bound body"),
    ]
    for submitted, submitted_url, route, submitted_body in rejected:
        result = await configured(
            http_request(
                submitted.to_authorization(), url=submitted_url, route=route, body=submitted_body
            )
        )
        assert isinstance(result, PaymentRequired)

    paid = await configured(
        http_request(selected.to_authorization(), url=url, route="/paid", body=b"bound body")
    )
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "first"
    assert method.settlements == 1
    assert len(failures) == 3


@pytest.mark.asyncio
async def test_requires_auth_compose_advertises_and_accepts_payment_authorization() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp(
        methods=[first.server, second.server],
        realm="api.example.com",
        secret_key="secret",
        requires_auth=True,
    )
    configured = server.compose(
        ("first/charge", {"amount": "1.00"}),
        ("second/charge", {"amount": "1.00"}),
    )

    unpaid = challenges(await configured(http_request("Bearer app-token")))
    assert all(item.header == "Payment-Authorization" for item in unpaid)
    assert all(
        'header="Payment-Authorization"' in item.to_www_authenticate(server.realm)
        for item in unpaid
    )

    paid = await configured(
        http_request(
            "Bearer app-token",
            payment_authorization=credential(unpaid[1]).to_authorization(),
        )
    )
    assert isinstance(paid, PaymentVerified)
    assert paid.receipt.reference == "second"
    assert second.settlements == 1
