"""Externally meaningful guarantees for composed server payments."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any, cast

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.server import ComposedChallenges, Intent, Mpp, VerifiableIntent, compose
from mpp.store import MemoryStore
from tests import MockRequest


class MockIntent:
    def __init__(self, name: str, reference: str) -> None:
        self.name = name
        self.reference = reference
        self._store: MemoryStore | None = None
        self.settlements = 0

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        del credential, request
        self.settlements += 1
        return Receipt.success(self.reference)


class MockMethod:
    def __init__(self, name: str, intent: str = "charge", reference: str | None = None) -> None:
        self.name = name
        self.currency = f"{name}-currency"
        self.recipient = f"{name}-recipient"
        self.decimals = 2
        self.intent = MockIntent(intent, reference or name)
        self.intents: Mapping[str, Intent | VerifiableIntent] = {intent: self.intent}

    def transform_request(
        self,
        request: dict[str, Any],
        _credential: Credential | None,
    ) -> dict[str, Any]:
        return {**request, "transformedBy": self.name}

    async def create_credential(self, challenge: Challenge) -> Credential:
        del challenge
        raise NotImplementedError


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


def test_multi_method_creation_wires_store_and_validates_configuration() -> None:
    class Server(Mpp):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.received_store = kwargs.get("store")
            super().__init__(*args, **kwargs)

    first = MockMethod("first")
    second = MockMethod("second")
    store = MemoryStore()
    server = Server.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="secret",
        store=store,
    )

    assert isinstance(server, Server)
    assert server.method is first
    assert server.methods == (first, second)
    assert first.intent._store is store
    assert second.intent._store is store
    assert server.received_store is store

    create = cast(Any, Mpp.create)
    with pytest.raises(ValueError, match="method= or methods="):
        create(realm="api.example.com", secret_key="secret")
    with pytest.raises(ValueError, match="not both"):
        create(method=first, methods=[second])
    with pytest.raises(ValueError, match="unique"):
        Mpp.create(
            methods=[first, first],
            realm="api.example.com",
            secret_key="secret",
        )


def test_compose_validates_public_entries_at_configuration_time() -> None:
    method = MockMethod("first")
    server = Mpp.create(method=method, realm="api.example.com", secret_key="secret")

    with pytest.raises(ValueError, match="at least one entry"):
        server.compose()
    with pytest.raises(ValueError, match="non-empty string amount"):
        server.compose(cast(Any, (method, {})))
    with pytest.raises(ValueError, match="unsupported compose option"):
        server.compose(cast(Any, (method, {"amount": "1", "ammount": "1"})))
    with pytest.raises(ValueError, match=r"meta must be a dict\[str, str\]"):
        server.compose(cast(Any, (method, {"amount": "1", "meta": {"plan": 1}})))
    with pytest.raises(ValueError, match="does not support refund"):
        server.compose(cast(Any, ("first/refund", {"amount": "1"})))
    with pytest.raises(ValueError, match="unknown payment method"):
        server.compose(cast(Any, ("other", {"amount": "1"})))


@pytest.mark.asyncio
async def test_explicit_compose_renders_all_offers_and_dispatches_one_payment() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="secret",
    )
    successes: list[dict[str, Any]] = []
    server.on_payment_success(successes.append)
    configured = server.compose(
        (first, {"amount": "1.50"}),
        ("second/charge", {"amount": "2.00"}),
    )

    @configured
    async def endpoint(
        _request: MockRequest,
        _credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    request = MockRequest(path="/paid", route="/paid")
    challenges = response_challenges(await endpoint(request))
    assert [item.request["amount"] for item in challenges] == ["150", "200"]

    paid_request = MockRequest(
        authorization=credential(challenges[1]).to_authorization(),
        path="/paid",
        route="/paid",
    )
    assert await endpoint(paid_request) == "second"
    assert second.intent.settlements == 1
    assert [event["method"] for event in successes] == ["second"]


@pytest.mark.asyncio
async def test_implicit_charge_and_pay_are_composition_conveniences() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="secret",
    )

    unpaid = await server.charge(None, "1.50")
    assert isinstance(unpaid, ComposedChallenges)
    assert [item.method for item in unpaid.challenges] == ["first", "second"]
    paid = await server.charge(
        credential(unpaid.challenges[1]).to_authorization(),
        "1.50",
    )
    assert not isinstance(paid, (Challenge, ComposedChallenges))
    assert paid[1].reference == "second"

    @server.pay(amount="2.00")
    async def endpoint(
        _request: MockRequest,
        _credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    challenges = response_challenges(await endpoint(MockRequest(path="/paid")))
    assert [item.method for item in challenges] == ["first", "second"]
    assert (
        await endpoint(
            MockRequest(
                authorization=credential(challenges[0]).to_authorization(),
                path="/paid",
            )
        )
        == "first"
    )

    only_charge = Mpp.create(
        methods=[MockMethod("charge"), MockMethod("session", intent="session")],
        realm="api.example.com",
        secret_key="secret",
    )
    assert isinstance(await only_charge.charge(None, "1.00"), Challenge)


@pytest.mark.asyncio
async def test_implicit_pay_supports_shared_non_charge_intents() -> None:
    first = MockMethod("first", intent="session")
    second = MockMethod("second", intent="session")
    server = Mpp.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="secret",
    )

    @server.pay(amount="1.00", intent="session")
    async def endpoint(
        _request: MockRequest,
        _credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    challenges = response_challenges(await endpoint(MockRequest(path="/session")))
    assert [item.intent for item in challenges] == ["session", "session"]
    assert (
        await endpoint(
            MockRequest(
                authorization=credential(challenges[1]).to_authorization(),
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
    first = Mpp.create(
        method=first_method,
        realm=first_realm,
        secret_key="first-secret",
    )
    second = Mpp.create(
        method=second_method,
        realm=second_realm,
        secret_key=second_secret,
    )
    first_events: list[dict[str, Any]] = []
    second_events: list[dict[str, Any]] = []
    first.on_payment_success(first_events.append)
    second.on_payment_success(second_events.append)
    first_offer = first.compose((first_method, {"amount": "1.00"}), body=b"first")
    second_offer = second.compose((second_method, {"amount": "1.00"}), body=second_body)
    configured = compose(first_offer, compose(second_offer))

    @configured
    async def endpoint(
        _request: MockRequest,
        _credential: Credential,
        receipt: Receipt,
    ) -> str:
        return receipt.reference

    challenges = response_challenges(await endpoint(MockRequest()))
    assert [item.realm for item in challenges] == [first_realm, second_realm]
    assert challenges[0].request == challenges[1].request

    paid = await configured.verify(credential(challenges[1]).to_authorization())
    assert not isinstance(paid, ComposedChallenges)
    assert paid[1].reference == "second"
    assert first_method.intent.settlements == 0
    assert first_events == []
    assert len(second_events) == 1


@pytest.mark.asyncio
async def test_meta_disambiguates_wire_identical_cross_instance_offers() -> None:
    first_method = MockMethod("shared", reference="first")
    second_method = MockMethod("shared", reference="second")
    first = Mpp.create(
        method=first_method,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    second = Mpp.create(
        method=second_method,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    configured = compose(
        first.compose((first_method, {"amount": "1.00", "meta": {"plan": "first"}})),
        second.compose((second_method, {"amount": "1.00", "meta": {"plan": "second"}})),
    )

    unpaid = await configured.verify(None)
    assert isinstance(unpaid, ComposedChallenges)
    assert [challenge.opaque for challenge in unpaid.challenges] == [
        {"plan": "first"},
        {"plan": "second"},
    ]

    paid = await configured.verify(credential(unpaid.challenges[1]).to_authorization())
    assert not isinstance(paid, ComposedChallenges)
    assert paid[1].reference == "second"
    assert first_method.intent.settlements == 0
    assert second_method.intent.settlements == 1


@pytest.mark.asyncio
async def test_wire_identical_cross_instance_offers_fail_closed() -> None:
    first_method = MockMethod("shared", reference="first")
    second_method = MockMethod("shared", reference="second")
    first = Mpp.create(
        method=first_method,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    second = Mpp.create(
        method=second_method,
        realm="shared.example.com",
        secret_key="shared-secret",
    )
    configured = compose(
        first.compose((first_method, {"amount": "1.00"})),
        second.compose((second_method, {"amount": "1.00"})),
    )

    unpaid = await configured.verify(None)
    assert isinstance(unpaid, ComposedChallenges)
    rejected = await configured.verify(credential(unpaid.challenges[1]).to_authorization())

    assert isinstance(rejected, ComposedChallenges)
    assert len(rejected.challenges) == 2
    assert first_method.intent.settlements == 0
    assert second_method.intent.settlements == 0


@pytest.mark.asyncio
async def test_composed_offer_rejects_tampered_opaque() -> None:
    method = MockMethod("first")
    server = Mpp.create(
        method=method,
        realm="api.example.com",
        secret_key="shared-secret",
    )
    configured = server.compose(
        (method, {"amount": "1.00", "meta": {"plan": "original"}}),
    )
    unpaid = await configured.verify(None)
    assert isinstance(unpaid, ComposedChallenges)
    challenge = unpaid.challenges[0]
    tampered_opaque = (
        Challenge.create(
            secret_key="shared-secret",
            realm=challenge.realm,
            method=challenge.method,
            intent=challenge.intent,
            request=challenge.request,
            expires=challenge.expires,
            digest=challenge.digest,
            meta={"plan": "tampered"},
        )
        .to_echo()
        .opaque
    )
    tampered = Credential(
        challenge=replace(challenge.to_echo(), opaque=tampered_opaque),
        payload={},
    )

    rejected = await configured.verify(tampered.to_authorization())
    assert isinstance(rejected, ComposedChallenges)
    assert method.intent.settlements == 0


@pytest.mark.asyncio
async def test_compose_rejects_unusable_authorization_without_settlement() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="shared-secret",
    )
    configured = server.compose(
        (first, {"amount": "1.00"}),
        (second, {"amount": "2.00"}),
    )
    unpaid = await configured.verify(None)
    assert isinstance(unpaid, ComposedChallenges)
    first_challenge = unpaid.challenges[0]
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
        rejected = await configured.verify(authorization)
        assert isinstance(rejected, ComposedChallenges)
        assert len(rejected.challenges) == 2

    assert first.intent.settlements == 0
    assert second.intent.settlements == 0


@pytest.mark.asyncio
async def test_repeated_offers_keep_body_hmac_and_route_scope_bindings() -> None:
    method = MockMethod("first")
    server = Mpp.create(method=method, realm="api.example.com", secret_key="secret")
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)
    body_calls = 0

    def body(request: MockRequest) -> bytes:
        nonlocal body_calls
        body_calls += 1
        assert request.body is not None
        return request.body

    configured = server.compose(
        (method, {"amount": "1.00"}),
        (method, {"amount": "2.00"}),
        body=body,
    )
    request = MockRequest(path="/paid", route="/paid", body=b"bound body")
    unpaid = await configured.verify(None, request)
    assert isinstance(unpaid, ComposedChallenges)
    assert [item.request["amount"] for item in unpaid.challenges] == ["100", "200"]
    assert body_calls == 1
    selected = credential(unpaid.challenges[1])

    forged = Credential(
        challenge=Challenge.create(
            secret_key="wrong-secret",
            realm="api.example.com",
            method="first",
            intent="charge",
            request=unpaid.challenges[1].request,
            expires=unpaid.challenges[1].expires,
            digest=unpaid.challenges[1].digest,
        ).to_echo(),
        payload={},
    )
    rejected = [
        (forged, request),
        (selected, MockRequest(path="/paid", route="/paid", body=b"wrong body")),
        (selected, MockRequest(path="/other", route="/other", body=b"bound body")),
    ]
    for submitted, submitted_request in rejected:
        result = await configured.verify(submitted.to_authorization(), submitted_request)
        assert isinstance(result, ComposedChallenges)

    paid = await configured.verify(selected.to_authorization(), request)
    assert not isinstance(paid, ComposedChallenges)
    assert paid[1].reference == "first"
    assert method.intent.settlements == 1
    assert len(failures) == 3


@pytest.mark.asyncio
async def test_requires_auth_compose_advertises_and_accepts_payment_authorization() -> None:
    first = MockMethod("first")
    second = MockMethod("second")
    server = Mpp.create(
        methods=[first, second],
        realm="api.example.com",
        secret_key="secret",
        requires_auth=True,
    )
    configured = server.compose(
        (first, {"amount": "1.00"}),
        (second, {"amount": "1.00"}),
    )

    unpaid = await configured.verify("Bearer app-token")
    assert isinstance(unpaid, ComposedChallenges)
    assert all(challenge.header == "Payment-Authorization" for challenge in unpaid.challenges)
    assert all(
        'header="Payment-Authorization"' in challenge.to_www_authenticate(server.realm)
        for challenge in unpaid.challenges
    )

    paid = await configured.verify(credential(unpaid.challenges[1]).to_authorization())
    assert not isinstance(paid, ComposedChallenges)
    assert paid[1].reference == "second"
    assert second.intent.settlements == 1
