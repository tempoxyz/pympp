import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import BaseModel

from mpp import Challenge, Method, Receipt, ServerMethod, VerifyContext, payment_request
from mpp.server import Mpp, PaymentRequired, Request, Response, compose

from ._fixtures import REALM, SECRET_KEY, TokenPayload, credential_header, receipt


class ChargeRequest(BaseModel):
    amount: str
    currency: str
    decimals: int
    recipient: str


class SessionDetails(BaseModel):
    sessionProtocol: str | None = None


class SessionRequest(BaseModel):
    amount: str
    currency: str
    methodDetails: SessionDetails
    unitType: str


def server(
    name: str, intent: str = "charge", request_model: type[BaseModel] = ChargeRequest, **hooks: Any
) -> ServerMethod:
    async def verify(_: VerifyContext[Any]) -> Receipt:
        return receipt(name, f"tx-{name}")

    hooks.setdefault("verify", verify)
    return ServerMethod(
        method=Method(
            name=name, intent=intent, request_model=request_model, payload_model=TokenPayload
        ),
        **hooks,
    )


alpha = server("alpha")
beta = server("beta")
session_v2 = server("tempo", "session", SessionRequest)
alternate_session = server("tempo", "session", SessionRequest, alias="alternateSession")

OPTS = {
    "amount": "1000",
    "currency": "0x0000000000000000000000000000000000000001",
    "decimals": 6,
    "expires": datetime.now(UTC) + timedelta(hours=1),
    "recipient": "0x0000000000000000000000000000000000000002",
}
SESSION_OPTS = {
    "amount": "100",
    "currency": "0x20c0000000000000000000000000000000000001",
    "expires": datetime.now(UTC) + timedelta(hours=1),
    "methodDetails": {"sessionProtocol": "v2"},
    "unitType": "request",
}
ALT_SESSION_OPTS = {**SESSION_OPTS, "methodDetails": {"sessionProtocol": "alternate"}}


def req(url: str = "https://example.com/resource", **headers: str) -> Request:
    return Request("GET", url, headers=headers)


def challenges_of(result: Any) -> list[Challenge]:
    assert isinstance(result, PaymentRequired)
    return Challenge.from_response_list(result.challenge)


def make(*methods: ServerMethod, **kwargs: Any) -> Mpp:
    return Mpp(methods=list(methods), realm=REALM, secret_key=SECRET_KEY, **kwargs)


async def pay(handle: Any, challenge: Challenge, **headers: str) -> Any:
    return await handle(
        req(Authorization=credential_header(challenge, {"token": "valid"}), **headers)
    )


async def test_multiple_www_authenticate_headers() -> None:
    result = await make(alpha, beta).compose((alpha, OPTS), (beta, OPTS))(req())
    www = result.challenge.headers.get("WWW-Authenticate")
    assert 'method="alpha"' in www
    assert 'method="beta"' in www
    assert len(result.challenge.headers.get_list("WWW-Authenticate")) == 2
    assert result.challenge.headers["Cache-Control"] == "no-store"
    body = json.loads(await result.challenge.read())
    assert body["title"] == "Payment Required"


@pytest.mark.parametrize(
    "currencies",
    [
        (
            "0x20c0000000000000000000000000000000000001",
            "0x20c0000000000000000000000000000000000002",
        ),
        (
            "0x20c0000000000000000000000000000000000002",
            "0x20c0000000000000000000000000000000000001",
        ),
    ],
)
async def test_implicit_composition_preserves_defaults_order(currencies: tuple[str, str]) -> None:
    class Req(BaseModel):
        amount: str
        currency: str
        recipient: str

    methods = [
        server("tempo", request_model=Req, defaults={"currency": c, "recipient": "0x2"})
        for c in currencies
    ]

    result = await make(*methods).charge(amount="1")(req())
    challenges = challenges_of(result)
    assert [c.request["currency"] for c in challenges] == list(currencies)
    assert len({c.id for c in challenges}) == 2


async def test_offer_snapshots_are_immutable() -> None:
    def can_offer(ctx: Any) -> bool:
        assert isinstance(ctx.request, MappingProxyType)
        assert isinstance(ctx.request["methodDetails"], MappingProxyType)
        with pytest.raises(TypeError):
            ctx.request["methodDetails"]["sessionProtocol"] = "changed"  # type: ignore[index]
        return True

    guarded = server("tempo", "session", SessionRequest, can_offer=can_offer)

    handler = make(guarded).compose((guarded, SESSION_OPTS))
    for _ in range(2):
        challenge = challenges_of(await handler(req()))[0]
        assert challenge.request["methodDetails"] == {"sessionProtocol": "v2"}


async def test_can_offer_without_select_offers() -> None:
    amounts: list[str] = []

    def can_offer(ctx: Any) -> bool:
        amounts.append(ctx.request["amount"])
        return int(ctx.request["amount"]) >= 100

    guarded = server("beta", can_offer=can_offer)
    handler = make(guarded).compose(
        (guarded, {**OPTS, "amount": "50"}), (guarded, {**OPTS, "amount": "100"})
    )
    assert len(handler.offers) == 2
    result = await handler(req())
    assert amounts == ["50", "100"]
    assert [c.request["amount"] for c in challenges_of(result)] == ["100"]


async def test_static_compose_applies_can_offer() -> None:
    guarded = server("beta", can_offer=lambda _: False)
    mppx = make(alpha, guarded)
    result = await compose(mppx.alpha.charge(**OPTS), mppx.beta.charge(**OPTS))(req())
    assert [c.method for c in challenges_of(result)] == ["alpha"]


async def test_can_offer_does_not_gate_direct_handler() -> None:
    calls: list[int] = []
    guarded = server("alpha", can_offer=lambda _: calls.append(1) or False)
    result = await make(guarded).alpha.charge(**OPTS)(req())
    assert result.status == 402
    assert calls == []


async def test_can_offer_filters_before_preflight_and_authorize() -> None:
    calls: list[str] = []
    guarded = server(
        "beta",
        can_offer=lambda _: False,
        preflight=lambda _: calls.append("preflight"),
        authorize=lambda _: calls.append("authorize"),
    )
    result = await make(alpha, guarded).compose((alpha, OPTS), (guarded, OPTS))(req())
    assert result.status == 402
    assert calls == []


@pytest.mark.parametrize(
    ("can_offer", "error"),
    [
        (lambda _: "yes", "can_offer() must return a boolean"),
        (lambda _: False, "No payment offers are available"),
    ],
)
async def test_invalid_can_offer(can_offer: Any, error: str) -> None:
    guarded = server("alpha", can_offer=can_offer)
    with pytest.raises(
        (TypeError, ValueError), match=error.replace("(", r"\(").replace(")", r"\)")
    ):
        await make(guarded).compose((guarded, OPTS))(req())


async def test_propagates_can_offer_rejections() -> None:
    error = RuntimeError("method offer selection failed")

    async def can_offer(_: Any) -> bool:
        raise error

    guarded = server("alpha", can_offer=can_offer)
    with pytest.raises(RuntimeError) as raised:
        await make(guarded).compose((guarded, OPTS))(req())
    assert raised.value is error


async def test_can_offer_does_not_prevent_redemption() -> None:
    calls: list[int] = []
    guarded = server("beta", can_offer=lambda _: calls.append(1) or False)
    mppx = make(guarded)
    challenge = await mppx.challenge.beta.charge(**OPTS)
    result = await pay(mppx.compose((guarded, OPTS)), challenge)
    assert result.status == 200
    assert calls == []


async def test_discovery_metadata() -> None:
    mppx = make(alpha, beta)
    configured = mppx.compose((alpha, OPTS), (beta, OPTS))
    assert [(o.name, o.intent, o.request["amount"]) for o in configured.offers] == [
        ("alpha", "charge", "1000"),
        ("beta", "charge", "1000"),
    ]

    async def custom(_: Any) -> PaymentRequired[Response]:
        return PaymentRequired(Response(402))

    composed = compose(mppx.alpha.charge(**OPTS), custom)  # type: ignore[arg-type]
    assert [(o.name, o.intent) for o in composed.offers] == [("alpha", "charge")]


async def test_duplicate_session_variants() -> None:
    mppx = make(session_v2, alternate_session)
    handler = mppx.compose(
        (mppx.tempo.session, SESSION_OPTS), (mppx.tempo.alternateSession, ALT_SESSION_OPTS)
    )
    assert [c.request["methodDetails"] for c in challenges_of(await handler(req()))] == [
        {"sessionProtocol": "v2"},
        {"sessionProtocol": "alternate"},
    ]
    assert len(challenges_of(await handler(req(**{"Accept-Payment": "tempo/session"})))) == 2


class TestAcceptPayment:
    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("beta/charge", ["beta"]),
            ("beta/charge;q=0.9, alpha/charge;q=0.3", ["beta", "alpha"]),
            ("alpha/*;q=1, alpha/charge;q=0, beta/*;q=0.5", ["beta"]),
            ("gamma/charge", ["alpha", "beta"]),
            ("not a valid header", ["alpha", "beta"]),
        ],
    )
    async def test_negotiation(self, header: str, expected: list[str]) -> None:
        result = await make(alpha, beta).compose((alpha, OPTS), (beta, OPTS))(
            req(**{"Accept-Payment": header})
        )
        assert [c.method for c in challenges_of(result)] == expected

    async def test_can_offer_before_negotiation(self) -> None:
        guarded = server("beta", can_offer=lambda _: False)
        result = await make(alpha, guarded).compose((alpha, OPTS), (guarded, OPTS))(
            req(**{"Accept-Payment": "beta/charge"})
        )
        assert [c.method for c in challenges_of(result)] == ["alpha"]


class TestDispatch:
    @pytest.mark.parametrize("index", [0, 1])
    async def test_dispatches_to_matching_handler(self, index: int) -> None:
        handle = make(alpha, beta).compose((alpha, OPTS), (beta, OPTS))
        challenge = challenges_of(await handle(req()))[index]
        result = await pay(handle, challenge)
        assert result.status == 200
        response = result.with_receipt(Response.json({"data": "ok"}))
        assert Receipt.from_headers(response.headers).method == ("alpha", "beta")[index]

    async def test_nested_composed_handler(self) -> None:
        mppx = make(alpha, beta)
        handle = compose(mppx.alpha.charge(**OPTS), compose(mppx.beta.charge(**OPTS)))
        beta_challenge = next(c for c in challenges_of(await handle(req())) if c.method == "beta")
        assert (await pay(handle, beta_challenge)).status == 200

    async def test_unknown_credential_method(self) -> None:
        handle = make(alpha).compose((alpha, OPTS))
        wrong = Challenge.create(
            id="wrong-id",
            intent="charge",
            method="unknown",
            realm=REALM,
            request={"amount": "1000", "currency": "0x01", "recipient": "0x02"},
        )
        result = await handle(req(Authorization=credential_header(wrong, {"token": "test"})))
        assert result.status == 402

    async def test_cross_route_protection(self) -> None:
        mppx = make(alpha)
        cheap = challenges_of(
            await mppx.compose((alpha, {**OPTS, "amount": "1"}))(req("https://example.com/cheap"))
        )[0]
        result = await pay(mppx.compose((alpha, {**OPTS, "amount": "1000000"})), cheap)
        assert result.status == 402
        assert "does not match" in json.loads(await result.challenge.read())["detail"]

    def test_requires_entries(self) -> None:
        with pytest.raises(ValueError, match="requires at least one entry"):
            make(alpha).compose()

    def test_unknown_method(self) -> None:
        with pytest.raises(ValueError, match='No handler for "beta/charge"'):
            make(alpha).compose((beta, OPTS))
        with pytest.raises(ValueError, match='No handler for "unknown/charge"'):
            make(alpha).compose(("unknown/charge", OPTS))

    async def test_string_keys_and_factories(self) -> None:
        mppx = make(alpha, beta)
        for entries in (
            (("alpha/charge", OPTS), ("beta/charge", OPTS)),
            (("alpha/charge", OPTS), (beta, OPTS)),
            ((mppx.alpha.charge, OPTS), (mppx.beta.charge, OPTS)),
            ((mppx.alpha.charge, OPTS), ("beta/charge", OPTS)),
        ):
            handle = mppx.compose(*entries)
            challenges = challenges_of(await handle(req()))
            assert [c.method for c in challenges] == ["alpha", "beta"]
            assert (await pay(handle, challenges[0])).status == 200

    @pytest.mark.parametrize(
        "variant",
        [
            {"currency": "0x0000000000000000000000000000000000000099"},
            {"recipient": "0x0000000000000000000000000000000000000088"},
        ],
    )
    async def test_same_key_different_economics(self, variant: dict[str, str]) -> None:
        handle = make(alpha).compose((alpha, OPTS), (alpha, {**OPTS, **variant}))
        challenges = challenges_of(await handle(req()))
        assert len(challenges) == 2
        assert (await pay(handle, challenges[1])).status == 200

    async def test_same_economics_different_meta(self) -> None:
        handle = make(alpha).compose(
            (alpha, {**OPTS, "meta": {"route": "a"}}), (alpha, {**OPTS, "meta": {"route": "b"}})
        )
        challenges = challenges_of(await handle(req()))
        first = payment_request.deserialize(challenges[0].opaque or "")
        assert first["route"] == "a"
        assert isinstance(first["_mppx_nonce"], str)
        assert payment_request.deserialize(challenges[1].opaque or "")["route"] == "b"
        assert (await pay(handle, challenges[1])).status == 200

    async def test_differ_only_in_amount(self) -> None:
        handle = make(alpha).compose(
            (alpha, {**OPTS, "amount": "1"}), (alpha, {**OPTS, "amount": "2"})
        )
        challenges = challenges_of(await handle(req()))
        assert (await pay(handle, challenges[0])).status == 200
        assert (await pay(handle, challenges[1])).status == 200

    async def test_mismatched_intent_falls_back_to_first_handler(self) -> None:
        handle = make(alpha).compose((alpha, OPTS))
        challenge = replace(challenges_of(await handle(req()))[0], intent="session")
        result = await handle(req(Authorization=credential_header(challenge, {"token": "valid"})))
        assert result.status == 402

    async def test_malformed_authorization(self) -> None:
        result = await make(alpha).compose((alpha, OPTS))(req(Authorization="Payment !!!"))
        assert result.status == 402

    async def test_stable_binding_errors_are_ignored(self) -> None:
        def stable_binding(request: dict[str, Any]) -> dict[str, Any]:
            if "currency" not in request:
                raise KeyError("currency")
            return {"currency": request["currency"]}

        guarded = server("alpha", stable_binding=stable_binding)
        handle = make(guarded, beta).compose((guarded, OPTS), (beta, OPTS))
        forged = Challenge.create(
            id="x", intent="charge", method="alpha", realm=REALM, request={"amount": "1"}
        )
        result = await handle(req(Authorization=credential_header(forged, {"token": "valid"})))
        assert result.status == 402

    async def test_single_handler_402_then_200(self) -> None:
        handle = make(alpha).compose((alpha, OPTS))
        challenge = challenges_of(await handle(req()))[0]
        assert (await pay(handle, challenge)).status == 200


class TestNestedAccessors:
    async def test_nested_handler(self) -> None:
        mppx = make(alpha, beta)
        assert mppx.alpha.charge is mppx["alpha/charge"]
        handle = mppx.alpha.charge(**OPTS)
        challenge = challenges_of(await handle(req()))[0]
        assert challenge.method == "alpha"
        assert (await pay(handle, challenge)).status == 200

    async def test_nested_accessors_with_static_compose(self) -> None:
        mppx = make(alpha, beta)
        handle = compose(mppx.alpha.charge(**OPTS), mppx.beta.charge(**OPTS))
        challenges = challenges_of(await handle(req()))
        assert [c.method for c in challenges] == ["alpha", "beta"]
        assert (await pay(handle, challenges[1])).status == 200

    def test_alias_keys(self) -> None:
        mppx = make(session_v2, alternate_session)
        assert mppx["tempo/alternateSession"] is mppx.tempo.alternateSession
        assert mppx["tempo/session"] is mppx.tempo.session

    def test_extensions(self) -> None:
        extended = server("ext", extensions={"helper": "value"})
        assert make(extended).ext.charge.helper == "value"
