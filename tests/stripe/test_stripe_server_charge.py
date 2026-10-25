import json
from typing import Any, cast

import httpx
import pytest

from mpp import BadRequestError, Challenge, Credential, Receipt
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request, Response
from mpp.stripe import STRIPE_PREVIEW_VERSION, ResolveContext
from mpp.stripe import server as stripe

REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"


def make_server(**kwargs: Any) -> Mpp:
    kwargs.setdefault("network_id", "internal")
    kwargs.setdefault("payment_method_types", ["card"])
    return Mpp(methods=[stripe.charge(**kwargs)], realm=REALM, secret_key=SECRET_KEY)


async def problem(result: Any) -> dict[str, Any]:
    assert isinstance(result, PaymentRequired)
    return json.loads(await result.challenge.read())


# -- offer availability ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("at_minimum", "below_minimum", "currency", "decimals", "normalized"),
    [
        ("0.50", "0.49", "usd", 2, "50"),
        ("0.30", "0.29", "gbp", 2, "30"),
        ("50", "49", "jpy", 0, "50"),
        ("10", "9.99", "mxn", 2, "1000"),
    ],
)
async def test_filters_offers_below_currency_minimum(
    make_stripe: Any,
    at_minimum: str,
    below_minimum: str,
    currency: str,
    decimals: int,
    normalized: str,
) -> None:
    method = stripe.charge(
        client=make_stripe(), network_id="internal", payment_method_types=["card"]
    )
    server = Mpp(methods=[method], realm=REALM, secret_key=SECRET_KEY)
    result = await server.compose(
        (method, {"amount": below_minimum, "currency": currency, "decimals": decimals}),
        (method, {"amount": at_minimum, "currency": currency, "decimals": decimals}),
    )(Request("GET", "https://example.com/resource"))
    assert isinstance(result, PaymentRequired)
    challenges = Challenge.deserialize_list(result.challenge.headers["WWW-Authenticate"])
    assert len(challenges) == 1
    assert challenges[0].request["amount"] == normalized
    assert challenges[0].request["currency"] == currency


async def test_composes_can_offer_after_currency_minimum(make_stripe: Any) -> None:
    offered: list[str] = []

    def can_offer(context: Any) -> bool:
        offered.append(context.request["amount"])
        return int(context.request["amount"]) >= 100

    method = stripe.charge(
        client=make_stripe(),
        can_offer=can_offer,
        network_id="internal",
        payment_method_types=["card"],
    )
    server = Mpp(methods=[method], realm=REALM, secret_key=SECRET_KEY)
    result = await server.compose(
        (method, {"amount": "0.49", "currency": "usd", "decimals": 2}),
        (method, {"amount": "0.50", "currency": "usd", "decimals": 2}),
        (method, {"amount": "1", "currency": "usd", "decimals": 2}),
    )(Request("GET", "https://example.com/resource"))
    assert isinstance(result, PaymentRequired)
    assert offered == ["50", "100"]
    challenges = Challenge.deserialize_list(result.challenge.headers["WWW-Authenticate"])
    assert [challenge.request["amount"] for challenge in challenges] == ["100"]


async def test_can_offer_decides_unknown_currency(make_stripe: Any) -> None:
    calls: list[Any] = []
    method = stripe.charge(
        client=make_stripe(),
        can_offer=lambda context: calls.append(context) or True,
        network_id="internal",
        payment_method_types=["card"],
    )
    server = Mpp(methods=[method], realm=REALM, secret_key=SECRET_KEY)
    result = await server.compose(
        (method, {"amount": "0.01", "currency": "unknown", "decimals": 2})
    )(Request("GET", "https://example.com/resource"))
    assert result.status == 402
    assert len(calls) == 1


# -- verification with a client ----------------------------------------------------------------


async def test_verifies_payment_via_client(make_stripe: Any, helpers: Any) -> None:
    client = make_stripe()
    server = make_server(client=client)
    challenge, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    assert isinstance(result, PaymentVerified)
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call.params == {
        "amount": 100,
        "automatic_payment_methods": {"allow_redirects": "never", "enabled": True},
        "confirm": True,
        "currency": "usd",
        "metadata": {
            "machine_payment": "true",
            "mpp_challenge_id": challenge.id,
            "mpp_intent": "charge",
            "mpp_sdk": stripe.sdk_identifier(),
        },
        "shared_payment_granted_token": "spt_test_token",
    }
    assert call.idempotency_key == f"mpp_{challenge.id}_spt_test_token"
    assert call.api_version == STRIPE_PREVIEW_VERSION
    assert call.stripe_account is None


async def test_includes_metadata_and_options(make_stripe: Any, helpers: Any) -> None:
    client = make_stripe()
    server = make_server(client=client, metadata={"plan": "pro"})
    handle = server.charge(
        amount="1",
        currency="usd",
        decimals=2,
        payment_intent_options={
            "amount": 999,
            "confirm": False,
            "customer": "cus_123",
            "currency": "eur",
            "hooks": {"inputs": {"tax": {"calculation": "taxcalc_123"}}},
            "metadata": {
                "machine_payment": "custom",
                "mpp_challenge_id": "custom",
                "plan": "enterprise",
                "request_id": "req_123",
            },
            "receipt_email": "customer@example.com",
        },
    )
    challenge, result = await helpers.pay(handle, {"spt": "spt_test_token"})
    assert "paymentIntentOptions" not in challenge.request
    assert challenge.request["methodDetails"]["metadata"] == {"plan": "pro"}
    assert result.status == 200
    params = client.calls[0].params
    assert params["amount"] == 100
    assert params["confirm"] is True
    assert params["customer"] == "cus_123"
    assert params["currency"] == "usd"
    assert params["hooks"] == {"inputs": {"tax": {"calculation": "taxcalc_123"}}}
    assert params["metadata"] == {
        "machine_payment": "custom",
        "mpp_challenge_id": "custom",
        "mpp_intent": "charge",
        "mpp_sdk": stripe.sdk_identifier(),
        "plan": "enterprise",
        "request_id": "req_123",
    }
    assert params["receipt_email"] == "customer@example.com"


async def test_resolves_options_after_challenge_validation(make_stripe: Any, helpers: Any) -> None:
    client = make_stripe()
    calls: list[str] = []

    async def options(context: ResolveContext) -> dict[str, Any]:
        calls.append("resolve")
        assert context.credential.challenge == context.challenge
        assert context.envelope is not None
        assert context.envelope.credential.challenge == context.credential.challenge
        assert context.request["amount"] == "100"
        return {
            "hooks": {"inputs": {"tax": {"calculation": f"taxcalc_{context.challenge.id}"}}},
            "metadata": {"order": "order_123"},
        }

    server = make_server(client=client)
    handle = server.charge(amount="1", currency="usd", decimals=2, payment_intent_options=options)
    challenge = helpers.challenge_of(await handle(Request("GET", "https://example.com")))
    assert calls == []
    assert "paymentIntentOptions" not in challenge.request

    forged = Credential(
        challenge=Challenge.from_dict({**challenge.to_dict(), "id": "forged"}),
        payload={"spt": "spt_test_token"},
    )
    assert (await handle(helpers.authorized(forged))).status == 402
    assert calls == []

    result = await handle(
        helpers.authorized(Credential(challenge=challenge, payload={"spt": "spt_test_token"}))
    )
    assert result.status == 200
    assert calls == ["resolve"]
    params = client.calls[0].params
    assert params["hooks"] == {"inputs": {"tax": {"calculation": f"taxcalc_{challenge.id}"}}}
    assert params["metadata"]["order"] == "order_123"


async def test_resolver_bad_request_error(make_stripe: Any, helpers: Any) -> None:
    client = make_stripe()

    async def options(context: ResolveContext) -> None:
        raise BadRequestError(reason="invalid tax location")

    server = make_server(client=client)
    handle = server.charge(amount="1", currency="usd", decimals=2, payment_intent_options=options)
    _, result = await helpers.pay(handle, {"spt": "spt_test_token"})
    assert isinstance(result, PaymentRequired)
    assert result.challenge.status == 400
    body = await problem(result)
    assert body["detail"] == "Bad request: invalid tax location."
    assert body["status"] == 400
    assert client.calls == []


async def test_secret_key_reports_stripe_error_message(
    monkeypatch: pytest.MonkeyPatch, helpers: Any
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, json={"error": {"message": "Your card was declined."}})

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
    server = make_server(secret_key="sk_test_123")
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    body = await problem(result)
    assert body["detail"] == (
        "Payment verification failed: Stripe PaymentIntent failed: Your card was declined.."
    )


def test_requires_exactly_one_of_client_or_secret_key(make_stripe: Any) -> None:
    with pytest.raises(TypeError):
        stripe.charge(network_id="internal", payment_method_types=["card"])
    with pytest.raises(TypeError):
        stripe.charge(
            client=make_stripe(),
            secret_key="sk",
            network_id="internal",
            payment_method_types=["card"],
        )


# -- externalId binding ------------------------------------------------------------------------


async def test_receipt_external_id_from_server_bound_request(
    make_stripe: Any, helpers: Any
) -> None:
    server = make_server(client=make_stripe())
    handle = server.charge(amount="1", currency="usd", decimals=2, external_id="server-order-123")
    _, result = await helpers.pay(
        handle, {"spt": "spt_test_token", "externalId": "server-order-123"}
    )
    assert isinstance(result, PaymentVerified)
    receipt = Receipt.from_headers(result.with_receipt(Response.text("OK")).headers)
    assert receipt.external_id == "server-order-123"


async def test_rejects_forged_external_id(make_stripe: Any, helpers: Any) -> None:
    client = make_stripe()
    server = make_server(client=client)
    handle = server.charge(amount="1", currency="usd", decimals=2, external_id="server-order-123")
    _, result = await helpers.pay(
        handle, {"spt": "spt_test_token", "externalId": "attacker-order-999"}
    )
    assert result.status == 402
    assert (await problem(result))["type"].endswith("/invalid-challenge")
    assert client.calls == []


async def test_ignores_payload_only_external_id(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe())
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2),
        {"spt": "spt_test_token", "externalId": "attacker-order-999"},
    )
    assert isinstance(result, PaymentVerified)
    receipt = Receipt.from_headers(result.with_receipt(Response.text("OK")).headers)
    assert receipt.external_id is None


# -- failures ----------------------------------------------------------------------------------


async def test_rejects_when_client_throws(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe(error=RuntimeError("Stripe API error")))
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    body = await problem(result)
    assert body["detail"] == (
        "Payment verification failed: Stripe PaymentIntent failed: Stripe API error."
    )


async def test_rejects_requires_action(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe(status="requires_action"))
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    body = await problem(result)
    assert body["type"] == "https://paymentauth.org/problems/payment-action-required"
    assert "requires action" in body["detail"]


async def test_unexpected_status_is_internal_error(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe(status="processing"))
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    assert result.challenge.status == 500


async def test_rejects_replayed_credential(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe())
    handle = server.charge(amount="1", currency="usd", decimals=2)
    challenge = helpers.challenge_of(await handle(Request("GET", "https://example.com")))
    credential = Credential(challenge=challenge, payload={"spt": "spt_test_token"})
    assert (await handle(helpers.authorized(credential))).status == 200
    replay = await handle(helpers.authorized(credential))
    assert replay.status == 402
    assert (await problem(replay))["detail"] == (
        "Payment verification failed: Payment has already been processed.."
    )


async def test_receipt_contains_reference(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe(id="pi_custom_ref"))
    _, result = await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    assert isinstance(result, PaymentVerified)
    response = result.with_receipt(Response.json({"ok": True}))
    receipt = Receipt.deserialize(response.headers["Payment-Receipt"])
    assert receipt.reference == "pi_custom_ref"
    assert receipt.method == "stripe"


async def test_on_payment_success_hook(make_stripe: Any, helpers: Any) -> None:
    seen: list[Any] = []
    server = make_server(client=make_stripe(), on_payment_success=seen.append)
    await helpers.pay(
        server.charge(amount="1", currency="usd", decimals=2), {"spt": "spt_test_token"}
    )
    assert len(seen) == 1
    assert seen[0].receipt.reference == "pi_mock_123"


def test_defaults_capture_configuration(make_stripe: Any) -> None:
    method = stripe.charge(
        client=make_stripe(),
        network_id="internal",
        payment_method_types=["card"],
        currency="usd",
        decimals=2,
        metadata={"plan": "pro"},
    )
    assert method.defaults == {
        "currency": "usd",
        "decimals": 2,
        "metadata": {"plan": "pro"},
        "network_id": "internal",
        "payment_method_types": ["card"],
    }


async def test_amount_default_from_charge_parameters(make_stripe: Any, helpers: Any) -> None:
    server = make_server(client=make_stripe(), amount="2", currency="eur", decimals=2)
    challenge = helpers.challenge_of(await server.charge()(Request("GET", "https://example.com")))
    assert challenge.request["amount"] == "200"
    assert challenge.request["currency"] == "eur"


def test_payment_intent_options_are_request_scoped_only(make_stripe: Any) -> None:
    # mppx forwards no factory-level paymentIntentOptions (its runtime drops them).
    with pytest.raises(TypeError):
        stripe.charge(
            client=make_stripe(),
            network_id="internal",
            payment_method_types=["card"],
            **cast(Any, {"payment_intent_options": {"customer": "cus_factory"}}),
        )
