from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential, CredentialParams, Receipt, expires
from mpp.client import Mpp as ClientMppx
from mpp.server import Mpp, PaymentVerified, Request, Response
from mpp.stripe import client as stripe_client
from mpp.stripe import server as stripe_server
from mpp.stripe.client import ChargeContext, TokenParams

REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"


async def create_challenge(make_stripe: Any, **request: Any) -> Challenge:
    server = Mpp(
        methods=[
            stripe_server.charge(
                client=make_stripe(), network_id="internal", payment_method_types=["card"]
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )
    result = await server.charge(amount="100", currency="usd", decimals=2, **request)(
        Request("GET", "https://example.com")
    )
    assert result.status == 402
    return Challenge.deserialize(result.challenge.headers["WWW-Authenticate"])


def recorder(spt: str = "spt_test_123") -> tuple[list[TokenParams], Any]:
    seen: list[TokenParams] = []

    async def create_token(params: TokenParams) -> str:
        seen.append(params)
        return spt

    return seen, create_token


async def test_forwards_client_to_create_token(make_stripe: Any) -> None:
    sdk = object()
    seen, create_token = recorder()
    method = stripe_client.charge(client=sdk, create_token=create_token, payment_method="pm_visa")
    challenge = await create_challenge(make_stripe)
    await method.create_credential(CredentialParams(challenge=challenge, context=None))
    assert seen[0].client is sdk


async def test_client_is_none_when_not_provided(make_stripe: Any) -> None:
    seen, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm_visa")
    await method.create_credential(CredentialParams(challenge=await create_challenge(make_stripe)))
    assert seen[0].client is None


async def test_create_token_receives_all_params(make_stripe: Any) -> None:
    sdk = object()
    seen, create_token = recorder()
    method = stripe_client.charge(
        client=sdk, create_token=create_token, payment_method="pm_card_visa"
    )
    challenge = await create_challenge(make_stripe)
    await method.create_credential(CredentialParams(challenge=challenge))
    params = seen[0]
    assert params.amount == "10000"
    assert params.currency == "usd"
    assert params.network_id == "internal"
    assert params.payment_method == "pm_card_visa"
    assert params.client is sdk
    assert params.challenge == challenge
    assert params.metadata is None
    parsed = expires.parse(challenge.expires or "")
    assert parsed is not None
    assert params.expires_at == int(parsed.timestamp())


async def test_produces_valid_credential(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm_card_visa")
    credential = await method.create_credential(
        CredentialParams(challenge=await create_challenge(make_stripe))
    )
    assert credential.startswith("Payment ")
    assert Credential.deserialize(credential).payload == {"spt": "spt_test_123"}


async def test_echoes_request_bound_external_id(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm_card_visa")
    challenge = await create_challenge(make_stripe, external_id="order_456")
    credential = Credential.deserialize(
        await method.create_credential(CredentialParams(challenge=challenge))
    )
    assert credential.payload == {"externalId": "order_456", "spt": "spt_test_123"}


async def test_request_external_id_overrides_local(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(
        create_token=create_token, external_id="client_order_999", payment_method="pm_card_visa"
    )
    challenge = await create_challenge(make_stripe, external_id="server_order_456")
    credential = Credential.deserialize(
        await method.create_credential(CredentialParams(challenge=challenge))
    )
    assert credential.payload == {"externalId": "server_order_456", "spt": "spt_test_123"}


async def test_local_external_id_fallback(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(
        create_token=create_token, external_id="client_order_999", payment_method="pm_card_visa"
    )
    credential = Credential.deserialize(
        await method.create_credential(
            CredentialParams(challenge=await create_challenge(make_stripe))
        )
    )
    assert credential.payload == {"externalId": "client_order_999", "spt": "spt_test_123"}


async def test_context_payment_method_overrides_default(make_stripe: Any) -> None:
    seen, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm_default")
    await method.create_credential(
        CredentialParams(
            challenge=await create_challenge(make_stripe),
            context=ChargeContext.model_validate({"paymentMethod": "pm_override"}),
        )
    )
    assert seen[0].payment_method == "pm_override"


async def test_requires_payment_method(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(create_token=create_token)
    with pytest.raises(ValueError, match="paymentMethod is required"):
        await method.create_credential(
            CredentialParams(challenge=await create_challenge(make_stripe))
        )


async def test_rejects_reserved_metadata_external_id(make_stripe: Any) -> None:
    _, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm")
    challenge = Challenge.create(
        realm=REALM,
        method="stripe",
        intent="charge",
        secret_key=SECRET_KEY,
        request={
            "amount": "100",
            "currency": "usd",
            "methodDetails": {
                "networkId": "internal",
                "paymentMethodTypes": ["card"],
                "metadata": {"externalId": "x"},
            },
        },
    )
    with pytest.raises(ValueError, match="reserved"):
        await method.create_credential(CredentialParams(challenge=challenge))


async def test_requires_network_id() -> None:
    _, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm")
    challenge = Challenge.create(
        realm=REALM,
        method="stripe",
        intent="charge",
        secret_key=SECRET_KEY,
        request={"amount": "100", "currency": "usd", "methodDetails": {}},
    )
    with pytest.raises(ValueError, match="networkId is required"):
        await method.create_credential(CredentialParams(challenge=challenge))


async def test_expires_at_defaults_to_one_hour(monkeypatch: pytest.MonkeyPatch) -> None:
    seen, create_token = recorder()
    method = stripe_client.charge(create_token=create_token, payment_method="pm")
    challenge = Challenge.create(
        realm=REALM,
        method="stripe",
        intent="charge",
        secret_key=SECRET_KEY,
        request={
            "amount": "100",
            "currency": "usd",
            "methodDetails": {"networkId": "internal", "paymentMethodTypes": ["card"]},
        },
    )
    now = expires.now()
    monkeypatch.setattr(expires, "now", lambda: now)
    await method.create_credential(CredentialParams(challenge=challenge))
    assert seen[0].expires_at == int(now.timestamp()) + 3600


def test_group_returns_charge() -> None:
    _, create_token = recorder()
    methods = stripe_client.stripe(create_token=create_token)
    assert [method.key for method in methods] == ["stripe/charge"]


async def test_mppx_create_credential_forwards_client(make_stripe: Any) -> None:
    sdk = object()
    seen, create_token = recorder()
    mppx = ClientMppx(
        methods=[stripe_client.charge(client=sdk, create_token=create_token, payment_method="pm")]
    )
    challenge = await create_challenge(make_stripe)
    response = httpx.Response(
        402,
        headers={"WWW-Authenticate": challenge.serialize()},
        request=httpx.Request("GET", "https://example.com"),
    )
    await mppx.create_credential(response)
    assert seen[0].client is sdk


async def test_end_to_end_fetch(make_stripe: Any) -> None:
    stripe = make_stripe(id="pi_e2e")
    server = Mpp(
        methods=[
            stripe_server.charge(
                client=stripe, network_id="internal", payment_method_types=["card"]
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )
    handle = server.charge(amount="1", currency="usd", decimals=2, external_id="order_1")

    async def app(request: httpx.Request) -> httpx.Response:
        result = await handle(Request(request.method, str(request.url), headers=request.headers))
        if isinstance(result, PaymentVerified):
            response = result.with_receipt(Response.text("paid"))
        else:
            response = result.challenge
        return httpx.Response(
            response.status, headers=response.headers, content=await response.read()
        )

    seen, create_token = recorder("spt_e2e")
    mppx = ClientMppx(
        methods=[stripe_client.charge(create_token=create_token, payment_method="pm_card_visa")],
        inner=httpx.MockTransport(app),
    )
    response = await mppx.fetch("https://api.example.com/resource")
    assert response.status_code == 200
    assert response.text == "paid"
    receipt = Receipt.from_headers(response.headers)
    assert receipt.reference == "pi_e2e"
    assert receipt.external_id == "order_1"
    assert seen[0].amount == "100"
    assert stripe.calls[0].params["shared_payment_granted_token"] == "spt_e2e"
