"""Stripe Connect settlement on SPT charges and recorded crypto payments."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import stripe

from mpp import Credential, Receipt
from mpp.errors import VerificationFailedError
from mpp.methods.stripe import ChargeIntent, ConnectSettlement, PaymentIntentContext, TransferData
from mpp.methods.stripe import server as stripe_server
from mpp.methods.stripe.crypto_payment_recorder import record_crypto_payment
from mpp.server import Mpp
from tests import challenge, http_request
from tests.test_stripe import SAMPLE_REQUEST, _make_credential
from tests.test_stripe_machine_payments import FakeStripeClient, make_payments

SETTLEMENT = ConnectSettlement(
    stripe_account="acct_platform_ctx",
    application_fee_amount=25,
    on_behalf_of="acct_seller",
    transfer_data=TransferData(destination="acct_seller", amount=100),
    transfer_group="order_123",
)
PARAMS = {
    "application_fee_amount": 25,
    "on_behalf_of": "acct_seller",
    "transfer_data": {"destination": "acct_seller", "amount": 100},
    "transfer_group": "order_123",
}
FORM = {
    "application_fee_amount": "25",
    "on_behalf_of": "acct_seller",
    "transfer_data[destination]": "acct_seller",
    "transfer_data[amount]": "100",
    "transfer_group": "order_123",
}


async def test_client_path_applies_settlement_and_account() -> None:
    client = FakeStripeClient()
    await ChargeIntent(client=client).verify(_make_credential(), SAMPLE_REQUEST, connect=SETTLEMENT)

    params, options = client.payment_intents.calls[0]
    assert {key: params[key] for key in PARAMS} == PARAMS
    assert options["stripe_account"] == "acct_platform_ctx"


async def test_secret_key_path_applies_settlement_and_account() -> None:
    http_client = AsyncMock(spec=httpx.AsyncClient)
    http_client.post.return_value = httpx.Response(
        200,
        json={"id": "pi_1", "status": "succeeded"},
        request=httpx.Request("POST", "https://api.stripe.com/v1/payment_intents"),
    )
    intent = ChargeIntent(secret_key="sk_test", http_client=http_client)
    await intent.verify(_make_credential(), SAMPLE_REQUEST, connect=SETTLEMENT)

    kwargs = http_client.post.call_args.kwargs
    assert kwargs["headers"]["Stripe-Account"] == "acct_platform_ctx"
    assert kwargs["data"]["shared_payment_granted_token"] == "spt_test_abc"
    assert {key: value for key, value in kwargs["data"].items() if key in FORM} == FORM


async def test_resolver_receives_context_and_none_omits_connect() -> None:
    seen: list[PaymentIntentContext] = []

    async def resolve(context: PaymentIntentContext) -> ConnectSettlement | None:
        seen.append(context)
        return None

    client = FakeStripeClient()
    await ChargeIntent(client=client).verify(_make_credential(), SAMPLE_REQUEST, connect=resolve)

    assert seen[0].request["amount"] == "150"
    assert seen[0].challenge.id == "test-challenge-id"
    params, options = client.payment_intents.calls[0]
    assert "stripe_account" not in options
    assert not PARAMS.keys() & params.keys()


@pytest.mark.parametrize(
    ("settlement", "reason"),
    [
        (ConnectSettlement(stripe_account=""), "stripe_account must be non-empty"),
        (ConnectSettlement(on_behalf_of=""), "on_behalf_of must be non-empty"),
        (ConnectSettlement(application_fee_amount=-1), "must be a non-negative integer"),
        (ConnectSettlement(application_fee_amount=151), "less than or equal"),
        (ConnectSettlement(transfer_data=TransferData(destination="")), "destination"),
        (
            ConnectSettlement(transfer_data=TransferData(destination="acct_x", amount=151)),
            "transfer_data.amount must be less than or equal",
        ),
    ],
)
async def test_invalid_settlement_fails_before_stripe(
    settlement: ConnectSettlement, reason: str
) -> None:
    client = FakeStripeClient()
    with pytest.raises(VerificationFailedError, match=reason):
        await ChargeIntent(client=client).verify(
            _make_credential(), SAMPLE_REQUEST, connect=lambda _: settlement
        )
    assert client.payment_intents.calls == []


async def test_server_charge_keeps_connect_out_of_challenge() -> None:
    client = FakeStripeClient()
    method = stripe_server.charge(
        network_id="bn_test", client=client, currency="usd", connect=SETTLEMENT
    )
    server = Mpp(methods=method, realm="api.example.com", secret_key="secret")
    handler = server.charge(amount="1.50")
    issued = challenge(await handler(http_request()))
    assert "acct" not in str(issued.request)

    credential = Credential(challenge=issued.to_echo(), payload={"spt": "spt_test"})
    await handler(http_request(credential.to_authorization()))
    assert client.payment_intents.calls[0][1]["stripe_account"] == "acct_platform_ctx"


async def test_machine_payments_route_spt_and_recorded_payments() -> None:
    connect = ConnectSettlement(stripe_account="acct_seller")
    client, payments = make_payments(connect=connect)
    server = Mpp(methods=payments.spt.charge(), realm="api.example.com", secret_key="secret")
    handler = server.charge(amount="1.00", recipient="bn_test")
    issued = challenge(await handler(http_request()))
    credential = Credential(challenge=issued.to_echo(), payload={"spt": "spt_test"})
    await handler(http_request(credential.to_authorization()))
    assert client.payment_intents.calls[0][1]["stripe_account"] == "acct_seller"

    class RejectOptional:
        calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

        def create(self, params: dict[str, Any], *, options: dict[str, Any]) -> Any:
            self.calls.append((params, options))
            if len(self.calls) == 1:
                raise stripe.InvalidRequestError("bad customer", "customer")

    recorder = RejectOptional()
    await record_crypto_payment(
        client=type("Client", (), {"payment_intents": recorder})(),
        network="tempo",
        metadata=None,
        credential=None,
        request={"amount": "10000"},
        receipt=Receipt.success("0xtest", method="tempo"),
        payment_intent_options={"customer": "cus_1"},
        connect=SETTLEMENT,
    )
    assert len(recorder.calls) == 2
    for params, options in recorder.calls:
        assert {key: params[key] for key in PARAMS} == PARAMS
        assert options["stripe_account"] == "acct_platform_ctx"
    assert "customer" not in recorder.calls[1][0]
