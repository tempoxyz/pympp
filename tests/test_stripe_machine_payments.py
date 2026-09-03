from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods.stripe import MachinePayments, create
from mpp.methods.stripe import _defaults as stripe_defaults
from mpp.methods.tempo._defaults import CHAIN_ID, PATH_USD, TESTNET_CHAIN_ID, USDC
from mpp.server import Mpp
from tests import MockRequest

TEMPO_ADDRESS = "0x" + "1" * 40


class FakePaymentIntents:
    def __init__(self, *, sync: bool = False) -> None:
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self.error: Exception | None = None
        if sync:
            self.create_async = None  # type: ignore[assignment]

    async def create_async(self, params: dict[str, Any], *, options: dict[str, Any]) -> Any:
        if self.error is not None:
            raise self.error
        return self.create(params, options=options)

    def create(self, params: dict[str, Any], *, options: dict[str, Any]) -> Any:
        self.calls.append((params, options))
        return SimpleNamespace(id="pi_test", status="succeeded")


class FakeStripeClient:
    def __init__(self, *, top_level_only: bool = False, sync: bool = False) -> None:
        self.payment_intents = FakePaymentIntents(sync=sync)
        if not top_level_only:
            self.v1 = type("V1", (), {"payment_intents": self.payment_intents})()


def make_payments(**overrides: Any) -> tuple[FakeStripeClient, MachinePayments]:
    client = overrides.pop("client", FakeStripeClient())
    return client, create(
        network_id=overrides.pop("network_id", "bn_test"),
        livemode=overrides.pop("livemode", False),
        client=cast(Any, client),
        **overrides,
    )


def test_defaults_are_spt_only_and_include_configured_metadata() -> None:
    _, payments = make_payments(metadata={"order": "123"})

    methods = payments.default_methods()
    spt = payments.spt.charge()
    request = spt.transform_request({"amount": "50", "currency": "usd"}, None)

    assert [method.name for method in methods] == ["stripe"]
    assert methods[0].recipient == "bn_test"
    assert request["methodDetails"] == {
        "metadata": {"order": "123"},
        "networkId": "bn_test",
        "paymentMethodTypes": ["card", "link"],
    }


def test_static_tempo_is_preferred_and_uses_network_defaults() -> None:
    _, test_payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    _, live_payments = make_payments(livemode=True, deposit_addresses={"tempo": TEMPO_ADDRESS})

    methods = test_payments.default_methods()
    test_tempo = test_payments.tempo.charge()
    live_tempo = live_payments.tempo.charge()

    assert [method.name for method in methods] == ["tempo", "stripe"]
    assert (test_tempo.recipient, test_tempo.chain_id) == (TEMPO_ADDRESS, TESTNET_CHAIN_ID)
    assert test_tempo.currency == PATH_USD
    assert (live_tempo.chain_id, live_tempo.currency) == (CHAIN_ID, USDC)


def test_methods_filter_amounts_below_stripe_minima() -> None:
    _, payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    spt_offer = payments.spt.charge().can_offer
    tempo_offer = payments.tempo.charge().can_offer
    assert spt_offer is not None and tempo_offer is not None

    assert not spt_offer({"amount": "49"})
    assert spt_offer({"amount": "50"})
    assert not tempo_offer({"amount": "9999"})
    assert tempo_offer({"amount": "10000"})


@pytest.mark.asyncio
async def test_spt_only_defaults_enforce_minimum_through_implicit_handlers() -> None:
    _, payments = make_payments()
    server = Mpp.create(
        methods=payments.default_methods(),
        realm="api.example.com",
        secret_key="secret",
    )

    with pytest.raises(ValueError, match="No payment offers"):
        await server.charge(None, "0.49")
    assert isinstance(await server.charge(None, "0.50"), Challenge)

    @server.pay(amount="0.49")
    async def endpoint(
        _request: MockRequest,
        _credential: Credential,
        _receipt: Receipt,
    ) -> None:
        return None

    with pytest.raises(ValueError, match="No payment offers"):
        await endpoint(MockRequest(path="/paid"))


def test_configuration_boundary_errors() -> None:
    with pytest.raises(TypeError, match="Unsupported Stripe client"):
        make_payments(client=object())
    with pytest.raises(ValueError, match=r"deposit_addresses\['tempo'\]"):
        make_payments()[1].tempo.charge()


@pytest.mark.asyncio
async def test_spt_uses_pinned_explicit_request_shape() -> None:
    client, payments = make_payments(metadata={"order": "123"})
    method = payments.spt.charge()
    request = method.transform_request(
        {"amount": "100", "currency": "usd", "recipient": "bn_test"}, None
    )
    challenge = Challenge.create(
        secret_key="secret",
        realm="api.example.com",
        method="stripe",
        intent="charge",
        request=request,
    )

    await cast(Any, method.intents["charge"]).verify(
        Credential(challenge=challenge.to_echo(), payload={"spt": "spt_test"}), request
    )

    params, options = client.payment_intents.calls[0]
    assert params["shared_payment_granted_token"] == "spt_test"
    assert params["payment_method_types"] == ["card", "link"]
    assert "automatic_payment_methods" not in params
    assert params["metadata"]["order"] == "123"
    assert options == {
        "headers": {"X-Request-Source": stripe_defaults.STRIPE_REQUEST_SOURCE},
        "idempotency_key": f"mpp_{challenge.id}_spt_test",
        "stripe_version": stripe_defaults.MACHINE_PAYMENTS_API_VERSION,
    }


def success_payload(reference: str, amount: int) -> ServerPaymentSuccessPayload:
    receipt = Receipt.success(reference, method="tempo")
    return cast(Any, {"receipt": receipt, "request": {"amount": str(amount)}})


@pytest.mark.asyncio
@pytest.mark.parametrize(("top_level_only", "sync"), [(False, False), (True, False), (True, True)])
async def test_tempo_hook_records_verified_payment_and_metadata(
    top_level_only: bool, sync: bool
) -> None:
    client, payments = make_payments(
        client=FakeStripeClient(top_level_only=top_level_only, sync=sync),
        deposit_addresses={"tempo": TEMPO_ADDRESS},
        metadata={"order": "123"},
    )
    handler = payments.tempo.charge().on_payment_success
    assert handler is not None

    for amount in (4_999, 5_000, 15_000):
        await cast(Any, handler)(success_payload(f"0x{amount}", amount))

    assert [params["amount"] for params, _ in client.payment_intents.calls] == [1, 2]
    params, options = client.payment_intents.calls[-1]
    assert params["metadata"] == {"machine_payment": "true", "order": "123"}
    assert params["payment_method_options"]["crypto"] == {
        "mode": "transaction_verification",
        "transaction_verification_options": {
            "network": "tempo",
            "transaction_hash": "0x15000",
        },
    }
    assert options == {
        "headers": {"X-Request-Source": stripe_defaults.STRIPE_REQUEST_SOURCE},
        "idempotency_key": "0x15000",
        "stripe_version": stripe_defaults.MACHINE_PAYMENTS_API_VERSION,
    }


@pytest.mark.asyncio
async def test_tempo_recording_is_best_effort(caplog: pytest.LogCaptureFixture) -> None:
    client, payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    client.payment_intents.error = RuntimeError("unavailable")
    handler = payments.tempo.charge().on_payment_success

    await cast(Any, handler)(success_payload("0xfailure", 10_000))

    assert "Tempo PI recording failed" in caplog.text and "0xfailure" in caplog.text
