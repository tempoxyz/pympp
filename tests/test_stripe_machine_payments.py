from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.errors import CredentialReplayedError
from mpp.methods.stripe import MachinePayments, create
from mpp.methods.stripe import _defaults as stripe_defaults
from mpp.methods.tempo import ChargeIntent as TempoChargeIntent
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._defaults import CHAIN_ID, PATH_USD, TESTNET_CHAIN_ID, USDC
from mpp.server import Mpp, ServerMethod, pay
from mpp.store import MemoryStore
from tests import MockRequest, challenge, http_request

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
        store=overrides.pop("store", MemoryStore()),
        **overrides,
    )


async def wire(method: ServerMethod, amount: str = "0.50") -> dict[str, Any]:
    """Return the wire request of the challenge ``method`` issues for ``amount``."""
    server = Mpp(methods=method, realm="api.example.com", secret_key="secret")
    return challenge(await server.charge(amount=amount)(http_request())).request


async def test_defaults_are_spt_only_and_include_configured_metadata() -> None:
    _, payments = make_payments(metadata={"order": "123"})

    methods = payments.default_methods()
    spt = payments.spt.charge()
    request = await wire(spt)

    assert [method.name for method in methods] == ["stripe"]
    assert (await wire(methods[0]))["recipient"] == "bn_test"
    assert request["methodDetails"] == {
        "metadata": {"order": "123"},
        "networkId": "bn_test",
        "paymentMethodTypes": ["card", "link"],
    }


async def test_static_tempo_is_preferred_and_uses_network_defaults() -> None:
    _, test_payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    _, live_payments = make_payments(livemode=True, deposit_addresses={"tempo": TEMPO_ADDRESS})

    methods = test_payments.default_methods()
    test_tempo = await wire(test_payments.tempo.charge())
    live_tempo = await wire(live_payments.tempo.charge())

    assert [method.name for method in methods] == ["tempo", "stripe"]
    assert (test_tempo["recipient"], test_tempo["methodDetails"]["chainId"]) == (
        TEMPO_ADDRESS,
        TESTNET_CHAIN_ID,
    )
    assert test_tempo["currency"] == PATH_USD
    assert (live_tempo["methodDetails"]["chainId"], live_tempo["currency"]) == (CHAIN_ID, USDC)
    # Stripe's Tempo rail stays on one currency rather than OUSD-first defaults.
    assert test_payments.tempo.charge().defaults == {"currency": PATH_USD}
    assert live_payments.tempo.charge().defaults == {"currency": USDC}


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
    server = Mpp(
        methods=payments.default_methods(),
        realm="api.example.com",
        secret_key="secret",
    )

    with pytest.raises(ValueError, match="No payment offers"):
        await server.charge(amount="0.49")(http_request())
    assert isinstance(challenge(await server.charge(amount="0.50")(http_request())), Challenge)

    @pay(server.charge(amount="0.49"))
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
    with pytest.raises(ValueError, match="shared atomic"):
        make_payments(store=object())
    with pytest.raises(ValueError, match=r"deposit_addresses\['tempo'\]"):
        make_payments()[1].tempo.charge()


@pytest.mark.asyncio
async def test_spt_uses_pinned_explicit_request_shape() -> None:
    client, payments = make_payments(metadata={"order": "123"})
    server = Mpp(methods=payments.spt.charge(), realm="api.example.com", secret_key="secret")
    handler = server.charge(amount="1.00", recipient="bn_test")
    issued = challenge(await handler(http_request()))

    credential = Credential(challenge=issued.to_echo(), payload={"spt": "spt_test"})
    await handler(http_request(credential.to_authorization()))

    params, options = client.payment_intents.calls[0]
    assert params["shared_payment_granted_token"] == "spt_test"
    assert params["payment_method_types"] == ["card", "link"]
    assert "automatic_payment_methods" not in params
    assert params["metadata"]["order"] == "123"
    assert options == {
        "headers": {"X-Request-Source": stripe_defaults.STRIPE_REQUEST_SOURCE},
        "idempotency_key": f"mpp_{issued.id}_spt_test",
        "max_network_retries": 0,
        "stripe_version": stripe_defaults.MACHINE_PAYMENTS_API_VERSION,
    }


@pytest.mark.asyncio
async def test_tempo_charge_uses_factory_store_for_replay_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    _, first = make_payments(store=store, deposit_addresses={"tempo": TEMPO_ADDRESS})
    _, second = make_payments(store=store, deposit_addresses={"tempo": TEMPO_ADDRESS})

    intents: list[TempoChargeIntent] = []

    class RecordingChargeIntent(TempoChargeIntent):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            intents.append(self)

    monkeypatch.setattr(tempo_server, "ChargeIntent", RecordingChargeIntent)
    first.tempo.charge()
    second.tempo.charge()
    first_intent, second_intent = intents

    assert first_intent._store is store
    assert second_intent._store is store
    tx_hash = "0x" + "ab" * 32
    assert await first_intent._reserve_hash(tx_hash) is not None
    with pytest.raises(CredentialReplayedError):
        await second_intent._reserve_hash(tx_hash)


BASE_ADDRESS = "0x" + "2" * 40


async def test_base_rail_is_added_after_defaults_when_configured() -> None:
    from mpp.methods.evm import BASE_SEPOLIA_USDC, BASE_USDC

    addresses = {"tempo": TEMPO_ADDRESS, "base": BASE_ADDRESS}
    _, payments = make_payments(deposit_addresses=addresses)
    _, live = make_payments(livemode=True, deposit_addresses=addresses)
    base: dict[str, Any] = {"facilitator": "https://facilitator.example"}

    methods = payments.default_methods(base=base)
    test_base = await wire(methods[-1], amount="0.01")
    live_base = await wire(live.base.charge(**base), amount="0.01")
    can_offer = methods[-1].can_offer
    assert can_offer is not None

    assert [method.name for method in methods] == ["tempo", "stripe", "evm"]
    assert [method.name for method in payments.default_methods()] == ["tempo", "stripe"]
    assert [m.name for m in make_payments()[1].default_methods(base=base)] == ["stripe"]
    assert (test_base["recipient"], test_base["currency"]) == (
        BASE_ADDRESS,
        BASE_SEPOLIA_USDC.address,
    )
    assert test_base["methodDetails"]["chainId"] == BASE_SEPOLIA_USDC.chain_id
    assert (live_base["currency"], live_base["methodDetails"]["chainId"]) == (
        BASE_USDC.address,
        BASE_USDC.chain_id,
    )
    assert not can_offer({"amount": "9999"})
    assert can_offer({"amount": "10000"})
    with pytest.raises(ValueError, match=r"deposit_addresses\['base'\]"):
        make_payments()[1].base.charge(facilitator="https://facilitator.example")


@pytest.mark.asyncio
async def test_base_charge_records_payment_in_stripe() -> None:
    from eth_account import Account

    from mpp.methods.evm import BASE_SEPOLIA_USDC
    from mpp.methods.evm import client as evm_client
    from mpp.runtime import CredentialParams

    client, payments = make_payments(
        deposit_addresses={"base": BASE_ADDRESS}, metadata={"order": "123"}
    )
    reference = "0x" + "cd" * 32
    method = payments.base.charge(metadata={"call": "yes"}, settle=lambda _: reference)
    server = Mpp(methods=method, realm="api.example.com", secret_key="secret")
    handler = server.charge(amount="0.25", payment_intent_options={"customer": "cus_test"})
    issued = challenge(await handler(http_request()))
    payer = evm_client.charge(
        currency=BASE_SEPOLIA_USDC, account=Account.from_key("0x" + "11" * 32)
    )
    authorization = await payer.create_credential(CredentialParams(challenge=issued))

    await handler(http_request(authorization))

    [(params, _)] = client.payment_intents.calls
    verification = params["payment_method_options"]["crypto"]["transaction_verification_options"]
    assert verification == {"network": "base", "transaction_hash": reference}
    assert params["amount"] == 25
    assert params["customer"] == "cus_test"
    assert params["metadata"]["order"] == "123"
    assert params["metadata"]["call"] == "yes"
