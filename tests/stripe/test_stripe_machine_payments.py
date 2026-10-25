"""Port of mppx ``stripe/server/Methods.test.ts`` (``stripe.create()`` machine payments)."""

import logging
from typing import Any

import pytest
from pydantic import BaseModel

from mpp import (
    CanOfferContext,
    Challenge,
    Credential,
    Method,
    PaymentSuccessHookContext,
    Receipt,
    RequestContext,
    RespondContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerifyContext,
    store,
)
from mpp.method import resolve
from mpp.server import Mpp, Request
from mpp.stripe import ResolveContext
from mpp.stripe import server as stripe
from mpp.stripe.server import MachinePayments

TEMPO_ADDRESS = "0x1111111111111111111111111111111111111111"
REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"

tempo_server = pytest.importorskip("mpp.tempo.server")


def create(client: Any, **kwargs: Any) -> MachinePayments:
    kwargs.setdefault("network_id", "test-profile")
    kwargs.setdefault("livemode", False)
    kwargs.setdefault("store", store.memory())
    return stripe.create(client=client, **kwargs)


def find(methods: list[ServerMethod], name: str, intent: str = "charge") -> ServerMethod:
    return next(m for m in methods if m.name == name and m.intent == intent)


def receipt(reference: str) -> Receipt:
    return Receipt(method="tempo", reference=reference, timestamp="2026-01-01T00:00:00Z")


def success(
    reference: str = "0xtx123",
    amount: str = "500000",
    *,
    challenge: Challenge | None = None,
    request_input: dict[str, Any] | None = None,
) -> PaymentSuccessHookContext:
    return PaymentSuccessHookContext(
        receipt=receipt(reference),
        request={"amount": amount},
        challenge=challenge,
        request_input=request_input,
    )


def offer(amount: str) -> CanOfferContext:
    return CanOfferContext(input=Request("GET", "http://x"), request={"amount": amount})


def challenge(id: str = "challenge_123", amount: str = "500000") -> Challenge:
    return Challenge(
        id=id, realm=REALM, method="solana", intent="charge", request={"amount": amount}
    )


class SolanaRequest(BaseModel):
    amount: str


class SolanaPayload(BaseModel):
    token: str | None = None


SOLANA = Method(
    name="solana", intent="charge", request_model=SolanaRequest, payload_model=SolanaPayload
)


async def _receipt(context: Any) -> Receipt:
    return Receipt(method="solana", reference="0xsolhash", timestamp="2026-01-01T00:00:00Z")


def solana(**hooks: Any) -> ServerMethod:
    if "verify" not in hooks and "broadcast" not in hooks:
        hooks["verify"] = _receipt
    return ServerMethod(method=SOLANA, **hooks)


# -- construction ------------------------------------------------------------------------------


def test_requires_atomic_store(make_stripe: Any) -> None:
    with pytest.raises(TypeError, match="shared atomic `store`"):
        stripe.create(client=make_stripe(), network_id="p", livemode=False, store=None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="shared atomic `store`"):
        stripe.create(client=make_stripe(), network_id="p", livemode=False, store=object())  # type: ignore[arg-type]


def test_requires_raw_request() -> None:
    class NoRaw:
        async def create_payment_intent(self, *args: Any, **kwargs: Any) -> Any: ...

    with pytest.raises(TypeError, match="raw_request"):
        create(NoRaw())


async def test_returns_tempo_and_spt_methods(make_stripe: Any) -> None:
    async def resolver(network: str) -> str:
        return TEMPO_ADDRESS

    methods = await create(make_stripe(), deposit_addresses=resolver).load_default_methods()
    assert [m.key for m in methods] == ["tempo/charge", "stripe/charge"]
    tempo = find(methods, "tempo")
    assert tempo.defaults is not None
    assert tempo.defaults["recipient"] == TEMPO_ADDRESS


def test_sync_default_methods_rejects_resolver(make_stripe: Any) -> None:
    async def resolver(network: str) -> str:
        return TEMPO_ADDRESS

    with pytest.raises(TypeError, match="load_default_methods"):
        create(make_stripe(), deposit_addresses=resolver).default_methods()


def test_forwards_metadata_to_spt_defaults(make_stripe: Any) -> None:
    methods = create(
        make_stripe(), deposit_addresses={"tempo": TEMPO_ADDRESS}, metadata={"agent_id": "a"}
    ).default_methods()
    spt = find(methods, "stripe")
    assert spt.defaults is not None
    assert spt.defaults["metadata"] == {"agent_id": "a"}
    assert spt.defaults["currency"] == "usd"
    assert spt.defaults["decimals"] == 2
    assert spt.defaults["payment_method_types"] == ["card", "link"]


async def test_forwards_metadata_to_crypto_recording(make_stripe: Any) -> None:
    client = make_stripe()
    methods = create(
        client, deposit_addresses={"tempo": TEMPO_ADDRESS}, metadata={"agent_id": "test-agent"}
    ).default_methods()
    tempo = find(methods, "tempo")
    assert tempo.on_payment_success is not None
    await resolve(
        tempo.on_payment_success(
            success(
                challenge=Challenge(
                    id="challenge_123", realm=REALM, method="tempo", intent="charge", request={}
                ),
                request_input={
                    "payment_intent_options": {
                        "customer": "cus_123",
                        "hooks": {"inputs": {"tax": {"calculation": "taxcalc_123"}}},
                        "metadata": {"machine_payment": "custom", "request_id": "req_123"},
                        "receipt_email": "customer@example.com",
                    }
                },
            )
        )
    )
    params = client.calls[0].params
    assert params["customer"] == "cus_123"
    assert params["hooks"] == {"inputs": {"tax": {"calculation": "taxcalc_123"}}}
    assert params["receipt_email"] == "customer@example.com"
    assert params["metadata"] == {
        "agent_id": "test-agent",
        "machine_payment": "custom",
        "mpp_challenge_id": "challenge_123",
        "mpp_intent": "charge",
        "mpp_sdk": stripe.sdk_identifier(),
        "request_id": "req_123",
    }


async def test_call_metadata_merges_with_factory_metadata(make_stripe: Any) -> None:
    client = make_stripe()
    mp = create(client, metadata={"agent_id": "a", "plan": "free"})
    method = mp.tempo_charge(recipient=TEMPO_ADDRESS, metadata={"plan": "pro"})
    assert method.on_payment_success is not None
    await resolve(method.on_payment_success(success()))
    metadata = client.calls[0].params["metadata"]
    assert metadata["agent_id"] == "a"
    assert metadata["plan"] == "pro"


async def test_no_fee_payer_without_hosted(make_stripe: Any) -> None:
    method = create(
        make_stripe(), livemode=True, deposit_addresses={"tempo": TEMPO_ADDRESS}
    ).default_methods()[0]
    assert method.resolve_request is not None
    request = await resolve(
        method.resolve_request(
            RequestContext(
                request={
                    "amount": "0.01",
                    "currency": "0x20C000000000000000000000b9537d11c60E8b50",
                    "decimals": 6,
                    "recipient": TEMPO_ADDRESS,
                }
            )
        )
    )
    assert request.get("fee_payer") is None


@pytest.mark.parametrize("excluded", ["tempo", "spt"])
async def test_exclude(make_stripe: Any, excluded: str) -> None:
    async def resolver(network: str) -> str:
        return TEMPO_ADDRESS

    methods = await create(make_stripe(), deposit_addresses=resolver).load_default_methods(
        exclude=[excluded]  # type: ignore[list-item]
    )
    name = "stripe" if excluded == "spt" else excluded
    assert not [m for m in methods if m.name == name]
    assert methods


# -- PI recording ------------------------------------------------------------------------------


async def test_on_payment_success_returns_awaitable(make_stripe: Any) -> None:
    client = make_stripe()
    tempo = create(client, deposit_addresses={"tempo": TEMPO_ADDRESS}).default_methods()[0]
    assert tempo.on_payment_success is not None
    result = tempo.on_payment_success(success())
    assert result is not None
    await result
    assert len(client.calls) == 1


async def test_does_not_execute_unresolved_resolver_after_payment(make_stripe: Any) -> None:
    client = make_stripe()
    calls: list[Any] = []
    tempo = create(client, deposit_addresses={"tempo": TEMPO_ADDRESS}).default_methods()[0]
    assert tempo.on_payment_success is not None
    await resolve(
        tempo.on_payment_success(
            success(
                request_input={
                    "payment_intent_options": lambda ctx: calls.append(ctx) or {"customer": "c"}
                }
            )
        )
    )
    assert calls == []
    assert "customer" not in client.calls[0].params


def test_on_payment_success_none_without_reference(make_stripe: Any) -> None:
    client = make_stripe()
    tempo = create(client, deposit_addresses={"tempo": TEMPO_ADDRESS}).default_methods()[0]
    assert tempo.on_payment_success is not None
    assert tempo.on_payment_success(success(reference="")) is None
    assert client.calls == []


# -- minimum amounts ---------------------------------------------------------------------------


def test_tempo_rejects_amounts_below_one_cent(make_stripe: Any) -> None:
    tempo = create(make_stripe(), deposit_addresses={"tempo": TEMPO_ADDRESS}).default_methods()[0]
    assert tempo.can_offer is not None
    assert tempo.can_offer(offer("9999")) is False
    assert tempo.can_offer(offer("10000")) is True


def test_custom_rail_inherits_minimum(make_stripe: Any) -> None:
    methods = create(
        make_stripe(), deposit_addresses={"tempo": TEMPO_ADDRESS, "solana": "SOLaddr"}
    ).default_methods(rails={"solana": lambda address: solana()})
    rail = find(methods, "solana")
    assert rail.can_offer is not None
    assert rail.can_offer(offer("5000")) is False
    assert rail.can_offer(offer("10000")) is True


def test_user_can_offer_checked_after_minimum(make_stripe: Any) -> None:
    calls: list[Any] = []

    def user(context: CanOfferContext) -> bool:
        calls.append(context)
        return False

    methods = create(make_stripe(), deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda address: solana(can_offer=user)}
    )
    rail = find(methods, "solana")
    assert rail.can_offer is not None
    assert rail.can_offer(offer("5000")) is False
    assert calls == []
    assert rail.can_offer(offer("50000")) is False
    assert len(calls) == 1


# -- custom rails ------------------------------------------------------------------------------


async def test_propagates_resolved_options_through_composed_success(make_stripe: Any) -> None:
    client = make_stripe()
    calls: list[str] = []

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        assert "payment_intent_options" not in context.request
        calls.append("validate")
        return Validation(
            challenge=context.credential.challenge,
            credential=context.credential,
            details=None,
            intent="charge",
            method="solana",
            request=context.request,
        )

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        assert "payment_intent_options" not in context.request
        calls.append("broadcast")
        return await _receipt(context)

    def options(context: ResolveContext) -> dict[str, Any]:
        calls.append("resolve")
        assert context.request["amount"] == "10000"
        return {"hooks": {"inputs": {"tax": {"calculation": f"taxcalc_{context.challenge.id}"}}}}

    methods = create(client, deposit_addresses={"solana": "SOLaddr"}).default_methods(
        exclude=["spt"], rails={"solana": lambda a: solana(validate=validate, broadcast=broadcast)}
    )
    rail = find(methods, "solana")
    mppx = Mpp(methods=[rail], realm=REALM, secret_key=SECRET_KEY)
    handle = mppx.compose((rail, {"amount": "10000", "payment_intent_options": options}))

    first = await handle(Request("GET", "https://api.example.com/paid"))
    assert first.status == 402
    assert calls == []
    issued = Challenge.deserialize(first.challenge.headers["WWW-Authenticate"])
    assert issued.request == {"amount": "10000"}
    credential = Credential(challenge=issued, payload={"token": "valid"})
    paid = await handle(
        Request(
            "GET",
            "https://api.example.com/paid",
            headers={"Authorization": credential.serialize()},
        )
    )
    assert paid.status == 200
    assert calls == ["validate", "resolve", "broadcast"]
    assert client.calls[0].params["hooks"] == {
        "inputs": {"tax": {"calculation": f"taxcalc_{issued.id}"}}
    }
    assert client.calls[0].params["payment_method_options"]["crypto"][
        "transaction_verification_options"
    ] == {"network": "solana", "transaction_hash": "0xsolhash"}


async def test_resolves_options_after_validation_before_broadcast(make_stripe: Any) -> None:
    client = make_stripe()
    calls: list[str] = []

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        calls.append("validate")
        return None  # type: ignore[return-value]

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        calls.append("broadcast")
        return await _receipt(context)

    async def options(context: ResolveContext) -> dict[str, Any]:
        calls.append("resolve")
        assert context.credential.challenge is context.challenge
        assert context.request["amount"] == "500000"
        return {"hooks": {"inputs": {"tax": {"calculation": f"taxcalc_{context.challenge.id}"}}}}

    methods = create(client, deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: solana(validate=validate, broadcast=broadcast)}
    )
    method = find(methods, "solana")
    assert method.resolve_request
    assert method.validate
    assert method.broadcast
    assert method.on_payment_success is not None
    request = await resolve(
        method.resolve_request(
            RequestContext(request={"amount": "10000", "payment_intent_options": options})
        )
    )
    issued = challenge()
    credential = Credential(challenge=issued, payload={})
    await method.validate(ValidateContext(credential=credential, request=request))
    assert calls == ["validate"]
    result = await method.broadcast(VerifyContext(credential=credential, request=request))
    assert calls == ["validate", "resolve", "broadcast"]
    assert request["payment_intent_options"].to_params() == {
        "hooks": {"inputs": {"tax": {"calculation": "taxcalc_challenge_123"}}}
    }
    await resolve(
        method.on_payment_success(
            PaymentSuccessHookContext(
                challenge=issued,
                receipt=result,
                request={"amount": "10000"},
                request_input=request,
            )
        )
    )
    assert client.calls[0].params["hooks"] == {
        "inputs": {"tax": {"calculation": "taxcalc_challenge_123"}}
    }


async def test_does_not_broadcast_when_resolution_fails(make_stripe: Any) -> None:
    broadcasts: list[Any] = []

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        broadcasts.append(context)
        return await _receipt(context)

    error = RuntimeError("Tax API unavailable")

    async def options(context: ResolveContext) -> None:
        raise error

    methods = create(make_stripe(), deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: solana(broadcast=broadcast)}
    )
    method = find(methods, "solana")
    assert method.resolve_request
    assert method.broadcast
    request = await resolve(
        method.resolve_request(
            RequestContext(request={"amount": "10000", "payment_intent_options": options})
        )
    )
    with pytest.raises(RuntimeError) as info:
        await method.broadcast(
            VerifyContext(credential=Credential(challenge=challenge(), payload={}), request=request)
        )
    assert info.value is error
    assert broadcasts == []


async def test_resolves_options_before_legacy_verify(make_stripe: Any) -> None:
    calls: list[str] = []

    async def verify(context: VerifyContext[Any]) -> Receipt:
        calls.append("verify")
        return await _receipt(context)

    def options(context: ResolveContext) -> dict[str, Any]:
        calls.append("resolve")
        assert context.request["amount"] == "500000"
        return {"metadata": {"order": "order_123"}}

    methods = create(make_stripe(), deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: solana(verify=verify)}
    )
    method = find(methods, "solana")
    assert method.resolve_request
    assert method.verify
    request = await resolve(
        method.resolve_request(
            RequestContext(request={"amount": "10000", "paymentIntentOptions": options})
        )
    )
    await method.verify(
        VerifyContext(credential=Credential(challenge=challenge(), payload={}), request=request)
    )
    assert calls == ["resolve", "verify"]
    assert request["payment_intent_options"].to_params() == {"metadata": {"order": "order_123"}}


async def test_keeps_options_out_of_rail_hooks(make_stripe: Any) -> None:
    seen: list[str] = []

    def strict(name: str, request: dict[str, Any]) -> None:
        assert not any(key in request for key in ("payment_intent_options", "paymentIntentOptions"))
        seen.append(name)

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        strict("validate", context.request)
        return None  # type: ignore[return-value]

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        strict("broadcast", context.request)
        return await _receipt(context)

    async def resolve_request(context: RequestContext) -> dict[str, Any]:
        strict("request", context.request)
        return {**context.request, "resolved": True}

    def respond(context: RespondContext[Any]) -> None:
        strict("respond", context.request)

    methods = create(make_stripe(), deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={
            "solana": lambda a: solana(
                validate=validate,
                broadcast=broadcast,
                resolve_request=resolve_request,
                respond=respond,
            )
        }
    )
    method = find(methods, "solana")
    assert method.resolve_request
    assert method.validate
    assert method.broadcast
    assert method.respond
    request = await resolve(
        method.resolve_request(
            RequestContext(
                request={
                    "amount": "10000",
                    "payment_intent_options": {"metadata": {"request_id": "req_123"}},
                }
            )
        )
    )
    assert "payment_intent_options" in request
    assert request["resolved"] is True
    credential = Credential(challenge=challenge(amount="10000"), payload={})
    await method.validate(ValidateContext(credential=credential, request=request))
    result = await method.broadcast(VerifyContext(credential=credential, request=request))
    await resolve(
        method.respond(RespondContext(credential=credential, request=request, receipt=result))
    )
    assert seen == ["request", "validate", "broadcast", "respond"]


def test_wrapped_request_model_strips_options(make_stripe: Any) -> None:
    methods = create(make_stripe(), deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: solana()}
    )
    method = find(methods, "solana")
    wire = method.method.normalize_request(
        {"amount": "1", "paymentIntentOptions": {"customer": "cus_1"}}
    )
    assert wire == {"amount": "1"}
    with pytest.raises(ValueError, match="customer"):
        method.method.normalize_request({"amount": "1", "payment_intent_options": {"customer": ""}})


async def test_composes_user_hook_with_recorder(make_stripe: Any) -> None:
    client = make_stripe()
    user_calls: list[Any] = []
    methods = create(client, deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: solana(on_payment_success=user_calls.append)}
    )
    rail = find(methods, "solana")
    assert rail.on_payment_success is not None
    params = success("0xsolhash", "10000")
    result = rail.on_payment_success(params)
    assert result is not None
    await result
    assert user_calls == [params]
    assert len(client.calls) == 1


async def test_recorder_alone_without_user_hook(make_stripe: Any) -> None:
    client = make_stripe()
    methods = create(client, deposit_addresses={"solana": "SOLaddr"}).default_methods(
        rails={"solana": lambda a: [solana()]}
    )
    rail = find(methods, "solana")
    assert rail.on_payment_success is not None
    await resolve(rail.on_payment_success(success("0xsolhash", "10000")))
    assert len(client.calls) == 1


def test_missing_rail_address(make_stripe: Any) -> None:
    with pytest.raises(ValueError, match="missing deposit address for solana"):
        create(make_stripe()).default_methods(rails={"solana": lambda a: solana()})


# -- deposit address cache ---------------------------------------------------------------------


async def test_clients_do_not_share_cached_addresses(make_stripe: Any) -> None:
    client1 = make_stripe()
    client2 = make_stripe(addresses={"list": "0xdifferent"})
    assert await create(client1).find_or_create_deposit_address("tempo") == "0xabc"
    assert await create(client2, livemode=True).find_or_create_deposit_address("tempo") == (
        "0xdifferent"
    )
    assert len(client1.raw_calls) == 1
    assert len(client2.raw_calls) == 1


async def test_same_client_reuses_cached_address(make_stripe: Any) -> None:
    client = make_stripe(addresses={"list": "0xcached"})
    mp = create(client)
    assert await mp.find_or_create_deposit_address("tempo") == "0xcached"
    assert await mp.find_or_create_deposit_address("tempo") == "0xcached"
    assert len(client.raw_calls) == 1


# -- independent methods -----------------------------------------------------------------------


async def test_independent_methods_untouched(make_stripe: Any) -> None:
    client = make_stripe()
    hook_calls: list[Any] = []
    independent = solana(on_payment_success=hook_calls.append)
    methods = [
        *create(client, deposit_addresses={"tempo": TEMPO_ADDRESS}).default_methods(),
        independent,
    ]
    assert find(methods, "solana") is independent
    assert independent.can_offer is None
    tempo = find(methods, "tempo")
    assert tempo.on_payment_success is not None
    await resolve(tempo.on_payment_success(success("0xtx1")))
    assert len(client.calls) == 1
    assert independent.on_payment_success is not None
    independent.on_payment_success(success("0xtx2"))
    assert len(client.calls) == 1
    assert len(hook_calls) == 1


# -- graceful degradation ----------------------------------------------------------------------


async def test_partial_resolver_failure_warns(
    make_stripe: Any, caplog: pytest.LogCaptureFixture
) -> None:
    async def resolver(network: str) -> str:
        if network == "tempo":
            raise RuntimeError("API unavailable")
        return "0x1234567890abcdef1234567890abcdef12345678"

    rail_addresses: list[str] = []
    with caplog.at_level(logging.WARNING, logger="mpp.stripe"):
        methods = await create(make_stripe(), deposit_addresses=resolver).load_default_methods(
            rails={"solana": lambda a: rail_addresses.append(a) or solana()}
        )
    assert not [m for m in methods if m.name == "tempo"]
    assert find(methods, "stripe")
    assert find(methods, "solana")
    assert rail_addresses == ["0x1234567890abcdef1234567890abcdef12345678"]
    assert "tempo method excluded" in caplog.text


def test_no_deposit_addresses_is_spt_only(make_stripe: Any) -> None:
    mp = create(make_stripe())
    assert [m.key for m in mp.default_methods()] == ["stripe/charge"]
    assert [m.key for m in mp.default_methods(rails={})] == ["stripe/charge"]


# -- tempo charge store guards -----------------------------------------------------------------


def test_rejects_conflicting_charge_store(make_stripe: Any) -> None:
    mp = create(make_stripe())
    with pytest.raises(ValueError, match="factory-level shared atomic `store`"):
        mp.tempo_charge(recipient=TEMPO_ADDRESS, store=store.memory())


def test_rejects_charge_store_namespace(make_stripe: Any) -> None:
    mp = create(make_stripe())
    with pytest.raises(ValueError, match="cannot override the shared store namespace"):
        mp.tempo_charge(recipient=TEMPO_ADDRESS, store_key_prefix="isolated:")


def test_tempo_charge_uses_shared_store_and_currency(make_stripe: Any) -> None:
    shared = store.memory()
    method = create(make_stripe(), store=shared).tempo_charge(recipient=TEMPO_ADDRESS, store=shared)
    assert method.defaults is not None
    assert method.defaults["currency"] == "0x20c0000000000000000000000000000000000000"
    live = create(make_stripe(), livemode=True).tempo_charge(recipient=TEMPO_ADDRESS)
    assert live.defaults is not None
    assert live.defaults["currency"] == "0x20C000000000000000000000b9537d11c60E8b50"


# -- caller overrides (mppx spreads user options after the rail defaults) ----------------------


async def test_tempo_charge_caller_overrides_defaults(make_stripe: Any) -> None:
    client = make_stripe()
    user_calls: list[Any] = []
    method = create(client).tempo_charge(
        recipient=TEMPO_ADDRESS,
        can_offer=lambda context: True,
        on_payment_success=user_calls.append,
        testnet=True,
    )
    assert method.can_offer is not None
    assert method.can_offer(offer("1")) is True  # replaces the 1-cent minimum
    assert method.on_payment_success is not None
    await resolve(method.on_payment_success(success()))
    assert len(user_calls) == 1
    assert client.calls == []  # Stripe recording hook replaced
