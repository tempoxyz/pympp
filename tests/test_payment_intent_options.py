"""Focused contracts for request-scoped Stripe PaymentIntent input."""

import asyncio
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import stripe

from mpp import Challenge, Credential, Receipt
from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods import Method
from mpp.methods.stripe import PaymentIntentContext, payment_intent_method
from mpp.methods.stripe import server as stripe_server
from mpp.methods.stripe.payment_intent_options import validate_options
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Validation
from mpp.server.method import ValidateContext, VerifyContext
from tests import challenges, http_request
from tests.test_stripe_machine_payments import TEMPO_ADDRESS, make_payments

OPTIONS = {
    "customer": "cus_test",
    "receipt_email": "buyer@example.com",
    "metadata": {"order_id": "order_test"},
    "hooks": {"inputs": {"tax": {"calculation": "taxcalc_test"}}},
}


class Rail:
    name = "charge"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def validate(self, context: ValidateContext) -> Validation:
        self.calls.append("validate")
        if not context.credential.payload.get("valid"):
            raise VerificationFailedError("invalid credential")
        return Validation(context.credential, {}, self.name, dict(context.challenge.request))

    async def broadcast(self, context: VerifyContext) -> Receipt:
        self.calls.append("broadcast")
        return Receipt.success("0xtest", method="tempo")


@dataclass(frozen=True, slots=True, kw_only=True)
class RawPayload(Method[Any, Any]):
    """A method definition whose credential payloads reach the hooks unparsed."""

    def parse_payload(self, payload: Any) -> Any:
        return payload


def settle_tempo_with(monkeypatch: pytest.MonkeyPatch, **hooks: Any) -> None:
    """Make ``payments.tempo.charge()`` settle with ``hooks`` instead of the Tempo chain."""
    wrap = payment_intent_method.with_payment_intent_input

    def wrapped(method: Any, *args: Any, **kwargs: Any) -> Any:
        settle = {"verify": None, "validate": None, "broadcast": None, **hooks}
        method = wrap(replace(method, **settle), *args, **kwargs)
        definition = {
            field.name: getattr(method.method, field.name) for field in fields(method.method)
        }
        return replace(method, method=RawPayload(**definition))

    monkeypatch.setattr(payment_intent_method, "with_payment_intent_input", wrapped)


@pytest.fixture(params=["stripe", "tempo"])
def payment(request, monkeypatch):
    rail = Rail()
    settle_tempo_with(monkeypatch, validate=rail.validate, broadcast=rail.broadcast)
    client, payments = make_payments(
        deposit_addresses={"tempo": TEMPO_ADDRESS}, metadata={"configured": "yes"}
    )
    method = payments.spt.charge() if request.param == "stripe" else payments.tempo.charge()
    return Mpp(methods=method, realm="example.com", secret_key="secret"), client, rail


def credential(challenge: Challenge, **payload: Any) -> Credential:
    return Credential(challenge.to_echo(), payload or {"spt": "spt_test", "valid": True})


async def pay(server: Mpp, authorization: str | None, options: Any = None, **extra: Any) -> Any:
    handler = server.charge(amount="0.50", payment_intent_options=options, **extra)
    return await handler(http_request(authorization))


async def issue(server: Mpp, options: Any = None) -> Challenge:
    return challenges(await pay(server, None, options))[0]


async def test_static_options_are_private_and_propagate_with_analytics(payment):
    server, client, rail = payment
    for options in (None, OPTIONS):
        challenge = await issue(server, options)
        assert "payment_intent_options" not in challenge.request
        await pay(server, credential(challenge).to_authorization(), options)
        params, _ = client.payment_intents.calls[-1]
        assert {
            key: params["metadata"][key]
            for key in ("machine_payment", "mpp_sdk", "mpp_challenge_id", "mpp_intent")
        } == {
            "machine_payment": "true",
            "mpp_sdk": f"pympp/{version('pympp')}",
            "mpp_challenge_id": challenge.id,
            "mpp_intent": "charge",
        }
        if options:
            assert {key: params[key] for key in ("customer", "receipt_email", "hooks")} == {
                key: options[key] for key in ("customer", "receipt_email", "hooks")
            }
            assert params["metadata"]["order_id"] == "order_test"
    assert len(client.payment_intents.calls) == 2
    if server.methods[0].name == "tempo":
        assert rail.calls == ["validate", "broadcast", "validate", "broadcast"]


async def test_deferred_resolver_skips_unpaid_and_rejected_credentials(payment):
    server, client, rail = payment
    resolver = AsyncMock(return_value=OPTIONS)
    challenge = await issue(server, resolver)
    expired = challenges(
        await pay(
            server,
            None,
            resolver,
            expires=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        )
    )[0]
    rejected = (
        "Payment broken",
        credential(replace(challenge, id="forged")).to_authorization(),
        credential(expired).to_authorization(),
    )
    for authorization in rejected:
        result = await pay(server, authorization, resolver)
        assert isinstance(result, PaymentRequired)
    result = await pay(server, credential(challenge, spt="").to_authorization(), resolver)
    assert isinstance(result, PaymentRequired)
    assert VerificationFailedError.title in (result.challenge.body or b"").decode()
    resolver.assert_not_called()
    assert not client.payment_intents.calls


async def test_resolver_runs_before_spt_payment_intent_or_tempo_broadcast(payment):
    server, client, rail = payment

    async def resolve(context: PaymentIntentContext):
        assert context.challenge.id == challenge.id and context.request == challenge.request
        assert not client.payment_intents.calls
        if server.methods[0].name == "tempo":
            assert rail.calls == ["validate"]
        raise BadRequestError("invalid tax country")

    challenge = await issue(server, resolve)
    result = await pay(server, credential(challenge).to_authorization(), resolve)
    assert isinstance(result, PaymentRequired)
    assert BadRequestError.title in (result.challenge.body or b"").decode()
    assert not client.payment_intents.calls and "broadcast" not in rail.calls


@pytest.mark.parametrize(
    "value",
    [
        {"amount": 1},
        {"confirm": False},
        {"idempotency_key": "x"},
        {"customer": ""},
        {"receipt_email": " "},
        {"metadata": {"bad": 1}},
        {"hooks": {"inputs": {"tax": {"calculation": ""}}}},
    ],
)
def test_options_reject_uncontrolled_or_invalid_values(value):
    with pytest.raises(BadRequestError):
        validate_options(value)


@pytest.mark.parametrize(
    "error,retries",
    [
        (stripe.InvalidRequestError("bad customer", "customer"), 1),
        (stripe.InvalidRequestError("bad amount", "amount"), 0),
        (stripe.APIConnectionError("timeout"), 0),
    ],
)
async def test_crypto_fallback_is_once_and_only_for_optional_field_rejection(
    error, retries, monkeypatch
):
    rail = Rail()
    settle_tempo_with(monkeypatch, validate=rail.validate, broadcast=rail.broadcast)
    client, payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    method = payments.tempo.charge()
    server = Mpp(methods=method, realm="example.com", secret_key="secret")
    calls = []

    async def create(params, *, options):
        calls.append((params, options))
        if len(calls) == 1:
            raise error
        return await client.payment_intents.create(params, options=options)

    client.payment_intents.create_async = create
    challenge = await issue(server, OPTIONS)
    await pay(server, credential(challenge).to_authorization(), OPTIONS)
    assert len(calls) == retries + 1
    if retries:
        assert calls[1][1]["idempotency_key"] == "0xtest_fallback"
        assert not {"customer", "receipt_email", "hooks"} & calls[1][0].keys()
        assert "configured" not in calls[1][0]["metadata"]


async def test_compose_and_direct_broadcast_accept_private_options(payment):
    server, client, rail = payment
    resolver = AsyncMock(return_value=OPTIONS)
    handler = server.compose(
        (server.methods[0], {"amount": "0.50", "payment_intent_options": resolver})
    )
    paid = credential(challenges(await handler(http_request()))[0])
    await server.broadcast_credential(paid, payment_intent_options=resolver)
    assert isinstance(await handler(http_request(paid.to_authorization())), PaymentVerified)
    assert resolver.await_count == 2 and len(client.payment_intents.calls) == 2


async def test_attempt_options_are_isolated(payment):
    server, client, rail = payment
    challenge = await issue(server)
    await asyncio.gather(
        *(
            pay(server, credential(challenge).to_authorization(), {"customer": customer})
            for customer in ("cus_a", "cus_b")
        )
    )
    assert {params["customer"] for params, _ in client.payment_intents.calls} == {"cus_a", "cus_b"}


async def test_raw_http_spt_supports_options_without_owning_injected_client():
    calls = []

    def respond(request):
        calls.append(request.content.decode())
        return httpx.Response(200, json={"id": "pi", "status": "succeeded"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
        method = stripe_server.charge(
            secret_key="sk_test", http_client=http, network_id="bn_test", currency="usd"
        )
        server = Mpp(methods=method, realm="example.com", secret_key="secret")
        challenge = await issue(server, OPTIONS)
        await pay(server, credential(challenge).to_authorization(), OPTIONS)
        assert "hooks%5Binputs%5D%5Btax%5D%5Bcalculation%5D=taxcalc_test" in calls[0]
        assert not http.is_closed


async def test_raw_http_spt_failure_does_not_expose_private_options():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                400, json={"error": {"message": "No such customer: cus_private"}}
            )
        )
    ) as http:
        method = stripe_server.charge(
            secret_key="sk_test", http_client=http, network_id="bn_test", currency="usd"
        )
        server = Mpp(methods=method, realm="example.com", secret_key="secret")
        challenge = await issue(server, OPTIONS)
        result = await pay(server, credential(challenge).to_authorization(), OPTIONS)
        assert isinstance(result, PaymentRequired)
        assert "cus_private" not in (result.challenge.body or b"").decode()


async def test_legacy_crypto_rail_remains_supported(monkeypatch):
    calls = []

    async def verify(context):
        calls.append("verify")
        return Receipt.success("0xlegacy", method="tempo")

    settle_tempo_with(monkeypatch, verify=verify)
    client, payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    method = payments.tempo.charge()
    server = Mpp(methods=method, realm="example.com", secret_key="secret")

    def resolver(context):
        calls.append("resolve")
        return None

    challenge = await issue(server, resolver)
    await pay(server, credential(challenge).to_authorization(), resolver)
    assert calls == ["resolve", "verify"] and len(client.payment_intents.calls) == 1


async def test_replacing_the_existing_tempo_callback_preserves_event_behavior(monkeypatch):
    # The actual rail rejects this malformed transaction before either callback;
    # use a verify-only rail to isolate callback registration behavior.
    async def verify(context):
        return Receipt.success("0xcallback", method="tempo")

    settle_tempo_with(monkeypatch, verify=verify)
    client, payments = make_payments(deposit_addresses={"tempo": TEMPO_ADDRESS})
    method, callback = payments.tempo.charge(), AsyncMock()
    method = replace(method, on_payment_success=callback)
    server = Mpp(methods=method, realm="example.com", secret_key="secret")
    challenge = await issue(server, {"metadata": {"order": "123"}})
    await pay(server, credential(challenge).to_authorization(), {"metadata": {"order": "123"}})
    callback.assert_awaited_once()
    assert client.payment_intents.calls[0][0]["metadata"]["order"] == "123"
