"""x402 through the server APIs without HTTP: Mpp.charge and verify_or_challenge."""

from __future__ import annotations

from typing import Any

import pytest
from eth_account import Account

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp.errors import MalformedCredentialError, VerificationFailedError
from mpp.events import PAYMENT_FAILED, EventDispatcher
from mpp.methods.evm import BASE_SEPOLIA_USDC, evm
from mpp.methods.tempo import ChargeIntent as TempoChargeIntent
from mpp.methods.tempo import tempo
from mpp.server import ComposedChallenges, Mpp, verify_or_challenge
from mpp.x402 import X402Input, decode_payment_required, payment_response_header
from tests.x402_harness import sign_x402_payment

PAYER = Account.from_key("0x" + "11" * 32)
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
URL = "https://api.example.com/paid"
REALM = "api.example.com"


def evm_method(**kwargs: Any):
    return evm(
        currency=BASE_SEPOLIA_USDC,
        recipient=RECIPIENT,
        settle=kwargs.pop("settle", lambda authorization: "0x" + "cd" * 32),
        **kwargs,
    )


def tempo_method():
    return tempo(intents={"charge": TempoChargeIntent()}, recipient=RECIPIENT, chain_id=42431)


async def accepted(server: Mpp) -> dict[str, Any]:
    result = await server.charge(None, "0.01", resource_url=URL)
    header = server.x402_payment_required(result, URL)  # type: ignore[arg-type]
    assert header is not None
    return dict(decode_payment_required(header)["accepts"][0])


class TestCharge:
    async def test_pays_with_payment_signature(self) -> None:
        server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
        signature = sign_x402_payment(PAYER, await accepted(server), URL)

        result = await server.charge(None, "0.01", payment_signature=signature, resource_url=URL)

        assert isinstance(result, tuple)
        credential, receipt = result
        assert receipt.reference == "0x" + "cd" * 32
        assert receipt.payer == PAYER.address
        assert payment_response_header(credential, receipt) is not None

    async def test_payment_signature_needs_the_resource_url(self) -> None:
        server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
        with pytest.raises(ValueError, match="resource_url"):
            await server.charge(None, "0.01", payment_signature="abc")

    async def test_ignores_payment_signature_without_x402_context(self) -> None:
        server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
        result = await server.charge(None, "0.01")
        assert isinstance(result, Challenge)

    async def test_mismatched_payment_raises_with_a_retry_challenge(self) -> None:
        server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
        signature = sign_x402_payment(PAYER, await accepted(server), URL)
        with pytest.raises(VerificationFailedError) as raised:
            await server.charge(None, "0.02", payment_signature=signature, resource_url=URL)
        assert isinstance(raised.value.retry_challenge, Challenge)
        assert raised.value.retry_challenge.request["amount"] == "20000"

    async def test_composed_server_routes_payment_signature_to_evm(self) -> None:
        server = Mpp.create(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        unpaid = await server.charge(None, "0.01", resource_url=URL)
        assert isinstance(unpaid, ComposedChallenges)
        header = server.x402_payment_required(unpaid, URL)
        assert header is not None
        offer = dict(decode_payment_required(header)["accepts"][0])

        result = await server.charge(
            None, "0.01", payment_signature=sign_x402_payment(PAYER, offer, URL), resource_url=URL
        )
        assert isinstance(result, tuple)
        assert result[0].challenge.method == "evm"

    async def test_composed_server_reports_a_malformed_payment(self) -> None:
        server = Mpp.create(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        result = await server.charge(None, "0.01", payment_signature="%%%", resource_url=URL)
        assert isinstance(result, ComposedChallenges)
        assert isinstance(result.error, MalformedCredentialError)
        header = server.x402_payment_required(result, URL)
        assert header is not None
        assert "invalid PAYMENT-SIGNATURE header" in decode_payment_required(header).get(
            "error", ""
        )

    async def test_x402_payment_required_forms(self) -> None:
        server = Mpp.create(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        unpaid = await server.charge(None, "0.01", resource_url=URL)
        assert isinstance(unpaid, ComposedChallenges)

        listed = server.x402_payment_required(list(unpaid.challenges), URL, error="try again")
        assert listed is not None
        assert decode_payment_required(listed).get("error") == "try again"

        tempo_only = [c for c in unpaid.challenges if c.method == "tempo"]
        assert server.x402_payment_required(tempo_only, URL) is None

        [evm_challenge] = [c for c in unpaid.challenges if c.method == "evm"]
        foreign = Challenge(
            id=evm_challenge.id,
            method="evm",
            intent="charge",
            request=evm_challenge.request,
            realm="elsewhere.example.com",
        )
        assert server.x402_payment_required(foreign, URL) is None


class TestVerifyOrChallenge:
    async def test_unexpected_settlement_errors_propagate_and_are_reported(self) -> None:
        def settle(authorization: Any) -> str:
            raise RuntimeError("boom")

        method = evm_method(settle=settle)
        intent = method.intents["charge"]
        request = method.transform_request(
            {"amount": "10000", "currency": method.currency, "recipient": RECIPIENT}, None
        )
        server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
        signature = sign_x402_payment(PAYER, await accepted(server), URL)
        events = EventDispatcher()
        failures: list[Any] = []
        events.on(PAYMENT_FAILED, failures.append)

        with pytest.raises(RuntimeError, match="boom"):
            await verify_or_challenge(
                authorization=None,
                intent=intent,
                request=request,
                realm=REALM,
                secret_key="k",
                method="evm",
                events=events,
                x402=X402Input(resource_url=URL, payment_signature=signature),
            )
        [failure] = failures
        assert failure["credential"].challenge.id.startswith("x402:")

    async def test_intents_without_x402_issue_a_challenge(self) -> None:
        result = await verify_or_challenge(
            authorization="Bearer api-key",
            intent=TempoChargeIntent(),
            request={"amount": "1", "currency": "0x" + "aa" * 20, "recipient": RECIPIENT},
            realm=REALM,
            secret_key="k",
            x402=X402Input(resource_url=URL, payment_signature="anything"),
        )
        assert isinstance(result, Challenge)


def test_payment_response_needs_a_chain_id() -> None:
    echo = ChallengeEcho(id="x402:1", realm=REALM, method="evm", intent="charge", request="!!")
    credential = Credential(challenge=echo, payload={"from": PAYER.address})
    assert payment_response_header(credential, Receipt.success("0x1", method="evm")) is None


async def test_plain_data_is_left_to_the_framework(caplog: pytest.LogCaptureFixture) -> None:
    """FastAPI applies response_model and status_code to returned data, so keep it."""
    import mpp.server.decorator as decorator
    from mpp.server.decorator import wrap_payment_handler

    echo = ChallengeEcho(id="x402:1", realm=REALM, method="evm", intent="charge", request="e30")
    credential = Credential(challenge=echo, payload={"from": PAYER.address})
    receipt = Receipt.success("0x1", method="evm")

    async def verify(authorization: Any, request: Any) -> Any:
        return credential, receipt

    async def handler(request: Any, credential: Any, receipt: Any) -> dict[str, str]:
        return {"secret": "kept for response_model to filter"}

    wrapped = wrap_payment_handler(handler, verify, lambda: REALM)
    decorator._warned_plain_x402_response = False
    with caplog.at_level("WARNING", logger="mpp.server.decorator"):
        result = await wrapped(object())
        await wrapped(object())

    assert result == {"secret": "kept for response_model to filter"}
    warnings = [r for r in caplog.records if "returned dict instead of a response" in r.message]
    assert len(warnings) == 1


async def test_unscoped_charge_accepts_a_payment_without_a_resource() -> None:
    server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
    signature = sign_x402_payment(PAYER, await accepted(server), None)
    result = await server.charge(None, "0.01", payment_signature=signature, resource_url=URL)
    assert isinstance(result, tuple)


async def test_charge_advertises_the_http_method() -> None:
    server = Mpp.create(method=evm_method(), realm=REALM, secret_key="k")
    result = await server.charge(None, "0.01", resource_url=URL, http_method="POST")
    header = server.x402_payment_required(result, URL, http_method="POST")  # type: ignore[arg-type]
    assert header is not None
    extensions = decode_payment_required(header).get("extensions", {})
    assert extensions["mppx"]["info"] == {"method": "POST"}

    offer = dict(decode_payment_required(header)["accepts"][0])
    signature = sign_x402_payment(PAYER, offer, URL, extensions=extensions)
    paid = await server.charge(
        None, "0.01", payment_signature=signature, resource_url=URL, http_method="POST"
    )
    assert isinstance(paid, tuple)
    with pytest.raises(VerificationFailedError, match="extensions do not match"):
        await server.charge(
            None, "0.01", payment_signature=signature, resource_url=URL, http_method="GET"
        )
