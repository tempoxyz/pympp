"""x402 through the server APIs without HTTP: route handlers and verify_or_challenge."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from eth_account import Account

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp.events import PAYMENT_FAILED, EventDispatcher
from mpp.methods.evm import BASE_SEPOLIA_USDC, evm
from mpp.methods.evm.server import charge as evm_charge
from mpp.methods.evm.server import facilitator_pay_to
from mpp.methods.tempo import ChargeIntent as TempoChargeIntent
from mpp.methods.tempo import server as tempo_server
from mpp.server import Mpp, PaymentRequired, PaymentVerified
from mpp.server.method import RequestContext
from mpp.server.verify import verify_or_challenge
from mpp.x402 import X402Input, decode_payment_required, payment_response_header
from tests import MockRequest, challenge, challenges, http_request
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
    return tempo_server.charge(recipient=RECIPIENT, chain_id=42431)


def x402_request(signature: str | None = None, *, url: str = URL, method: str = "GET"):
    headers = {"PAYMENT-SIGNATURE": signature} if signature is not None else None
    return http_request(url=url, method=method, headers=headers)


def payment_required(result: Any) -> str | None:
    assert isinstance(result, PaymentRequired), result
    return result.challenge.headers.get("PAYMENT-REQUIRED")


async def accepted(server: Mpp) -> dict[str, Any]:
    header = payment_required(await server.charge(amount="0.01")(x402_request()))
    assert header is not None
    return dict(decode_payment_required(header)["accepts"][0])


async def signed(server: Mpp, resource_url: str | None = URL) -> str:
    header = payment_required(await server.charge(amount="0.01")(x402_request()))
    assert header is not None
    required = decode_payment_required(header)
    return sign_x402_payment(
        PAYER,
        dict(required["accepts"][0]),
        resource_url,
        extensions=dict(required.get("extensions", {})),
    )


class TestCharge:
    async def test_pays_with_payment_signature(self) -> None:
        server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
        signature = await signed(server)

        result = await server.charge(amount="0.01")(x402_request(signature))

        assert isinstance(result, PaymentVerified)
        credential, receipt = result.credential, result.receipt
        assert receipt.reference == "0x" + "cd" * 32
        assert receipt.payer == PAYER.address
        assert payment_response_header(credential, receipt) is not None

    async def test_payment_signature_needs_the_resource_url(self) -> None:
        server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
        result = await server.charge(amount="0.01")(x402_request("abc", url="/paid"))
        challenge(result)
        assert payment_required(result) is None

    async def test_ignores_payment_signature_without_x402_context(self) -> None:
        server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
        result = await server.charge(amount="0.01")(http_request())
        challenge(result)

    async def test_mismatched_payment_raises_with_a_retry_challenge(self) -> None:
        server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
        signature = await signed(server)
        result = await server.charge(amount="0.02")(x402_request(signature))
        assert challenge(result).request["amount"] == "20000"
        header = payment_required(result)
        assert header is not None
        assert "does not match" in decode_payment_required(header).get("error", "")

    async def test_composed_server_routes_payment_signature_to_evm(self) -> None:
        server = Mpp(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        handler = server.charge(amount="0.01")
        unpaid = await handler(x402_request())
        assert "evm" in [c.method for c in challenges(unpaid)]
        header = payment_required(unpaid)
        assert header is not None
        required = decode_payment_required(header)
        offer = dict(required["accepts"][0])
        extensions = dict(required.get("extensions", {}))

        result = await handler(
            x402_request(sign_x402_payment(PAYER, offer, URL, extensions=extensions))
        )
        assert isinstance(result, PaymentVerified)
        assert result.credential.challenge.method == "evm"

    async def test_x402_payment_must_pay_a_selected_offer(self) -> None:
        allow_evm = True
        server = Mpp(
            methods=[tempo_method(), evm_method()],
            realm=REALM,
            secret_key="k",
            select_offers=lambda offers, _context: [
                offer for offer in offers if allow_evm or offer.method.name != "evm"
            ],
        )
        handler = server.charge(amount="0.01")
        header = payment_required(await handler(x402_request()))
        assert header is not None
        required = decode_payment_required(header)
        signature = sign_x402_payment(
            PAYER,
            dict(required["accepts"][0]),
            URL,
            extensions=dict(required.get("extensions", {})),
        )

        allow_evm = False
        result = await handler(x402_request(signature))

        assert {c.method for c in challenges(result)} == {"tempo"}
        assert "does not match" in (result.challenge.body or b"").decode()

    async def test_x402_requirements_come_from_the_selected_offer(self) -> None:
        server = Mpp(
            methods=[evm_method(max_timeout_seconds=60), evm_method(max_timeout_seconds=120)],
            realm=REALM,
            secret_key="k",
            select_offers=lambda offers, _context: offers[1:],
        )
        handler = server.charge(amount="0.01")
        header = payment_required(await handler(x402_request()))
        assert header is not None
        required = decode_payment_required(header)
        assert [accept["maxTimeoutSeconds"] for accept in required["accepts"]] == [120]
        signature = sign_x402_payment(
            PAYER,
            dict(required["accepts"][0]),
            URL,
            extensions=dict(required.get("extensions", {})),
        )

        assert isinstance(await handler(x402_request(signature)), PaymentVerified)

    async def test_composed_server_reports_a_malformed_payment(self) -> None:
        server = Mpp(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        handler = server.charge(amount="0.01")
        result = await handler(x402_request("%%%"))
        assert "evm" in [c.method for c in challenges(result)]
        assert isinstance(result, PaymentRequired)
        assert "invalid PAYMENT-SIGNATURE header" in (result.challenge.body or b"").decode()
        header = payment_required(result)
        assert header is not None
        assert "invalid PAYMENT-SIGNATURE header" in decode_payment_required(header).get(
            "error", ""
        )

    async def test_x402_payment_required_forms(self) -> None:
        server = Mpp(methods=[tempo_method(), evm_method()], realm=REALM, secret_key="k")
        unpaid = await server.charge(amount="0.01")(x402_request())
        assert payment_required(unpaid) is not None

        tempo_only = await server.tempo.charge(amount="0.01")(x402_request())
        assert payment_required(tempo_only) is None

        relative = await server.evm.charge(amount="0.01")(x402_request(url="/paid"))
        assert payment_required(relative) is None


class TestVerifyOrChallenge:
    async def test_unexpected_settlement_errors_propagate_and_are_reported(self) -> None:
        def settle(authorization: Any) -> str:
            raise RuntimeError("boom")

        method = evm_method(settle=settle)
        intent = method.x402
        assert method.resolve_request is not None
        request = method.resolve_request(RequestContext(request={"amount": "0.01"}))
        assert isinstance(request, dict) and intent is not None
        server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
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
    import mpp.server.http as http
    from mpp.server import pay

    echo = ChallengeEcho(id="x402:1", realm=REALM, method="evm", intent="charge", request="e30")
    credential = Credential(challenge=echo, payload={"from": PAYER.address})
    receipt = Receipt.success("0x1", method="evm")

    async def verify(request: Any) -> Any:
        return PaymentVerified(credential=credential, receipt=receipt)

    async def handler(request: Any, credential: Any, receipt: Any) -> dict[str, str]:
        return {"secret": "kept for response_model to filter"}

    wrapped = pay(verify)(handler)  # type: ignore[arg-type]
    http._warned_plain_x402_response = False
    with caplog.at_level("WARNING"):
        result = await wrapped(MockRequest())
        await wrapped(MockRequest())

    assert result == {"secret": "kept for response_model to filter"}
    warnings = [r for r in caplog.records if "returned dict instead of a response" in r.message]
    assert len(warnings) == 1


async def test_charge_rejects_a_payment_without_route_metadata() -> None:
    server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
    signature = sign_x402_payment(PAYER, await accepted(server), None)
    result = await server.charge(amount="0.01")(x402_request(signature))
    assert isinstance(result, PaymentRequired)
    assert "does not bind required route metadata" in (result.challenge.body or b"").decode()


async def test_charge_advertises_the_http_method() -> None:
    server = Mpp(methods=evm_method(), realm=REALM, secret_key="k")
    handler = server.charge(amount="0.01")
    header = payment_required(await handler(x402_request(method="POST")))
    assert header is not None
    extensions = decode_payment_required(header).get("extensions", {})
    assert extensions["mppx"]["info"]["method"] == "POST"

    offer = dict(decode_payment_required(header)["accepts"][0])
    signature = sign_x402_payment(PAYER, offer, URL, extensions=extensions)
    paid = await handler(x402_request(signature, method="POST"))
    assert isinstance(paid, PaymentVerified)
    rejected = await handler(x402_request(signature, method="GET"))
    assert isinstance(rejected, PaymentRequired)
    assert "extensions do not match" in (rejected.challenge.body or b"").decode()


class TestX402Extra:
    async def test_adds_extra_to_the_x402_requirements(self) -> None:
        server = Mpp(
            methods=evm_method(x402_extra={"tempoSettlement": "0x" + "55" * 20}),
            realm=REALM,
            secret_key="k",
        )
        offer = await accepted(server)
        assert offer["extra"] == {
            "tempoSettlement": "0x" + "55" * 20,
            "assetTransferMethod": "eip3009",
            "name": "USDC",
            "version": "2",
        }

    def test_edits_to_nested_extra_do_not_change_later_requirements(self) -> None:
        method = evm_method(x402_extra={"nested": {"value": 1}})
        intent = method.x402
        assert intent is not None
        request = {
            "amount": "1",
            "currency": "0x" + "11" * 20,
            "recipient": "0x" + "22" * 20,
            "methodDetails": {"chainId": 8453},
        }
        intent.x402_requirements(request)["extra"]["nested"]["value"] = 2  # type: ignore[attr-defined]
        assert intent.x402_requirements(request)["extra"]["nested"] == {"value": 1}  # type: ignore[attr-defined]

    async def test_extra_cannot_override_the_eip3009_fields(self) -> None:
        server = Mpp(
            methods=evm_method(
                x402_extra={"assetTransferMethod": "permit2", "name": "x", "version": "9"}
            ),
            realm=REALM,
            secret_key="k",
        )
        offer = await accepted(server)
        assert offer["extra"] == {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"}

    async def test_payment_echoing_the_extra_settles_through_the_facilitator(self) -> None:
        settled: list[dict[str, Any]] = []
        deposit = "0x" + "44" * 20

        class DepositFacilitator:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any:
                return {"isValid": True, "payer": PAYER.address}

            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any:
                settled.append(dict(payment_requirements))
                return {
                    "success": True,
                    "transaction": "0x" + "cd" * 32,
                    "network": "eip155:84532",
                    "payer": PAYER.address,
                }

            async def supported(self) -> Any:
                return {
                    "kinds": [
                        {
                            "x402Version": 2,
                            "scheme": "exact",
                            "network": "eip155:84532",
                            "extra": {"payTo": deposit},
                        }
                    ]
                }

        facilitator = DepositFacilitator()
        recipient = await facilitator_pay_to(facilitator, network="eip155:84532")  # type: ignore[arg-type]
        server = Mpp(
            methods=evm_charge(
                currency=BASE_SEPOLIA_USDC,
                recipient=recipient,
                facilitator=facilitator,  # type: ignore[arg-type]
                x402_extra={"tempoSettlement": "0x" + "55" * 20},
            ),
            realm=REALM,
            secret_key="k",
        )
        offer = await accepted(server)
        assert offer["payTo"].lower() == deposit

        result = await server.charge(amount="0.01")(x402_request(await signed(server)))

        assert isinstance(result, PaymentVerified), result
        assert settled[0]["payTo"].lower() == deposit
        assert settled[0]["extra"]["tempoSettlement"] == "0x" + "55" * 20

    def test_rejects_a_non_object_extra(self) -> None:
        with pytest.raises(ValueError, match="x402_extra"):
            evm_method(x402_extra=["nope"])

    @pytest.mark.parametrize(
        "value",
        [Decimal("1.5"), float("nan"), float("inf"), 9007199254740993, {"at": datetime.now(UTC)}],
    )
    def test_rejects_a_non_canonical_json_extra(self, value: Any) -> None:
        with pytest.raises(ValueError, match="x402_extra must be canonical JSON"):
            evm_method(x402_extra={"nested": {"value": value}})

    @pytest.mark.parametrize("value", [1e20, -1e16, 2.0**53, [{"deep": 1e300}]])
    def test_rejects_floats_a_javascript_client_cannot_echo(self, value: Any) -> None:
        with pytest.raises(ValueError, match="at most 2\\*\\*53 - 1"):
            evm_method(x402_extra={"nested": {"value": value}})

    def test_accepts_small_floats(self) -> None:
        assert evm_method(x402_extra={"rate": 1.5, "big": 2**53 - 1}) is not None

    @pytest.mark.parametrize("extra", [{"1": "a", 1: "b"}, {"nested": [{2: "x"}]}, {None: 1}])
    def test_rejects_non_string_keys(self, extra: Any) -> None:
        with pytest.raises(ValueError, match="keys must be strings"):
            evm_method(x402_extra=extra)

    def test_rejects_deep_nesting(self) -> None:
        extra: Any = {"leaf": 1}
        # Shallow enough for json.dumps, too deep to deep-copy safely.
        for _ in range(300):
            extra = {"n": extra}
        with pytest.raises(ValueError, match="nest at most 64 levels"):
            evm_method(x402_extra=extra)

    def test_accepts_nesting_within_the_limit(self) -> None:
        extra: Any = 1
        for _ in range(63):
            extra = {"n": extra}
        assert evm_method(x402_extra=extra) is not None

    def test_rejects_an_oversized_extra(self) -> None:
        with pytest.raises(ValueError, match="at most 8192 bytes"):
            evm_method(x402_extra={"blob": "a" * 8192})
