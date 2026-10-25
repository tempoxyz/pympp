"""Conformance vector ``stripe-external-id-binding.json`` (mirrors the golden mppx adapter)."""

import json
from pathlib import Path
from typing import Any

import pytest

from mpp import Challenge, Credential, InvalidChallengeError, PaymentError
from mpp.server import Mpp
from mpp.stripe import PaymentIntent
from mpp.stripe import server as stripe

VECTOR = (
    Path(__file__).parents[2]
    / "vendor/mpp-tools/conformance/vectors/stripe-external-id-binding.json"
)
SECRET_KEY = "conformance-stripe-secret-32-bytes-min"
SCENARIOS = json.loads(VECTOR.read_text())["scenarios"]


class VectorStripe:
    def __init__(self, spt: str, intent: dict[str, Any]) -> None:
        self.spt = spt
        self.intent = intent

    async def create_payment_intent(
        self,
        params: Any,
        *,
        api_version: str,
        idempotency_key: str | None = None,
        stripe_account: str | None = None,
    ) -> PaymentIntent:
        if params["shared_payment_granted_token"] != self.spt:
            raise RuntimeError("Unexpected shared_payment_granted_token")
        return PaymentIntent(
            id=self.intent["id"],
            status=self.intent["status"],
            replayed=bool(self.intent.get("replayed")),
        )


async def verify_stripe_external_id_binding(input: dict[str, Any]) -> dict[str, Any]:
    request = input["request"]
    method_details = request.get("methodDetails") or {}
    mppx = Mpp(
        secret_key=SECRET_KEY,
        methods=[
            stripe.charge(
                amount=str(request.get("amount", "0")),
                client=VectorStripe(input["payload"]["spt"], input["paymentIntent"]),
                currency=str(request.get("currency", "usd")),
                decimals=0,
                network_id=method_details.get("networkId", "conformance"),
                payment_method_types=[
                    str(t) for t in method_details.get("paymentMethodTypes", ["card"])
                ],
            )
        ],
    )
    challenge = Challenge.create(
        secret_key=SECRET_KEY,
        realm="conformance.local",
        method="stripe",
        intent="charge",
        request=request,
        expires="2099-01-29T12:05:30Z",
    )
    try:
        receipt = await mppx.verify_credential(
            Credential(challenge=challenge, payload=input["payload"])
        )
    except InvalidChallengeError:
        return {"ok": False, "errorType": "invalid_challenge"}
    except PaymentError:
        return {"ok": False, "errorType": "verification_failed"}
    return {"ok": True, "receipt": {**receipt.to_dict(), "timestamp": "2026-01-29T12:00:30Z"}}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
async def test_stripe_external_id_binding(scenario: dict[str, Any]) -> None:
    assert await verify_stripe_external_id_binding(scenario["input"]) == scenario["expected"]
