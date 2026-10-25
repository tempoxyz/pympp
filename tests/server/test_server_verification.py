"""Conformance server-verification cases (vendor/mpp-tools/conformance/server-verification)."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from mpp import (
    Challenge,
    Credential,
    InvalidChallengeError,
    Method,
    PaymentError,
    PaymentExpiredError,
    Receipt,
    ServerMethod,
    VerificationFailedError,
    VerifyContext,
)
from mpp.challenge import compute_id
from mpp.server import Mpp

CASES = Path(__file__).parents[2] / "vendor/mpp-tools/conformance/server-verification/cases.json"
STRONG_SECRET = "conformance-server-verification-secret-32b"


class AnyRequest(BaseModel):
    model_config = ConfigDict(extra="allow")


class HashPayload(BaseModel):
    type: str
    hash: str


def _cases() -> list[Any]:
    return [pytest.param(case, id=case["name"]) for case in json.loads(CASES.read_text())["cases"]]


def _error_type(error: PaymentError) -> str:
    if isinstance(error, PaymentExpiredError):
        return "payment_expired"
    if isinstance(error, InvalidChallengeError):
        return "invalid_challenge"
    if isinstance(error, VerificationFailedError):
        return "verification_failed"
    raise AssertionError(f"unexpected error {error!r}")


@pytest.mark.parametrize("case", _cases())
async def test_server_verification(case: dict[str, Any]) -> None:
    data = case["input"]
    challenge = Challenge.from_dict(data["credential"]["challenge"])

    # The vectors are signed with a short demo key; prove our HMAC agrees, then re-sign the
    # echoed challenge with a production-strength key (Mpp enforces >= 32 bytes).
    binding = {
        "realm": challenge.realm,
        "method": challenge.method,
        "intent": challenge.intent,
        "request": challenge.request,
        "expires": challenge.expires,
    }
    vector_id = compute_id(data["secretKey"], **binding)
    if challenge.id == vector_id:
        challenge = replace(challenge, id=compute_id(STRONG_SECRET, **binding))

    async def verify(context: VerifyContext[Any]) -> Receipt:
        if data.get("verificationError"):
            raise VerificationFailedError(reason=data["verificationError"])
        return Receipt(
            method=context.credential.challenge.method,
            reference="conformance-receipt",
            timestamp="2026-01-29T12:00:00Z",
        )

    method = Method(
        name=data["method"],
        intent=data["intent"],
        request_model=AnyRequest,
        payload_model=HashPayload,
    )
    mppx = Mpp(
        methods=[ServerMethod(method=method, verify=verify)],
        realm=data["realm"],
        secret_key=STRONG_SECRET,
    )
    credential = Credential(challenge=challenge, payload=data["credential"]["payload"])

    try:
        receipt = await mppx.verify_credential(
            credential, request=data["request"], realm=data["realm"]
        )
        result: dict[str, Any] = {"ok": True, "receipt": receipt.to_dict()}
    except PaymentError as error:
        result = {"ok": False, "errorType": _error_type(error)}
    assert result == case["expected"]
