"""Ported from mppx src/Method.test.ts."""

from typing import Any

import pytest
from pydantic import BaseModel

from mpp import (
    Challenge,
    Credential,
    InvalidChallengeError,
    InvalidPayloadError,
    Method,
    PaymentExpiredError,
    Receipt,
    ServerMethod,
    ValidateContext,
    Validation,
    VerificationFailedError,
    VerifyContext,
    broadcast_credential,
    expires,
    validate_credential,
)


class AmountRequest(BaseModel):
    amount: str


class TokenPayload(BaseModel):
    token: str


base = Method(
    name="alpha", intent="charge", request_model=AmountRequest, payload_model=TokenPayload
)


def credential(**changes: Any) -> Credential[Any]:
    challenge = Challenge.create(
        id="challenge-id",
        expires=changes.pop("expires", expires.seconds(60)),
        intent="charge",
        method=changes.pop("method", "alpha"),
        realm="example.com",
        request={"amount": "1000"},
    )
    return Credential(challenge=challenge, payload=changes.pop("payload", {"token": "valid"}))


def _receipt() -> Receipt:
    return Receipt(method="alpha", reference="reference", timestamp=expires.seconds(0))


def test_method_definition() -> None:
    assert (base.name, base.intent) == ("alpha", "charge")
    assert base.normalize_request({"amount": "1", "extra": "stripped"}) == {"amount": "1"}


def test_requires_verify_or_broadcast() -> None:
    with pytest.raises(TypeError):
        ServerMethod(method=base)

    async def verify(_: VerifyContext[Any]) -> Receipt:
        return _receipt()

    with pytest.raises(TypeError):
        ServerMethod(method=base, verify=verify, broadcast=verify)
    with pytest.raises(TypeError):
        ServerMethod(method=base, verify=verify, validate=verify)  # type: ignore[arg-type]


def split_method(calls: list[str]) -> ServerMethod:
    async def validate(ctx: ValidateContext[Any]) -> Validation[Any]:
        calls.append(f"validate:{ctx.operation}")
        assert isinstance(ctx.credential.payload, TokenPayload)
        return Validation(
            challenge=ctx.credential.challenge,
            credential=ctx.credential,
            details={},
            intent="charge",
            method="alpha",
            request=ctx.request,
        )

    async def broadcast(_: VerifyContext[Any]) -> Receipt:
        calls.append("broadcast")
        return _receipt()

    return ServerMethod(method=base, validate=validate, broadcast=broadcast)


async def test_validates_without_broadcasting() -> None:
    calls: list[str] = []
    result = await validate_credential([split_method(calls)], credential())
    assert calls == ["validate:validate"]
    assert result.method == "alpha"


async def test_revalidates_before_broadcasting() -> None:
    calls: list[str] = []
    receipt = await broadcast_credential([split_method(calls)], credential().serialize())
    assert calls == ["validate:broadcast", "broadcast"]
    assert receipt.reference == "reference"


async def test_validate_requires_validate_hook() -> None:
    async def verify(_: VerifyContext[Any]) -> Receipt:
        return _receipt()

    with pytest.raises(
        VerificationFailedError, match="does not support non-mutating credential validation"
    ):
        await validate_credential([ServerMethod(method=base, verify=verify)], credential())


async def test_prepare_errors() -> None:
    calls: list[str] = []
    methods = [split_method(calls)]
    with pytest.raises(InvalidChallengeError, match="no registered method for beta/charge"):
        await broadcast_credential(methods, credential(method="beta"))
    with pytest.raises(PaymentExpiredError):
        await broadcast_credential(methods, credential(expires="2020-01-01T00:00:00Z"))
    with pytest.raises(InvalidPayloadError):
        await broadcast_credential(methods, credential(payload={"nope": 1}))
    assert calls == []
