"""Tests for split credential validation and broadcast."""

from dataclasses import replace
from typing import Any

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.errors import InvalidChallengeError, VerificationFailedError
from mpp.server import (
    Intent,
    Mpp,
    Validation,
    broadcast_credential,
    validate_credential,
    verify_or_challenge,
)
from tests import make_bound_credential, make_credential


class SplitCharge:
    name = "charge"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def validate(self, credential: Credential, request: dict) -> Validation:
        self.calls.append("validate")
        return Validation(
            credential=credential,
            details={"mode": "pull"},
            intent=self.name,
            request=request,
        )

    async def broadcast(self, credential: Credential, request: dict) -> Receipt:
        self.calls.append("broadcast")
        return Receipt.success("split-reference")

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        self.calls.append("verify")
        return Receipt.success("legacy-reference")


class FakeMethod:
    name = "tempo"

    def __init__(self, charge: SplitCharge) -> None:
        self.intents: dict[str, Intent] = {"charge": charge}

    async def create_credential(self, challenge: Challenge) -> Credential:  # pragma: no cover
        raise NotImplementedError


@pytest.mark.asyncio
async def test_validation_is_non_mutating() -> None:
    intent = SplitCharge()
    result = await validate_credential(
        intent=intent,
        credential=make_credential(payload={}),
        request={"amount": "1000"},
    )

    assert result.details == {"mode": "pull"}
    assert intent.calls == ["validate"]


@pytest.mark.asyncio
async def test_broadcast_revalidates_before_terminal_hook() -> None:
    intent = SplitCharge()
    receipt = await broadcast_credential(
        intent=intent,
        credential=make_credential(payload={}),
        request={},
    )

    assert receipt.reference == "split-reference"
    assert intent.calls == ["validate", "broadcast"]


@pytest.mark.asyncio
async def test_legacy_intent_falls_back_to_verify() -> None:
    calls: list[str] = []

    class LegacyCharge:
        name = "charge"

        async def verify(self, credential: Credential, request: dict) -> Receipt:
            calls.append("verify")
            return Receipt.success("legacy-reference")

    legacy = LegacyCharge()
    with pytest.raises(VerificationFailedError, match="non-mutating"):
        await validate_credential(
            intent=legacy,
            credential=make_credential(payload={}),
            request={},
        )

    receipt = await broadcast_credential(
        intent=legacy,
        credential=make_credential(payload={}),
        request={},
    )
    assert receipt.reference == "legacy-reference"
    assert calls == ["verify"]


@pytest.mark.asyncio
async def test_route_uses_split_lifecycle() -> None:
    intent = SplitCharge()
    request = {"amount": "1000"}
    credential = make_bound_credential(
        payload={},
        request=request,
        realm="api.example.com",
        secret_key="test-secret",
    )

    result = await verify_or_challenge(
        authorization=credential.to_authorization(),
        intent=intent,
        request=request,
        realm="api.example.com",
        secret_key="test-secret",
    )

    assert isinstance(result, tuple)
    assert result[1].reference == "split-reference"
    assert intent.calls == ["validate", "broadcast"]


@pytest.mark.asyncio
async def test_mpp_exposes_bound_lifecycle() -> None:
    intent = SplitCharge()
    server = Mpp.create(
        method=FakeMethod(intent),
        realm="api.example.com",
        secret_key="test-secret",
    )
    request = {"amount": "1000"}
    credential = make_bound_credential(
        payload={},
        request=request,
        realm=server.realm,
        secret_key=server.secret_key,
    )

    validation = await server.validate_credential(credential.to_authorization(), request=request)
    receipt = await server.broadcast_credential(credential, intent="charge", request=request)
    alias_receipt = await server.verify_credential(credential)

    assert validation.request == request
    assert receipt.reference == "split-reference"
    assert alias_receipt.reference == "split-reference"
    assert intent.calls == [
        "validate",
        "validate",
        "broadcast",
        "validate",
        "broadcast",
    ]


@pytest.mark.asyncio
async def test_bound_broadcast_emits_success_but_validation_is_advisory() -> None:
    intent = SplitCharge()
    server = Mpp.create(
        method=FakeMethod(intent),
        realm="api.example.com",
        secret_key="test-secret",
    )
    events: list[tuple[str, dict[str, Any]]] = []
    server.on_payment_success(lambda payload: events.append(("success", payload)))
    server.on_payment_failed(lambda payload: events.append(("failed", payload)))
    request = {"amount": "1000"}
    credential = make_bound_credential(
        payload={},
        request=request,
        realm=server.realm,
        secret_key=server.secret_key,
    )

    await server.validate_credential(credential)
    assert events == []

    receipt = await server.broadcast_credential(credential)

    assert len(events) == 1
    name, payload = events[0]
    assert name == "success"
    assert payload["challenge"].id == credential.challenge.id
    assert payload["credential"] == credential
    assert payload["intent"] == "charge"
    assert payload["method"] == "tempo"
    assert payload["receipt"] == receipt
    assert payload["request"] == request


@pytest.mark.asyncio
async def test_bound_broadcast_and_alias_emit_failures() -> None:
    class RejectingCharge(SplitCharge):
        async def validate(self, credential: Credential, request: dict) -> Validation:
            self.calls.append("validate")
            raise VerificationFailedError("risk denied")

    intent = RejectingCharge()
    server = Mpp.create(
        method=FakeMethod(intent),
        realm="api.example.com",
        secret_key="test-secret",
    )
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)
    request = {"amount": "1000"}
    credential = make_bound_credential(
        payload={},
        request=request,
        realm=server.realm,
        secret_key=server.secret_key,
    )

    with pytest.raises(VerificationFailedError, match="risk denied"):
        await server.broadcast_credential(credential)
    with pytest.raises(VerificationFailedError, match="risk denied"):
        await server.verify_credential(credential)

    assert len(failures) == 2
    for payload in failures:
        assert payload["challenge"].id == credential.challenge.id
        assert payload["credential"] == credential
        assert payload["intent"] == "charge"
        assert payload["method"] == "tempo"
        assert isinstance(payload["error"], VerificationFailedError)
        assert payload["request"] == request
    assert intent.calls == ["validate", "validate"]


@pytest.mark.asyncio
async def test_mpp_rejects_tampered_bound_credential() -> None:
    intent = SplitCharge()
    server = Mpp.create(
        method=FakeMethod(intent),
        realm="api.example.com",
        secret_key="test-secret",
    )
    credential = make_bound_credential(
        payload={},
        request={},
        realm=server.realm,
        secret_key=server.secret_key,
    )
    credential = replace(
        credential,
        challenge=replace(credential.challenge, id="tampered"),
    )

    with pytest.raises(InvalidChallengeError):
        await server.validate_credential(credential)
    assert intent.calls == []


@pytest.mark.asyncio
async def test_invalid_validation_result_is_rejected() -> None:
    class InvalidSplit(SplitCharge):
        async def validate(self, credential: Credential, request: dict) -> Validation:
            return {}  # type: ignore[return-value]

    with pytest.raises(VerificationFailedError, match="invalid validation result"):
        await validate_credential(
            intent=InvalidSplit(),
            credential=make_credential(payload={}),
            request={},
        )
