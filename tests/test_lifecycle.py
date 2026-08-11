"""Tests for credential validation and broadcast."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mpp import Challenge, Credential, Receipt, _body_digest
from mpp.errors import (
    InvalidChallengeError,
    MalformedCredentialError,
    PaymentExpiredError,
    PaymentMethodUnsupportedError,
    VerificationFailedError,
)
from mpp.server import (
    Intent,
    Mpp,
    Validation,
    VerifiableIntent,
    broadcast_credential,
    validate_credential,
    verify_or_challenge,
)
from tests import make_bound_credential, make_credential


class VerifiableCharge:
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
        return Receipt.success("verifiable-reference")


class FakeMethod:
    name = "tempo"

    def __init__(self, charge: VerifiableCharge) -> None:
        self.intents: dict[str, Intent | VerifiableIntent] = {"charge": charge}

    async def create_credential(self, challenge: Challenge) -> Credential:  # pragma: no cover
        raise NotImplementedError


def _server(intent: VerifiableCharge | None = None) -> Mpp:
    return Mpp.create(
        method=FakeMethod(intent or VerifiableCharge()),
        realm="api.example.com",
        secret_key="test-secret",
    )


def _bound(request: dict[str, Any] | None = None, **kwargs: Any) -> Credential:
    kwargs.setdefault("realm", "api.example.com")
    kwargs.setdefault("secret_key", "test-secret")
    return make_bound_credential(payload={}, request=request or {}, **kwargs)


@pytest.mark.asyncio
async def test_validation_is_non_mutating() -> None:
    intent = VerifiableCharge()
    result = await validate_credential(
        intent=intent,
        credential=make_credential(payload={}),
        request={"amount": "1000"},
    )

    assert result.details == {"mode": "pull"}
    assert intent.calls == ["validate"]


@pytest.mark.asyncio
async def test_broadcast_revalidates_before_terminal_hook() -> None:
    intent = VerifiableCharge()
    receipt = await broadcast_credential(
        intent=intent,
        credential=make_credential(payload={}),
        request={},
    )

    assert receipt.reference == "verifiable-reference"
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
async def test_route_uses_verifiable_lifecycle() -> None:
    intent = VerifiableCharge()
    request = {"amount": "1000"}
    credential = _bound(request)

    result = await verify_or_challenge(
        authorization=credential.to_authorization(),
        intent=intent,
        request=request,
        realm="api.example.com",
        secret_key="test-secret",
    )

    assert isinstance(result, tuple)
    assert result[1].reference == "verifiable-reference"
    assert intent.calls == ["validate", "broadcast"]


@pytest.mark.asyncio
async def test_mpp_exposes_bound_lifecycle() -> None:
    intent = VerifiableCharge()
    server = _server(intent)
    request = {"amount": "1000"}
    credential = _bound(request)

    validation = await server.validate_credential(credential.to_authorization(), request=request)
    receipt = await server.broadcast_credential(credential, intent="charge", request=request)

    assert validation.request == request
    assert receipt.reference == "verifiable-reference"
    assert intent.calls == ["validate", "validate", "broadcast"]


@pytest.mark.asyncio
async def test_bound_broadcast_emits_success_but_validation_is_advisory() -> None:
    intent = VerifiableCharge()
    server = _server(intent)
    events: list[tuple[str, dict[str, Any]]] = []
    server.on_payment_success(lambda payload: events.append(("success", payload)))
    server.on_payment_failed(lambda payload: events.append(("failed", payload)))
    request = {"amount": "1000"}
    credential = _bound(request)

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
async def test_bound_broadcast_emits_failures() -> None:
    class RejectingCharge(VerifiableCharge):
        async def validate(self, credential: Credential, request: dict) -> Validation:
            self.calls.append("validate")
            raise VerificationFailedError("risk denied")

    intent = RejectingCharge()
    server = _server(intent)
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)
    request = {"amount": "1000"}
    credential = _bound(request)

    with pytest.raises(VerificationFailedError, match="risk denied"):
        await server.broadcast_credential(credential)

    assert len(failures) == 1
    for payload in failures:
        assert payload["challenge"].id == credential.challenge.id
        assert payload["credential"] == credential
        assert payload["intent"] == "charge"
        assert payload["method"] == "tempo"
        assert isinstance(payload["error"], VerificationFailedError)
        assert payload["request"] == request
    assert intent.calls == ["validate"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential", "route_request"),
    [
        (_bound(realm="other.example.com"), None),
        (_bound({"amount": "1000"}), {"amount": "2000"}),
    ],
)
async def test_bound_broadcast_emits_preparation_failures(
    credential: Credential,
    route_request: dict[str, Any] | None,
) -> None:
    server = _server()
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)

    with pytest.raises(InvalidChallengeError):
        await server.broadcast_credential(credential, request=route_request)

    assert len(failures) == 1
    assert failures[0]["challenge"].id == credential.challenge.id
    assert failures[0]["credential"] == credential
    assert isinstance(failures[0]["error"], InvalidChallengeError)


@pytest.mark.asyncio
async def test_invalid_intent_has_a_typed_failure() -> None:
    class InvalidCharge:
        name = "charge"

    with pytest.raises(VerificationFailedError, match="verification or broadcast"):
        await broadcast_credential(
            intent=InvalidCharge(),  # type: ignore[arg-type]
            credential=make_credential(payload={}),
            request={},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["id", "realm", "method", "request", "expires"])
async def test_mpp_rejects_tampered_bound_credential(field: str) -> None:
    intent = VerifiableCharge()
    credential = _bound()
    credential = replace(
        credential,
        challenge=replace(credential.challenge, **{field: "tampered"}),
    )

    with pytest.raises((InvalidChallengeError, MalformedCredentialError)):
        await _server(intent).validate_credential(credential)
    assert intent.calls == []


@pytest.mark.asyncio
async def test_mpp_rejects_credential_bound_to_other_realm_or_method() -> None:
    server = _server()

    with pytest.raises(InvalidChallengeError, match="realm does not match"):
        await server.validate_credential(_bound(realm="other.example.com"))
    with pytest.raises(PaymentMethodUnsupportedError):
        await server.validate_credential(_bound(method="stripe"))


@pytest.mark.asyncio
async def test_mpp_rejects_intent_mismatches() -> None:
    server = _server()

    with pytest.raises(InvalidChallengeError, match="intent does not match"):
        await server.validate_credential(_bound(), intent="refund")
    with pytest.raises(PaymentMethodUnsupportedError):
        await server.validate_credential(_bound(intent="refund"))


@pytest.mark.asyncio
async def test_mpp_rejects_request_mismatch() -> None:
    credential = _bound(request={"amount": "1000"})

    with pytest.raises(InvalidChallengeError, match="request does not match"):
        await _server().validate_credential(credential, request={"amount": "2000"})


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["validate_credential", "broadcast_credential"])
async def test_mpp_contextless_lifecycle_uses_authenticated_echo(operation: str) -> None:
    body = {"resource": "bound"}
    credential = _bound(
        request={"amount": "1000"},
        digest=_body_digest.compute(body),
        meta={"route": "bound"},
    )

    result = await getattr(_server(), operation)(credential)

    if operation == "validate_credential":
        assert result.request == {"amount": "1000"}
    else:
        assert result.reference == "verifiable-reference"


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["validate_credential", "broadcast_credential"])
async def test_mpp_accepts_matching_context_bindings(operation: str) -> None:
    request = {"amount": "1000"}
    meta = {"route": "bound"}
    body = {"resource": "bound"}
    credential = _bound(request, digest=_body_digest.compute(body), meta=meta)

    await getattr(_server(), operation)(credential, request=request, meta=meta, body=body)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["validate_credential", "broadcast_credential"])
@pytest.mark.parametrize(
    ("meta", "body", "reason"),
    [
        ({"route": "other"}, {"resource": "bound"}, "opaque"),
        ({"route": "bound"}, {"resource": "other"}, "body digest mismatch"),
    ],
)
async def test_mpp_rejects_context_binding_mismatch(
    operation: str,
    meta: dict[str, str],
    body: dict[str, Any],
    reason: str,
) -> None:
    request = {"amount": "1000"}
    expected_meta = {"route": "bound"}
    expected_body = {"resource": "bound"}
    credential = _bound(
        request,
        digest=_body_digest.compute(expected_body),
        meta=expected_meta,
    )
    intent = VerifiableCharge()

    with pytest.raises(InvalidChallengeError, match=reason):
        await getattr(_server(intent), operation)(
            credential,
            request=request,
            meta=meta,
            body=body,
        )
    assert intent.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["validate_credential", "broadcast_credential"])
async def test_mpp_rejects_missing_context_bindings(operation: str) -> None:
    request = {"amount": "1000"}
    body = {"resource": "bound"}
    credential = _bound(
        request,
        digest=_body_digest.compute(body),
        meta={"route": "bound"},
    )
    intent = VerifiableCharge()

    with pytest.raises(InvalidChallengeError, match="opaque"):
        await getattr(_server(intent), operation)(credential, request=request)
    assert intent.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["not-a-credential", "Payment ???"])
async def test_mpp_rejects_malformed_serialized_credential(value: str) -> None:
    with pytest.raises(MalformedCredentialError):
        await _server().validate_credential(value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expires",
    [
        None,
        "not-a-date",
        (datetime.now() + timedelta(hours=1)).isoformat(),  # naive: no timezone
        (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    ],
)
async def test_mpp_rejects_missing_or_invalid_expiry(expires: str | None) -> None:
    challenge = Challenge.create(
        secret_key="test-secret",
        realm="api.example.com",
        method="tempo",
        intent="charge",
        request={},
        expires=expires,
    )
    credential = Credential(challenge=challenge.to_echo(), payload={})

    with pytest.raises(PaymentExpiredError):
        await _server().validate_credential(credential)


@pytest.mark.asyncio
async def test_invalid_validation_result_is_rejected() -> None:
    class InvalidVerifiable(VerifiableCharge):
        async def validate(self, credential: Credential, request: dict) -> Validation:
            return {}  # type: ignore[return-value]

    with pytest.raises(VerificationFailedError, match="invalid validation result"):
        await validate_credential(
            intent=InvalidVerifiable(),
            credential=make_credential(payload={}),
            request={},
        )
