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
from mpp.server import Mpp, ServerMethod, ValidateContext, Validation, VerifyContext
from mpp.server.verify import verify_or_challenge
from tests import make_bound_credential, server_method


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


CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"


def charge_method(charge: VerifiableCharge, **kwargs: Any) -> ServerMethod:
    """Serve the hooks of a charge, which receive the wire request, as a ServerMethod."""

    async def validate(context: ValidateContext) -> Validation:
        return await charge.validate(context.credential, context.challenge.request)

    async def broadcast(context: VerifyContext) -> Receipt:
        return await charge.broadcast(context.credential, context.challenge.request)

    return server_method(validate=validate, broadcast=broadcast, **kwargs)


def _server(intent: VerifiableCharge | None = None) -> Mpp:
    return Mpp(
        methods=charge_method(
            intent or VerifiableCharge(),
            request={"currency": CURRENCY, "recipient": RECIPIENT},
        ),
        realm="api.example.com",
        secret_key="test-secret",
    )


def _bound(request: dict[str, Any] | None = None, **kwargs: Any) -> Credential:
    kwargs.setdefault("realm", "api.example.com")
    kwargs.setdefault("secret_key", "test-secret")
    return make_bound_credential(payload={}, request=_wire(request), **kwargs)


def _wire(request: dict[str, Any] | None) -> dict[str, Any]:
    if not request:
        return {}
    return {"currency": CURRENCY, "recipient": RECIPIENT, **request}


@pytest.mark.asyncio
async def test_validation_is_non_mutating() -> None:
    intent = VerifiableCharge()
    result = await _server(intent).validate_credential(_bound({"amount": "1000"}))

    assert result.details == {"mode": "pull"}
    assert intent.calls == ["validate"]


@pytest.mark.asyncio
async def test_broadcast_revalidates_before_terminal_hook() -> None:
    intent = VerifiableCharge()
    receipt = await _server(intent).broadcast_credential(_bound())

    assert receipt.reference == "verifiable-reference"
    assert intent.calls == ["validate", "broadcast"]


@pytest.mark.asyncio
async def test_legacy_intent_falls_back_to_verify() -> None:
    calls: list[str] = []

    async def verify(context: VerifyContext) -> Receipt:
        calls.append("verify")
        return Receipt.success("legacy-reference")

    legacy = Mpp(
        methods=server_method(verify=verify), realm="api.example.com", secret_key="test-secret"
    )
    with pytest.raises(VerificationFailedError, match="non-mutating"):
        await legacy.validate_credential(_bound())

    receipt = await legacy.broadcast_credential(_bound())
    assert receipt.reference == "legacy-reference"
    assert receipt.payer is None
    assert calls == ["verify"]


@pytest.mark.asyncio
async def test_route_uses_verifiable_lifecycle() -> None:
    intent = VerifiableCharge()
    request = {"amount": "1000"}
    credential = _bound(request)

    result = await verify_or_challenge(
        authorization=credential.to_authorization(),
        intent=intent,
        request=_wire(request),
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

    assert validation.request == _wire(request)
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
    assert payload["request"] == _wire(request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("validated", "broadcast", "expected"),
    [
        ("0x" + "aa" * 20, None, "0x" + "aa" * 20),
        (None, None, None),
        ("0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "bb" * 20),
    ],
)
async def test_verified_payer_reaches_success_path(
    validated: str | None, broadcast: str | None, expected: str | None
) -> None:
    class PayerCharge(VerifiableCharge):
        async def validate(self, credential: Credential, request: dict) -> Validation:
            return replace(await super().validate(credential, request), payer=validated)

        async def broadcast(self, credential: Credential, request: dict) -> Receipt:
            return replace(await super().broadcast(credential, request), payer=broadcast)

    intent = PayerCharge()
    server = _server(intent)
    successes: list[dict[str, Any]] = []
    server.on_payment_success(successes.append)
    request = {"amount": "1000"}
    credential = _bound(request)

    route = await verify_or_challenge(
        authorization=credential.to_authorization(),
        intent=intent,
        request=_wire(request),
        realm="api.example.com",
        secret_key="test-secret",
    )
    receipt = await server.broadcast_credential(credential, request=request)

    assert isinstance(route, tuple)
    assert route[1].payer == expected
    assert receipt.payer == expected
    assert successes[0]["receipt"].payer == expected


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
        assert payload["request"] == _wire(request)
    assert intent.calls == ["validate"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential", "route_request"),
    [
        (_bound(realm="other.example.com"), None),
        (_bound({"amount": "1000"}), {"amount": "2000"}),
        (_bound(method="stripe"), None),
    ],
)
async def test_bound_broadcast_emits_preparation_failures(
    credential: Credential,
    route_request: dict[str, Any] | None,
) -> None:
    server = _server()
    failures: list[dict[str, Any]] = []
    server.on_payment_failed(failures.append)

    with pytest.raises((InvalidChallengeError, PaymentMethodUnsupportedError)):
        await server.broadcast_credential(credential, request=route_request)

    assert len(failures) == 1
    assert failures[0]["challenge"].id == credential.challenge.id
    assert failures[0]["credential"] == credential
    assert failures[0]["method"] == "tempo"
    assert isinstance(failures[0]["error"], (InvalidChallengeError, PaymentMethodUnsupportedError))


@pytest.mark.asyncio
async def test_invalid_intent_has_a_typed_failure() -> None:
    with pytest.raises(TypeError, match="requires verify or broadcast"):
        server_method()


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
        assert result.request == _wire({"amount": "1000"})
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
        await _server(InvalidVerifiable()).validate_credential(_bound())
