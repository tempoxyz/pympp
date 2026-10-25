import base64
import json

import pytest

from mpp import x402
from mpp.x402 import (
    InvalidJsonHeaderError,
    PaymentPayload,
    PaymentRequired,
    decode_payment_required,
    decode_payment_required_envelope,
    decode_payment_response,
    decode_payment_signature,
    encode_payment_required,
    encode_payment_response,
    encode_payment_signature,
)

PAYMENT_REQUIRED = {
    "accepts": [
        {
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
            "maxTimeoutSeconds": 60,
            "network": "eip155:84532",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "scheme": "exact",
        }
    ],
    "resource": {"mimeType": "application/json", "url": "https://api.example.com/premium-data"},
    "extensions": {
        "mppx": {
            "info": {"method": "GET"},
            "schema": {
                "properties": {"method": {"type": "string"}},
                "required": ["method"],
                "type": "object",
            },
        }
    },
    "x402Version": 2,
}

PAYMENT_PAYLOAD = {
    "accepted": {
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "maxTimeoutSeconds": 60,
        "network": "eip155:84532",
        "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "scheme": "exact",
    },
    "payload": {
        "authorization": {
            "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
            "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
            "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "validAfter": "1740672089",
            "validBefore": "1740672154",
            "value": "10000",
        },
        "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
    },
    "x402Version": 2,
}


def raw(value: object) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


def test_round_trips_payment_required() -> None:
    header = encode_payment_required(PAYMENT_REQUIRED)
    decoded = decode_payment_required(header)
    assert decoded == PaymentRequired.model_validate(PAYMENT_REQUIRED)
    assert decoded.to_dict() == PAYMENT_REQUIRED


def test_round_trips_payment_signature() -> None:
    header = encode_payment_signature(PAYMENT_PAYLOAD)
    decoded = decode_payment_signature(header)
    assert decoded == PaymentPayload.model_validate(PAYMENT_PAYLOAD)
    assert decoded.to_dict() == PAYMENT_PAYLOAD


def test_round_trips_payment_response() -> None:
    value = {"network": "eip155:8453", "payer": "0x1", "success": True, "transaction": "0xab"}
    assert decode_payment_response(encode_payment_response(value)).to_dict() == value


def test_encodes_like_json_stringify_of_schema_ordered_object() -> None:
    # zod emits keys in schema (alphabetical) order and drops unknown keys.
    header = encode_payment_required({**PAYMENT_REQUIRED, "unknown": True})
    body = base64.b64decode(header).decode()
    assert body.startswith('{"accepts":[{"amount":"10000","asset":')
    assert '"extensions":{"mppx":' in body
    assert body.endswith('"x402Version":2}')
    assert "unknown" not in body
    assert " " not in body


def test_payment_signature_uses_padded_standard_base64() -> None:
    header = encode_payment_signature(PAYMENT_PAYLOAD)
    assert header == base64.b64encode(base64.b64decode(header)).decode()


@pytest.mark.parametrize(
    "value",
    [
        "not base64!",
        raw("text"),
        raw({**PAYMENT_REQUIRED, "x402Version": 1}),
        raw({**PAYMENT_REQUIRED, "accepts": []}),
        raw({**PAYMENT_REQUIRED, "resource": {"url": ""}}),
    ],
)
def test_rejects_invalid_payment_required(value: str) -> None:
    with pytest.raises(InvalidJsonHeaderError, match=r"Invalid base64 JSON header\."):
        decode_payment_required(value)


def test_rejects_unsupported_scheme_in_strict_decode() -> None:
    accepts = [{**PAYMENT_REQUIRED["accepts"][0], "scheme": "upto"}]  # type: ignore[index]
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_required(raw({**PAYMENT_REQUIRED, "accepts": accepts}))


def test_envelope_leaves_accepts_unvalidated() -> None:
    solana = {"network": "solana:mainnet", "scheme": "exact"}
    envelope = decode_payment_required_envelope(
        raw({**PAYMENT_REQUIRED, "accepts": [solana], "extensions": {"bad": 1}})
    )
    assert envelope.accepts == [solana]
    assert envelope.extensions is None
    assert envelope.resource.url == "https://api.example.com/premium-data"


@pytest.mark.parametrize(
    "value",
    [
        raw([]),
        raw({**PAYMENT_REQUIRED, "x402Version": 1}),
        raw({**PAYMENT_REQUIRED, "accepts": {}}),
        raw({**PAYMENT_REQUIRED, "resource": {}}),
    ],
)
def test_envelope_rejects_malformed(value: str) -> None:
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_required_envelope(value)


def test_header_names_match_mppx() -> None:
    assert x402.PAYMENT_REQUIRED_HEADER == "PAYMENT-REQUIRED"
    assert x402.PAYMENT_SIGNATURE_HEADER == "PAYMENT-SIGNATURE"
    assert x402.LEGACY_PAYMENT_SIGNATURE_HEADER == "X-PAYMENT"
    assert x402.PAYMENT_RESPONSE_HEADER == "PAYMENT-RESPONSE"


def _without(value: dict[str, object], key: str) -> dict[str, object]:
    return {k: v for k, v in value.items() if k != key}


@pytest.mark.parametrize(
    "value",
    [
        _without(PAYMENT_PAYLOAD, "x402Version"),
        {**PAYMENT_PAYLOAD, "resource": None},
        {**PAYMENT_PAYLOAD, "extensions": None},
        {**PAYMENT_PAYLOAD, "accepted": {**PAYMENT_PAYLOAD["accepted"], "extra": None}},  # type: ignore[dict-item]
    ],
    ids=["missing-version", "null-resource", "null-extensions", "null-extra"],
)
def test_payment_signature_requires_version_and_rejects_nulls(value: dict[str, object]) -> None:
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_signature(raw(value))


@pytest.mark.parametrize(
    "value",
    [
        _without(PAYMENT_REQUIRED, "x402Version"),
        {**PAYMENT_REQUIRED, "error": None},
        {**PAYMENT_REQUIRED, "extensions": None},
        {**PAYMENT_REQUIRED, "resource": {"url": "https://a.example", "description": None}},
    ],
    ids=["missing-version", "null-error", "null-extensions", "null-resource-field"],
)
def test_payment_required_requires_version_and_rejects_nulls(value: dict[str, object]) -> None:
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_required(raw(value))


@pytest.mark.parametrize(
    ("model", "value"),
    [
        (
            x402.SettleResponse,
            {"network": "eip155:1", "success": False, "transaction": "", "errorMessage": None},
        ),
        (
            x402.SettleResponse,
            {"network": "eip155:1", "success": True, "transaction": "0x", "payer": None},
        ),
        (x402.VerifyResponse, {"isValid": False, "invalidReason": None}),
        (x402.VerifyResponse, {"isValid": True, "payer": None}),
    ],
)
def test_facilitator_responses_reject_nulls(model: type, value: dict[str, object]) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must not be null"):
        model.model_validate(value)  # type: ignore[attr-defined]


def test_rejects_oversized_headers() -> None:
    value = raw(
        {**PAYMENT_PAYLOAD, "extensions": {"pad": {"info": {"x": "a" * 70_000}, "schema": {}}}}
    )
    with pytest.raises(InvalidJsonHeaderError) as error:
        decode_payment_signature(value)
    assert error.value.reason == "header is too large"


def test_rejects_deeply_nested_json() -> None:
    nested: object = {}
    for _ in range(5000):
        nested = {"a": nested}
    value = raw({**PAYMENT_PAYLOAD, "extensions": {"deep": {"info": nested, "schema": {}}}})
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_signature(value)


def test_rejects_lone_surrogates() -> None:
    body = json.dumps({**PAYMENT_PAYLOAD, "resource": {"description": "x", "url": "u"}})
    value = base64.b64encode(body.replace('"x"', '"\\ud800"').encode()).decode()
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_signature(value)


@pytest.mark.parametrize("number", [2**60, -(2**53), float("inf")], ids=["big", "negative", "inf"])
def test_rejects_values_rfc8785_cannot_canonicalize(number: float) -> None:
    value = raw({**PAYMENT_PAYLOAD, "extensions": {"n": {"info": {"n": number}, "schema": {}}}})
    with pytest.raises(InvalidJsonHeaderError):
        decode_payment_signature(value)
    # The largest safe integer still canonicalizes.
    safe = raw({**PAYMENT_PAYLOAD, "extensions": {"n": {"info": {"n": 2**53 - 1}, "schema": {}}}})
    assert decode_payment_signature(safe).extensions is not None


def test_reports_the_unsupported_version() -> None:
    with pytest.raises(InvalidJsonHeaderError) as error:
        decode_payment_signature(raw({**PAYMENT_PAYLOAD, "x402Version": 1}))
    assert error.value.reason == "x402Version must be 2"
    assert str(error.value) == "Invalid base64 JSON header."
