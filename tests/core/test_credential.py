import base64
import json

import httpx
import pytest

from mpp import (
    Challenge,
    Credential,
    Header,
    InvalidCredentialEncodingError,
    _base64url,
    extract_payment_scheme,
)

CHALLENGE = Challenge.create(
    id="x7Tg2pLqR9mKvNwY3hBcZa",
    realm="api.example.com",
    method="tempo",
    intent="charge",
    request={"amount": "1000"},
)


def _wire(header: str) -> dict:
    return json.loads(_base64url.decode_text(header.split(" ", 1)[1]))


def _encode(obj: object) -> str:
    return "Payment " + _base64url.encode(json.dumps(obj))


def test_from_and_source() -> None:
    credential = Credential(
        challenge=CHALLENGE,
        payload={"hash": "0xabcd"},
        source="did:pkh:eip155:1:0x1234567890abcdef",
    )
    assert credential.source == "did:pkh:eip155:1:0x1234567890abcdef"
    assert credential.payload == {"hash": "0xabcd"}


def test_serialize_roundtrip() -> None:
    header = Credential(challenge=CHALLENGE, payload={"signature": "0x1234"}).serialize()
    assert header.startswith("Payment ")
    parsed = Credential.deserialize(header)
    assert parsed.challenge == CHALLENGE
    assert parsed.payload == {"signature": "0x1234"}
    assert parsed.source is None


def test_roundtrip_preserves_source() -> None:
    original = Credential(
        challenge=CHALLENGE, payload={"hash": "0xabcd"}, source="did:pkh:eip155:1:0x1"
    )
    parsed = Credential.deserialize(original.serialize())
    assert parsed.source == original.source
    assert parsed.payload == original.payload


def test_serializes_opaque_as_string() -> None:
    challenge = Challenge.create(
        id="opaque123",
        intent="charge",
        method="tempo",
        realm="api.example.com",
        request={"amount": "1000"},
        meta={"pi": "pi_3abc123XYZ"},
    )
    wire = _wire(Credential(challenge=challenge, payload={"signature": "0x1234"}).serialize())
    assert wire["challenge"]["opaque"] == "eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"
    assert "meta" not in wire["challenge"]


def test_echoes_raw_opaque() -> None:
    raw = Challenge.deserialize(
        'Payment id="opaque123", realm="api.example.com", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0", opaque="eXkgd3Jvbmc"'
    )
    wire = _wire(Credential(challenge=raw, payload={"signature": "0x1234"}).serialize())
    assert wire["challenge"]["opaque"] == "eXkgd3Jvbmc"


BASE_WIRE = {
    "id": "opaque123",
    "intent": "charge",
    "method": "tempo",
    "realm": "api.example.com",
    "request": "eyJhbW91bnQiOiIxMDAwIn0",
}


def test_spec_opaque_string() -> None:
    credential = Credential.deserialize(
        _encode(
            {
                "challenge": {**BASE_WIRE, "opaque": "eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"},
                "payload": {"signature": "0x1234"},
            }
        )
    )
    assert credential.challenge.opaque == "eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"
    assert credential.challenge.meta is None
    assert credential.challenge.request == {"amount": "1000"}


def test_drops_injected_meta_when_opaque_is_string() -> None:
    credential = Credential.deserialize(
        _encode(
            {
                "challenge": {
                    **BASE_WIRE,
                    "meta": {"_mppx_scope": "GET /admin"},
                    "opaque": "eyJfbXBweF9zY29wZSI6IkdFVCAvcHVibGljIn0",
                },
                "payload": {"signature": "0x1234"},
            }
        )
    )
    assert credential.challenge.opaque == "eyJfbXBweF9zY29wZSI6IkdFVCAvcHVibGljIn0"
    assert credential.challenge.meta is None


def test_non_json_opaque() -> None:
    credential = Credential.deserialize(
        _encode({"challenge": {**BASE_WIRE, "opaque": "eXkgd3Jvbmc"}, "payload": {}})
    )
    assert credential.challenge.opaque == "eXkgd3Jvbmc"


def test_legacy_object_opaque() -> None:
    credential = Credential.deserialize(
        _encode({"challenge": {**BASE_WIRE, "opaque": {"pi": "pi_3abc123XYZ"}}, "payload": {}})
    )
    assert credential.challenge.opaque == "eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"
    assert credential.challenge.meta == {"pi": "pi_3abc123XYZ"}


def test_legacy_object_opaque_non_string_values() -> None:
    with pytest.raises(InvalidCredentialEncodingError, match=r"Invalid base64url or JSON."):
        Credential.deserialize(
            _encode({"challenge": {**BASE_WIRE, "opaque": {"pi": 123}}, "payload": {}})
        )


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("Bearer abc123", "Missing Payment scheme."),
        ("Payment !!invalid!!", "Invalid base64url or JSON."),
        ("Payment " + base64.b64encode(b"not valid json").decode(), "Invalid base64url or JSON."),
    ],
)
def test_errors(value: str, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        Credential.deserialize(value)


@pytest.mark.parametrize(
    "challenge",
    [
        {"id": "abc123"},
        {**BASE_WIRE, "digest": "invalid-digest-format"},
    ],
)
def test_invalid_challenge(challenge: dict) -> None:
    encoded = base64.b64encode(
        json.dumps({"challenge": challenge, "payload": {}}).encode()
    ).decode()
    with pytest.raises(ValueError, match="Invalid base64url or JSON"):
        Credential.deserialize(f"Payment {encoded}")


class TestFromHeaders:
    def test_extracts(self) -> None:
        headers = httpx.Headers(
            {
                "Authorization": Credential(
                    challenge=CHALLENGE, payload={"signature": "0x1234"}
                ).serialize()
            }
        )
        credential = Credential.from_headers(headers)
        assert credential.challenge.id == "x7Tg2pLqR9mKvNwY3hBcZa"
        assert credential.payload == {"signature": "0x1234"}

    def test_multiple_schemes(self) -> None:
        headers = httpx.Headers(
            [
                ("Authorization", "Bearer some-jwt-token"),
                ("Authorization", Credential(challenge=CHALLENGE, payload={}).serialize()),
            ]
        )
        assert Credential.from_headers(headers).challenge.id == CHALLENGE.id

    def test_alternate_header(self) -> None:
        headers = httpx.Headers(
            {Header.PAYMENT_AUTHORIZATION: Credential(challenge=CHALLENGE, payload={}).serialize()}
        )
        assert (
            Credential.from_headers(headers, header=Header.PAYMENT_AUTHORIZATION).challenge.id
            == CHALLENGE.id
        )

    def test_missing_header(self) -> None:
        with pytest.raises(ValueError, match=r"Missing Authorization header."):
            Credential.from_headers(httpx.Headers())

    def test_no_payment_scheme(self) -> None:
        with pytest.raises(ValueError, match=r"Missing Payment scheme."):
            Credential.from_headers(httpx.Headers({"Authorization": "Bearer some-jwt-token"}))


@pytest.mark.parametrize(
    "header",
    [
        "Bearer " + "a" * (64 * 1024) + ", Payment abc",
        "Basic a," * (64 * 1024),
        " " * (64 * 1024) + "Payment abc",
        "Payment " + "a" * (64 * 1024),
    ],
)
def test_rejects_oversized_input(header: str) -> None:
    assert extract_payment_scheme(header) is None
    with pytest.raises(InvalidCredentialEncodingError):
        Credential.deserialize(header)


@pytest.mark.parametrize("field", ["opaque", "request"])
def test_accepts_expanded_fields(field: str) -> None:
    extra = (
        {"opaque": "a" * (12 * 1024)} if field == "opaque" else {"request": {"data": "a" * 12277}}
    )
    large = Challenge.create(**{**CHALLENGE.to_dict(), **extra})
    parsed = Challenge.deserialize(large.serialize())
    header = Credential(challenge=parsed, payload={"type": "hash", "hash": "0x1"}).serialize()
    assert len(header) > 16 * 1024
    assert extract_payment_scheme(header) == header
    assert Credential.deserialize(header).challenge == parsed


def test_accepts_credential_at_limit() -> None:
    prefix = Credential(challenge=CHALLENGE, payload={"type": "hash", "hash": "0x1"}).serialize()
    text = _base64url.decode_text(prefix[len("Payment ") :]).ljust(49146, " ")
    header = "Payment " + _base64url.encode(text)
    assert len(header) == 64 * 1024
    assert extract_payment_scheme(header) == header
    assert Credential.deserialize(header).challenge == CHALLENGE
