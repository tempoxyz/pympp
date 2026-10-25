"""Ported from mppx src/Challenge.test.ts."""

import re
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
import pytest
from pydantic import ValidationError

from mpp import Challenge, Header
from mpp.server import Response

from ._fixtures import charge_method

BASE = {"realm": "api.example.com", "method": "tempo", "intent": "charge"}


class TestCreate:
    def test_creates_challenge(self) -> None:
        challenge = Challenge.create(
            id="abc123",
            request={"amount": "1000000", "currency": "0x1234", "recipient": "0xabcd"},
            **BASE,
        )
        assert challenge.to_dict() == {
            "id": "abc123",
            "intent": "charge",
            "method": "tempo",
            "realm": "api.example.com",
            "request": {"amount": "1000000", "currency": "0x1234", "recipient": "0xabcd"},
        }

    def test_optional_fields(self) -> None:
        challenge = Challenge.create(
            id="abc123",
            request={"amount": "1000000"},
            digest="sha-256=abc",
            expires="2025-01-06T12:00:00Z",
            **BASE,
        )
        assert challenge.digest == "sha-256=abc"
        assert challenge.expires == "2025-01-06T12:00:00Z"

    def test_expires_as_datetime(self) -> None:
        challenge = Challenge.create(
            id="abc123",
            request={"amount": "1"},
            expires=datetime(2025, 1, 6, 12, tzinfo=UTC),
            **BASE,
        )
        assert challenge.expires == "2025-01-06T12:00:00.000Z"

    def test_preserves_alternate_credential_header(self) -> None:
        challenge = Challenge.create(
            id="abc123", request={"amount": "1"}, header=Header.PAYMENT_AUTHORIZATION, **BASE
        )
        assert f'header="{Header.PAYMENT_AUTHORIZATION}"' in challenge.serialize()
        assert (
            Challenge.deserialize(challenge.serialize()).credential_header
            == Header.PAYMENT_AUTHORIZATION
        )

    def test_omits_default_credential_header(self) -> None:
        params = {
            "secret_key": "test-secret-key-test-secret-key-32",
            "request": {"amount": "1"},
            **BASE,
        }
        challenge = Challenge.create(header=Header.AUTHORIZATION, **params)  # type: ignore[arg-type]
        implicit = Challenge.create(**params)  # type: ignore[arg-type]
        assert challenge.header is None
        assert challenge.id == implicit.id
        assert "header=" not in challenge.serialize()
        assert challenge.credential_header == Header.AUTHORIZATION

    def test_rejects_empty_id(self) -> None:
        with pytest.raises(ValueError, match="`id` must not be empty"):
            Challenge.create(id="", request={"amount": "1"}, **BASE)

    def test_requires_id_or_secret(self) -> None:
        with pytest.raises(TypeError):
            Challenge.create(request={}, **BASE)


HMAC_VECTORS = [
    ({"request": {"amount": "1000000"}}, "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4"),
    (
        {"request": {"amount": "1000000"}, "expires": "2025-01-06T12:00:00Z"},
        "ChPX33RkKSZoSUyZcu8ai4hhkvjZJFkZVnvWs5s0iXI",
    ),
    (
        {
            "request": {"amount": "1000000"},
            "digest": "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE",
        },
        "JHB7EFsPVb-xsYCo8LHcOzeX1gfXWVoUSzQsZhKAfKM",
    ),
    (
        {
            "request": {"amount": "1000000"},
            "expires": "2025-01-06T12:00:00Z",
            "digest": "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE",
        },
        "m39jbWWCIfmfJZSwCfvKFFtBl0Qwf9X4nOmDb21peLA",
    ),
    (
        {"request": {"amount": "1000000"}, "meta": {"pi": "pi_3abc123XYZ"}},
        "rxzKZ2qjXvinqCH96RORTZEPs1KXsA-0AUjrCAPFOWc",
    ),
    (
        {
            "request": {"amount": "1000000"},
            "expires": "2025-01-06T12:00:00Z",
            "meta": {"pi": "pi_3abc123XYZ"},
        },
        "KAfoMrA4fnzS1DPWN_cUv_b3_yHxCizdp6OhH7gluMY",
    ),
    (
        {"request": {"amount": "1000000"}, "description": "Test payment"},
        "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4",
    ),
    (
        {"request": {"amount": "1000000", "currency": "0x1234", "recipient": "0xabcd"}},
        "_H5TOnnlW0zduQ5OhQ3EyLVze_TqxLDPda2CGZPZxOc",
    ),
    (
        {
            "request": {
                "amount": "1000000",
                "currency": "0x1234",
                "methodDetails": {"chainId": 42431},
            }
        },
        "TqujwpuDDg_zsWGINAd5XObO2rRe6uYufpqvtDmr6N8",
    ),
    ({"request": {}}, "yLN7yChAejW9WNmb54HpJIWpdb1WWXeA3_aCx4dxmkU"),
    ({"request": {"amount": "1000000"}, "meta": {}}, "vb4IyH-0LdJ3s7L0QAw8jIzcZkyxksPhIvEfmHmzA9k"),
    (
        {"request": {"amount": "1000000"}, "realm": "payments.other.com"},
        "3F5bOo2a9RUihdwKk4hGRvBvzQmVPBMDvW0YM-8GD00",
    ),
    (
        {"request": {"amount": "1000000"}, "method": "stripe"},
        "o0ra2sd7HcB4Ph0Vns69gRDUhSj5WNOnUopcDqKPLz4",
    ),
    (
        {"request": {"amount": "1000000"}, "intent": "session"},
        "aAY7_IEDzsznNYplhOSE8cERQxvjFcT4Lcn-7FHjLVE",
    ),
    (
        {"request": {"amount": "1000000"}, "meta": {"deposit": "dep_456", "pi": "pi_3abc123XYZ"}},
        "aKskU8sadR5ZuFbUCsIwhO-ENxuVpTw17FdwHEXsJDk",
    ),
]


@pytest.mark.parametrize(("params", "expected"), HMAC_VECTORS)
def test_hmac_vectors(params: dict[str, object], expected: str) -> None:
    challenge = Challenge.create(secret_key="test-vector-secret", **{**BASE, **params})  # type: ignore[arg-type]
    assert challenge.id == expected


def test_hmac_same_and_different_secrets() -> None:
    a = Challenge.create(secret_key="secret", request={"amount": "1"}, **BASE)
    b = Challenge.create(secret_key="secret", request={"amount": "1"}, **BASE)
    c = Challenge.create(secret_key="secret2", request={"amount": "1"}, **BASE)
    assert a.id == b.id
    assert a.id != c.id


class TestForMethod:
    request: ClassVar[dict[str, Any]] = {
        "amount": "1",
        "currency": "0x20c0000000000000000000000000000000000001",
        "decimals": 6,
        "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
    }

    def test_validates_and_transforms(self) -> None:
        challenge = Challenge.for_method(
            charge_method,
            id="abc123",
            realm="api.example.com",
            expires="2025-01-06T12:00:00Z",
            request=self.request,
        )
        assert challenge.request == {
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000001",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
        }

    def test_method_details(self) -> None:
        challenge = Challenge.for_method(
            charge_method,
            id="abc123",
            realm="api.example.com",
            request={**self.request, "chainId": 42431, "feePayer": True},
        )
        assert challenge.request["methodDetails"] == {"chainId": 42431, "feePayer": True}

    def test_hmac_bound(self) -> None:
        challenge = Challenge.for_method(
            charge_method, realm="api.example.com", request=self.request, secret_key="my-secret"
        )
        assert challenge.verify("my-secret")

    def test_invalid_request(self) -> None:
        with pytest.raises(ValidationError):
            Challenge.for_method(
                charge_method,
                id="abc123",
                realm="api.example.com",
                request={**self.request, "amount": 123},
            )

    def test_explicit_empty_id_does_not_fall_back_to_secret(self) -> None:
        with pytest.raises(ValueError, match="`id` must not be empty"):
            Challenge.for_method(
                charge_method,
                id="",
                secret_key="my-secret",
                realm="api.example.com",
                request=self.request,
            )

    def test_meta_sets_opaque(self) -> None:
        challenge = Challenge.for_method(
            charge_method,
            id="abc123",
            realm="api.example.com",
            request=self.request,
            meta={"payment_intent": "pi_3abc123XYZ"},
        )
        assert challenge.meta == {"payment_intent": "pi_3abc123XYZ"}
        assert challenge.opaque == "eyJwYXltZW50X2ludGVudCI6InBpXzNhYmMxMjNYWVoifQ"


class TestSerialize:
    def test_serializes(self) -> None:
        header = Challenge.create(
            id="abc123", request={"amount": "1000000", "currency": "USD"}, **BASE
        ).serialize()
        assert header.startswith("Payment ")
        for part in (
            'id="abc123"',
            'realm="api.example.com"',
            'method="tempo"',
            'intent="charge"',
            'request="',
        ):
            assert part in header

    @pytest.mark.parametrize(
        ("description", "escaped"),
        [
            ("Plain payment description", "Plain payment description"),
            ('Pay "premium"', 'Pay \\"premium\\"'),
            ("Path C:\\tempo\\api", "Path C:\\\\tempo\\\\api"),
            ('Pay "premium" path C:\\tempo\\api', 'Pay \\"premium\\" path C:\\\\tempo\\\\api'),
            ("Ends with slash \\", "Ends with slash \\\\"),
            (
                "1 \u00d7 Classmatic \u2014 General Admission",
                "1 \u00d7 Classmatic \\u2014 General Admission",
            ),
            ('Tickets \U0001f39f\ufe0f "VIP"', 'Tickets \\ud83c\\udf9f\\ufe0f \\"VIP\\"'),
        ],
    )
    def test_escapes_quoted_strings(self, description: str, escaped: str) -> None:
        header = Challenge.create(
            id="abc123", request={"amount": "1"}, description=description, **BASE
        ).serialize()
        assert f'description="{escaped}"' in header
        assert Challenge.deserialize(header).description == description

    def test_valid_header_value(self) -> None:
        description = "1 \u00d7 Classmatic \u2014 General Admission \U0001f39f\ufe0f"
        header = Challenge.create(
            id="abc123", request={"amount": "1"}, description=description, **BASE
        ).serialize()
        assert all(ord(char) <= 0xFF for char in header)
        Response(402, headers={"WWW-Authenticate": header})
        assert Challenge.deserialize(header).description == description

    def test_rejects_crlf(self) -> None:
        challenge = Challenge.create(
            id="abc123", request={"amount": "1"}, description="Line one\r\nLine two", **BASE
        )
        with pytest.raises(ValueError, match=r"Invalid quoted-string value."):
            challenge.serialize()


PAYMENT_HEADER = Challenge.create(
    id="abc123", request={"amount": "1000000", "currency": "USD"}, **BASE
).serialize()
REQUEST_PARAM = re.search(r'request="([^"]+)"', PAYMENT_HEADER).group(1)  # type: ignore[union-attr]


class TestDeserialize:
    def test_deserializes(self) -> None:
        assert Challenge.deserialize(PAYMENT_HEADER).to_dict() == {
            "id": "abc123",
            "intent": "charge",
            "method": "tempo",
            "realm": "api.example.com",
            "request": {"amount": "1000000", "currency": "USD"},
        }

    @pytest.mark.parametrize(
        "header",
        [
            re.sub(
                r"\b(id|realm|method|intent|request)=", lambda m: m.group(0).upper(), PAYMENT_HEADER
            ),
            re.sub(
                r"\b(id|realm|method|intent|request)=",
                lambda m: m.group(0)[0].upper() + m.group(0)[1:],
                PAYMENT_HEADER,
            ),
        ],
    )
    def test_case_insensitive_param_names(self, header: str) -> None:
        assert Challenge.deserialize(header) == Challenge.deserialize(PAYMENT_HEADER)

    @pytest.mark.parametrize(
        "header",
        [
            PAYMENT_HEADER,
            f'Bearer realm="api", {PAYMENT_HEADER}',
            PAYMENT_HEADER.replace("Payment ", "payment ", 1),
            f'Bearer error_description="retry with Payment challenge", {PAYMENT_HEADER}',
            f'{PAYMENT_HEADER}, Bearer realm="fallback"',
        ],
    )
    def test_extracts_payment_scheme(self, header: str) -> None:
        challenge = Challenge.deserialize(header)
        assert (challenge.id, challenge.method, challenge.intent) == ("abc123", "tempo", "charge")

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ('premium \\"access\\"', 'premium "access"'),
            ("tier\\,premium", "tier,premium"),
            ("path\\\\alpha", "path\\alpha"),
        ],
    )
    def test_quoted_string_escapes(self, value: str, expected: str) -> None:
        header = (
            f'Payment id="abc123", realm="api.example.com", method="tempo", intent="charge", '
            f'request="{REQUEST_PARAM}", description="{value}"'
        )
        assert Challenge.deserialize(header).description == expected

    @pytest.mark.parametrize(
        "name", ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"]
    )
    def test_extension_parameter_names(self, name: str) -> None:
        header = f'{PAYMENT_HEADER}, {name}="value"'
        assert Challenge.deserialize(header).id == "abc123"
        with pytest.raises(ValueError, match=f"Duplicate parameter: {name.lower()}"):
            Challenge.deserialize(f'{header}, {name}="duplicate"')

    @pytest.mark.parametrize(
        ("header", "error"),
        [
            ("Bearer token", "Missing Payment scheme."),
            (
                'Payment id="a", realm="api", method="tempo", intent="charge", request="e30", id="b"',
                "Duplicate parameter: id",
            ),
            (
                'Payment id="a", realm="api", method="tempo", intent="charge", request="e30", ID="b"',
                "Duplicate parameter: id",
            ),
            (
                'Payment id="a", realm="api", method="tempo", intent="charge", request="e30", description="oops',
                "Unterminated quoted-string.",
            ),
            (
                'Payment id="a", realm="api", method="Tempo", intent="charge", request="e30"',
                'Invalid method: "Tempo". Must be lowercase per spec.',
            ),
            (
                'Payment id="a", realm="api", method="tempo", intent="charge", request="e30", ="value"',
                "Malformed auth-param.",
            ),
            ('Payment id="", realm="api", method="tempo", intent="charge", request="e30"', "id"),
        ],
    )
    def test_errors(self, header: str, error: str) -> None:
        with pytest.raises(ValueError, match=re.escape(error)):
            Challenge.deserialize(header)

    def test_missing_required_fields(self) -> None:
        with pytest.raises(ValueError, match="Missing request parameter"):
            Challenge.deserialize('Payment realm="test"')

    def test_missing_request(self) -> None:
        with pytest.raises(ValueError, match=r"Missing request parameter."):
            Challenge.deserialize(
                'Bearer realm="api", Payment id="a", realm="api", method="tempo", intent="charge"'
            )

    def test_oversized_request(self) -> None:
        header = f'Payment id="a", realm="api", method="tempo", intent="charge", request="{"a" * (16 * 1024 + 1)}"'
        with pytest.raises(ValueError, match=r"Request parameter too large."):
            Challenge.deserialize(header)

    def test_roundtrip_optional(self) -> None:
        original = Challenge.create(
            id="abc123",
            request={"amount": "1"},
            digest="sha-256=abc",
            expires="2025-01-06T12:00:00Z",
            **BASE,
        )
        parsed = Challenge.deserialize(original.serialize())
        assert parsed.digest == "sha-256=abc"
        assert parsed.expires == "2025-01-06T12:00:00Z"

    def test_unknown_extension_with_unterminated_quote_is_ignored(self) -> None:
        header = PAYMENT_HEADER + ', fuzz="' + "\\" * 12000
        assert Challenge.deserialize(header).id == "abc123"


SECOND_HEADER = Challenge.create(
    id="second", request={"amount": "1000000", "currency": "USD"}, **BASE
).serialize()
BASE_CHALLENGE = {
    "id": "first",
    "realm": "api.example.com",
    "method": "stripe",
    "intent": "charge",
    "request": {"amount": "50", "currency": "usd"},
}


class TestDeserializeList:
    def test_reported_stripe_and_tempo(self) -> None:
        stripe_header = (
            'Payment id="k3fGx9QpLmZ2vT8sWyR4nB6cD1eH5jA7uN0iO2aS9dU", realm="example.com", method="stripe", intent="charge", '
            'request="eyJhbW91bnQiOiI1MCIsImN1cnJlbmN5IjoidXNkIiwiZXh0ZXJuYWxJZCI6Im9yZGVyLTEyMyIsIm1ldGhvZERldGFpbHMiOnsibmV0d29ya0lkIjoicHJvZmlsZV8wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwicGF5bWVudE1ldGhvZFR5cGVzIjpbImNhcmQiLCJsaW5rIl19fQ", '
            'description="Agentcash card payment test", expires="2026-09-01T00:00:00.000Z", '
            'opaque="eyJfbXBweF9zY29wZSI6ImNvZmZlZXNob3A6b3JkZXI6b3JkZXItMTIzOnBheSJ9"'
        )
        challenges = Challenge.deserialize_list(f"{stripe_header}, {SECOND_HEADER}")
        assert len(challenges) == 2
        assert challenges[0].method == "stripe"
        assert challenges[0].description == "Agentcash card payment test"
        assert challenges[1].id == "second"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("description", "Agentcash card payment test"),
            ("description", "Payment at the start"),
            ("description", 'Use "Payment now", then retry \\'),
            ("description", "comma, Payment fake challenge"),
            ("id", "id with Payment text"),
            ("intent", "payment plan"),
            ("realm", "Payment realm"),
            ("opaque", "opaque Payment value"),
        ],
    )
    def test_ignores_scheme_like_text(self, field: str, value: str) -> None:
        first = Challenge(**{**BASE_CHALLENGE, field: value}).serialize()  # type: ignore[arg-type]
        challenges = Challenge.deserialize_list(f"{first}, {SECOND_HEADER}")
        assert len(challenges) == 2
        assert getattr(challenges[0], field) == value
        assert challenges[1].id == "second"

    def test_case_insensitive_among_other_schemes(self) -> None:
        first = Challenge(**BASE_CHALLENGE).serialize()  # type: ignore[arg-type]
        header = (
            f'Bearer error_description="use Payment challenge", {first}, '
            f'Digest realm="fallback Payment realm", {SECOND_HEADER.replace("Payment ", "pAyMeNt\t", 1)}'
        )
        assert [c.id for c in Challenge.deserialize_list(header)] == ["first", "second"]

    def test_quoted_payment_text_is_not_a_challenge(self) -> None:
        with pytest.raises(ValueError, match=r"No Payment schemes found."):
            Challenge.deserialize_list('Bearer error_description="use Payment challenge"')


class TestFromResponse:
    challenge = Challenge.create(id="abc123", request={"amount": "1"}, **BASE)

    def test_from_headers(self) -> None:
        headers = httpx.Headers({"WWW-Authenticate": self.challenge.serialize()})
        assert Challenge.from_headers(headers).id == "abc123"

    def test_missing_header(self) -> None:
        with pytest.raises(ValueError, match=r"Missing WWW-Authenticate header."):
            Challenge.from_headers(httpx.Headers())

    def test_from_response(self) -> None:
        response = httpx.Response(402, headers={"WWW-Authenticate": self.challenge.serialize()})
        assert Challenge.from_response(response).realm == "api.example.com"
        assert (
            Challenge.from_response(
                Response(402, {"WWW-Authenticate": self.challenge.serialize()})
            ).id
            == "abc123"
        )

    def test_non_402(self) -> None:
        with pytest.raises(ValueError, match=r"Response status is not 402."):
            Challenge.from_response(httpx.Response(401))

    def test_402_without_header(self) -> None:
        with pytest.raises(ValueError, match=r"Missing WWW-Authenticate header."):
            Challenge.from_response(httpx.Response(402))


class TestVerify:
    def test_valid(self) -> None:
        challenge = Challenge.create(secret_key="my-secret", request={"amount": "1000000"}, **BASE)
        assert challenge.verify("my-secret")
        assert not challenge.verify("wrong-secret")

    def test_tampered(self) -> None:
        challenge = Challenge.create(secret_key="my-secret", request={"amount": "1000000"}, **BASE)
        tampered = Challenge(**{**challenge.to_dict(), "request": {"amount": "2000000"}})
        assert not tampered.verify("my-secret")


class TestOpaque:
    def test_meta_sets_opaque(self) -> None:
        challenge = Challenge.create(
            id="abc123", request={"amount": "1"}, meta={"pi": "pi_3abc123XYZ"}, **BASE
        )
        assert challenge.meta == {"pi": "pi_3abc123XYZ"}
        assert challenge.opaque == "eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"
        assert "opaque" not in challenge.request

    def test_no_meta(self) -> None:
        challenge = Challenge.create(id="abc123", request={"amount": "1"}, **BASE)
        assert challenge.opaque is None
        assert challenge.meta is None

    def test_roundtrip_raw_string(self) -> None:
        original = Challenge.create(
            id="abc123",
            request={"amount": "1"},
            meta={"pi": "pi_3abc123XYZ", "deposit": "dep_456"},
            **BASE,
        )
        parsed = Challenge.deserialize(original.serialize())
        assert parsed.opaque == "eyJkZXBvc2l0IjoiZGVwXzQ1NiIsInBpIjoicGlfM2FiYzEyM1hZWiJ9"
        assert parsed.meta is None

    def test_non_json_opaque_is_not_parsed(self) -> None:
        header = (
            'Payment id="abc123", realm="api.example.com", method="tempo", intent="charge", '
            'request="eyJhbW91bnQiOiIxMDAwMDAwIn0", opaque="eXkgd3Jvbmc"'
        )
        challenge = Challenge.deserialize(header)
        assert challenge.opaque == "eXkgd3Jvbmc"
        assert challenge.meta is None

    def test_empty_meta(self) -> None:
        challenge = Challenge.create(id="abc123", request={"amount": "1"}, meta={}, **BASE)
        assert challenge.meta == {}
        assert challenge.opaque == "e30"

    def test_opaque_affects_id(self) -> None:
        def make(meta: dict[str, str] | None) -> str:
            return Challenge.create(
                secret_key="test-secret", request={"amount": "1"}, meta=meta, **BASE
            ).id

        assert make({"pi": "pi_3abc123XYZ"}) != make(None)
        assert make({"pi": "pi_111"}) != make({"pi": "pi_222"})
        assert make({"pi": "x"}) == make({"pi": "x"})

    def test_verify_detects_tampered_opaque(self) -> None:
        challenge = Challenge.create(
            secret_key="my-secret", request={"amount": "1"}, meta={"pi": "pi_3abc123XYZ"}, **BASE
        )
        assert challenge.verify("my-secret")
        tampered = Challenge(
            **{
                **challenge.to_dict(),
                "meta": {"pi": "pi_TAMPERED"},
                "opaque": "eyJwaSI6InBpX1RBTVBFUkVEIn0",
            }
        )
        assert not tampered.verify("my-secret")


def test_protocol_tag_is_not_part_of_equality() -> None:
    challenge = Challenge.create(id="abc123", request={"amount": "1"}, **BASE)
    from dataclasses import replace

    tagged = replace(challenge, protocol="x402")
    assert tagged == challenge
    assert tagged.serialize() == challenge.serialize()
