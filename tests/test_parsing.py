"""Tests for header parsing and formatting."""

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp._parsing import MAX_AUTHORIZATION_SIZE, MAX_HEADER_PAYLOAD_SIZE, ParseError
from mpp.server.verify import _extract_payment_scheme
from tests import make_credential

INVALID_PAYMENT_METHOD_IDS = ("Tempo", "tempo2", "tempo-pay", "tempo_pay", "tempo.pay")


def _b64_json(data: Mapping[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


class TestChallenge:
    def test_roundtrip(self) -> None:
        """Challenge should survive roundtrip through header format."""
        challenge = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "currency": "0x123", "recipient": "0x456"},
        )

        header = challenge.to_www_authenticate("api.example.com")
        parsed = Challenge.from_www_authenticate(header)

        assert parsed.id == challenge.id
        assert parsed.method == challenge.method
        assert parsed.intent == challenge.intent
        assert parsed.request == challenge.request

    def test_parse_valid_header(self) -> None:
        """Should parse a valid WWW-Authenticate header."""
        # request = {} -> base64url = "e30"
        header = (
            'Payment id="test", realm="api.example.com", '
            'method="tempo", intent="charge", request="e30"'
        )
        challenge = Challenge.from_www_authenticate(header)

        assert challenge.id == "test"
        assert challenge.method == "tempo"
        assert challenge.intent == "charge"

    def test_parse_invalid_scheme(self) -> None:
        """Should reject non-Payment schemes."""
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate('Bearer realm="api.example.com"')

    def test_parse_missing_realm(self) -> None:
        """Should reject headers without realm."""
        header = 'Payment id="test", method="tempo", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Missing 'realm' field"):
            Challenge.from_www_authenticate(header)

    def test_parse_invalid_base64(self) -> None:
        """Should reject invalid base64 in request field."""
        header = (
            'Payment id="test", realm="test", method="tempo", '
            'intent="charge", request="!!!invalid!!!"'
        )
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate(header)

    def test_parse_non_dict_json(self) -> None:
        """Should reject JSON that decodes to non-dict in request field."""
        import base64

        # base64 of JSON array []
        b64_array = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
        header = (
            f'Payment id="test", realm="test", method="tempo", '
            f'intent="charge", request="{b64_array}"'
        )
        with pytest.raises(ParseError, match="Expected JSON object"):
            Challenge.from_www_authenticate(header)

    def test_parse_missing_fields(self) -> None:
        """Should reject challenges missing required fields."""
        # Missing method field
        header = 'Payment id="test", realm="test", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Missing 'method' field"):
            Challenge.from_www_authenticate(header)

    @pytest.mark.parametrize("method", INVALID_PAYMENT_METHOD_IDS)
    def test_parse_rejects_invalid_method_id(self, method: str) -> None:
        header = (
            f'Payment id="test", realm="api.example.com", method="{method}", '
            'intent="charge", request="e30"'
        )

        with pytest.raises(ParseError, match="Invalid payment method id"):
            Challenge.from_www_authenticate(header)

    def test_roundtrip_with_optional_fields(self) -> None:
        """Challenge with optional fields should survive roundtrip."""
        challenge = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2025-01-15T12:00:00Z",
            digest="sha-256=:abc123:",
            description="Pay for API access",
        )

        header = challenge.to_www_authenticate("api.example.com")
        parsed = Challenge.from_www_authenticate(header)

        assert parsed.id == challenge.id
        assert parsed.method == challenge.method
        assert parsed.intent == challenge.intent
        assert parsed.request == challenge.request
        assert parsed.expires == challenge.expires
        assert parsed.digest == challenge.digest
        assert parsed.description == challenge.description

    def test_roundtrip_with_opaque(self) -> None:
        challenge = Challenge(
            id="test-id-opaque",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            opaque={"pi": "pi_123"},
        )

        header = challenge.to_www_authenticate("api.example.com")
        parsed = Challenge.from_www_authenticate(header)

        assert parsed.opaque == {"pi": "pi_123"}

    def test_parse_duplicate_param_raises(self) -> None:
        header = (
            'Payment id="test", realm="api.example.com", method="tempo", '
            'intent="charge", intent="session", request="e30"'
        )
        with pytest.raises(ParseError, match="Duplicate parameter: intent"):
            Challenge.from_www_authenticate(header)

    @pytest.mark.parametrize(
        "rename",
        [str.upper, lambda name: name[0].upper() + name[1:]],
        ids=["uppercase", "mixed-case"],
    )
    def test_parse_case_insensitive_param_names(self, rename) -> None:
        header = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        ).to_www_authenticate("api.example.com")
        renamed = re.sub(
            r"\b(id|realm|method|intent|request)=",
            lambda match: f"{rename(match.group(1))}=",
            header,
        )
        assert renamed != header

        assert Challenge.from_www_authenticate(renamed) == Challenge.from_www_authenticate(header)

    def test_parse_case_insensitive_duplicate_param_raises(self) -> None:
        header = (
            'Payment id="a", realm="api", method="tempo", intent="charge", request="e30", ID="b"'
        )
        with pytest.raises(ParseError, match="Duplicate parameter: id"):
            Challenge.from_www_authenticate(header)

    def test_parse_request_too_large(self) -> None:
        oversized = "a" * (MAX_HEADER_PAYLOAD_SIZE + 1)
        header = (
            'Payment id="test", realm="api.example.com", method="tempo", '
            f'intent="charge", request="{oversized}"'
        )
        with pytest.raises(ParseError, match="Header payload exceeds maximum size"):
            Challenge.from_www_authenticate(header)

    def test_parse_invalid_opaque_base64(self) -> None:
        header = (
            'Payment id="test", realm="api.example.com", method="tempo", '
            'intent="charge", request="e30", opaque="not!valid!base64"'
        )
        with pytest.raises(ParseError, match="Invalid base64 or JSON encoding"):
            Challenge.from_www_authenticate(header)

    def test_format_rejects_crlf_in_description(self) -> None:
        challenge = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            description="bad\nvalue",
        )

        with pytest.raises(ParseError, match="invalid CRLF"):
            challenge.to_www_authenticate("api.example.com")

    @pytest.mark.parametrize(
        ("escaped", "expected"),
        [
            (r"em dash \u2014 and coffee \u2615", "em dash — and coffee ☕"),
            (r"grinning \ud83d\ude00 face", "grinning 😀 face"),
            ("café naïve", "café naïve"),
            (r"lone \ud83d here", "lone \ufffd here"),
            (r"lone \ude00 here", "lone \ufffd here"),
            (r"not an escape \\u2014", r"not an escape \u2014"),
            (r"short \u12 tail", "short u12 tail"),
        ],
    )
    def test_parse_unicode_quoted_strings(self, escaped: str, expected: str) -> None:
        header = (
            f'Payment id="test", realm="api.example.com", method="tempo", '
            f'intent="charge", request="e30", description="{escaped}"'
        )

        assert Challenge.from_www_authenticate(header).description == expected

    def test_format_unicode_quoted_strings_as_utf16_escapes(self) -> None:
        challenge = Challenge(
            id="test",
            method="tempo",
            intent="charge",
            request={},
            description="Payment — coffee ☕ 😀",
        )

        header = challenge.to_www_authenticate("api.example.com")

        assert 'description="Payment \\u2014 coffee \\u2615 \\ud83d\\ude00"' in header
        assert Challenge.from_www_authenticate(header).description == challenge.description

    def test_www_authenticate_roundtrip_preserves_credential_header(self) -> None:
        challenge = Challenge.create(
            secret_key="test-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            header="Payment-Authorization",
        )
        header = challenge.to_www_authenticate("api.example.com")
        parsed = Challenge.from_www_authenticate(header)

        assert 'header="Payment-Authorization"' in header
        assert parsed.header == "Payment-Authorization"
        assert parsed.credential_header == "Payment-Authorization"
        assert parsed.verify("test-secret", "api.example.com")

    def test_www_authenticate_omits_default_authorization_header(self) -> None:
        challenge = Challenge.create(
            secret_key="test-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            header="authorization",
        )
        header = challenge.to_www_authenticate("api.example.com")

        assert "header=" not in header
        assert challenge.header is None

    def test_parse_www_authenticate_rejects_invalid_header_name(self) -> None:
        request_b64 = _b64_json({"amount": "1000000"})
        header = (
            'Payment id="abc", realm="api.example.com", method="tempo", '
            f'intent="charge", request="{request_b64}", header="not a header"'
        )

        with pytest.raises(ParseError, match="Invalid HTTP header name"):
            Challenge.from_www_authenticate(header)


class TestCredential:
    @pytest.mark.parametrize(
        "description", [None, "", "Test purchase", "Payment for caf\u00e9 \u2615"]
    )
    def test_description_survives_challenge_to_credential(self, description: str | None) -> None:
        challenge = Challenge.create(
            secret_key="test-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            description=description,
        )
        echo = challenge.to_echo()
        assert echo.description == description

        credential = Credential(challenge=echo, payload={"proof": "synthetic"})
        header = credential.to_authorization()
        encoded = header.removeprefix("Payment ")
        wire = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if description is None:
            assert "description" not in wire["challenge"]
        else:
            assert wire["challenge"]["description"] == description
        assert Credential.from_authorization(header).challenge.description == description

        changed = replace(challenge, description="Different display text")
        assert changed.id == challenge.id
        assert changed.verify("test-secret", "api.example.com")

    @pytest.mark.parametrize(
        "description", [None, "", "Test purchase", "Payment for caf\u00e9 \u2615"]
    )
    def test_parse_preserves_credential_description(self, description: str | None) -> None:
        challenge = {
            "id": "test-id",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": "e30",
        }
        if description is not None:
            challenge["description"] = description
        data = {"challenge": challenge, "payload": {"proof": "synthetic"}}

        credential = Credential.from_authorization("Payment " + _b64_json(data))
        assert credential.challenge.description == description
        encoded = credential.to_authorization().removeprefix("Payment ")
        assert json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))) == data

    @pytest.mark.parametrize("description", ["x\ry", "x\ny", "x\r\ny"])
    def test_rejects_header_unsafe_description(self, description):
        data = {
            "challenge": {
                "id": "test",
                "method": "tempo",
                "description": description,
            },
            "payload": {},
        }
        with pytest.raises(ParseError, match="invalid CRLF"):
            Credential.from_authorization("Payment " + _b64_json(data))

    def test_roundtrip(self) -> None:
        """Credential should survive roundtrip through header format."""
        credential = make_credential(
            challenge_id="test-id-123",
            payload={"hash": "0xabc123"},
            source="did:pkh:eip155:1:0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.id == credential.challenge.id
        assert parsed.payload == credential.payload
        assert parsed.source == credential.source

    def test_roundtrip_without_source(self) -> None:
        """Credential without source should roundtrip."""
        credential = make_credential(
            challenge_id="test-id",
            payload={"signature": "0x123"},
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.id == credential.challenge.id
        assert parsed.payload == credential.payload
        assert parsed.source is None

    def test_parse_invalid_scheme(self) -> None:
        """Should reject non-Payment schemes."""
        with pytest.raises(ParseError):
            Credential.from_authorization("Bearer abc123")

    def test_parse_missing_id(self) -> None:
        """Should reject credentials without challenge."""
        header = "Payment eyJwYXlsb2FkIjp7fX0"  # {"payload": {}}
        with pytest.raises(ParseError):
            Credential.from_authorization(header)

    def test_parse_missing_payload(self) -> None:
        data = {
            "challenge": {
                "id": "test-id",
                "realm": "api.example.com",
                "method": "tempo",
                "intent": "charge",
                "request": "e30",
            }
        }
        header = "Payment " + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip(
            "="
        )
        with pytest.raises(ParseError, match="Credential missing required field: payload"):
            Credential.from_authorization(header)

    def test_parse_challenge_not_object(self) -> None:
        data = {"challenge": "not-an-object", "payload": {}}
        header = "Payment " + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip(
            "="
        )
        with pytest.raises(ParseError, match="Credential challenge must be an object"):
            Credential.from_authorization(header)

    def test_parse_challenge_missing_id(self) -> None:
        data = {
            "challenge": {
                "realm": "api.example.com",
                "method": "tempo",
                "intent": "charge",
                "request": "e30",
            },
            "payload": {},
        }
        header = "Payment " + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip(
            "="
        )
        with pytest.raises(ParseError, match="Credential challenge missing required field: id"):
            Credential.from_authorization(header)

    @pytest.mark.parametrize("method", INVALID_PAYMENT_METHOD_IDS)
    def test_parse_rejects_invalid_challenge_method_id(self, method: str) -> None:
        data = {
            "challenge": {
                "id": "test-id",
                "realm": "api.example.com",
                "method": method,
                "intent": "charge",
                "request": "e30",
            },
            "payload": {},
        }
        header = "Payment " + _b64_json(data)

        with pytest.raises(ParseError, match="Invalid payment method id"):
            Credential.from_authorization(header)

    def test_roundtrip_with_optional_challenge_fields(self) -> None:
        credential = Credential(
            challenge=ChallengeEcho(
                id="test-id",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request="e30",
                digest="sha-256=:abc123:",
                opaque="eyJwaSI6InBpXzEyMyJ9",
            ),
            payload={"hash": "0xabc123"},
            source="did:example:client",
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.digest == credential.challenge.digest
        assert parsed.challenge.opaque == credential.challenge.opaque

    def test_roundtrip_preserves_header(self) -> None:
        echo = ChallengeEcho(
            id="test-id",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request="eyJhbW91bnQiOiIxMDAwMDAwIn0",
            header="Payment-Authorization",
        )
        credential = Credential(
            challenge=echo,
            payload={"type": "transaction", "signature": "0xabc"},
        )
        parsed = Credential.from_authorization(credential.to_authorization())

        assert parsed.challenge.header == "Payment-Authorization"


class TestAuthorizationSizeLimit:
    @pytest.mark.parametrize(
        "header",
        [
            "Bearer " + "a" * MAX_AUTHORIZATION_SIZE + ", Payment abc",
            "Basic a," * MAX_AUTHORIZATION_SIZE,
            " " * MAX_AUTHORIZATION_SIZE + "Payment abc",
            "Payment " + "a" * MAX_AUTHORIZATION_SIZE,
        ],
    )
    def test_rejects_oversized_input_before_extraction(self, header: str) -> None:
        assert _extract_payment_scheme(header) is None
        with pytest.raises(ParseError, match="exceeds maximum size"):
            Credential.from_authorization(header)

    def test_accepts_credential_echoing_request_at_the_limit(self) -> None:
        request = _b64_json({"data": "a" * 12276})
        assert len(request) == MAX_HEADER_PAYLOAD_SIZE
        credential = make_credential(payload={"hash": "0x1"}, request=request)

        header = credential.to_authorization()
        assert len(header) > MAX_HEADER_PAYLOAD_SIZE
        assert _extract_payment_scheme(header) == header
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.request == request

    def test_accepts_credential_at_the_limit(self) -> None:
        credential = make_credential(payload={"hash": "0x1"})
        token = credential.to_authorization()[len("Payment ") :]
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        padded = raw.ljust((MAX_AUTHORIZATION_SIZE - len("Payment ")) // 4 * 3)
        header = "Payment " + base64.urlsafe_b64encode(padded.encode()).decode().rstrip("=")
        assert len(header) == MAX_AUTHORIZATION_SIZE

        assert _extract_payment_scheme(header) == header
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.id == credential.challenge.id


class TestReceipt:
    def test_roundtrip(self) -> None:
        """Receipt should survive roundtrip through header format."""
        timestamp = datetime(2024, 1, 20, 12, 0, 0, tzinfo=UTC)
        receipt = Receipt(
            status="success",
            timestamp=timestamp,
            reference="0xabc123def456",
        )

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.status == receipt.status
        assert parsed.timestamp == receipt.timestamp
        assert parsed.reference == receipt.reference

    def test_payer_is_not_serialized(self) -> None:
        receipt = Receipt.success("0xabc123", timestamp=datetime(2024, 1, 20, tzinfo=UTC))
        with_payer = replace(receipt, payer="0x" + "aa" * 20)

        assert with_payer.to_payment_receipt() == receipt.to_payment_receipt()
        assert Receipt.from_payment_receipt(with_payer.to_payment_receipt()).payer is None

    def test_success_factory(self) -> None:
        """Receipt.success() should create success receipt with timestamp."""
        receipt = Receipt.success("0xabc123")
        assert receipt.status == "success"
        assert receipt.reference == "0xabc123"
        assert isinstance(receipt.timestamp, datetime)
        assert receipt.timestamp.tzinfo is not None

    def test_parse_invalid_status(self) -> None:
        """Should reject invalid status values."""
        # {"status":"pending","timestamp":"2024-01-20T12:00:00Z","reference":"0x"}
        b64 = (
            "eyJzdGF0dXMiOiJwZW5kaW5nIiwidGltZXN0YW1wIjoiMjAyNC0wMS0yMFQxMjowMDow"
            "MFoiLCJyZWZlcmVuY2UiOiIweCJ9"
        )
        with pytest.raises(ParseError):
            Receipt.from_payment_receipt(b64)

    def test_roundtrip_with_optional_fields(self) -> None:
        timestamp = datetime(2024, 1, 20, 12, 0, 0, tzinfo=UTC)
        receipt = Receipt(
            status="success",
            timestamp=timestamp,
            reference="0xabc123def456",
            method="tempo",
            external_id="order-123",
            extra={"plan": "pro"},
            subscription_id="sub_123",
        )

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.method == "tempo"
        assert parsed.external_id == "order-123"
        assert parsed.extra == {"plan": "pro"}
        assert parsed.subscription_id == "sub_123"

    def test_parse_preserves_foreign_subscription_id(self) -> None:
        payload = {
            "status": "success",
            "method": "tempo",
            "timestamp": "2024-01-20T12:00:00Z",
            "reference": "0xabc123def456",
            "subscriptionId": "sub_123",
        }
        header = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        parsed = Receipt.from_payment_receipt(header)

        assert parsed.subscription_id == "sub_123"
        roundtripped = Receipt.from_payment_receipt(parsed.to_payment_receipt())
        assert roundtripped.subscription_id == "sub_123"

    def test_roundtrip_preserves_funding_currency(self) -> None:
        receipt = Receipt.success(
            "0xabc", funding_currency="0x20c0000000000000000000000000000000000001"
        )
        header = receipt.to_payment_receipt()
        encoded = json.loads(base64.urlsafe_b64decode(header + "==").decode())
        assert encoded["fundingCurrency"] == "0x20c0000000000000000000000000000000000001"

        parsed = Receipt.from_payment_receipt(header)
        assert parsed.funding_currency == "0x20c0000000000000000000000000000000000001"
        assert parsed.extensions is None
        assert "fundingCurrency" not in json.loads(
            base64.urlsafe_b64decode(Receipt.success("0xabc").to_payment_receipt() + "==").decode()
        )

    def test_funding_currency_from_extensions_is_still_emitted(self) -> None:
        token = "0x20c0000000000000000000000000000000000001"
        receipt = Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference="0xabc",
            extensions={"fundingCurrency": token},
        )
        encoded = json.loads(base64.urlsafe_b64decode(receipt.to_payment_receipt() + "==").decode())
        assert encoded["fundingCurrency"] == token
        both = Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference="0xabc",
            extensions={"fundingCurrency": "0xother"},
            funding_currency=token,
        )
        encoded = json.loads(base64.urlsafe_b64decode(both.to_payment_receipt() + "==").decode())
        assert encoded["fundingCurrency"] == token

    def test_payer_keeps_its_positional_slot(self) -> None:
        receipt = Receipt(
            "success", datetime.now(UTC), "0xabc", "tempo", None, None, None, None, "0xpayer"
        )
        assert receipt.payer == "0xpayer"
        assert receipt.funding_currency is None

    def test_roundtrip_preserves_method_specific_fields(self) -> None:
        payload = {
            "status": "success",
            "method": "tempo",
            "timestamp": "2024-01-20T12:00:00Z",
            "reference": "0xabc123def456",
            "challengeId": "challenge-123",
            "originTxHash": "0xdeadbeef",
            "destinationNetwork": "eip155:1",
        }
        header = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        parsed = Receipt.from_payment_receipt(header)

        assert parsed.extensions == {
            "challengeId": "challenge-123",
            "originTxHash": "0xdeadbeef",
            "destinationNetwork": "eip155:1",
        }
        roundtripped = Receipt.from_payment_receipt(parsed.to_payment_receipt())
        assert roundtripped.extensions == parsed.extensions

        encoded_payload = json.loads(
            base64.urlsafe_b64decode(parsed.to_payment_receipt() + "==").decode()
        )
        assert encoded_payload["challengeId"] == "challenge-123"
        assert encoded_payload["originTxHash"] == "0xdeadbeef"
        assert encoded_payload["destinationNetwork"] == "eip155:1"

    def test_parse_invalid_timestamp(self) -> None:
        payload = {
            "status": "success",
            "timestamp": "not-a-timestamp",
            "reference": "0xabc",
            "method": "tempo",
        }
        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        with pytest.raises(ParseError, match="Invalid timestamp format"):
            Receipt.from_payment_receipt(b64)

    @pytest.mark.parametrize("method", INVALID_PAYMENT_METHOD_IDS)
    def test_parse_rejects_invalid_method_id(self, method: str) -> None:
        payload = {
            "status": "success",
            "timestamp": "2024-01-20T12:00:00Z",
            "reference": "0xabc",
            "method": method,
        }
        b64 = _b64_json(payload)

        with pytest.raises(ParseError, match="Invalid payment method id"):
            Receipt.from_payment_receipt(b64)


@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
@pytest.mark.parametrize("field", ["id", "realm", "intent", "expires", "digest", "opaque"])
def test_rejects_surrogates_in_credential_echo(field: str, surrogate: str) -> None:
    body = {
        "challenge": {
            "id": "id",
            "realm": "test",
            "method": "tempo",
            "intent": "charge",
            "request": {},
        },
        "payload": {},
    }
    body["challenge"][field] = surrogate
    with pytest.raises(ParseError, match="Invalid base64 or JSON encoding"):
        Credential.from_authorization("Payment " + _b64_json(body))


@pytest.mark.parametrize("payload", [{"key": "\ud800"}, {"\udfff": "value"}, ["\ud800"]])
def test_rejects_nested_surrogates(payload: object) -> None:
    from mpp._parsing import _b64_decode

    with pytest.raises(ParseError):
        _b64_decode(_b64_json({"payload": payload}))


def test_accepts_valid_supplementary_unicode() -> None:
    from mpp._parsing import _b64_decode

    assert _b64_decode(_b64_json({"text": "\U0001f600"})) == {"text": "\U0001f600"}
