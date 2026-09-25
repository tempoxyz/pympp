"""Tests for header parsing and formatting."""

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime

import pytest

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp._parsing import MAX_HEADER_PAYLOAD_SIZE, ParseError
from tests import make_credential

INVALID_PAYMENT_METHOD_IDS = ("Tempo", "tempo.pay")
# Regression coverage for AGR-2026-102: the canonical grammar
# (^[a-z][a-z0-9:_-]*$) allows digits, colons, underscores, and hyphens after
# the first character. These used to be rejected by a letters-only check.
VALID_EXTENDED_PAYMENT_METHOD_IDS = ("tempo2", "tempo-pay", "tempo_pay", "vendor:method", "x402")


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

    @pytest.mark.parametrize("method", VALID_EXTENDED_PAYMENT_METHOD_IDS)
    def test_parse_accepts_extended_charset_method_id(self, method: str) -> None:
        header = (
            f'Payment id="test", realm="api.example.com", method="{method}", '
            'intent="charge", request="e30"'
        )

        challenge = Challenge.from_www_authenticate(header)
        assert challenge.method == method

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

    # Regression tests for AGR-2026-103: auth-parameter names are
    # case-insensitive (RFC 9110 §11.2), but the duplicate check and storage
    # key both used the original casing, so "id" and "ID" were treated as
    # distinct parameters instead of a rejected duplicate.

    def test_parse_rejects_case_variant_duplicate_param(self) -> None:
        header = (
            'Payment id="test", realm="api.example.com", method="tempo", '
            'intent="charge", INTENT="session", request="e30"'
        )
        with pytest.raises(ParseError, match="Duplicate parameter: INTENT"):
            Challenge.from_www_authenticate(header)

    def test_parse_accepts_mixed_case_param_names_without_duplicates(self) -> None:
        # Mixed-case parameter names are fine as long as none collide once
        # normalized -- this isn't about requiring lowercase on the wire.
        header = (
            'Payment ID="test", Realm="api.example.com", Method="tempo", '
            'Intent="charge", Request="e30"'
        )
        challenge = Challenge.from_www_authenticate(header)
        assert challenge.id == "test"
        assert challenge.method == "tempo"

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
