"""Tests for header parsing and formatting."""

import base64
import json
from datetime import UTC, datetime

import pytest

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp._parsing import MAX_HEADER_PAYLOAD_SIZE, ParseError
from tests import make_credential


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
        )

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.method == "tempo"
        assert parsed.external_id == "order-123"
        assert parsed.extra == {"plan": "pro"}

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
