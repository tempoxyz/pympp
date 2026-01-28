"""Tests for header parsing and formatting."""

from datetime import UTC, datetime

import pytest

from mpay import Challenge, ChallengeEcho, Credential, Receipt
from mpay._parsing import ParseError


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
        expires_dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
        challenge = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=expires_dt,
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


class TestCredential:
    def test_roundtrip(self) -> None:
        """Credential should survive roundtrip through header format."""
        credential = Credential(
            challenge=ChallengeEcho(
                id="test-id-123",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={"hash": "0xabc123"},
            source="did:pkh:eip155:1:0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.id == credential.challenge.id
        assert parsed.challenge.realm == credential.challenge.realm
        assert parsed.challenge.method == credential.challenge.method
        assert parsed.challenge.intent == credential.challenge.intent
        assert parsed.challenge.request == credential.challenge.request
        assert parsed.payload == credential.payload
        assert parsed.source == credential.source

    def test_roundtrip_without_source(self) -> None:
        """Credential without source should roundtrip."""
        credential = Credential(
            challenge=ChallengeEcho(
                id="test-id",
                realm="test.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "500"},
            ),
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

    def test_parse_missing_challenge(self) -> None:
        """Should reject credentials without challenge."""
        header = "Payment eyJwYXlsb2FkIjp7fX0"  # {"payload": {}}
        with pytest.raises(ParseError, match="challenge"):
            Credential.from_authorization(header)

    def test_roundtrip_with_optional_challenge_fields(self) -> None:
        """Credential with optional challenge fields should roundtrip."""
        expires_dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
        credential = Credential(
            challenge=ChallengeEcho(
                id="test-id",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
                expires=expires_dt,
                digest="sha-256=:abc123:",
                description="Test payment",
            ),
            payload={"hash": "0xabc"},
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.challenge.expires == credential.challenge.expires
        assert parsed.challenge.digest == credential.challenge.digest
        assert parsed.challenge.description == credential.challenge.description


class TestReceipt:
    def test_roundtrip(self) -> None:
        """Receipt should survive roundtrip through header format."""
        timestamp = datetime(2024, 1, 20, 12, 0, 0, tzinfo=UTC)
        receipt = Receipt(
            status="success",
            method="tempo",
            timestamp=timestamp,
            reference="0xabc123def456",
        )

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.status == receipt.status
        assert parsed.method == receipt.method
        assert parsed.timestamp == receipt.timestamp
        assert parsed.reference == receipt.reference

    def test_roundtrip_failed(self) -> None:
        """Failed receipt should roundtrip."""
        receipt = Receipt.failed("0x000", method="tempo")

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.status == "failed"
        assert parsed.method == "tempo"

    def test_success_factory(self) -> None:
        """Receipt.success() should create success receipt with timestamp."""
        receipt = Receipt.success("0xabc123", method="tempo")
        assert receipt.status == "success"
        assert receipt.method == "tempo"
        assert receipt.reference == "0xabc123"
        assert isinstance(receipt.timestamp, datetime)
        assert receipt.timestamp.tzinfo is not None

    def test_failed_factory(self) -> None:
        """Receipt.failed() should create failed receipt with timestamp."""
        receipt = Receipt.failed("0xdef456", method="tempo")
        assert receipt.status == "failed"
        assert receipt.method == "tempo"
        assert receipt.reference == "0xdef456"
        assert isinstance(receipt.timestamp, datetime)

    def test_parse_invalid_status(self) -> None:
        """Should reject invalid status values."""
        # {"status":"pending","method":"tempo","timestamp":"2024-01-20T12:00:00Z","reference":"0x"}
        import base64
        import json

        data = {
            "status": "pending",
            "method": "tempo",
            "timestamp": "2024-01-20T12:00:00Z",
            "reference": "0x",
        }
        b64 = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(ParseError):
            Receipt.from_payment_receipt(b64)

    def test_parse_missing_method(self) -> None:
        """Should reject receipts without method field."""
        import base64
        import json

        data = {
            "status": "success",
            "timestamp": "2024-01-20T12:00:00Z",
            "reference": "0x123",
        }
        b64 = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(ParseError, match="method"):
            Receipt.from_payment_receipt(b64)
