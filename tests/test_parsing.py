"""Tests for header parsing and formatting."""

from datetime import UTC, datetime

import pytest

from mpay import Challenge, Credential, Receipt
from mpay._parsing import ParseError


class TestChallenge:
    def test_roundtrip(self) -> None:
        """Challenge should survive roundtrip through header format."""
        challenge = Challenge(
            id="test-id-123",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "asset": "0x123", "destination": "0x456"},
        )

        header = challenge.to_www_authenticate("api.example.com")
        parsed = Challenge.from_www_authenticate(header)

        assert parsed.id == challenge.id
        assert parsed.method == challenge.method
        assert parsed.intent == challenge.intent
        assert parsed.request == challenge.request

    def test_parse_valid_header(self) -> None:
        """Should parse a valid WWW-Authenticate header."""
        # {"id":"test","method":"tempo","intent":"charge","request":{}}
        b64 = "eyJpZCI6InRlc3QiLCJtZXRob2QiOiJ0ZW1wbyIsImludGVudCI6ImNoYXJnZSIsInJlcXVlc3QiOnt9fQ"
        header = f'Payment realm="api.example.com", {b64}'
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
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate("Payment eyJpZCI6InRlc3QifQ")

    def test_parse_invalid_base64(self) -> None:
        """Should reject invalid base64."""
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate('Payment realm="test", !!!invalid!!!')

    def test_parse_non_dict_json(self) -> None:
        """Should reject JSON that decodes to non-dict."""
        import base64

        # base64 of JSON array []
        b64_array = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
        with pytest.raises(ParseError, match="Expected JSON object"):
            Challenge.from_www_authenticate(f'Payment realm="test", {b64_array}')

    def test_parse_missing_fields(self) -> None:
        """Should reject challenges missing required fields."""
        # {"id":"test","intent":"charge","request":{}} - missing method
        b64 = "eyJpZCI6InRlc3QiLCJpbnRlbnQiOiJjaGFyZ2UiLCJyZXF1ZXN0Ijp7fX0"
        header = f'Payment realm="test", {b64}'
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate(header)


class TestCredential:
    def test_roundtrip(self) -> None:
        """Credential should survive roundtrip through header format."""
        credential = Credential(
            id="test-id-123",
            payload={"hash": "0xabc123"},
            source="did:pkh:eip155:1:0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.id == credential.id
        assert parsed.payload == credential.payload
        assert parsed.source == credential.source

    def test_roundtrip_without_source(self) -> None:
        """Credential without source should roundtrip."""
        credential = Credential(
            id="test-id",
            payload={"signature": "0x123"},
        )

        header = credential.to_authorization()
        parsed = Credential.from_authorization(header)

        assert parsed.id == credential.id
        assert parsed.payload == credential.payload
        assert parsed.source is None

    def test_parse_invalid_scheme(self) -> None:
        """Should reject non-Payment schemes."""
        with pytest.raises(ParseError):
            Credential.from_authorization("Bearer abc123")

    def test_parse_missing_id(self) -> None:
        """Should reject credentials without id."""
        header = "Payment eyJwYXlsb2FkIjp7fX0"  # {"payload": {}}
        with pytest.raises(ParseError):
            Credential.from_authorization(header)


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

    def test_roundtrip_failed(self) -> None:
        """Failed receipt should roundtrip."""
        receipt = Receipt.failed("0x000")

        header = receipt.to_payment_receipt()
        parsed = Receipt.from_payment_receipt(header)

        assert parsed.status == "failed"

    def test_success_factory(self) -> None:
        """Receipt.success() should create success receipt with timestamp."""
        receipt = Receipt.success("0xabc123")
        assert receipt.status == "success"
        assert receipt.reference == "0xabc123"
        assert isinstance(receipt.timestamp, datetime)
        assert receipt.timestamp.tzinfo is not None

    def test_failed_factory(self) -> None:
        """Receipt.failed() should create failed receipt with timestamp."""
        receipt = Receipt.failed("0xdef456")
        assert receipt.status == "failed"
        assert receipt.reference == "0xdef456"
        assert isinstance(receipt.timestamp, datetime)

    def test_parse_invalid_status(self) -> None:
        """Should reject invalid status values."""
        # {"status":"pending","timestamp":"2024-01-20T12:00:00Z","reference":"0x"}
        b64 = (
            "eyJzdGF0dXMiOiJwZW5kaW5nIiwidGltZXN0YW1wIjoiMjAyNC0wMS0yMFQxMjowMDow"
            "MFoiLCJyZWZlcmVuY2UiOiIweCJ9"
        )
        with pytest.raises(ParseError):
            Receipt.from_payment_receipt(b64)
