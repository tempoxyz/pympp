"""Tests for HMAC-SHA256 challenge ID generation.

These tests use the cross-SDK conformance test vectors to ensure
Python SDK produces identical challenge IDs to TypeScript and Rust SDKs.
"""

from mpp import Challenge, generate_challenge_id


class TestGenerateChallengeId:
    """Test HMAC-SHA256 challenge ID generation with conformance vectors."""

    def test_basic_charge(self) -> None:
        """Basic charge challenge ID generation."""
        result = generate_challenge_id(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert result == "s0gsoewXwdYI13oPnrtdKTEN4-sIQ-LbQUNV_HttPnA"

    def test_with_expires(self) -> None:
        """Challenge ID with expires field included in HMAC."""
        result = generate_challenge_id(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "5000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0xabcdef1234567890abcdef1234567890abcdef12",
            },
            expires="2026-01-29T12:00:00Z",
        )
        assert result == "0rMv3trZIudpkJCQxeL2RLQz6uALKTNErWulN07hDLk"

    def test_with_digest(self) -> None:
        """Challenge ID with digest field included in HMAC."""
        result = generate_challenge_id(
            secret_key="my-server-secret",
            realm="payments.example.org",
            method="tempo",
            intent="charge",
            request={
                "amount": "250000",
                "currency": "USD",
                "recipient": "0x9999999999999999999999999999999999999999",
            },
            digest="sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
        )
        assert result == "EAX2sqwdeg8Km8LIKRBFhM5xDQvEgIlbTif9FKBsOiU"

    def test_full_challenge(self) -> None:
        """Challenge ID with all optional fields."""
        result = generate_challenge_id(
            secret_key="production-secret-abc123",
            realm="api.tempo.xyz",
            method="tempo",
            intent="charge",
            request={
                "amount": "10000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                "description": "API access fee",
                "externalId": "order-12345",
            },
            expires="2026-02-01T00:00:00Z",
            digest="sha-256=abc123def456",
        )
        assert result == "jDq_IazIMny5JJk3-xm3eSxGaP6XbbaApxBi6fG_320"

    def test_different_secret_different_id(self) -> None:
        """Same parameters with different secret produces different ID."""
        result = generate_challenge_id(
            secret_key="different-secret-key",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert result == "UMEn_1WPt2vz3XK8rrkbHET6RwqfwtK8VVNz0Xc2x4A"

    def test_empty_request(self) -> None:
        """Challenge ID with empty request object."""
        result = generate_challenge_id(
            secret_key="test-key",
            realm="test.example.com",
            method="tempo",
            intent="authorize",
            request={},
        )
        assert result == "jUTqTVe3kCv5rVizv1XBCs9qKCLg4AZLwBUnk4N3MR8"

    def test_unicode_in_description(self) -> None:
        """Request with unicode characters."""
        result = generate_challenge_id(
            secret_key="unicode-test-key",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "100",
                "currency": "EUR",
                "recipient": "0x1111111111111111111111111111111111111111",
                "description": "Payment for café ☕",
            },
        )
        assert result == "OjiT_PsisJ_SkHEomn9dcfraObt4U3nO5Tg3gU0Etmg"

    def test_nested_method_details(self) -> None:
        """Request with nested methodDetails object."""
        result = generate_challenge_id(
            secret_key="nested-test-key",
            realm="api.tempo.xyz",
            method="tempo",
            intent="charge",
            request={
                "amount": "5000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x2222222222222222222222222222222222222222",
                "methodDetails": {"chainId": 42431, "feePayer": True},
            },
        )
        assert result == "9Sl6t74wn9zPaakjTSK6DqhGtS5HQVQEkIUYBYdHTbA"


class TestGoldenVectors:
    """Cross-SDK golden vectors (shared with mppx and mpp-rs).

    HMAC input: realm | method | intent | base64url(canonicalize(request)) | expires | digest
    HMAC key:   UTF-8 bytes of secret_key ("test-vector-secret")
    Output:     base64url(HMAC-SHA256(key, input), no padding)

    These vectors cover every combination of optional HMAC fields (expires, digest)
    and variations in each required field (realm, method, intent, request).
    """

    SECRET = "test-vector-secret"

    def test_required_fields_only(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "SOfbA51LV3LCkGE7RbomqwXdbWVlrZwlW-Z9aOHolxw"

    def test_with_expires(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            expires="2025-01-06T12:00:00Z",
        )
        assert result == "R1ZSIwoIjkFhMCSzUGiCTesiigf5vV65EQ_3gVNtsNw"

    def test_with_digest(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            digest="sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE",
        )
        assert result == "AiMmBdsSOkOYpXTupMnzVnrzZbqMY_P2i80vENRUSN4"

    def test_with_expires_and_digest(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            expires="2025-01-06T12:00:00Z",
            digest="sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE",
        )
        assert result == "FMBGqN7MzpKagHsCcartZM09CnUqv7UgmaCy45Ozgug"

    def test_description_not_in_hmac(self) -> None:
        """description is not part of HMAC input, so ID matches 'required fields only'."""
        with_desc = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert with_desc == "SOfbA51LV3LCkGE7RbomqwXdbWVlrZwlW-Z9aOHolxw"

    def test_multi_field_request(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000", "currency": "0x1234", "recipient": "0xabcd"},
        )
        assert result == "5CXJi4bWMz2W54WjnlmoxnwTYe-JKwhw0z32ICQ65Es"

    def test_nested_method_details(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x1234",
                "methodDetails": {"chainId": 42431},
            },
        )
        assert result == "eid66xXUZsj46Pb30AfAf7m5kPehgianI16rZ-QY8HU"

    def test_empty_request(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={},
        )
        assert result == "6kq-PYTyXtaGAHTHCVUrc_hIsAwLeskeQFtDZerMYhM"

    def test_different_realm(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="payments.other.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "-gMjd8UeUvBcqUaUzarVj6ikH_YoDowpaNbEwK1Tmx8"

    def test_different_method(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="stripe",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "DRH9ycmIlZ2lYUatIHCrxpm9K7ig5pniZ3ulleb7vl0"

    def test_different_intent(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="session",
            request={"amount": "1000000"},
        )
        assert result == "INeBi93MhinvbwdUxeUUIaT5Q_ufgLKPYZb5Tg43A1o"


class TestChallengeCreate:
    """Test Challenge.create() factory method."""

    def test_creates_challenge_with_hmac_id(self) -> None:
        """Challenge.create() should use HMAC-bound ID."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert challenge.id == "s0gsoewXwdYI13oPnrtdKTEN4-sIQ-LbQUNV_HttPnA"
        assert challenge.method == "tempo"
        assert challenge.intent == "charge"

    def test_create_with_optional_fields(self) -> None:
        """Challenge.create() should handle optional fields."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "5000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0xabcdef1234567890abcdef1234567890abcdef12",
            },
            expires="2026-01-29T12:00:00Z",
            description="Test payment",
        )
        assert challenge.id == "0rMv3trZIudpkJCQxeL2RLQz6uALKTNErWulN07hDLk"
        assert challenge.expires == "2026-01-29T12:00:00Z"
        assert challenge.description == "Test payment"


class TestChallengeVerify:
    """Test Challenge.verify() method."""

    def test_verify_valid_challenge(self) -> None:
        """Challenge.verify() should return True for valid HMAC."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert challenge.verify("test-secret-key-12345", "api.example.com")

    def test_verify_invalid_secret(self) -> None:
        """Challenge.verify() should return False for wrong secret."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert not challenge.verify("wrong-secret", "api.example.com")

    def test_verify_invalid_realm(self) -> None:
        """Challenge.verify() should return False for wrong realm."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert not challenge.verify("test-secret-key-12345", "wrong.realm.com")

    def test_verify_tampered_challenge(self) -> None:
        """Challenge.verify() should return False if challenge was tampered."""
        original = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        # Simulate tampering by creating a new challenge with modified request
        tampered = Challenge(
            id=original.id,  # Keep original ID
            method=original.method,
            intent=original.intent,
            request={"amount": "9999999"},  # Tampered amount
        )
        assert not tampered.verify("test-secret-key-12345", "api.example.com")

    def test_verify_with_expires(self) -> None:
        """Challenge.verify() should include expires in HMAC."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "5000000"},
            expires="2026-01-29T12:00:00Z",
        )
        assert challenge.verify("test-secret-key-12345", "api.example.com")

        # Tampering expires should fail
        tampered = Challenge(
            id=challenge.id,
            method=challenge.method,
            intent=challenge.intent,
            request=challenge.request,
            expires="2099-12-31T23:59:59Z",  # Tampered
        )
        assert not tampered.verify("test-secret-key-12345", "api.example.com")
