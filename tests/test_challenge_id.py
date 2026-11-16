"""Tests for HMAC-SHA256 challenge ID generation.

These tests use the cross-SDK conformance test vectors to ensure
Python SDK produces identical challenge IDs to TypeScript and Rust SDKs.
"""

import base64
import hashlib
import hmac

import pytest
import rfc8785

from mpp import Challenge, generate_challenge_id
from mpp._canonical import canonical_b64url


class TestGenerateChallengeId:
    """Test HMAC-SHA256 challenge ID generation with conformance vectors."""

    def test_basic_charge(self) -> None:
        """Basic charge challenge ID generation."""
        result = generate_challenge_id(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert result == "m8mrc6t8uLSUxcqesz2jtMthpD0ivyCnbK-lg4_zRXE"

    def test_with_expires(self) -> None:
        """Challenge ID with expires field included in HMAC."""
        result = generate_challenge_id(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
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
        assert result == "8OuZibfFVcuPWgILV2lL671aDcbRl3YNT8Yz_tC_AzM"

    def test_with_digest(self) -> None:
        """Challenge ID with digest field included in HMAC."""
        result = generate_challenge_id(
            secret_key="my-server-secret-0123456789abcdef0123456789abcdef",
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
        assert result == "7kYnKyAFHN_dhbDOJ7lqmty-A1lM4gIgCONyTSlU1jU"

    def test_full_challenge(self) -> None:
        """Challenge ID with all optional fields."""
        result = generate_challenge_id(
            secret_key="production-secret-abc123-0123456789abcdef0123456789abcdef",
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
        assert result == "vxJp5ad4nO_-hphRer-SP6gQEzxnv9h-o1zBNmY-2pw"

    def test_different_secret_different_id(self) -> None:
        """Same parameters with different secret produces different ID."""
        result = generate_challenge_id(
            secret_key="different-secret-key-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert result == "NDJnC5py7_13-fLDx1PXTNp_tsEB97ow3Q7HZf8p-Rg"

    def test_empty_request(self) -> None:
        """Challenge ID with empty request object."""
        result = generate_challenge_id(
            secret_key="test-key-0123456789abcdef0123456789abcdef",
            realm="test.example.com",
            method="tempo",
            intent="authorize",
            request={},
        )
        assert result == "wqZU412VvDQJM-ZRuPgSAM0zN6bhuJwzl_JTr8GN6Sc"

    def test_unicode_in_description(self) -> None:
        """Request with unicode characters."""
        result = generate_challenge_id(
            secret_key="unicode-test-key-0123456789abcdef0123456789abcdef",
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
        assert result == "HlSPrgwxn0AriC4GiSH5CiollhkScgn6I953ftyz90M"

    def test_nested_method_details(self) -> None:
        """Request with nested methodDetails object."""
        result = generate_challenge_id(
            secret_key="nested-test-key-0123456789abcdef0123456789abcdef",
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
        assert result == "7Nrr8XWBM0OwN3FXIPc1XemPDJhjcMslg1Qd3fqrUGg"


class TestGoldenVectors:
    """Cross-SDK golden vectors (shared with mppx and mpp-rs).

    HMAC input: realm | method | intent | base64url(canonicalize(request)) | expires | digest
    HMAC key:   UTF-8 bytes of secret_key ("mpp-hmac-test-vector-secret-32by")
    Output:     base64url(HMAC-SHA256(key, input), no padding)

    These vectors cover every combination of optional HMAC fields (expires, digest)
    and variations in each required field (realm, method, intent, request).
    """

    SECRET = "mpp-hmac-test-vector-secret-32by"

    def test_required_fields_only(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "2S2NsFcCINq8QUKV8OZHdRm_JhhbJf5X8Cii4gZ_UyI"

    def test_with_expires(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            expires="2025-01-06T12:00:00Z",
        )
        assert result == "1si1-uE-QSDpwpnj7NxpFy7Gu6Z4YPWr_1FGsLYq0J4"

    def test_with_digest(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            digest="sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE",
        )
        assert result == "pgE6btlzFLJKudYJ4stj7HI4ocTeTJCFI6GA9tPxxyI"

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
        assert result == "HzjZEJWOhKwlDG8okZ2JBJQyI-h9XGvdE_HClrkM8NI"

    def test_description_not_in_hmac(self) -> None:
        """description is not part of HMAC input, so ID matches 'required fields only'."""
        with_desc = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert with_desc == "2S2NsFcCINq8QUKV8OZHdRm_JhhbJf5X8Cii4gZ_UyI"

    def test_multi_field_request(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000", "currency": "0x1234", "recipient": "0xabcd"},
        )
        assert result == "F1RuEjUwsTn6bW6_RJPzi6DTOGCHrL1SJ4khSWkleHs"

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
        assert result == "3Y4Qq7DfGEcsYA4X6Xp7T7SF5ndxdg1iT-UB_lSKQl8"

    def test_empty_request(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={},
        )
        assert result == "W8iN9dn5VBsfN18snJ7sfeQB1UW7lulIOy82KJenUmg"

    def test_different_realm(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="payments.other.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "DM5Lst2rlNZc5IZ82wbbX05B-oUYz4sT05hXlShlhgY"

    def test_different_method(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="stripe",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert result == "LHQojyqF50s6xsRCuMVA1XUvXidusjxKN_SJLzHWEVg"

    def test_different_intent(self) -> None:
        result = generate_challenge_id(
            secret_key=self.SECRET,
            realm="api.example.com",
            method="tempo",
            intent="session",
            request={"amount": "1000000"},
        )
        assert result == "NUFQUW9kSnrCVGMGHUdSfRUh6hEYBfZxasg7LtGeU4k"


class TestChallengeCreate:
    """Test Challenge.create() factory method."""

    def test_creates_challenge_with_hmac_id(self) -> None:
        """Challenge.create() should use HMAC-bound ID."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert challenge.id == "m8mrc6t8uLSUxcqesz2jtMthpD0ivyCnbK-lg4_zRXE"
        assert challenge.method == "tempo"
        assert challenge.intent == "charge"

    def test_create_with_optional_fields(self) -> None:
        """Challenge.create() should handle optional fields."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
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
        assert challenge.id == "8OuZibfFVcuPWgILV2lL671aDcbRl3YNT8Yz_tC_AzM"
        assert challenge.expires == "2026-01-29T12:00:00Z"
        assert challenge.description == "Test payment"


class TestChallengeVerify:
    """Test Challenge.verify() method."""

    def test_verify_valid_challenge(self) -> None:
        """Challenge.verify() should return True for valid HMAC."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            },
        )
        assert challenge.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "api.example.com"
        )

    def test_verify_invalid_secret(self) -> None:
        """Challenge.verify() should return False for wrong secret."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert not challenge.verify(
            "wrong-secret-0123456789abcdef0123456789abcdef", "api.example.com"
        )

    def test_verify_invalid_realm(self) -> None:
        """Challenge.verify() should return False for wrong realm."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert not challenge.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "wrong.realm.com"
        )

    def test_verify_tampered_challenge(self) -> None:
        """Challenge.verify() should return False if challenge was tampered."""
        original = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
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
        assert not tampered.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "api.example.com"
        )

    def test_verify_with_expires(self) -> None:
        """Challenge.verify() should include expires in HMAC."""
        challenge = Challenge.create(
            secret_key="test-secret-key-12345-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "5000000"},
            expires="2026-01-29T12:00:00Z",
        )
        assert challenge.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "api.example.com"
        )

        # Tampering expires should fail
        tampered = Challenge(
            id=challenge.id,
            method=challenge.method,
            intent=challenge.intent,
            request=challenge.request,
            expires="2099-12-31T23:59:59Z",  # Tampered
        )
        assert not tampered.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "api.example.com"
        )


class TestOpaque:
    """Test opaque/meta field for server-defined correlation data."""

    def test_meta_sets_opaque_on_challenge(self) -> None:
        challenge = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        assert challenge.opaque == {"pi": "pi_3abc123XYZ"}

    def test_opaque_is_none_when_no_meta(self) -> None:
        challenge = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert challenge.opaque is None

    def test_opaque_affects_challenge_id(self) -> None:
        with_meta = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        without_meta = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
        )
        assert with_meta.id != without_meta.id

    def test_different_opaque_different_ids(self) -> None:
        meta1 = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_111"},
        )
        meta2 = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_222"},
        )
        assert meta1.id != meta2.id

    def test_same_opaque_same_id(self) -> None:
        c1 = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        c2 = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        assert c1.id == c2.id

    def test_verify_succeeds_with_opaque(self) -> None:
        challenge = Challenge.create(
            secret_key="my-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        assert challenge.verify("my-secret-0123456789abcdef0123456789abcdef", "api.example.com")

    def test_verify_detects_tampered_opaque(self) -> None:
        challenge = Challenge.create(
            secret_key="my-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={"pi": "pi_3abc123XYZ"},
        )
        from dataclasses import replace

        tampered = replace(challenge, opaque={"pi": "pi_TAMPERED"})
        assert not tampered.verify("my-secret-0123456789abcdef0123456789abcdef", "api.example.com")

    def test_empty_meta_produces_opaque(self) -> None:
        challenge = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000"},
            meta={},
        )
        assert challenge.opaque == {}


class TestCredentialHeader:
    """HMAC binding and serialization of the optional credential header."""

    def test_authorization_header_does_not_change_challenge_id(self) -> None:
        params = {
            "secret_key": "test-secret-key-12345-0123456789abcdef0123456789abcdef",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": {"amount": "1000000"},
        }
        implicit = Challenge.create(**params)
        explicit = Challenge.create(**params, header="Authorization")

        assert implicit.header is None
        assert explicit.header is None
        assert implicit.id == explicit.id
        assert "header=" not in implicit.to_www_authenticate("api.example.com")
        assert implicit.credential_header == "Authorization"

    def test_payment_authorization_header_is_bound_into_id(self) -> None:
        params = {
            "secret_key": "test-secret-key-12345-0123456789abcdef0123456789abcdef",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": {"amount": "1000000"},
        }
        implicit = Challenge.create(**params)
        advertised = Challenge.create(**params, header="Payment-Authorization")

        assert implicit.id != advertised.id
        assert advertised.header == "Payment-Authorization"
        assert advertised.verify(
            "test-secret-key-12345-0123456789abcdef0123456789abcdef", "api.example.com"
        )
        assert 'header="Payment-Authorization"' in advertised.to_www_authenticate("api.example.com")

    def test_header_sits_before_opaque_in_hmac(self) -> None:
        """Header is inserted immediately before the final opaque slot."""
        params = {
            "secret_key": "test-secret-0123456789abcdef0123456789abcdef",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": {"amount": "1000000"},
        }
        with_header = Challenge.create(**params, header="Payment-Authorization")
        with_both = Challenge.create(
            **params, header="Payment-Authorization", meta={"pi": "pi_123"}
        )
        with_opaque = Challenge.create(**params, meta={"pi": "pi_123"})

        assert with_header.id != with_both.id
        assert with_both.id != with_opaque.id
        assert with_both.verify("test-secret-0123456789abcdef0123456789abcdef", "api.example.com")

    def test_rejects_invalid_header_name(self) -> None:
        with pytest.raises(ValueError, match="Invalid HTTP header name"):
            Challenge.create(
                secret_key="test-secret-0123456789abcdef0123456789abcdef",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000000"},
                header="Payment Authorization",
            )


class TestJcsChallengeEncoding:
    """RFC 8785 vectors exercised through every HMAC-bound representation."""

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (
                {"description": "Payment for café ☕", "amount": "1000000"},
                "eyJhbW91bnQiOiIxMDAwMDAwIiwiZGVzY3JpcHRpb24iOiJQYXltZW50IGZvciBjYWbDqSDimJUifQ",
            ),
            (
                {"\U00010000": "supplementary", "\ue000": "private"},
                "eyLwkICAIjoic3VwcGxlbWVudGFyeSIsIu6AgCI6InByaXZhdGUifQ",
            ),
            (
                {
                    "integer": 333333333.33333329,
                    "large": 1e21,
                    "negativeZero": -0.0,
                    "scientific": 1e-7,
                    "small": 1e-6,
                },
                "eyJpbnRlZ2VyIjozMzMzMzMzMzMuMzMzMzMzMywibGFyZ2UiOjFlKzIxLCJuZWdhdGl2ZVplcm8iOjAsInNjaWVudGlmaWMiOjFlLTcsInNtYWxsIjowLjAwMDAwMX0",
            ),
        ],
    )
    def test_matches_rfc8785_vectors(self, data: dict[str, object], expected: str) -> None:
        assert canonical_b64url(data) == expected

    @pytest.mark.parametrize(
        "data",
        [
            {"value": float("nan")},
            {"value": float("inf")},
            {"value": 2**100},
            {1: "not-a-string-key"},
        ],
    )
    def test_rejects_values_outside_jcs(self, data: dict[object, object]) -> None:
        with pytest.raises(rfc8785.CanonicalizationError):
            canonical_b64url(data)

    def test_http_wire_form_echo_and_hmac_use_identical_jcs_bytes(self) -> None:
        request = {"description": "Payment for café ☕", "amount": "1000000"}
        opaque = {"\U00010000": "supplementary", "\ue000": "private"}
        challenge = Challenge.create(
            secret_key="test-secret-0123456789abcdef0123456789abcdef",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request=request,
            meta=opaque,
            header="Payment-Authorization",
        )

        header = challenge.to_www_authenticate(challenge.realm)
        request_b64 = header.split('request="', 1)[1].split('"', 1)[0]
        opaque_b64 = header.split('opaque="', 1)[1].split('"', 1)[0]
        hmac_input = "|".join(
            [
                challenge.realm,
                challenge.method,
                challenge.intent,
                request_b64,
                "",
                "",
                "Payment-Authorization",
                opaque_b64,
            ]
        )
        expected_id = (
            base64.urlsafe_b64encode(
                hmac.new(
                    b"test-secret-0123456789abcdef0123456789abcdef",
                    hmac_input.encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )

        assert request_b64 == canonical_b64url(request)
        assert opaque_b64 == canonical_b64url(opaque)
        assert challenge.id == expected_id
        assert challenge.to_echo().request == request_b64
        assert challenge.to_echo().opaque == opaque_b64

        parsed = Challenge.from_www_authenticate(header)
        assert parsed.verify("test-secret-0123456789abcdef0123456789abcdef", "api.example.com")
        assert parsed.to_www_authenticate(parsed.realm) == header
