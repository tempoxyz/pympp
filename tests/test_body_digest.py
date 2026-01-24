"""Tests for body digest computation and verification."""

import json

from mpp._body_digest import compute, verify


class TestCompute:
    def test_dict_body(self) -> None:
        """Should compute digest for dict (JSON-serialized with compact separators)."""
        digest = compute({"key": "value"})
        assert digest.startswith("sha-256=")
        assert len(digest) > len("sha-256=")

    def test_str_body(self) -> None:
        """Should compute digest for string body."""
        digest = compute("hello world")
        assert digest.startswith("sha-256=")

    def test_bytes_body(self) -> None:
        """Should compute digest for bytes body."""
        digest = compute(b"raw bytes")
        assert digest.startswith("sha-256=")

    def test_str_and_bytes_equivalent(self) -> None:
        """String and its UTF-8 encoding should produce the same digest."""
        text = "hello world"
        assert compute(text) == compute(text.encode("utf-8"))

    def test_dict_compact_serialization(self) -> None:
        """Dict should be serialized with compact separators (no spaces)."""
        # A dict with spaces in a regular json.dumps would differ
        digest_dict = compute({"a": 1})
        digest_str = compute('{"a":1}')
        assert digest_dict == digest_str

    def test_different_bodies_different_digests(self) -> None:
        """Different bodies should produce different digests."""
        assert compute("foo") != compute("bar")

    def test_empty_body(self) -> None:
        """Empty body should still produce a valid digest."""
        digest = compute("")
        assert digest.startswith("sha-256=")
        assert compute(b"") == digest

    def test_known_sha256_vector(self) -> None:
        """Empty string digest should match the known SHA-256 of empty bytes."""
        assert compute("") == "sha-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

    def test_large_body(self) -> None:
        """1MB body should compute and roundtrip-verify successfully."""
        body = b"x" * 1_000_000
        assert verify(compute(body), body) is True

    def test_unicode_body(self) -> None:
        """Unicode string and its UTF-8 encoding should produce the same digest."""
        text = "héllo wörld 🌍"
        assert compute(text) == compute(text.encode("utf-8"))

    def test_digest_is_valid_base64(self) -> None:
        """Digest payload should decode as valid base64 to exactly 32 bytes."""
        import base64

        digest = compute("some data")
        payload = digest.removeprefix("sha-256=")
        raw = base64.b64decode(payload)
        assert len(raw) == 32

    def test_key_order_independent(self) -> None:
        """Dict digests should be identical regardless of key insertion order."""
        d1 = {"z": "1", "a": "2", "m": "3"}
        d2 = {"a": "2", "m": "3", "z": "1"}
        assert compute(d1) == compute(d2)

    def test_matches_canonical_json(self) -> None:
        """Dict digest should match digest of canonical (sorted) JSON string."""
        d = {"b": "2", "a": "1"}
        canonical = json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        assert compute(d) == compute(canonical)

    def test_nested_dict_key_order(self) -> None:
        """Nested dict should also be sorted by keys."""
        d1 = {"outer_z": {"inner_b": 1, "inner_a": 2}, "outer_a": 3}
        d2 = {"outer_a": 3, "outer_z": {"inner_a": 2, "inner_b": 1}}
        assert compute(d1) == compute(d2)


class TestVerify:
    def test_matching_digest_returns_true(self) -> None:
        """Should return True when digest matches body."""
        body = {"amount": "1000", "currency": "USD"}
        digest = compute(body)
        assert verify(digest, body) is True

    def test_mismatched_digest_returns_false(self) -> None:
        """Should return False when digest doesn't match body."""
        digest = compute("original body")
        assert verify(digest, "different body") is False

    def test_roundtrip_str(self) -> None:
        """Compute then verify should always succeed for strings."""
        body = "test body content"
        assert verify(compute(body), body) is True

    def test_roundtrip_bytes(self) -> None:
        """Compute then verify should always succeed for bytes."""
        body = b"\x00\x01\x02"
        assert verify(compute(body), body) is True

    def test_roundtrip_dict(self) -> None:
        """Compute then verify should always succeed for dicts."""
        body = {"nested": {"key": [1, 2, 3]}}
        assert verify(compute(body), body) is True

    def test_tampered_digest(self) -> None:
        """Tampered digest value should fail verification."""
        body = "test"
        assert verify("sha-256=AAAA", body) is False

    def test_wrong_algorithm_prefix(self) -> None:
        """Digest with wrong algorithm prefix should fail verification."""
        assert verify("sha-512=AAAA", "test") is False

    def test_empty_digest_string(self) -> None:
        """Empty digest string should fail verification."""
        assert verify("", "test") is False
