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

    def test_preserves_insertion_order_like_mppx(self) -> None:
        """Dict digests hash JSON in insertion order, matching mppx's JSON.stringify."""
        body = {"z": "1", "a": "2"}
        # mppx: BodyDigest.compute({ z: '1', a: '2' })
        assert compute(body) == "sha-256=WSxerte9Ij4rZhT5zPpISv1H2Sjidi2PaHo2Iu8d+Mc="
        assert compute(body) == compute('{"z":"1","a":"2"}')
        assert compute(body) != compute({"a": "2", "z": "1"})

    def test_nested_dict_preserves_insertion_order(self) -> None:
        """Nested dicts also keep insertion order."""
        body = {"outer_z": {"inner_b": 1, "inner_a": 2}, "outer_a": 3}
        assert compute(body) == "sha-256=EVh89pgYAJz45/LcDMXKrGwCn8DVHGu3b28UfZw1dBE="
        assert compute(body) == compute(json.dumps(body, separators=(",", ":")))


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


class TestJavaScriptKeyOrder:
    def test_integer_keys_first_like_json_stringify(self) -> None:
        """Integer-index keys come first in numeric order, like JSON.stringify."""
        body = {"b": 1, "1": 2}
        assert compute(body) == compute('{"1":2,"b":1}')
        body = {"z": "1", "10": "a", "2": "b", "a": "c"}
        assert compute(body) == compute('{"2":"b","10":"a","z":"1","a":"c"}')

    def test_non_index_numeric_keys_keep_insertion_order(self) -> None:
        """Leading zeros, negatives and keys above 2**32-2 are ordinary string keys."""
        body = {"b": 1, "01": 2, "-1": 3, "4294967295": 4, "4294967294": 5}
        assert compute(body) == compute('{"4294967294":5,"b":1,"01":2,"-1":3,"4294967295":4}')

    def test_nested_integer_keys(self) -> None:
        """Ordering applies inside nested dicts and lists."""
        body = {"x": [{"b": 1, "0": 2}], "5": {"a": 1, "3": 2}}
        assert compute(body) == compute('{"5":{"3":2,"a":1},"x":[{"0":2,"b":1}]}')


class TestLegacyDigest:
    def test_accepts_sorted_key_digest_for_dict(self) -> None:
        """Digests issued by earlier releases (sorted keys) still verify."""
        body = {"z": "1", "a": "2"}
        legacy = compute('{"a":"2","z":"1"}')
        assert compute(body) != legacy
        assert verify(legacy, body) is True

    def test_legacy_fallback_is_dict_only(self) -> None:
        """String bodies are hashed as-is with no fallback."""
        assert verify(compute('{"a":"2","z":"1"}'), '{"z":"1","a":"2"}') is False
