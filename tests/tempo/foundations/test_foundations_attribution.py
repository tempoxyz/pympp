from __future__ import annotations

import re

from mpp.tempo import attribution
from mpp.tempo._internal.hexutil import keccak256

ARBITRARY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


def _keccak_prefix(value: str, size: int) -> str:
    return "0x" + keccak256(value.encode())[:size].hex()


class TestTag:
    def test_is_a_4_byte_hex_string(self) -> None:
        assert re.fullmatch(r"0x[0-9a-f]{8}", attribution.TAG, re.IGNORECASE)

    def test_is_deterministic(self) -> None:
        assert attribution.TAG == "0xef1ed712"


class TestEncode:
    def test_returns_a_32_byte_hex_string(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert re.fullmatch(r"0x[0-9a-f]{64}", memo, re.IGNORECASE)

    def test_starts_with_tag_and_version_byte(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert memo[:10].lower() == attribution.TAG.lower()
        assert memo[10:12] == "01"

    def test_produces_deterministic_memos(self) -> None:
        a = attribution.encode(challenge_id="challenge-a", server_id="api.example.com")
        b = attribution.encode(challenge_id="challenge-b", server_id="api.example.com")
        assert a != b
        c = attribution.encode(challenge_id="challenge-a", server_id="api.example.com")
        assert a == c

    def test_encodes_server_fingerprint(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert f"0x{memo[12:32]}".lower() == _keccak_prefix("api.example.com", 10)

    def test_encodes_client_fingerprint(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="my-app", server_id="api.example.com"
        )
        assert f"0x{memo[32:52]}".lower() == _keccak_prefix("my-app", 10)

    def test_encodes_zero_client_bytes_when_no_client_id(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert f"0x{memo[32:52]}" == attribution.ANONYMOUS

    def test_treats_empty_client_id_as_anonymous(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="", server_id="api.example.com"
        )
        assert f"0x{memo[32:52]}" == attribution.ANONYMOUS
        decoded = attribution.decode(memo)
        assert decoded is not None
        assert decoded.client_fingerprint is None


class TestIsMppMemo:
    def test_true_for_encoded_memos(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert attribution.is_mpp_memo(memo) is True

    def test_true_for_encoded_memos_with_client_id(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="my-app", server_id="api.example.com"
        )
        assert attribution.is_mpp_memo(memo) is True

    def test_false_for_zero_memo(self) -> None:
        assert attribution.is_mpp_memo("0x" + "00" * 32) is False

    def test_false_for_arbitrary_memo(self) -> None:
        assert attribution.is_mpp_memo(ARBITRARY) is False

    def test_false_for_short_hex(self) -> None:
        assert attribution.is_mpp_memo("0x1234") is False

    def test_false_for_wrong_version(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert attribution.is_mpp_memo(f"{memo[:10]}ff{memo[12:]}") is False

    def test_handles_mixed_case_hex(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        mixed = f"0x{memo[:10].upper()[2:]}{memo[10:]}"
        assert attribution.is_mpp_memo(mixed) is True


class TestVerifyServer:
    def test_true_for_matching_server_id(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert attribution.verify_server(memo, "api.example.com") is True

    def test_true_for_matching_server_id_with_client_id(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="my-app", server_id="api.example.com"
        )
        assert attribution.verify_server(memo, "api.example.com") is True

    def test_false_for_wrong_server_id(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert attribution.verify_server(memo, "other.example.com") is False

    def test_false_for_non_mpp_memo(self) -> None:
        assert attribution.verify_server(ARBITRARY, "api.example.com") is False


class TestDecode:
    def test_decodes_memo_with_server_and_client(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="my-app", server_id="api.example.com"
        )
        result = attribution.decode(memo)
        assert result is not None
        assert result.version == 1
        assert re.fullmatch(r"0x[0-9a-f]{20}", result.server_fingerprint, re.IGNORECASE)
        assert result.client_fingerprint is not None
        assert re.fullmatch(r"0x[0-9a-f]{20}", result.client_fingerprint, re.IGNORECASE)
        assert re.fullmatch(r"0x[0-9a-f]{14}", result.nonce, re.IGNORECASE)

    def test_decodes_anonymous_client_as_none(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        result = attribution.decode(memo)
        assert result is not None
        assert result.client_fingerprint is None

    def test_returns_none_for_non_mpp_memo(self) -> None:
        assert attribution.decode(ARBITRARY) is None

    def test_different_challenge_ids_produce_different_nonces(self) -> None:
        a = attribution.decode(
            attribution.encode(challenge_id="challenge-a", server_id="api.example.com")
        )
        b = attribution.decode(
            attribution.encode(challenge_id="challenge-b", server_id="api.example.com")
        )
        assert a is not None
        assert b is not None
        assert a.nonce != b.nonce

    def test_server_fingerprint_matches_keccak(self) -> None:
        memo = attribution.encode(
            challenge_id="test-challenge-1", client_id="my-app", server_id="api.example.com"
        )
        result = attribution.decode(memo)
        assert result is not None
        assert result.server_fingerprint.lower() == _keccak_prefix("api.example.com", 10)

    def test_nonce_matches_keccak_challenge_id(self) -> None:
        result = attribution.decode(
            attribution.encode(challenge_id="challenge-123", server_id="api.example.com")
        )
        assert result is not None
        assert result.nonce.lower() == _keccak_prefix("challenge-123", 7)

    def test_returns_none_for_wrong_version(self) -> None:
        memo = attribution.encode(challenge_id="test-challenge-1", server_id="api.example.com")
        assert attribution.decode(f"{memo[:10]}ff{memo[12:]}") is None


class TestVerifyChallengeBinding:
    def test_true_for_matching_challenge_id(self) -> None:
        memo = attribution.encode(challenge_id="challenge-123", server_id="api.example.com")
        assert attribution.verify_challenge_binding(memo, "challenge-123") is True

    def test_false_for_wrong_challenge_id(self) -> None:
        memo = attribution.encode(challenge_id="challenge-123", server_id="api.example.com")
        assert attribution.verify_challenge_binding(memo, "challenge-456") is False

    def test_false_for_non_mpp_memo(self) -> None:
        assert attribution.verify_challenge_binding(ARBITRARY, "challenge-123") is False
