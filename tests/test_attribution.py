"""Tests for MPP attribution memo encoding."""

from mpp.methods.tempo._attribution import (
    TAG,
    DecodedMemo,
    challenge_nonce,
    decode,
    encode,
    is_mpp_memo,
    verify_challenge_binding,
    verify_server,
)


class TestTag:
    def test_tag_value(self) -> None:
        assert TAG == bytes.fromhex("ef1ed712")

    def test_tag_length(self) -> None:
        assert len(TAG) == 4


class TestEncode:
    def test_produces_66_char_hex(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert memo.startswith("0x")
        assert len(memo) == 66

    def test_with_client_id(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com", client_id="my-app")
        assert len(memo) == 66
        assert is_mpp_memo(memo)

    def test_without_client_id_is_anonymous(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        decoded = decode(memo)
        assert decoded is not None
        assert decoded.client_fingerprint is None

    def test_challenge_bound_nonce_is_deterministic(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert memo == encode(challenge_id="challenge-1", server_id="api.example.com")
        assert memo != encode(challenge_id="challenge-2", server_id="api.example.com")


class TestChallengeNonce:
    def test_is_deterministic(self) -> None:
        assert challenge_nonce("challenge-1") == challenge_nonce("challenge-1")

    def test_changes_for_different_challenges(self) -> None:
        assert challenge_nonce("challenge-1") != challenge_nonce("challenge-2")

    def test_is_seven_bytes(self) -> None:
        assert len(challenge_nonce("challenge-1")) == 7


class TestIsMppMemo:
    def test_true_for_encoded(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert is_mpp_memo(memo) is True

    def test_false_for_zeros(self) -> None:
        assert is_mpp_memo("0x" + "00" * 32) is False

    def test_false_for_wrong_length(self) -> None:
        assert is_mpp_memo("0xabcd") is False

    def test_false_for_wrong_version(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        bad = memo[:10] + "ff" + memo[12:]
        assert is_mpp_memo(bad) is False

    def test_false_for_non_hex(self) -> None:
        assert is_mpp_memo("0x" + "zz" * 32) is False


class TestVerifyServer:
    def test_correct_server(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert verify_server(memo, "api.example.com") is True

    def test_wrong_server(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert verify_server(memo, "other.example.com") is False

    def test_non_mpp_memo(self) -> None:
        assert verify_server("0x" + "00" * 32, "api.example.com") is False


class TestVerifyChallengeBinding:
    def test_correct_challenge(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert verify_challenge_binding(memo, "challenge-1") is True

    def test_wrong_challenge(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert verify_challenge_binding(memo, "challenge-2") is False

    def test_non_mpp_memo(self) -> None:
        assert verify_challenge_binding("0x" + "00" * 32, "challenge-1") is False


class TestDecode:
    def test_round_trip(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com", client_id="my-app")
        decoded = decode(memo)
        assert decoded is not None
        assert isinstance(decoded, DecodedMemo)
        assert decoded.version == 1
        assert decoded.server_fingerprint.startswith("0x")
        assert len(decoded.server_fingerprint) == 22  # 0x + 20 hex chars (10 bytes)
        assert decoded.client_fingerprint is not None
        assert decoded.nonce.startswith("0x")
        assert len(decoded.nonce) == 16  # 0x + 14 hex chars (7 bytes)

    def test_returns_none_for_non_mpp(self) -> None:
        assert decode("0x" + "00" * 32) is None

    def test_returns_none_for_non_hex(self) -> None:
        assert decode("0x" + "zz" * 32) is None

    def test_anonymous_client(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        decoded = decode(memo)
        assert decoded is not None
        assert decoded.client_fingerprint is None

    def test_different_challenge_ids_produce_different_nonces(self) -> None:
        first = decode(encode(challenge_id="challenge-1", server_id="api.example.com"))
        second = decode(encode(challenge_id="challenge-2", server_id="api.example.com"))
        assert first is not None
        assert second is not None
        assert first.nonce != second.nonce
