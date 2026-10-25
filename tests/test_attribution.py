"""Tests for MPP attribution memo encoding."""

from eth_hash.auto import keccak

from mpp.methods.tempo import attribution
from mpp.methods.tempo.attribution import (
    ANONYMOUS,
    TAG,
    DecodedMemo,
    decode,
    encode,
    is_mpp_memo,
    verify_challenge_binding,
    verify_server,
)


def _hash_prefix(value: str, size: int) -> str:
    return "0x" + keccak(value.encode())[:size].hex()


def test_public_surface() -> None:
    assert set(attribution.__all__) == {
        "ANONYMOUS",
        "TAG",
        "DecodedMemo",
        "decode",
        "encode",
        "is_mpp_memo",
        "verify_challenge_binding",
        "verify_server",
    }
    assert not hasattr(attribution, "challenge_nonce")


class TestConstants:
    def test_tag_is_keccak_prefix(self) -> None:
        assert TAG == "0xef1ed712"
        assert TAG == _hash_prefix("mpp", 4)

    def test_anonymous_is_ten_zero_bytes(self) -> None:
        assert ANONYMOUS == "0x" + "00" * 10

    def test_encoded_memo_layout(self) -> None:
        memo = encode(challenge_id="challenge-1", server_id="api.example.com")
        assert memo.startswith(TAG + "01")
        assert memo[32:52] == ANONYMOUS[2:]


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
        assert decode(memo) == DecodedMemo(
            version=1,
            server_fingerprint=_hash_prefix("api.example.com", 10),
            client_fingerprint=_hash_prefix("my-app", 10),
            nonce=_hash_prefix("challenge-1", 7),
        )

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
