"""``src/tempo/internal/proof.test.ts``, plus ``recoverAuthorizedProofSigner``
(``src/tempo/server/Charge.ts``) coverage."""

from __future__ import annotations

import pytest

from mpp.tempo import proof
from mpp.tempo._internal import proof as internal_proof
from mpp.tempo._internal.account import secp256k1_account
from mpp.tempo._internal.proof import (
    PkhSource,
    hash_typed_data,
    legacy_v2_typed_data,
    recover_authorized_proof_signer,
)
from mpp.tempo._internal.signature import (
    KeychainEnvelope,
    KeychainSignature,
    deserialize,
    keychain_parts,
    keychain_signature,
    parse_secp256k1,
    recover_address,
    serialize,
)

# --- Proof.test.ts -----------------------------------------------------------


class TestPublicProof:
    def test_proof_source_constructs_did_pkh(self) -> None:
        assert (
            proof.proof_source(address="0xAbCdEf1234567890AbCdEf1234567890AbCdEf12", chain_id=42431)
            == "did:pkh:eip155:42431:0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"
        )

    def test_parse_proof_source_parses_valid_source(self) -> None:
        assert proof.parse_proof_source(
            "did:pkh:eip155:42431:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141"
        ) == PkhSource(address="0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141", chain_id=42431)

    def test_parse_pkh_source_parses_valid_source(self) -> None:
        assert proof.parse_pkh_source(
            "did:pkh:eip155:42431:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141"
        ) == PkhSource(address="0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141", chain_id=42431)

    def test_parse_proof_source_rejects_invalid_source(self) -> None:
        assert (
            proof.parse_proof_source("did:pkh:eip155:01:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141")
            is None
        )


# --- Proof.conformance.test.ts -----------------------------------------------

ACCOUNT = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
CHAIN_ID = 42431
CHALLENGE_ID = "kM9xPqWvT2nJrHsY4aDfEb"
DIGEST = "0x3860a700a55e02ad3c2dc047e92489feceecbdb0a801d948e1d9f0b61ea9bc3f"
PRIVATE_KEY = "0x" + "01" * 32
REALM = "api.example.com"
SIGNATURE = (
    "0x53f5d64d9f995e841b4212639b2e17e508e96752e10316df3814a16443dcbdb6"
    "26c082190a4c3ecc3148101eb443d15bd83b579380b1be735a9c99f0df36c9fe1b"
)
PARAMS = {"account": ACCOUNT, "chain_id": CHAIN_ID, "challenge_id": CHALLENGE_ID, "realm": REALM}


def _recover(typed_data: dict[str, object], signature: str) -> str:
    return recover_address(hash_typed_data(typed_data), parse_secp256k1(signature))


class TestConformance:
    def test_typed_data_is_canonical_v3_contract(self) -> None:
        assert proof.typed_data(**PARAMS) == {
            "domain": {"name": "MPP", "version": "3", "chainId": CHAIN_ID},
            "types": {
                "Proof": [
                    {"name": "account", "type": "address"},
                    {"name": "challengeId", "type": "string"},
                    {"name": "realm", "type": "string"},
                ]
            },
            "primaryType": "Proof",
            "message": {"account": ACCOUNT, "challengeId": CHALLENGE_ID, "realm": REALM},
        }

    def test_hash_matches_digest_vector(self) -> None:
        assert proof.hash(**PARAMS) == DIGEST

    def test_wallet_produces_signature_vector(self) -> None:
        account = secp256k1_account(PRIVATE_KEY)
        assert account.address == ACCOUNT
        assert account.sign_typed_data(proof.typed_data(**PARAMS)) == SIGNATURE

    def test_signature_vector_recovers_to_bound_wallet(self) -> None:
        assert _recover(proof.typed_data(**PARAMS), SIGNATURE) == ACCOUNT

    def test_different_account_changes_digest(self) -> None:
        other = "0x000000000000000000000000000000000000dEaD"
        assert proof.hash(**{**PARAMS, "account": other}) != DIGEST

    def test_proof_cannot_be_replayed_against_different_wallet(self) -> None:
        signature = secp256k1_account(PRIVATE_KEY).sign_typed_data(proof.typed_data(**PARAMS))
        swapped = "0x000000000000000000000000000000000000dEaD"
        recovered = _recover(proof.typed_data(**{**PARAMS, "account": swapped}), signature)
        assert recovered != swapped
        assert recovered != ACCOUNT

    def test_access_key_delegation_swapping_source_breaks_recovery(self) -> None:
        access_key = secp256k1_account("0x" + "02" * 32)
        root_a = ACCOUNT
        signature = access_key.sign_typed_data(proof.typed_data(**{**PARAMS, "account": root_a}))
        assert access_key.address != root_a

        recovered_for_a = _recover(proof.typed_data(**{**PARAMS, "account": root_a}), signature)
        assert recovered_for_a == access_key.address

        root_b = "0x000000000000000000000000000000000000bEEF"
        recovered_for_b = _recover(proof.typed_data(**{**PARAMS, "account": root_b}), signature)
        assert recovered_for_b != access_key.address

    def test_legacy_v2_proof_does_not_verify_under_v3(self) -> None:
        account = secp256k1_account(PRIVATE_KEY)
        legacy = legacy_v2_typed_data(chain_id=CHAIN_ID, challenge_id=CHALLENGE_ID, realm=REALM)
        assert legacy == {
            "domain": {"name": "MPP", "version": "2", "chainId": CHAIN_ID},
            "types": {
                "Proof": [
                    {"name": "challengeId", "type": "string"},
                    {"name": "realm", "type": "string"},
                ]
            },
            "primaryType": "Proof",
            "message": {"challengeId": CHALLENGE_ID, "realm": REALM},
        }
        legacy_signature = account.sign_typed_data(legacy)
        assert _recover(proof.typed_data(**PARAMS), legacy_signature) != account.address


# --- internal/proof.test.ts --------------------------------------------------

PARSE_PKH_SOURCE_CASES = [
    pytest.param(
        "did:pkh:eip155:42431:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141",
        PkhSource(address="0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141", chain_id=42431),
        id="parses a valid did:pkh:eip155 source",
    ),
    pytest.param("did:pkh:eip155:not-a-number:0x1234", None, id="rejects non-numeric chain ids"),
    pytest.param(
        "did:pkh:eip155:01:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141",
        None,
        id="rejects leading-zero chain ids",
    ),
    pytest.param(
        "did:pkh:eip155:9007199254740992:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141",
        None,
        id="rejects unsafe integer chain ids",
    ),
    pytest.param("did:pkh:eip155:42431:not-an-address", None, id="rejects invalid addresses"),
    pytest.param(
        "did:pkh:eip155:42431:0xAbCdEf1234567890AbCdEf1234567890AbCdEf12:extra",
        None,
        id="rejects extra path segments",
    ),
    pytest.param(
        "did:pkh:solana:42431:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141",
        None,
        id="rejects unsupported namespaces",
    ),
]


class TestInternalProof:
    def test_types_has_account_challenge_id_realm(self) -> None:
        types = {name: [dict(f) for f in fields] for name, fields in internal_proof.TYPES.items()}
        assert types == {
            "Proof": [
                {"name": "account", "type": "address"},
                {"name": "challengeId", "type": "string"},
                {"name": "realm", "type": "string"},
            ]
        }
        assert internal_proof.PRIMARY_TYPE == "Proof"

    def test_domain(self) -> None:
        assert internal_proof.domain(42431) == {"name": "MPP", "version": "3", "chainId": 42431}

    def test_domain_uses_provided_chain_id(self) -> None:
        assert internal_proof.domain(1)["chainId"] == 1
        assert internal_proof.domain(99999)["chainId"] == 99999

    def test_message_wraps_fields(self) -> None:
        assert internal_proof.message(
            account="0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
            challenge_id="abc123",
            realm="api.example.com",
        ) == {
            "account": "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
            "challengeId": "abc123",
            "realm": "api.example.com",
        }

    def test_proof_source_constructs_did_pkh(self) -> None:
        assert (
            internal_proof.proof_source(address="0x1234567890abcdef", chain_id=42431)
            == "did:pkh:eip155:42431:0x1234567890abcdef"
        )

    def test_proof_source_preserves_address_casing(self) -> None:
        address = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"
        assert internal_proof.proof_source(address=address, chain_id=1) == (
            f"did:pkh:eip155:1:{address}"
        )

    @pytest.mark.parametrize(("source", "expected"), PARSE_PKH_SOURCE_CASES)
    def test_parse_pkh_source(self, source: str, expected: PkhSource | None) -> None:
        assert internal_proof.parse_pkh_source(source) == expected


# --- recoverAuthorizedProofSigner (server/Charge.ts) -------------------------

ACCESS_KEY_PK = "0x" + "02" * 32
ACCESS_KEY_ADDRESS = secp256k1_account(ACCESS_KEY_PK).address
PROOF_ARGS = {"chain_id": CHAIN_ID, "challenge_id": CHALLENGE_ID, "realm": REALM}


class TestRecoverAuthorizedProofSigner:
    def test_root_signature_recovers_root(self) -> None:
        signature = secp256k1_account(PRIVATE_KEY).sign_typed_data(proof.typed_data(**PARAMS))
        assert (
            recover_authorized_proof_signer(
                **PROOF_ARGS, signature=signature, source_address=ACCOUNT
            )
            == ACCOUNT
        )

    @pytest.mark.parametrize("version", ["v1", "v2"])
    def test_keychain_recovers_access_key(self, version: str) -> None:
        access = secp256k1_account(ACCESS_KEY_PK, access=ACCOUNT, keychain_version=version)  # type: ignore[arg-type]
        signature = access.sign_typed_data(proof.typed_data(**PARAMS))
        envelope = deserialize(signature)
        assert isinstance(envelope, KeychainSignature | KeychainEnvelope)
        assert keychain_parts(envelope)[2] == version
        assert (
            recover_authorized_proof_signer(
                **PROOF_ARGS, signature=signature, source_address=ACCOUNT
            )
            == ACCESS_KEY_ADDRESS
        )

    @pytest.mark.parametrize("version", ["v1", "v2"])
    def test_keychain_rejects_mismatched_user_address(self, version: str) -> None:
        other = "0x000000000000000000000000000000000000bEEF"
        access = secp256k1_account(ACCESS_KEY_PK, access=ACCOUNT, keychain_version=version)  # type: ignore[arg-type]
        signature = access.sign_typed_data(proof.typed_data(**{**PARAMS, "account": other}))
        assert (
            recover_authorized_proof_signer(**PROOF_ARGS, signature=signature, source_address=other)
            is None
        )

    def test_keychain_user_address_compared_case_insensitively(self) -> None:
        access = secp256k1_account(ACCESS_KEY_PK, access=ACCOUNT)
        signature = access.sign_typed_data(proof.typed_data(**{**PARAMS, "account": ACCOUNT}))
        assert (
            recover_authorized_proof_signer(
                **PROOF_ARGS, signature=signature, source_address=ACCOUNT.lower()
            )
            is not None
        )

    def test_keychain_swapped_source_recovers_different_signer(self) -> None:
        access = secp256k1_account(ACCESS_KEY_PK, access=ACCOUNT)
        signature = access.sign_typed_data(proof.typed_data(**PARAMS))
        # Re-wrap the same inner signature for root B: the rebuilt message
        # (account = B) recovers some other key, never the authorized one.
        root_b = "0x000000000000000000000000000000000000bEEF"
        envelope = deserialize(signature)
        assert isinstance(envelope, KeychainSignature)
        forged = serialize(keychain_signature(user_address=root_b, inner=envelope.inner))
        recovered = recover_authorized_proof_signer(
            **PROOF_ARGS, signature=forged, source_address=root_b
        )
        assert recovered != ACCESS_KEY_ADDRESS

    @pytest.mark.parametrize("signature", ["0x", "0xdeadbeef", "0x" + "ff" * 65, "not-hex"])
    def test_malformed_signature_returns_none(self, signature: str) -> None:
        assert (
            recover_authorized_proof_signer(
                **PROOF_ARGS, signature=signature, source_address=ACCOUNT
            )
            is None
        )
