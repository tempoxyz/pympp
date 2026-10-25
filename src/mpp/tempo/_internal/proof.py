"""Zero-amount Tempo proof credentials (EIP-712 domain ``MPP`` version ``3``).

The ``account`` field binds the signature to the payer wallet, so a proof
signed for one account cannot be replayed against another - including across
an access key that is authorized for several accounts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from eth_account.messages import encode_typed_data

from mpp.tempo._internal.address import is_address, is_equal
from mpp.tempo._internal.hexutil import keccak256, to_bytes, to_hex
from mpp.tempo._internal.signature import (
    InvalidSignatureEnvelopeError,
    KeychainEnvelope,
    KeychainSignature,
    deserialize,
    extract_address,
    keychain_parts,
    keychain_sign_payload,
    verify,
)

PRIMARY_TYPE: Final = "Proof"
"""EIP-712 primary type for proof credentials."""

TYPES: Final = {
    "Proof": (
        {"name": "account", "type": "address"},
        {"name": "challengeId", "type": "string"},
        {"name": "realm", "type": "string"},
    )
}
"""EIP-712 type definitions for proof credentials."""

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_PKH_SOURCE_RE: Final = re.compile(r"did:pkh:eip155:(0|[1-9][0-9]*):([^:]+)")


def domain(chain_id: int) -> dict[str, Any]:
    """The EIP-712 domain for a proof credential."""
    return {"name": "MPP", "version": "3", "chainId": chain_id}


def message(*, account: str, challenge_id: str, realm: str) -> dict[str, str]:
    """The EIP-712 message for a proof credential."""
    return {"account": account, "challengeId": challenge_id, "realm": realm}


def typed_data(*, account: str, chain_id: int, challenge_id: str, realm: str) -> dict[str, Any]:
    """The complete EIP-712 payload: the canonical, wallet-bound proof contract."""
    return {
        "domain": domain(chain_id),
        "types": {name: [dict(field) for field in fields] for name, fields in TYPES.items()},
        "primaryType": PRIMARY_TYPE,
        "message": message(account=account, challenge_id=challenge_id, realm=realm),
    }


def hash_typed_data(data: dict[str, Any]) -> bytes:
    """EIP-712 signing digest of a typed-data payload."""
    signable = encode_typed_data(full_message=data)
    return keccak256(b"\x19" + signable.version + signable.header + signable.body)


def hash(*, account: str, chain_id: int, challenge_id: str, realm: str) -> str:
    """The EIP-712 digest (signing payload) for a proof credential."""
    data = typed_data(account=account, chain_id=chain_id, challenge_id=challenge_id, realm=realm)
    return to_hex(hash_typed_data(data))


def legacy_v2_typed_data(*, chain_id: int, challenge_id: str, realm: str) -> dict[str, Any]:
    """The pre-binding proof contract (domain ``MPP`` version ``2``, no ``account``).

    mppx rejects these proofs; this exists for the ``tempo-proof`` conformance
    vector (the historical v2 proof vector that mpp-tools keeps) and for tests
    asserting v2 proofs do not verify under the current contract.
    """
    return {
        "domain": {"name": "MPP", "version": "2", "chainId": chain_id},
        "types": {
            "Proof": [
                {"name": "challengeId", "type": "string"},
                {"name": "realm", "type": "string"},
            ]
        },
        "primaryType": PRIMARY_TYPE,
        "message": {"challengeId": challenge_id, "realm": realm},
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class PkhSource:
    address: str
    chain_id: int


def proof_source(*, address: str, chain_id: int) -> str:
    """The expected ``did:pkh`` source DID for a proof credential."""
    return f"did:pkh:eip155:{chain_id}:{address}"


def parse_pkh_source(source: str) -> PkhSource | None:
    """Parses a ``did:pkh:eip155:<chainId>:<address>`` DID."""
    match = _PKH_SOURCE_RE.fullmatch(source)
    if match is None:
        return None
    chain_id = int(match.group(1))
    address = match.group(2)
    if chain_id > _MAX_SAFE_INTEGER or not is_address(address):
        return None
    return PkhSource(address=address, chain_id=chain_id)


def recover_authorized_proof_signer(
    *, chain_id: int, challenge_id: str, realm: str, signature: str, source_address: str
) -> str | None:
    """Recovers the key that signed a proof for ``source_address``.

    Returns the access key address for keychain envelopes (which must be
    bound to ``source_address``) or the primitive signer otherwise, or ``None``
    when the envelope is malformed or does not verify. Callers must still
    check that a recovered access key is active for ``source_address``.
    """
    try:
        envelope = deserialize(signature)
        proof_hash = to_bytes(
            hash(account=source_address, chain_id=chain_id, challenge_id=challenge_id, realm=realm)
        )
        if isinstance(envelope, KeychainSignature | KeychainEnvelope):
            user_address, inner, version = keychain_parts(envelope)
            if not is_equal(user_address, source_address):
                return None
            payload = (
                keychain_sign_payload(proof_hash, source_address) if version == "v2" else proof_hash
            )
        else:
            payload, inner = proof_hash, envelope
        signer = extract_address(inner, payload)
        return signer if verify(inner, payload=payload, address=signer) else None
    except (InvalidSignatureEnvelopeError, ValueError):
        return None
