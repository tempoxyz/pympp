"""Tempo zero-amount proof credentials (mppx ``tempo/internal/proof.ts``).

A zero-amount ``tempo/charge`` challenge is paid with a proof: an EIP-712 ``Proof`` signature
binding the payer account to the challenge ID and realm, in the ``MPP`` version 3 domain. The
credential's ``source`` names the payer as a ``did:pkh:eip155:<chainId>:<address>`` DID. Session
bootstrap uses one to authenticate the payer before returning a channel snapshot.

Only primitive secp256k1 signatures are produced and accepted, as for session vouchers;
keychain (access-key) and smart-account proofs are not supported yet.
"""

from __future__ import annotations

import re
from typing import Any

from eth_abi.abi import encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session._voucher import (
    _recover_canonical,  # pyright: ignore[reportPrivateUsage]
    _sign_digest,  # pyright: ignore[reportPrivateUsage]
)

DOMAIN_NAME = "MPP"
DOMAIN_VERSION = "3"

_DOMAIN_TYPEHASH = keccak(b"EIP712Domain(string name,string version,uint256 chainId)")
_PROOF_TYPEHASH = keccak(b"Proof(address account,string challengeId,string realm)")
_PKH_SOURCE = re.compile(r"^did:pkh:eip155:(0|[1-9]\d*):(0x[0-9a-fA-F]{40})$")


def proof_digest(*, account: str, chain_id: int, challenge_id: str, realm: str) -> str:
    """The EIP-712 digest a proof signs (mppx ``Proof.hash``)."""
    domain = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256"],
            [
                _DOMAIN_TYPEHASH,
                keccak(DOMAIN_NAME.encode()),
                keccak(DOMAIN_VERSION.encode()),
                chain_id,
            ],
        )
    )
    struct = keccak(
        encode(
            ["bytes32", "address", "bytes32", "bytes32"],
            [_PROOF_TYPEHASH, account, keccak(challenge_id.encode()), keccak(realm.encode())],
        )
    )
    return "0x" + keccak(b"\x19\x01" + domain + struct).hex()


def sign_proof(account: Any, *, chain_id: int, challenge_id: str, realm: str) -> str:
    """Sign a proof bound to ``account.address``; returns the 65-byte signature as 0x-hex."""
    digest = proof_digest(
        account=account.address, chain_id=chain_id, challenge_id=challenge_id, realm=realm
    )
    return _sign_digest(account, digest)


def verify_proof(
    signature: str, *, account: str, chain_id: int, challenge_id: str, realm: str
) -> bool:
    """Whether ``signature`` is ``account``'s proof for the challenge."""
    try:
        digest = proof_digest(
            account=account, chain_id=chain_id, challenge_id=challenge_id, realm=realm
        )
    except Exception:
        return False
    signer = _recover_canonical(signature, digest)
    return signer is not None and signer.lower() == account.lower()


def proof_source(address: str, chain_id: int) -> str:
    """The ``did:pkh`` source DID of a proof credential."""
    return f"did:pkh:eip155:{chain_id}:{address}"


def parse_pkh_source(source: str) -> tuple[str, int] | None:
    """The ``(address, chain_id)`` of a ``did:pkh:eip155`` source, else None."""
    match = _PKH_SOURCE.match(source)
    if match is None:
        return None
    return match.group(2), int(match.group(1))
