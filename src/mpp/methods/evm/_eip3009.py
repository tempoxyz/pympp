"""EIP-3009 typed data, signing and recovery (mppx ``src/evm/Types.ts``)."""

from __future__ import annotations

import json
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

AUTHORIZATION_TYPES: dict[str, list[dict[str, str]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}
"""EIP-712 types for ``transferWithAuthorization``."""


def authorization_domain(
    *, name: str, version: str, chain_id: int, currency: str
) -> dict[str, Any]:
    """Return the EIP-712 domain of a token's EIP-3009 authorizations."""
    return {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": to_checksum_address(currency),
    }


def authorization_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the typed-data message for an authorization payload."""
    return {
        "from": to_checksum_address(payload["from"]),
        "to": to_checksum_address(payload["to"]),
        "value": int(payload["value"]),
        "validAfter": int(payload["validAfter"]),
        "validBefore": int(payload["validBefore"]),
        "nonce": bytes.fromhex(payload["nonce"][2:]),
    }


def recover_authorizer(*, domain: dict[str, Any], payload: dict[str, Any], signature: str) -> str:
    """Recover the checksummed address that signed an authorization."""
    signable = encode_typed_data(
        domain_data=domain,
        message_types=AUTHORIZATION_TYPES,
        message_data=authorization_message(payload),
    )
    return to_checksum_address(Account.recover_message(signable, signature=signature))


def sign_authorization(account: Any, *, domain: dict[str, Any], payload: dict[str, Any]) -> str:
    """Sign an authorization with an eth-account ``LocalAccount``."""
    signed = account.sign_typed_data(
        domain_data=domain,
        message_types=AUTHORIZATION_TYPES,
        message_data=authorization_message(payload),
    )
    signature = signed.signature.hex()
    return signature if signature.startswith("0x") else f"0x{signature}"


def challenge_hash(challenge_id: str, realm: str) -> str:
    """Return the Payment-auth EVM challenge hash used as the EIP-3009 nonce.

    ``keccak256(JSON.stringify([id, realm]))``, matching mppx.
    """
    encoded = json.dumps([challenge_id, realm], separators=(",", ":"), ensure_ascii=False)
    return "0x" + keccak(text=encoded).hex()


def network_of(chain_id: int) -> str:
    """Return the CAIP-2 network identifier of an EVM chain."""
    return f"eip155:{chain_id}"


def to_source(*, address: str, chain_id: int) -> str:
    """Return the ``did:pkh`` source of an EVM payer."""
    return f"did:pkh:eip155:{chain_id}:{to_checksum_address(address)}"
