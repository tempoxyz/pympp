"""x402 ``exact`` EIP-3009 payment signing for clients.

Mirrors mppx's ``src/x402/client/Exact.ts``: checks an x402 challenge against
the client's policy, then signs a ``transferWithAuthorization`` and encodes the
x402 v2 payment payload for ``PAYMENT-SIGNATURE``.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

from eth_utils.address import to_checksum_address

from mpp import Challenge
from mpp._typing import is_mapping
from mpp.methods.evm._eip3009 import authorization_domain, sign_authorization
from mpp.x402._client import payment_requirements
from mpp.x402._header import encode_payment_signature
from mpp.x402._server import ROUTE_BINDING_EXTENSION, route_nonce
from mpp.x402._types import EIP3009, X402_VERSION, PaymentRequirements, X402FormatError

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_UINT256_MAX = 2**256 - 1
VALID_AFTER_SKEW_SECONDS = 600
"""How far back ``validAfter`` is set, tolerating clock skew (mppx: 600 seconds)."""


def _chain_id(network: str) -> int:
    return int(network.split(":", 1)[1])


def check_exact(
    challenge: Challenge,
    *,
    chain_id: int,
    currency: str,
    max_amount: int | None,
) -> PaymentRequirements:
    """Return the challenge's requirements if this client may sign them.

    Applies mppx's ``assertPolicy`` with the client's single chain and currency
    as the allowlists, then its ``canHandleChallenge`` checks.

    Raises:
        ValueError: The challenge is malformed or outside the client's policy.
    """
    try:
        accepted = payment_requirements(challenge)
    except X402FormatError as error:
        raise ValueError(f"x402 exact requirements are malformed: {error}") from error
    network_chain_id = _chain_id(accepted["network"])
    if network_chain_id != chain_id:
        raise ValueError(f"x402 exact chain ID is not allowed: {network_chain_id}")
    asset = accepted["asset"]
    if not _ADDRESS_RE.fullmatch(asset) or asset.lower() != currency.lower():
        raise ValueError(f"x402 exact currency is not allowed: {asset}")
    amount = int(accepted["amount"])
    if amount > _UINT256_MAX:
        raise ValueError("x402 exact amount exceeds uint256")
    if max_amount is not None and amount > max_amount:
        raise ValueError("x402 exact amount exceeds max_amount")
    if not _ADDRESS_RE.fullmatch(accepted["payTo"]):
        raise ValueError("x402 exact payTo must be an address")
    resource = challenge.request.get("resource")
    if not is_mapping(resource) or not resource.get("url"):
        raise ValueError("x402 exact EIP-3009 requires resource information")
    extra: dict[str, Any] = dict(accepted.get("extra") or {})
    transfer_method = extra.get("assetTransferMethod", EIP3009)
    if transfer_method != EIP3009:
        raise ValueError(f"x402 exact {transfer_method} signing is not implemented")
    if not isinstance(extra.get("name"), str) or not isinstance(extra.get("version"), str):
        raise ValueError("x402 exact EIP-3009 requires token name and version")
    return accepted


def _with_nonce_salt(extensions: dict[str, Any]) -> dict[str, Any]:
    binding = extensions[ROUTE_BINDING_EXTENSION]
    return {
        **extensions,
        ROUTE_BINDING_EXTENSION: {
            **binding,
            "info": {**binding["info"], "nonce": os.urandom(32).hex()},
        },
    }


def create_payment_signature(
    challenge: Challenge,
    *,
    account: Any,
    chain_id: int,
    currency: str,
    max_amount: int | None,
) -> str:
    """Sign an x402 challenge and return its ``PAYMENT-SIGNATURE`` header value.

    The authorization is valid from 600 seconds ago until ``maxTimeoutSeconds``
    from now. Its nonce is random, or, when the server sent mppx's
    ``extensions.mppx`` route binding, the route-bound nonce over the salted
    extensions, as mppx's client signs.
    """
    accepted = check_exact(challenge, chain_id=chain_id, currency=currency, max_amount=max_amount)
    resource = challenge.request["resource"]
    extensions = challenge.request.get("extensions")
    if is_mapping(extensions) and is_mapping(extensions.get(ROUTE_BINDING_EXTENSION)):
        extensions = _with_nonce_salt(dict(extensions))
        nonce = route_nonce(accepted=accepted, resource=resource, extensions=extensions)
    else:
        nonce = "0x" + os.urandom(32).hex()
    extra: dict[str, Any] = dict(accepted.get("extra") or {})
    now = int(time.time())
    authorization = {
        "from": to_checksum_address(account.address),
        "to": to_checksum_address(accepted["payTo"]),
        "value": accepted["amount"],
        "validAfter": str(now - VALID_AFTER_SKEW_SECONDS),
        "validBefore": str(now + int(accepted["maxTimeoutSeconds"])),
        "nonce": nonce,
    }
    signature = sign_authorization(
        account,
        domain=authorization_domain(
            name=extra["name"],
            version=extra["version"],
            chain_id=chain_id,
            currency=accepted["asset"],
        ),
        payload=authorization,
    )
    payment: dict[str, Any] = {
        "x402Version": X402_VERSION,
        "accepted": accepted,
        "payload": {"authorization": authorization, "signature": signature},
        "resource": resource,
    }
    if extensions is not None:
        payment["extensions"] = extensions
    return encode_payment_signature(payment)  # type: ignore[arg-type]
