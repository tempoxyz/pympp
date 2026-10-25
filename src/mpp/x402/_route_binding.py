"""Route binding for x402 exact payments: binds the route into the EIP-3009 nonce."""

import hashlib
from collections.abc import Mapping
from typing import Any

from mpp import payment_request
from mpp.x402._types import Extension, PaymentRequirements, ResourceInfo


def nonce(
    *,
    accepted: PaymentRequirements,
    extensions: Mapping[str, Extension],
    resource: ResourceInfo,
) -> str:
    """Computes the route-bound EIP-3009 nonce for an x402 exact payment.

    ``sha256(serialize(accepted) | serialize(resource) | serialize(extensions))`` where
    ``serialize`` is the base64url JCS payment-request encoding.
    """
    parts = [
        payment_request.serialize(accepted.to_dict()),
        payment_request.serialize(resource.to_dict()),
        payment_request.serialize(_extensions_dict(extensions)),
    ]
    return "0x" + hashlib.sha256("|".join(parts).encode()).hexdigest()


def _extensions_dict(extensions: Mapping[str, Extension]) -> dict[str, Any]:
    return {key: value.to_dict() for key, value in extensions.items()}
