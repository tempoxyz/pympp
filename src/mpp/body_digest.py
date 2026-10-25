"""Request body digests (``sha-256=<base64>``) bound into challenges via ``digest``."""

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from mpp import _json
from mpp._base64url import encode_standard

__all__ = [
    "compute",
    "verify",
]


def compute(body: Mapping[str, Any] | str | bytes) -> str:
    """Computes a SHA-256 digest of ``body``.

    Mappings are serialized like ``JSON.stringify``; strings are UTF-8 encoded.

    Returns:
        A digest string in the format ``sha-256=<base64>``.
    """
    if isinstance(body, Mapping):
        raw = _json.dumps(body).encode()
    elif isinstance(body, str):
        raw = body.encode()
    else:
        raw = body
    return f"sha-256={encode_standard(hashlib.sha256(raw).digest())}"


def verify(digest: str, body: Mapping[str, Any] | str | bytes) -> bool:
    """Returns whether ``digest`` matches ``body`` (constant-time comparison)."""
    return hmac.compare_digest(compute(body).encode(), digest.encode())
