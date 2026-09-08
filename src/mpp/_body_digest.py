"""Body digest computation and verification.

Computes SHA-256 digests of request bodies for binding challenges to
specific HTTP request content.
"""

import base64
import hashlib
import hmac
import json
from typing import Any


def compute(body: str | bytes | dict[str, Any]) -> str:
    """Compute a SHA-256 digest of a request body.

    Args:
        body: The request body as a string, bytes, or dict (JSON-serialized).

    Returns:
        Digest in the format ``sha-256=<base64>``.
    """
    if isinstance(body, dict):
        body = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    if isinstance(body, str):
        body = body.encode("utf-8")
    digest = hashlib.sha256(body).digest()
    encoded = base64.b64encode(digest).decode("ascii")
    return f"sha-256={encoded}"


def _unwrap(digest: str) -> tuple[str, str] | None:
    """Split a digest into its algorithm and base64 value.

    Accepts both the bare ``sha-256=<base64>`` form this module emits and the
    RFC 9530 Byte Sequence form ``sha-256=:<base64>:`` used by the MPP spec,
    so a digest produced by a spec-conformant peer still verifies here.

    Returns None if the string is not a digest at all.
    """
    algorithm, separator, value = digest.partition("=")
    if not separator:
        return None
    if len(value) >= 2 and value.startswith(":") and value.endswith(":"):
        value = value[1:-1]
    return algorithm.lower(), value


def verify(digest: str, body: str | bytes | dict[str, Any]) -> bool:
    """Verify a body digest matches the expected value.

    Args:
        digest: The digest string to verify. Both ``sha-256=<base64>`` and the
            RFC 9530 form ``sha-256=:<base64>:`` are accepted.
        body: The request body to check against.

    Returns:
        True if the digest matches, False otherwise.
    """
    received = _unwrap(digest)
    if received is None:
        return False

    algorithm, value = received
    if algorithm != "sha-256":
        return False

    expected = compute(body).removeprefix("sha-256=")
    return hmac.compare_digest(expected, value)
