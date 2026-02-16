"""Body digest computation and verification.

Computes SHA-256 digests of request bodies for binding challenges to
specific HTTP request content.
"""

import base64
import hashlib
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
        body = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    if isinstance(body, str):
        body = body.encode("utf-8")
    digest = hashlib.sha256(body).digest()
    encoded = base64.b64encode(digest).decode("ascii")
    return f"sha-256={encoded}"


def verify(digest: str, body: str | bytes | dict[str, Any]) -> bool:
    """Verify a body digest matches the expected value.

    Args:
        digest: The digest string to verify (format: ``sha-256=<base64>``).
        body: The request body to check against.

    Returns:
        True if the digest matches, False otherwise.
    """
    return compute(body) == digest
