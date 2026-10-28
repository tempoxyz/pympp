"""Body digest computation and verification.

Computes SHA-256 digests of request bodies for binding challenges to
specific HTTP request content.
"""

import base64
import hashlib
import hmac
import json
import re
from typing import Any

_MAX_ARRAY_INDEX = 2**32 - 2
_SURROGATE = re.compile("[\ud800-\udfff]")


def _is_array_index(key: str) -> bool:
    """Return True for keys JavaScript treats as array indices (``"0"``..``"4294967294"``)."""
    if not key or not key.isascii() or not key.isdigit():
        return False
    if len(key) > 1 and key[0] == "0":
        return False
    # Check length before int() so huge digit strings never hit Python's
    # int-conversion limit; 2**32 - 2 has 10 digits.
    if len(key) > len(str(_MAX_ARRAY_INDEX)):
        return False
    return int(key) <= _MAX_ARRAY_INDEX


def _js_key(key: Any) -> Any:
    if isinstance(key, str):
        return key
    if isinstance(key, bool):
        return "true" if key else "false"
    if isinstance(key, int):
        return str(key)
    return None


def _js_order(value: Any) -> Any:
    """Reorder dict keys the way JavaScript enumerates object properties.

    ``JSON.stringify`` emits integer-index keys first in ascending numeric
    order, then the remaining string keys in insertion order.
    """
    if isinstance(value, dict):
        index_items: list[tuple[int, Any, Any]] = []
        other_items: list[tuple[Any, Any]] = []
        for key, item in value.items():
            js_key = _js_key(key)
            if isinstance(js_key, str) and _is_array_index(js_key):
                index_items.append((int(js_key), key, _js_order(item)))
            else:
                other_items.append((key, _js_order(item)))
        index_items.sort(key=lambda entry: entry[0])
        return {key: item for _, key, item in index_items} | dict(other_items)
    if isinstance(value, (list, tuple)):
        return [_js_order(item) for item in value]
    return value


def _join_surrogate_pairs(text: str) -> str:
    """Combine adjacent surrogate code points into the character they encode."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _json(value: Any, *, sort_keys: bool = False) -> str:
    """Compact JSON like ``JSON.stringify``, which escapes lone surrogates as ``\\udXXX``."""
    text = json.dumps(value, separators=(",", ":"), sort_keys=sort_keys, ensure_ascii=False)
    if _SURROGATE.search(text) is None:
        return text
    return _SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", _join_surrogate_pairs(text))


def _utf8(text: str) -> bytes:
    """Encode like ``TextEncoder``: lone surrogates become U+FFFD."""
    if _SURROGATE.search(text) is None:
        return text.encode("utf-8")
    return _SURROGATE.sub("\ufffd", _join_surrogate_pairs(text)).encode("utf-8")


def _serialize(body: str | bytes | dict[str, Any]) -> bytes:
    if isinstance(body, dict):
        body = _json(_js_order(body))
    if isinstance(body, str):
        body = _utf8(body)
    return body


def _encode(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.b64encode(digest).decode("ascii")
    return f"sha-256={encoded}"


def compute(body: str | bytes | dict[str, Any]) -> str:
    """Compute a SHA-256 digest of a request body.

    Dict bodies are serialized like mppx's ``JSON.stringify``: compact,
    integer-index keys first in ascending order, then other keys in
    insertion order.

    Args:
        body: The request body as a string, bytes, or dict (JSON-serialized).

    Returns:
        Digest in the format ``sha-256=<base64>``.
    """
    return _encode(_serialize(body))


def _compute_legacy(body: dict[str, Any]) -> str:
    """Digest of a dict body as earlier pympp releases computed it (sorted keys)."""
    return _encode(_json(body, sort_keys=True).encode("utf-8"))


def verify(digest: str, body: str | bytes | dict[str, Any]) -> bool:
    """Verify a body digest matches the expected value.

    For dict bodies, the sorted-key digest issued by earlier pympp releases is
    also accepted, so challenges issued before an upgrade (or by an older
    replica) still verify. New digests are always issued in the mppx form.

    Args:
        digest: The digest string to verify (format: ``sha-256=<base64>``).
        body: The request body to check against.

    Returns:
        True if the digest matches, False otherwise.
    """
    # The digest may come from an unauthenticated credential; hmac.compare_digest
    # raises TypeError for non-ASCII str inputs, so reject those outright.
    if not isinstance(digest, str) or not digest.isascii():
        return False
    if hmac.compare_digest(compute(body), digest):
        return True
    if isinstance(body, dict):
        return hmac.compare_digest(_compute_legacy(body), digest)
    return False
