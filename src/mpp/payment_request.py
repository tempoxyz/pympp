"""Payment request (``request`` auth-param) encoding: base64url of RFC 8785 canonical JSON."""

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from mpp import _base64url, _json

__all__ = [
    "deserialize",
    "from_method",
    "serialize",
]


if TYPE_CHECKING:
    from mpp.method import Method


def serialize(request: Mapping[str, Any]) -> str:
    """Serializes a request to an unpadded base64url string of its canonical JSON."""
    return _base64url.encode(_json.canonicalize(request))


def deserialize(encoded: str) -> Any:
    """Deserializes a base64url string to a JSON value (normally a request object).

    Raises:
        ValueError: On invalid base64url, UTF-8 or JSON.
    """
    return _json.loads(_base64url.decode_text(encoded))


def from_method(method: "Method", request: Mapping[str, Any]) -> dict[str, Any]:
    """Validates ``request`` against ``method``'s request model and returns its wire form."""
    return method.normalize_request(request)
