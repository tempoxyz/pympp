"""Base64url helpers shared by the wire codecs.

Encoding always emits the URL-safe alphabet without padding. Decoding accepts both the
URL-safe and the standard alphabet, with or without padding (mppx/ox are lenient the same
way), but rejects characters outside those alphabets.
"""

import base64
import binascii
import re

_VALID = re.compile(r"^[A-Za-z0-9+/_-]*={0,2}\Z")


def encode(data: bytes | str) -> str:
    """Encodes bytes (or UTF-8 text) as unpadded base64url."""
    raw = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(value: str) -> bytes:
    """Decodes base64url (or standard base64) text, padded or not.

    Raises:
        ValueError: If the value contains characters outside the base64 alphabets.
    """
    if not _VALID.match(value):
        raise ValueError("Invalid base64url character.")
    stripped = value.rstrip("=").replace("+", "-").replace("/", "_")
    if len(stripped) % 4 == 1:
        raise ValueError("Invalid base64url length.")
    try:
        return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))
    except binascii.Error as error:
        raise ValueError("Invalid base64url.") from error


def decode_text(value: str) -> str:
    """Decodes base64url text into a UTF-8 string (strict UTF-8)."""
    return decode(value).decode("utf-8")


def encode_standard(data: bytes) -> str:
    """Encodes bytes as padded standard base64 (used by body digests)."""
    return base64.b64encode(data).decode("ascii")
