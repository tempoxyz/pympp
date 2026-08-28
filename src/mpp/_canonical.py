"""RFC 8785 canonical JSON helpers for challenge-bound values."""

from __future__ import annotations

import base64
from typing import Any

import rfc8785


def canonical_b64url(data: Any) -> str:
    """Encode data as JCS JSON in unpadded base64url form."""
    canonical = rfc8785.dumps(data)
    return base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=")
