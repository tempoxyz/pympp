"""Typed entry points into the ``rlp`` package, which ships no type information."""

from __future__ import annotations

from typing import Any, cast

import rlp  # pyright: ignore[reportMissingTypeStubs]

DecodingError = rlp.DecodingError
RLPException = rlp.exceptions.RLPException  # pyright: ignore[reportUnknownMemberType]


def decode(data: bytes) -> Any:
    """Decode RLP ``data`` into nested lists of ``bytes``."""
    return rlp.decode(data)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]


def encode(obj: Any) -> bytes:
    """RLP-encode ``obj``."""
    # rlp's inferred return type includes its cache's Atomic; encode returns bytes.
    return cast(bytes, rlp.encode(obj))  # pyright: ignore[reportUnknownMemberType]
