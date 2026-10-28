"""Shared atheris harness for the fuzz targets in this directory.

Each target calls :func:`fuzz` with a one-input function. An exception that
escapes it, other than the ones the target documents as allowed, is a crash:
libFuzzer stops and writes the input under ``-artifact_prefix``.

A target may also pass ``known_bugs``, exceptions from a known bug in the
code it fuzzes, so a nightly run keeps exploring past them; set
``FUZZ_STRICT=1`` to treat them as crashes.
"""

from __future__ import annotations

import base64
import os
import sys
from collections.abc import Callable

import atheris


def b64url(data: bytes) -> str:
    """Encode ``data`` as unpadded base64url, the wire form of header payloads."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def fuzz(
    test_one_input: Callable[[bytes], None],
    allowed: tuple[type[BaseException], ...],
    known_bugs: tuple[type[BaseException], ...] = (),
) -> None:
    """Run libFuzzer on ``test_one_input``, allowing only ``allowed`` to escape.

    ``known_bugs`` are tolerated too, unless ``FUZZ_STRICT=1``.
    """
    tolerated = allowed if os.environ.get("FUZZ_STRICT") == "1" else allowed + known_bugs

    def guarded(data: bytes) -> None:
        try:
            test_one_input(data)
        except tolerated:
            pass

    atheris.Setup(sys.argv, guarded)
    atheris.Fuzz()
