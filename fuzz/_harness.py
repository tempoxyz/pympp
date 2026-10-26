"""Shared atheris harness for the fuzz targets in this directory.

Each target calls :func:`fuzz` with a one-input function. An exception that
escapes it, other than the ones the target documents as allowed, is a crash:
libFuzzer stops and writes the input under ``-artifact_prefix``.

Known bugs that already have a failing (xfail) test are tolerated so a nightly
run keeps exploring past them; set ``FUZZ_STRICT=1`` to treat them as crashes.
"""

from __future__ import annotations

import base64
import os
import sys
from collections.abc import Callable

import atheris

# Deeply nested JSON (about 10k levels) inside the 64 KiB Authorization limit
# raises RecursionError from json.loads instead of ParseError. Tracked by the
# xfail tests test_deeply_nested_credential_json (test_parsing_properties.py)
# and test_deeply_nested_credential_reports_failure (test_engine_events.py);
# drop it from here once they pass.
KNOWN_BUGS: tuple[type[BaseException], ...] = (RecursionError,)


def b64url(data: bytes) -> str:
    """Encode ``data`` as unpadded base64url, the wire form of header payloads."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def fuzz(
    test_one_input: Callable[[bytes], None],
    allowed: tuple[type[BaseException], ...],
) -> None:
    """Run libFuzzer on ``test_one_input``, allowing only ``allowed`` to escape."""
    tolerated = allowed if os.environ.get("FUZZ_STRICT") == "1" else allowed + KNOWN_BUGS

    def guarded(data: bytes) -> None:
        try:
            test_one_input(data)
        except tolerated:
            pass

    atheris.Setup(sys.argv, guarded)
    atheris.Fuzz()
