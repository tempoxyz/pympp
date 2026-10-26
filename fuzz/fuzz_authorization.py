"""Fuzz parse_authorization: only ParseError may escape.

Each input is tried as a raw header and as the JSON credential of a
``Payment <base64url>`` header.
"""

from __future__ import annotations

import atheris
from _harness import b64url, fuzz

with atheris.instrument_imports(include=["mpp"]):
    from mpp._parsing import ParseError, parse_authorization


def test_one_input(data: bytes) -> None:
    try:
        parse_authorization(data.decode("latin-1"))
    except ParseError:
        pass
    parse_authorization(f"Payment {b64url(data)}")


if __name__ == "__main__":
    fuzz(test_one_input, allowed=(ParseError,))
