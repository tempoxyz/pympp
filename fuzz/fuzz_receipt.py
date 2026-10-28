"""Fuzz parse_payment_receipt: only ParseError may escape.

Each input is tried as a raw header and as the receipt JSON it encodes.
"""

from __future__ import annotations

import atheris
from _harness import HEADER_JSON_BUGS, b64url, fuzz

with atheris.instrument_imports(include=["mpp"]):
    from mpp._parsing import ParseError, parse_payment_receipt


def test_one_input(data: bytes) -> None:
    try:
        parse_payment_receipt(data.decode("latin-1"))
    except ParseError:
        pass
    parse_payment_receipt(b64url(data))


if __name__ == "__main__":
    fuzz(test_one_input, allowed=(ParseError,), known_bugs=HEADER_JSON_BUGS)
