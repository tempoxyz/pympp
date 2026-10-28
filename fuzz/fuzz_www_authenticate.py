"""Fuzz parse_www_authenticate: only ParseError may escape.

Each input is tried as a raw header and as the base64url ``request`` of an
otherwise valid challenge, so mutations also reach the JSON layer.
"""

from __future__ import annotations

import atheris
from _harness import HEADER_JSON_BUGS, b64url, fuzz

with atheris.instrument_imports(include=["mpp"]):
    from mpp._parsing import ParseError, parse_www_authenticate


def test_one_input(data: bytes) -> None:
    try:
        parse_www_authenticate(data.decode("latin-1"))
    except ParseError:
        pass
    parse_www_authenticate(
        f'Payment id="x", realm="r", method="tempo", intent="charge", request="{b64url(data)}"'
    )


if __name__ == "__main__":
    fuzz(test_one_input, allowed=(ParseError,), known_bugs=HEADER_JSON_BUGS)
