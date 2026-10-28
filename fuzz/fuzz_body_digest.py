"""Fuzz request body digests: compute and verify never raise, and round-trip.

Inputs are tried as bytes, as a str body and, when they parse, as a JSON
object body, the three body types the digest accepts.
"""

from __future__ import annotations

import json

import atheris
from _harness import fuzz

with atheris.instrument_imports(include=["mpp"]):
    from mpp import _body_digest


def check(body: str | bytes | dict) -> None:
    digest = _body_digest.compute(body)
    assert _body_digest.verify(digest, body)
    assert not _body_digest.verify(digest + "x", body)


def test_one_input(data: bytes) -> None:
    check(data)
    text = data.decode("utf-8", "replace")
    _body_digest.verify(text, data)
    check(text)
    try:
        body = json.loads(data)
    except ValueError:
        return
    if isinstance(body, dict):
        check(body)


if __name__ == "__main__":
    fuzz(test_one_input, allowed=())
