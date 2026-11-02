"""Malformed authentication parameters must not be skipped during parsing."""

import pytest

from mpp._parsing import MAX_AUTHORIZATION_SIZE, ParseError, _parse_auth_params


@pytest.mark.parametrize(
    "value", ["garbage id=ok", "a=ok junk", "a=ok,", 'a="unterminated', "a=ok,,b=yes"]
)
def test_reject_malformed_parameters(value: str) -> None:
    with pytest.raises(ParseError):
        _parse_auth_params(value)


@pytest.mark.parametrize("size", [1024, 8192, MAX_AUTHORIZATION_SIZE])
def test_reject_long_missing_separator(size: int) -> None:
    with pytest.raises(ParseError):
        _parse_auth_params("a" * size)


def test_reject_oversized_parameters() -> None:
    with pytest.raises(ParseError, match="maximum size"):
        _parse_auth_params('a="' + "x" * MAX_AUTHORIZATION_SIZE + '"')


@pytest.mark.parametrize(
    "value, expected",
    [
        ('a="comma, quote\\"", b=token', {"a": 'comma, quote"', "b": "token"}),
        (" a = token \t, B=other \t", {"a": "token", "b": "other"}),
        ("", {}),
    ],
)
def test_valid_parameters(value: str, expected: dict[str, str]) -> None:
    assert _parse_auth_params(value) == expected
