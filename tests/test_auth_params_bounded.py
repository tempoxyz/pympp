"""Authentication parsing stays bounded, including malformed optional suffixes."""

import pytest

from mpp._parsing import MAX_AUTHORIZATION_SIZE, ParseError, _parse_auth_params


@pytest.mark.parametrize(
    "value, expected",
    [("garbage id=ok", {}), ("a=ok junk", {"a": "ok"}), ('a="unterminated', {})],
)
def test_malformed_suffix_stops_parsing(value: str, expected: dict[str, str]) -> None:
    assert _parse_auth_params(value) == expected


@pytest.mark.parametrize("size", [1024, 8192, MAX_AUTHORIZATION_SIZE])
def test_long_missing_separator(size: int) -> None:
    assert _parse_auth_params("a" * size) == {}


def test_malformed_optional_extensions_keep_required_parameters() -> None:
    from mpp._parsing import parse_www_authenticate

    required = (
        'Payment id="bounded", realm="example.com", method="tempo", intent="charge", request="e30"'
    )
    for suffix in [', fuzz="' + "\\" * 24_000, ', description="Payment for "Premium" service"']:
        challenge = parse_www_authenticate(required + suffix)
        assert challenge.id == "bounded"
        assert challenge.request == {}


def test_reject_oversized_parameters() -> None:
    with pytest.raises(ParseError, match="maximum size"):
        _parse_auth_params('a="' + "x" * MAX_AUTHORIZATION_SIZE + '"')


@pytest.mark.parametrize(
    "value, expected",
    [
        ('a="comma, quote\\"", b=token', {"a": 'comma, quote"', "b": "token"}),
        (" a = token \t, B=other \t", {"a": "token", "b": "other"}),
        ("", {}),
        ("a=ok,,b=yes, ", {"a": "ok", "b": "yes"}),
        (
            "foo.bar=one, 1x=two, !#$%&'*+.^_`|~-=three",
            {"foo.bar": "one", "1x": "two", "!#$%&'*+.^_`|~-": "three"},
        ),
    ],
)
def test_valid_parameters(value: str, expected: dict[str, str]) -> None:
    assert _parse_auth_params(value) == expected


def test_raw_challenge_is_bounded_before_normalization() -> None:
    from mpp._parsing import parse_www_authenticate
    from mpp.client.transport import _payment_challenges

    header = " " * MAX_AUTHORIZATION_SIZE + 'Payment id="x"'
    with pytest.raises(ParseError, match="maximum size"):
        parse_www_authenticate(header)
    assert _payment_challenges(header) == []
