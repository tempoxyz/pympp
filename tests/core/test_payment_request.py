import pytest
from pydantic import ValidationError

from mpp import _json, payment_request

from ._fixtures import charge_method

REQUEST = {
    "amount": "1",
    "currency": "0x20c0000000000000000000000000000000000001",
    "decimals": 6,
    "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
}


def test_from_method() -> None:
    assert payment_request.from_method(charge_method, REQUEST) == {
        "amount": "1000000",
        "currency": "0x20c0000000000000000000000000000000000001",
        "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
    }
    assert payment_request.from_method(charge_method, {**REQUEST, "chainId": 42431})[
        "methodDetails"
    ] == {"chainId": 42431}


def test_invalid_request() -> None:
    with pytest.raises(ValidationError):
        payment_request.from_method(charge_method, {"amount": 123})


def test_serialize_roundtrip() -> None:
    request = {
        "amount": "1000000",
        "currency": "0x1",
        "recipient": "0x2",
        "nested": {"b": 2, "a": [1, {"y": 1, "x": 2}]},
    }
    encoded = payment_request.serialize(request)
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded
    assert payment_request.deserialize(encoded) == request
    assert payment_request.serialize({"b": 1, "a": 2}) == payment_request.serialize(
        {"a": 2, "b": 1}
    )


def test_special_characters() -> None:
    request = {"description": 'Test "quoted" & <special> chars 日本'}
    assert payment_request.deserialize(payment_request.serialize(request)) == request


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, "1"),
        (0.5, "0.5"),
        (-0.0, "0"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (123.456, "123.456"),
        (1.5e300, "1.5e+300"),
    ],
)
def test_js_number_formatting(value: float, expected: str) -> None:
    assert _json.format_number(value) == expected


def test_canonicalize_sorts_by_utf16_code_units() -> None:
    assert _json.canonicalize({"\U0001f600": 1, "￿": 2, "a": None, "B": True}) == (
        '{"B":true,"a":null,"\U0001f600":1,"￿":2}'
    )
