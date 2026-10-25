"""Validation patterns match the whole value with ASCII digits, like JavaScript regexes."""

import pytest
from pydantic import TypeAdapter, ValidationError

from mpp import _base64url
from mpp.evm._types import Amount as EvmAmount
from mpp.stripe import ChargeRequest
from mpp.tempo._internal.address import is_address
from mpp.x402._types import AtomicAmount, EvmNetwork


def test_base64url_rejects_trailing_newline() -> None:
    with pytest.raises(ValueError, match="Invalid base64url character"):
        _base64url.decode("YWJj\n")


def test_address_rejects_trailing_newline() -> None:
    address = "0x" + "11" * 20
    assert is_address(address)
    assert not is_address(address + "\n")


@pytest.mark.parametrize("value", ["\u0661\u0660\u0660", "\uff11\uff10"])
def test_amount_types_reject_non_ascii_digits(value: str) -> None:
    for annotation in (EvmAmount, AtomicAmount):
        with pytest.raises(ValidationError):
            TypeAdapter(annotation).validate_python(value)
    stripe = {"currency": "usd", "decimals": 2, "networkId": "n", "paymentMethodTypes": ["card"]}
    ChargeRequest.model_validate({**stripe, "amount": "100"})
    with pytest.raises(ValidationError, match="amount"):
        ChargeRequest.model_validate({**stripe, "amount": value})


def test_network_rejects_non_ascii_digits() -> None:
    assert TypeAdapter(EvmNetwork).validate_python("eip155:8453") == "eip155:8453"
    with pytest.raises(ValidationError):
        TypeAdapter(EvmNetwork).validate_python("eip155:\u0668\u0664\u0665\u0663")
