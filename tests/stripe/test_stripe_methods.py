from decimal import ROUND_HALF_UP, Decimal, localcontext

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from mpp.stripe import ChargePayload, ChargeRequest, charge
from mpp.stripe._internal.units import parse_units

BASE = {
    "amount": "1",
    "currency": "usd",
    "decimals": 2,
    "networkId": "profile_123",
    "paymentMethodTypes": ["card"],
}


def test_name_and_intent() -> None:
    assert charge.intent == "charge"
    assert charge.name == "stripe"


def test_validates_valid_request() -> None:
    wire = charge.normalize_request(
        {
            **BASE,
            "expires": "2025-02-05T12:05:00Z",
            "metadata": {"example": "metadata"},
            "paymentIntentOptions": {
                "customer": "cus_123",
                "hooks": {"inputs": {"tax": {"calculation": "taxcalc_123"}}},
                "metadata": {"order": "123"},
                "receipt_email": "customer@example.com",
            },
        }
    )
    assert wire == {
        "amount": "100",
        "currency": "usd",
        "methodDetails": {
            "metadata": {"example": "metadata"},
            "networkId": "profile_123",
            "paymentMethodTypes": ["card"],
        },
    }


def test_snake_case_input() -> None:
    wire = charge.normalize_request(
        {
            "amount": "0.5",
            "currency": "usd",
            "decimals": 2,
            "network_id": "profile_123",
            "payment_method_types": ["card"],
            "external_id": "order_1",
            "description": "Coffee",
            "recipient": "acct_1",
        }
    )
    assert wire == {
        "amount": "50",
        "currency": "usd",
        "description": "Coffee",
        "externalId": "order_1",
        "recipient": "acct_1",
        "methodDetails": {"networkId": "profile_123", "paymentMethodTypes": ["card"]},
    }


def test_accepts_options_resolver_without_invoking_it() -> None:
    calls: list[object] = []

    def resolver(context: object) -> dict[str, str]:
        calls.append(context)
        return {"customer": "cus_123"}

    wire = charge.normalize_request({**BASE, "paymentIntentOptions": resolver})
    assert calls == []
    assert "paymentIntentOptions" not in wire


def test_rejects_invalid_request() -> None:
    with pytest.raises(ValidationError):
        charge.normalize_request({"amount": "1"})


def test_accepts_customer_without_metadata() -> None:
    charge.normalize_request({**BASE, "paymentIntentOptions": {"customer": "cus_123"}})


@pytest.mark.parametrize(
    "options",
    [
        {"customer": ""},
        {"hooks": {"inputs": {"tax": {"calculation": ""}}}},
        {"receipt_email": ""},
    ],
)
def test_rejects_empty_option_strings(options: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        charge.normalize_request({**BASE, "paymentIntentOptions": options})


def test_requires_decimals() -> None:
    request = {key: value for key, value in BASE.items() if key != "decimals"}
    with pytest.raises(ValidationError):
        charge.normalize_request(request)


@pytest.mark.parametrize("decimals", [-1, 1.5, "2"])
def test_rejects_invalid_decimals(decimals: object) -> None:
    with pytest.raises(ValidationError):
        ChargeRequest.model_validate({**BASE, "decimals": decimals})


def test_requires_payment_method_types() -> None:
    with pytest.raises(ValidationError):
        charge.normalize_request({**BASE, "paymentMethodTypes": []})


def test_validates_spt_payload() -> None:
    payload = charge.parse_payload({"spt": "spt_test_123", "externalId": "client_order_789"})
    assert payload == ChargePayload.model_validate(
        {"spt": "spt_test_123", "externalId": "client_order_789"}
    )
    assert payload.external_id == "client_order_789"


def test_rejects_invalid_payload() -> None:
    with pytest.raises(ValidationError):
        charge.parse_payload({"signature": "0x..."})


# -- parse_units -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "decimals", "expected"),
    [
        ("1", 2, 100),
        ("1.2345", 4, 12_345),
        ("1.2345000", 4, 12_345),
        ("69.49", 0, 69),
        ("69.5", 0, 70),
        ("69.2349", 3, 69_235),
        ("69.2355", 3, 69_236),
        ("999999.99999", 3, 1_000_000_000),
        ("0.00000000059", 9, 1),
        ("1.4499999999999999999", 1, 14),
        ("1.14999999999999999", 1, 11),
        ("6942069420.12345678912345", 18, 6_942_069_420_123_456_789_123_450_000),
        ("-1.235", 2, -124),
        (".5", 2, 50),
        ("1.", 2, 100),
    ],
)
def test_parse_units(value: str, decimals: int, expected: int) -> None:
    assert parse_units(value, decimals) == expected


def _reference(value: str, decimals: int) -> int:
    """Rounds half away from zero, like viem ``parseUnits``."""
    text = value.replace("-", "")
    text = f"0{text}" if text.startswith(".") else text
    with localcontext(prec=500):
        magnitude = Decimal(text.rstrip(".") or "0").scaleb(decimals)
        result = int(magnitude.quantize(Decimal(1), rounding=ROUND_HALF_UP))
    return -result if value.startswith("-") else result


_digits = st.text("0123456789", max_size=100)
_unsigned = st.one_of(
    st.text("0123456789", min_size=1, max_size=100),
    st.tuples(st.text("0123456789", min_size=1, max_size=100), _digits).map(
        lambda parts: f"{parts[0]}.{parts[1]}"
    ),
    st.text("0123456789", min_size=1, max_size=100).map(lambda fraction: f".{fraction}"),
)
_decimal = st.tuples(st.booleans(), _unsigned).map(lambda v: f"{'-' if v[0] else ''}{v[1]}")


@given(_decimal, st.integers(min_value=0, max_value=50))
def test_parse_units_matches_reference(value: str, decimals: int) -> None:
    assert parse_units(value, decimals) == _reference(value, decimals)


@pytest.mark.parametrize("value", ["", ".", "-", "-.", "1.2.3", "1e3", "NaN", "1\n", "\u0661"])
def test_parse_units_rejects_invalid_value(value: str) -> None:
    with pytest.raises(ValueError, match="not a valid decimal number"):
        parse_units(value, 2)


@pytest.mark.parametrize("decimals", [-1, 1.5, float("nan"), float("inf"), True])
def test_parse_units_rejects_invalid_decimals(decimals: object) -> None:
    with pytest.raises(ValueError, match="Decimals must be a non-negative integer"):
        parse_units("1", decimals)  # type: ignore[arg-type]
