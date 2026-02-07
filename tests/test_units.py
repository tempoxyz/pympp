"""Tests for unit conversion utilities."""

import pytest

from mpay._units import parse_units, transform_units


class TestParseUnits:
    def test_whole_number(self) -> None:
        assert parse_units("1", 6) == 1_000_000

    def test_decimal(self) -> None:
        assert parse_units("1.5", 6) == 1_500_000

    def test_small_decimal(self) -> None:
        assert parse_units("0.000025", 6) == 25

    def test_zero_decimals(self) -> None:
        assert parse_units("100", 0) == 100

    def test_large_amount(self) -> None:
        assert parse_units("10", 6) == 10_000_000

    def test_zero(self) -> None:
        assert parse_units("0", 6) == 0

    def test_invalid_amount(self) -> None:
        with pytest.raises(ValueError, match="Invalid amount"):
            parse_units("abc", 6)

    def test_fractional_base_units(self) -> None:
        with pytest.raises(ValueError, match="fractional base units"):
            parse_units("0.0000001", 6)


class TestTransformUnits:
    def test_converts_amount(self) -> None:
        result = transform_units(
            {
                "amount": "1",
                "decimals": 6,
                "currency": "0x123",
            }
        )
        assert result["amount"] == "1000000"
        assert result["currency"] == "0x123"
        assert "decimals" not in result

    def test_converts_suggested_deposit(self) -> None:
        result = transform_units(
            {
                "amount": "0.000025",
                "decimals": 6,
                "unitType": "llm_token",
                "suggestedDeposit": "10",
            }
        )
        assert result["amount"] == "25"
        assert result["suggestedDeposit"] == "10000000"
        assert "decimals" not in result

    def test_no_decimals_passthrough(self) -> None:
        request = {"amount": "1000000", "currency": "0x123"}
        result = transform_units(request)
        assert result == request

    def test_none_suggested_deposit(self) -> None:
        result = transform_units(
            {
                "amount": "1",
                "decimals": 6,
                "suggestedDeposit": None,
            }
        )
        assert result["amount"] == "1000000"
        assert result["suggestedDeposit"] is None

    def test_no_mutation(self) -> None:
        original = {"amount": "1", "decimals": 6}
        transform_units(original)
        assert "decimals" in original
        assert original["amount"] == "1"


class TestParseUnitsEdgeCases:
    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            parse_units("-1", 6)

    def test_negative_fractional_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            parse_units("-0.01", 6)

    def test_nan_raises(self) -> None:
        with pytest.raises(ValueError, match="finite"):
            parse_units("NaN", 6)

    def test_infinity_raises(self) -> None:
        with pytest.raises(ValueError, match="finite"):
            parse_units("Infinity", 6)

    def test_negative_infinity_raises(self) -> None:
        with pytest.raises(ValueError, match="finite"):
            parse_units("-Infinity", 6)

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="required"):
            parse_units("", 6)

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="required"):
            parse_units("   ", 6)

    def test_whitespace_stripped(self) -> None:
        assert parse_units(" 1.5 ", 6) == 1_500_000
