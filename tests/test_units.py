"""Tests for unit conversion utilities."""

import pytest

from mpp._units import parse_units, transform_units


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

    def test_amount_longer_than_decimal_context_precision_is_exact(self) -> None:
        """Amounts past 28 significant digits must not be rounded.

        Scaling through the active decimal context would round these to a
        different, still-integral value and return a silently wrong amount.
        """
        assert parse_units("999999999999999999999999999999", 0) == 999999999999999999999999999999
        assert (
            parse_units("12345678901234567890.123456789012345678", 18)
            == 12345678901234567890123456789012345678
        )

    def test_fractional_base_units_still_rejected_for_long_amounts(self) -> None:
        with pytest.raises(ValueError, match="fractional base units"):
            parse_units("0.1234567890123456789012345678901", 6)

    def test_extreme_negative_exponent_is_rejected_without_building_a_divisor(
        self,
    ) -> None:
        """A tiny exponent must be rejected from the exponent alone.

        The scaled divisor for these values has millions of digits. Deciding
        divisibility by comparing the exponent to the digit count avoids
        materializing it, so this stays immediate instead of spending seconds
        and megabytes on a value that is rejected either way.
        """
        with pytest.raises(ValueError, match="fractional base units"):
            parse_units("1e-10000000", 6)

        with pytest.raises(ValueError, match="fractional base units"):
            parse_units("1e-1000000000", 6)

    def test_zero_is_zero_at_any_scale(self) -> None:
        assert parse_units("0.000", 6) == 0
        assert parse_units("0e-10000000", 6) == 0

    @pytest.mark.parametrize(("value", "decimals"), [("100", -2), ("1000", -3), ("7", -1)])
    def test_negative_decimals_rejected(self, value: str, decimals: int) -> None:
        """A negative scale divides the amount rather than scaling it.

        It also failed inconsistently: "100" with -2 decimals returned 1
        while "7" with -1 raised, so an under-charge only surfaced when the
        division left a remainder. mpp-go rejects negative decimals outright.
        """
        with pytest.raises(ValueError, match="decimals must be non-negative"):
            parse_units(value, decimals)

    def test_transform_units_rejects_negative_decimals(self) -> None:
        with pytest.raises(ValueError, match="decimals must be non-negative"):
            transform_units({"amount": "100", "decimals": -2})

    def test_transform_units_rejects_bool_decimals(self) -> None:
        """``bool`` is an ``int`` subclass, so ``true`` would scale by 1."""
        with pytest.raises(ValueError, match="decimals must be an integer"):
            transform_units({"amount": "1.5", "decimals": True})
