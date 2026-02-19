"""Tests for expires helper functions."""

import re
from datetime import UTC, datetime, timedelta

from mpp._expires import days, hours, minutes, months, seconds, weeks, years

ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _parse(iso: str) -> datetime:
    """Parse an ISO 8601 string with Z suffix."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


class TestExpiresHelpers:
    def test_seconds_format(self) -> None:
        """seconds() should produce valid ISO 8601 with 3-digit ms and Z suffix."""
        result = seconds(30)
        assert ISO_PATTERN.match(result)

    def test_seconds_value(self) -> None:
        """seconds(30) should be ~30s from now."""
        before = datetime.now(UTC)
        result = _parse(seconds(30))
        after = datetime.now(UTC) + timedelta(seconds=30)
        assert before + timedelta(seconds=29) <= result <= after + timedelta(seconds=1)

    def test_minutes_format(self) -> None:
        result = minutes(5)
        assert ISO_PATTERN.match(result)

    def test_minutes_value(self) -> None:
        before = datetime.now(UTC)
        result = _parse(minutes(5))
        assert result > before + timedelta(minutes=4)

    def test_hours_format(self) -> None:
        result = hours(1)
        assert ISO_PATTERN.match(result)

    def test_hours_value(self) -> None:
        before = datetime.now(UTC)
        result = _parse(hours(2))
        assert result > before + timedelta(hours=1)

    def test_days_format(self) -> None:
        result = days(1)
        assert ISO_PATTERN.match(result)

    def test_days_value(self) -> None:
        before = datetime.now(UTC)
        result = _parse(days(7))
        assert result > before + timedelta(days=6)

    def test_weeks_format(self) -> None:
        result = weeks(1)
        assert ISO_PATTERN.match(result)

    def test_weeks_value(self) -> None:
        before = datetime.now(UTC)
        result = _parse(weeks(2))
        assert result > before + timedelta(weeks=1)

    def test_months_format(self) -> None:
        result = months(1)
        assert ISO_PATTERN.match(result)

    def test_months_value(self) -> None:
        """months(1) should be ~30 days from now."""
        before = datetime.now(UTC)
        result = _parse(months(1))
        assert result > before + timedelta(days=29)

    def test_years_format(self) -> None:
        result = years(1)
        assert ISO_PATTERN.match(result)

    def test_years_value(self) -> None:
        """years(1) should be ~365 days from now."""
        before = datetime.now(UTC)
        result = _parse(years(1))
        assert result > before + timedelta(days=364)

    def test_all_end_with_z(self) -> None:
        """All helpers should produce timestamps ending with Z."""
        for fn in [seconds, minutes, hours, days, weeks, months, years]:
            assert fn(1).endswith("Z")

    def test_all_have_3_digit_ms(self) -> None:
        """All helpers should have exactly 3-digit milliseconds."""
        for fn in [seconds, minutes, hours, days, weeks, months, years]:
            result = fn(1)
            ms_part = result.split(".")[1].rstrip("Z")
            assert len(ms_part) == 3
