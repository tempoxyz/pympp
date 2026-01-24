"""Tests for expires helper functions."""

import re
from datetime import UTC, datetime, timedelta

import pytest

from mpp._expires import _to_iso, days, hours, minutes, months, seconds, weeks, years

ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

HELPERS = [
    (seconds, 30, timedelta(seconds=30)),
    (minutes, 5, timedelta(minutes=5)),
    (hours, 2, timedelta(hours=2)),
    (days, 7, timedelta(days=7)),
    (weeks, 2, timedelta(weeks=2)),
    (months, 1, timedelta(days=30)),
    (years, 1, timedelta(days=365)),
]


def _parse(iso: str) -> datetime:
    """Parse an ISO 8601 string with Z suffix."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


class TestExpiresHelpers:
    @pytest.mark.parametrize(
        "fn,n,delta",
        HELPERS,
        ids=lambda x: x.__name__ if callable(x) else repr(x),
    )
    def test_format(self, fn, n, delta) -> None:
        """Each helper should produce valid ISO 8601 with 3-digit ms and Z suffix."""
        assert ISO_PATTERN.match(fn(n))

    @pytest.mark.parametrize(
        "fn,n,delta",
        HELPERS,
        ids=lambda x: x.__name__ if callable(x) else repr(x),
    )
    def test_value(self, fn, n, delta) -> None:
        """Result should be tightly bracketed: before + delta <= result <= after + delta.

        The lower bound is adjusted by 1 ms because _to_iso truncates
        microseconds to milliseconds (floor), so the serialized timestamp
        can be up to 999 µs less than the actual instant.
        """
        before = datetime.now(UTC)
        result = _parse(fn(n))
        after = datetime.now(UTC)
        ms_truncation = timedelta(milliseconds=1)
        assert before + delta - ms_truncation <= result <= after + delta

    @pytest.mark.parametrize(
        "fn,n,delta",
        HELPERS,
        ids=lambda x: x.__name__ if callable(x) else repr(x),
    )
    def test_result_is_utc(self, fn, n, delta) -> None:
        """Parsed result should always be timezone-aware and in UTC."""
        result = _parse(fn(n))
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(0)

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


class TestToIso:
    """_to_iso should use isoformat() for robust timezone handling."""

    def test_utc_datetime_ends_with_z(self) -> None:
        """UTC datetime should produce timestamp ending with Z."""
        dt = datetime(2025, 6, 15, 12, 30, 45, 123456, tzinfo=UTC)
        result = _to_iso(dt)
        assert result.endswith("Z")
        assert "+00:00" not in result

    def test_millisecond_precision(self) -> None:
        """Output should have exactly millisecond precision."""
        dt = datetime(2025, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)
        result = _to_iso(dt)
        ms_part = result.split(".")[1].rstrip("Z")
        assert len(ms_part) == 3

    def test_zero_microseconds(self) -> None:
        """Zero microseconds should produce .000Z."""
        dt = datetime(2025, 1, 1, 0, 0, 0, 0, tzinfo=UTC)
        result = _to_iso(dt)
        assert result == "2025-01-01T00:00:00.000Z"

    def test_sub_millisecond_truncation(self) -> None:
        """Microseconds should be truncated to milliseconds."""
        dt = datetime(2025, 6, 15, 10, 30, 0, 123456, tzinfo=UTC)
        result = _to_iso(dt)
        assert ".123Z" in result

    def test_roundtrip_parse(self) -> None:
        """Output should be parseable back to a datetime."""
        dt = datetime(2025, 3, 15, 8, 45, 30, 789000, tzinfo=UTC)
        result = _to_iso(dt)
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        assert parsed.year == 2025
        assert parsed.month == 3
        assert parsed.second == 30
