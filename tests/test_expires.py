"""Tests for expires helper functions."""

import re
from datetime import UTC, datetime, timedelta

import pytest

from mpp._expires import days, hours, minutes, months, seconds, weeks, years

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
