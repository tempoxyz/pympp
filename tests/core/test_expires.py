"""Ported from mppx src/Expires.test.ts."""

from datetime import UTC, datetime

import pytest

from mpp import InvalidChallengeError, PaymentExpiredError, expires

FIXED = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(expires, "now", lambda: FIXED)


@pytest.mark.parametrize(
    ("fn", "n", "expected"),
    [
        (expires.seconds, 30, "2025-06-15T12:00:30.000Z"),
        (expires.seconds, 0, "2025-06-15T12:00:00.000Z"),
        (expires.seconds, -60, "2025-06-15T11:59:00.000Z"),
        (expires.minutes, 5, "2025-06-15T12:05:00.000Z"),
        (expires.minutes, -10, "2025-06-15T11:50:00.000Z"),
        (expires.hours, 2, "2025-06-15T14:00:00.000Z"),
        (expires.hours, -3, "2025-06-15T09:00:00.000Z"),
        (expires.days, 1, "2025-06-16T12:00:00.000Z"),
        (expires.days, -2, "2025-06-13T12:00:00.000Z"),
        (expires.weeks, 1, "2025-06-22T12:00:00.000Z"),
        (expires.weeks, -1, "2025-06-08T12:00:00.000Z"),
        (expires.months, 1, "2025-07-15T12:00:00.000Z"),
        (expires.months, -1, "2025-05-16T12:00:00.000Z"),
        (expires.years, 1, "2026-06-15T12:00:00.000Z"),
        (expires.years, -1, "2024-06-15T12:00:00.000Z"),
        (expires.years, 0, "2025-06-15T12:00:00.000Z"),
    ],
)
def test_relative(fn: object, n: int, expected: str) -> None:
    assert fn(n) == expected  # type: ignore[operator]


def test_ensure() -> None:
    assert expires.ensure("2025-06-15T12:00:01Z") == "2025-06-15T12:00:01Z"
    with pytest.raises(InvalidChallengeError, match="missing required expires field"):
        expires.ensure(None, "ch")
    with pytest.raises(
        InvalidChallengeError, match=r'Challenge "ch" is invalid: malformed expires timestamp.'
    ):
        expires.ensure("not-a-date", "ch")
    with pytest.raises(PaymentExpiredError, match=r"Payment expired at 2025-06-15T11:59:59Z."):
        expires.ensure("2025-06-15T11:59:59Z")


def test_parse_handles_offsets_and_long_fractions() -> None:
    assert expires.parse("2025-06-15T14:00:00+02:00") == FIXED
    assert expires.parse("2025-06-15T12:00:00.123456789Z") is not None
    assert expires.parse("garbage") is None


def test_ensure_rejects_at_expiry_instant() -> None:
    # pympp#319 / mppx#1078: a challenge is expired once its expires instant is reached.
    with pytest.raises(PaymentExpiredError):
        expires.ensure("2025-06-15T12:00:00.000Z")
    assert expires.ensure("2025-06-15T12:00:00.001Z") == "2025-06-15T12:00:00.001Z"
