"""Expires helpers for generating ISO 8601 datetime strings."""

from datetime import UTC, datetime, timedelta


def _to_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with Z suffix and millisecond precision."""
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def seconds(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` seconds from now."""
    return _to_iso(datetime.now(UTC) + timedelta(seconds=n))


def minutes(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` minutes from now."""
    return _to_iso(datetime.now(UTC) + timedelta(minutes=n))


def hours(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` hours from now."""
    return _to_iso(datetime.now(UTC) + timedelta(hours=n))


def days(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` days from now."""
    return _to_iso(datetime.now(UTC) + timedelta(days=n))


def weeks(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` weeks from now."""
    return _to_iso(datetime.now(UTC) + timedelta(weeks=n))


def months(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` months (30 days) from now."""
    return _to_iso(datetime.now(UTC) + timedelta(days=n * 30))


def years(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` years (365 days) from now."""
    return _to_iso(datetime.now(UTC) + timedelta(days=n * 365))
