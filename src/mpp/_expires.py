"""Expires helpers for generating ISO 8601 datetime strings."""

from datetime import UTC, datetime, timedelta


def seconds(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` seconds from now."""
    return (datetime.now(UTC) + timedelta(seconds=n)).isoformat()


def minutes(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` minutes from now."""
    return (datetime.now(UTC) + timedelta(minutes=n)).isoformat()


def hours(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` hours from now."""
    return (datetime.now(UTC) + timedelta(hours=n)).isoformat()


def days(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` days from now."""
    return (datetime.now(UTC) + timedelta(days=n)).isoformat()


def weeks(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` weeks from now."""
    return (datetime.now(UTC) + timedelta(weeks=n)).isoformat()


def months(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` months (30 days) from now."""
    return (datetime.now(UTC) + timedelta(days=n * 30)).isoformat()


def years(n: int) -> str:
    """Returns an ISO 8601 datetime string `n` years (365 days) from now."""
    return (datetime.now(UTC) + timedelta(days=n * 365)).isoformat()
