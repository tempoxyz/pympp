"""Challenge expiry helpers.

The relative helpers (``minutes(5)`` …) return ISO 8601 strings in the exact format JavaScript's
``Date.prototype.toISOString`` produces (UTC, millisecond precision, ``Z`` suffix).
"""

import re
from datetime import UTC, datetime, timedelta

from mpp.errors import InvalidChallengeError, PaymentExpiredError

__all__ = [
    "DATETIME_PATTERN",
    "DatetimeInput",
    "days",
    "ensure",
    "hours",
    "minutes",
    "months",
    "now",
    "parse",
    "seconds",
    "to_datetime_string",
    "to_iso",
    "weeks",
    "years",
]


DATETIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z", re.ASCII
)
"""ISO 8601 datetime accepted on the wire (mppx ``z.datetime()``)."""

type DatetimeInput = str | datetime
"""An ISO 8601 datetime string or a ``datetime`` (naive values are treated as UTC)."""


def to_iso(value: datetime) -> str:
    """Formats a datetime like JavaScript ``toISOString()`` (``YYYY-MM-DDTHH:MM:SS.sssZ``)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def to_datetime_string(value: DatetimeInput) -> str:
    """Serializes an ISO 8601 string or datetime for wire output (strings pass through)."""
    return value if isinstance(value, str) else to_iso(value)


def parse(value: str) -> datetime | None:
    """Parses an ISO 8601 timestamp into an aware datetime, or ``None`` when malformed."""
    text = value.strip()
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?\Z", text, re.ASCII)
    if match:
        base, fraction, zone = match.groups()
        fraction = (fraction or "")[:7]  # `.` + at most microseconds
        text = f"{base}{fraction}{'+00:00' if zone in (None, 'Z') else zone}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def ensure(expires: str | None, challenge_id: str | None = None) -> str:
    """Asserts that ``expires`` is present, well-formed, and still in the future.

    Returns:
        The validated ``expires`` value.

    Raises:
        InvalidChallengeError: When missing or malformed.
        PaymentExpiredError: When the timestamp has been reached.
    """
    if not expires:
        raise InvalidChallengeError(id=challenge_id, reason="missing required expires field")
    parsed = parse(expires)
    if parsed is None:
        raise InvalidChallengeError(id=challenge_id, reason="malformed expires timestamp")
    # A challenge is expired from its ``expires`` instant on (mppx ``Expires.assert``).
    if parsed <= now():
        raise PaymentExpiredError(expires=expires)
    return expires


def now() -> datetime:
    """Returns the current UTC time (single clock source; patchable in tests)."""
    return datetime.now(UTC)


def _from_now(delta: timedelta) -> str:
    return to_iso(now() + delta)


def seconds(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` seconds from now."""
    return _from_now(timedelta(seconds=n))


def minutes(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` minutes from now."""
    return _from_now(timedelta(minutes=n))


def hours(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` hours from now."""
    return _from_now(timedelta(hours=n))


def days(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` days from now."""
    return _from_now(timedelta(days=n))


def weeks(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` weeks from now."""
    return _from_now(timedelta(weeks=n))


def months(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` months (30 days) from now."""
    return _from_now(timedelta(days=30 * n))


def years(n: float) -> str:
    """Returns an ISO 8601 datetime string ``n`` years (365 days) from now."""
    return _from_now(timedelta(days=365 * n))
