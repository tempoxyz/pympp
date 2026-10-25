"""Shared defaults for all payment methods."""

DEFAULT_TIMEOUT = 30.0
"""HTTP request timeout in seconds."""

DEFAULT_CONFIRMATION_TIMEOUT = 30.0
"""Seconds to wait for a broadcast transaction's receipt."""

DEFAULT_PAID_RETRY_TIMEOUT = DEFAULT_CONFIRMATION_TIMEOUT + 5.0
"""Minimum paid-retry read timeout in seconds, covering the server's confirmation window."""
