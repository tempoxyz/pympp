"""Retry policy for transient errors in PaymentTransport."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RetryPolicy:
    """Exponential backoff retry policy for transient 5xx errors.

    Example:
        transport = PaymentTransport(
            methods=[tempo(...)],
            retry_policy=RetryPolicy(max_attempts=5, backoff_delays=[0.1, 0.5, 1.0, 2.0]),
        )

        # Disable retry entirely:
        async with Client(methods=[tempo(...)], retry_policy=None) as client:
            response = await client.get(url)
    """

    max_attempts: int = 3
    backoff_delays: list[float] = field(default_factory=lambda: [0.5, 1.0])
    retryable_status_codes: frozenset[int] = field(
        default_factory=lambda: frozenset({500, 502, 503, 504})
    )
    retry_on_connect_error: bool = True
