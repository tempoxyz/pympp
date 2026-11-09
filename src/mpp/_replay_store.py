"""Guard against instance-local replay protection where it is unsafe.

Methods built without a store fall back to an in-memory one, which only
remembers the Credentials this process accepted. That is fine in development
and tests, but in production or on a multi-instance or serverless platform
another instance (or this one after a restart) would accept the same
Credential again, so the fallback refuses to start there, as in mppx.
"""

from __future__ import annotations

import os

# Set by platforms that run several instances, or restart them freely.
_PLATFORM_VARS = (
    "AWS_LAMBDA_FUNCTION_NAME",
    "DYNO",
    "FLY_APP_NAME",
    "K_SERVICE",
    "NETLIFY",
    "RAILWAY_ENVIRONMENT",
    "RENDER",
    "VERCEL",
)
# ``NODE_ENV`` is accepted for parity with mppx.
_ENVIRONMENT_VARS = ("MPP_ENV", "NODE_ENV")


def production_runtime() -> str | None:
    """Return the variable that marks this runtime as production, or ``None``."""
    for name in _PLATFORM_VARS:
        if os.environ.get(name):
            return name
    for name in _ENVIRONMENT_VARS:
        if os.environ.get(name, "").strip().lower() == "production":
            return f"{name}=production"
    return None


def check_fallback_allowed(method: str, option: str) -> None:
    """Raise when *method* would fall back to an in-memory store in production.

    Args:
        method: The method missing a store, such as ``tempo.charge``.
        option: Where to pass one, such as ``tempo.charge(store=...) or Mpp(store=...)``.

    Raises:
        RuntimeError: If :func:`production_runtime` detects production.
    """
    reason = production_runtime()
    if reason is None:
        return
    raise RuntimeError(
        f"{method} has no store configured, and this runtime looks like production or a "
        f"multi-instance platform ({reason}), where an in-memory store lets another instance "
        f"accept a replayed Credential. Pass a shared store via {option}: "
        "mpp.stores.RedisStore (Redis or Valkey), mpp.stores.SQLStore (Postgres) or "
        "mpp.stores.SQLiteStore (one instance). To accept instance-local replay protection, "
        "pass mpp.stores.MemoryStore() explicitly."
    )
