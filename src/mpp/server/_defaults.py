from __future__ import annotations

import os

_SECRET_KEY_NAME = "MPP_SECRET_KEY"

_REALM_ENV_VARS = [
    "MPP_REALM",
    "FLY_APP_NAME",
    "HEROKU_APP_NAME",
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "VERCEL_URL",
    "WEBSITE_HOSTNAME",
]


def detect_realm() -> str:
    """Detect server realm from environment.

    ``HOST`` and ``HOSTNAME`` are not read: container runtimes set
    ``HOSTNAME`` per replica, and the realm is bound into the challenge ID,
    so replicas would reject each other's credentials.
    """
    for var in _REALM_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value

    return "localhost"


def detect_secret_key() -> str:
    """Get server secret key from environment.

    The secret key is required and must be provided via ``MPP_SECRET_KEY`` or
    passed explicitly to server APIs.
    """
    value = os.environ.get(_SECRET_KEY_NAME)
    if value and value.strip():
        return value

    raise ValueError("Missing secret key. Set MPP_SECRET_KEY or pass secret_key explicitly.")
