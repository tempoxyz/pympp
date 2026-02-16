from __future__ import annotations

import os
import uuid
from pathlib import Path

from dotenv import dotenv_values

_ENV_FILE = Path(".env")
_SECRET_KEY_NAME = "MPP_SECRET_KEY"

_REALM_ENV_VARS = [
    "MPP_REALM",
    "VERCEL_URL",
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "HOST",
    "HOSTNAME",
]


def detect_realm() -> str:
    """Detect server realm from environment."""
    for var in _REALM_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value

    return "localhost"


def _read_env_file(key: str) -> str | None:
    if not _ENV_FILE.exists():
        return None
    values = dotenv_values(_ENV_FILE)
    return values.get(key)


def detect_secret_key() -> str:
    """Get or generate a persistent secret key."""
    value = os.environ.get(_SECRET_KEY_NAME)
    if value:
        return value

    value = _read_env_file(_SECRET_KEY_NAME)
    if value:
        return value

    value = str(uuid.uuid4())
    with _ENV_FILE.open("a") as f:
        f.write(f"{_SECRET_KEY_NAME}={value}\n")
    return value
