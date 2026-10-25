"""Environment-based configuration defaults (realm / secret key)."""

import os

_VARIABLES: dict[str, tuple[str, ...]] = {
    "realm": (
        "MPP_REALM",
        "FLY_APP_NAME",
        "HEROKU_APP_NAME",
        "RAILWAY_PUBLIC_DOMAIN",
        "RENDER_EXTERNAL_HOSTNAME",
        "VERCEL_URL",
        "WEBSITE_HOSTNAME",
    ),
    "secret_key": ("MPP_SECRET_KEY",),
}


def get(key: str) -> str | None:
    """Returns the first non-empty environment variable configured for ``key``."""
    for name in _VARIABLES[key]:
        value = os.environ.get(name)
        if value:
            return value
    return None
