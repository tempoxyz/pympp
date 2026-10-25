"""Ported from mppx src/internal/env.test.ts."""

import pytest

from mpp import _env

VARS = [
    "MPP_REALM",
    "FLY_APP_NAME",
    "HEROKU_APP_NAME",
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "VERCEL_URL",
    "WEBSITE_HOSTNAME",
    "MPP_SECRET_KEY",
]


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in VARS:
        monkeypatch.delenv(name, raising=False)


def test_unset() -> None:
    assert _env.get("realm") is None
    assert _env.get("secret_key") is None


def test_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MPP_SECRET_KEY", "sk_live_abc123")
    assert _env.get("secret_key") == "sk_live_abc123"


def test_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLY_APP_NAME", "fly-app")
    monkeypatch.setenv("VERCEL_URL", "my-app.vercel.app")
    assert _env.get("realm") == "fly-app"
    monkeypatch.setenv("MPP_REALM", "custom-realm")
    assert _env.get("realm") == "custom-realm"


def test_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERCEL_URL", "my-app.vercel.app")
    assert _env.get("realm") == "my-app.vercel.app"
