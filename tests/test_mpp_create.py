"""Tests for Mpp.create() simplified API."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.methods.tempo import tempo
from mpp.methods.tempo.intents import ChargeIntent
from mpp.server import Mpp


@pytest.fixture
def test_intent():
    from mpp.server import intent

    @intent(name="charge")
    async def _intent(credential: Credential, request: dict) -> Receipt:
        return Receipt.success("0xabc")

    return _intent


class TestMppCreate:
    def test_create_with_explicit_args(self) -> None:
        method = tempo(
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            intents={"charge": ChargeIntent()},
        )
        srv = Mpp.create(
            method=method,
            realm="api.example.com",
            secret_key="test-secret",
        )
        assert srv.realm == "api.example.com"
        assert srv.secret_key == "test-secret"
        assert srv.method.currency == "0x20c0000000000000000000000000000000000000"
        assert srv.method.recipient == "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

    def test_create_auto_realm(self) -> None:
        with patch.dict(os.environ, {"MPP_REALM": "auto.example.com"}):
            srv = Mpp.create(
                method=tempo(intents={"charge": ChargeIntent()}),
                secret_key="test-secret",
            )
            assert srv.realm == "auto.example.com"

    def test_create_auto_realm_vercel(self) -> None:
        with patch.dict(os.environ, {"VERCEL_URL": "my-app.vercel.app"}, clear=False):
            os.environ.pop("MPP_REALM", None)
            os.environ.pop("HOST", None)
            os.environ.pop("HOSTNAME", None)
            srv = Mpp.create(
                method=tempo(intents={"charge": ChargeIntent()}),
                secret_key="test-secret",
            )
            assert srv.realm == "my-app.vercel.app"

    def test_create_auto_realm_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            srv = Mpp.create(
                method=tempo(intents={"charge": ChargeIntent()}),
                secret_key="test-secret",
            )
            assert srv.realm == "localhost"

    def test_create_auto_secret_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("mpp.server._defaults._ENV_FILE", env_file),
        ):
            srv = Mpp.create(
                method=tempo(intents={"charge": ChargeIntent()}),
                realm="test.com",
            )
            assert len(srv.secret_key) == 36  # UUID format
            assert env_file.exists()
            assert f"MPP_SECRET_KEY={srv.secret_key}" in env_file.read_text()

    def test_create_auto_secret_key_from_env(self) -> None:
        with patch.dict(os.environ, {"MPP_SECRET_KEY": "env-secret"}):
            srv = Mpp.create(
                method=tempo(intents={"charge": ChargeIntent()}),
                realm="test.com",
            )
            assert srv.secret_key == "env-secret"

    def test_create_auto_secret_key_stable(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("mpp.server._defaults._ENV_FILE", env_file),
        ):
            srv1 = Mpp.create(method=tempo(intents={"charge": ChargeIntent()}), realm="test.com")
            srv2 = Mpp.create(method=tempo(intents={"charge": ChargeIntent()}), realm="test.com")
            assert srv1.secret_key == srv2.secret_key


class TestMppCharge:
    @pytest.mark.asyncio
    async def test_charge_returns_challenge(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert result.method == "tempo"
        assert result.intent == "charge"
        assert result.request["amount"] == "500000"
        assert result.request["currency"] == "0x20c0000000000000000000000000000000000000"
        assert result.request["recipient"] == "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        assert "expires" in result.request

    @pytest.mark.asyncio
    async def test_charge_auto_expires_5_minutes(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        before = datetime.now(UTC)
        result = await srv.charge(authorization=None, amount="1.00")
        after = datetime.now(UTC)

        assert isinstance(result, Challenge)
        expires = datetime.fromisoformat(result.request["expires"])
        assert expires > before + timedelta(minutes=4, seconds=59)
        assert expires < after + timedelta(minutes=5, seconds=1)

    @pytest.mark.asyncio
    async def test_charge_explicit_expires(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        exp = "2030-01-20T12:00:00+00:00"
        result = await srv.charge(authorization=None, amount="1.00", expires=exp)
        assert isinstance(result, Challenge)
        assert result.request["expires"] == exp

    @pytest.mark.asyncio
    async def test_charge_amount_conversion(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="0.001")
        assert isinstance(result, Challenge)
        assert result.request["amount"] == "1000"

    @pytest.mark.asyncio
    async def test_charge_whole_dollar_amount(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(authorization=None, amount="100")
        assert isinstance(result, Challenge)
        assert result.request["amount"] == "100000000"

    @pytest.mark.asyncio
    async def test_charge_override_currency_recipient(self) -> None:
        srv = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                intents={"charge": ChargeIntent()},
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(
            authorization=None,
            amount="1.00",
            currency="0xoverride",
            recipient="0xother",
        )
        assert isinstance(result, Challenge)
        assert result.request["currency"] == "0xoverride"
        assert result.request["recipient"] == "0xother"

    @pytest.mark.asyncio
    async def test_charge_defaults_currency_to_usdc(self) -> None:
        """Currency defaults to USDC when not explicitly set."""
        from mpp.methods.tempo import USDC

        method = tempo(intents={"charge": ChargeIntent()})
        assert method.currency == USDC

    @pytest.mark.asyncio
    async def test_charge_missing_recipient_raises(self) -> None:
        srv = Mpp.create(
            method=tempo(currency="0xabc", intents={"charge": ChargeIntent()}),
            realm="test.com",
            secret_key="test-secret",
        )
        with pytest.raises(ValueError, match="recipient must be set"):
            await srv.charge(authorization=None, amount="1.00")
