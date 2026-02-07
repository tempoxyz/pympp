"""Tests for Mpay.create() simplified API."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from mpay import Challenge, Credential, Receipt
from mpay.methods.tempo import tempo
from mpay.server import Mpay


@pytest.fixture
def test_intent():
    from mpay.server import intent

    @intent(name="charge")
    async def _intent(credential: Credential, request: dict) -> Receipt:
        return Receipt.success("0xabc")

    return _intent


class TestMpayCreate:
    def test_create_with_explicit_args(self) -> None:
        method = tempo(
            currency="0x20c0000000000000000000000000000000000001",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        mpay = Mpay.create(
            method=method,
            realm="api.example.com",
            secret_key="test-secret",
        )
        assert mpay.realm == "api.example.com"
        assert mpay.secret_key == "test-secret"
        assert mpay.method.currency == "0x20c0000000000000000000000000000000000001"
        assert mpay.method.recipient == "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"

    def test_create_auto_realm(self) -> None:
        with patch.dict(os.environ, {"MPAY_REALM": "auto.example.com"}):
            mpay = Mpay.create(
                method=tempo(),
                secret_key="test-secret",
            )
            assert mpay.realm == "auto.example.com"

    def test_create_auto_realm_vercel(self) -> None:
        with patch.dict(os.environ, {"VERCEL_URL": "my-app.vercel.app"}, clear=False):
            os.environ.pop("MPAY_REALM", None)
            os.environ.pop("HOST", None)
            os.environ.pop("HOSTNAME", None)
            mpay = Mpay.create(
                method=tempo(),
                secret_key="test-secret",
            )
            assert mpay.realm == "my-app.vercel.app"

    def test_create_auto_realm_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            mpay = Mpay.create(
                method=tempo(),
                secret_key="test-secret",
            )
            assert mpay.realm == "localhost"

    def test_create_auto_secret_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("mpay.server._defaults._ENV_FILE", env_file),
        ):
            mpay = Mpay.create(
                method=tempo(),
                realm="test.com",
            )
            assert len(mpay.secret_key) == 36  # UUID format
            assert env_file.exists()
            assert f"MPAY_SECRET_KEY={mpay.secret_key}" in env_file.read_text()

    def test_create_auto_secret_key_from_env(self) -> None:
        with patch.dict(os.environ, {"MPAY_SECRET_KEY": "env-secret"}):
            mpay = Mpay.create(
                method=tempo(),
                realm="test.com",
            )
            assert mpay.secret_key == "env-secret"

    def test_create_auto_secret_key_stable(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("mpay.server._defaults._ENV_FILE", env_file),
        ):
            mpay1 = Mpay.create(method=tempo(), realm="test.com")
            mpay2 = Mpay.create(method=tempo(), realm="test.com")
            assert mpay1.secret_key == mpay2.secret_key


class TestMpayCharge:
    @pytest.mark.asyncio
    async def test_charge_returns_challenge(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await mpay.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert result.method == "tempo"
        assert result.intent == "charge"
        assert result.request["amount"] == "500000"
        assert result.request["currency"] == "0x20c0000000000000000000000000000000000001"
        assert result.request["recipient"] == "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        assert "expires" in result.request

    @pytest.mark.asyncio
    async def test_charge_auto_expires_5_minutes(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        before = datetime.now(UTC)
        result = await mpay.charge(authorization=None, amount="1.00")
        after = datetime.now(UTC)

        assert isinstance(result, Challenge)
        expires = datetime.fromisoformat(result.request["expires"])
        assert expires > before + timedelta(minutes=4, seconds=59)
        assert expires < after + timedelta(minutes=5, seconds=1)

    @pytest.mark.asyncio
    async def test_charge_explicit_expires(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        exp = "2030-01-20T12:00:00+00:00"
        result = await mpay.charge(authorization=None, amount="1.00", expires=exp)
        assert isinstance(result, Challenge)
        assert result.request["expires"] == exp

    @pytest.mark.asyncio
    async def test_charge_amount_conversion(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await mpay.charge(authorization=None, amount="0.001")
        assert isinstance(result, Challenge)
        assert result.request["amount"] == "1000"

    @pytest.mark.asyncio
    async def test_charge_whole_dollar_amount(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await mpay.charge(authorization=None, amount="100")
        assert isinstance(result, Challenge)
        assert result.request["amount"] == "100000000"

    @pytest.mark.asyncio
    async def test_charge_override_currency_recipient(self) -> None:
        mpay = Mpay.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000001",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await mpay.charge(
            authorization=None,
            amount="1.00",
            currency="0xoverride",
            recipient="0xother",
        )
        assert isinstance(result, Challenge)
        assert result.request["currency"] == "0xoverride"
        assert result.request["recipient"] == "0xother"

    @pytest.mark.asyncio
    async def test_charge_missing_currency_raises(self) -> None:
        mpay = Mpay.create(
            method=tempo(),
            realm="test.com",
            secret_key="test-secret",
        )
        with pytest.raises(ValueError, match="currency must be set"):
            await mpay.charge(authorization=None, amount="1.00")

    @pytest.mark.asyncio
    async def test_charge_missing_recipient_raises(self) -> None:
        mpay = Mpay.create(
            method=tempo(currency="0xabc"),
            realm="test.com",
            secret_key="test-secret",
        )
        with pytest.raises(ValueError, match="recipient must be set"):
            await mpay.charge(authorization=None, amount="1.00")
