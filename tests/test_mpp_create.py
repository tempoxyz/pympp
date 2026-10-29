"""Tests for the Mpp server engine constructor and route handlers."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from mpp.methods.tempo import server as tempo_server
from mpp.server import Mpp
from tests import challenge, http_request


class TestMppCreate:
    def test_create_with_explicit_args(self) -> None:
        method = tempo_server.charge(
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        srv = Mpp(
            methods=method,
            realm="api.example.com",
            secret_key="test-secret",
        )
        assert srv.realm == "api.example.com"
        assert srv.secret_key == "test-secret"
        assert [configured.key for configured in srv.methods] == ["tempo/charge"]

    def test_create_auto_realm(self) -> None:
        with patch.dict(os.environ, {"MPP_REALM": "auto.example.com"}):
            srv = Mpp(
                methods=tempo_server.charge(),
                secret_key="test-secret",
            )
            assert srv.realm == "auto.example.com"

    def test_create_auto_realm_vercel(self) -> None:
        with patch.dict(os.environ, {"VERCEL_URL": "my-app.vercel.app"}, clear=False):
            os.environ.pop("MPP_REALM", None)
            os.environ.pop("HOST", None)
            os.environ.pop("HOSTNAME", None)
            srv = Mpp(
                methods=tempo_server.charge(),
                secret_key="test-secret",
            )
            assert srv.realm == "my-app.vercel.app"

    def test_create_auto_realm_fallback(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            srv = Mpp(
                methods=tempo_server.charge(),
                secret_key="test-secret",
            )
            assert srv.realm == "localhost"

    def test_create_auto_realm_ignores_host_env_vars(self) -> None:
        env = {"HOST": "0.0.0.0", "HOSTNAME": "api-7d9f8c6b5-x2k4p"}
        with patch.dict(os.environ, env, clear=True):
            srv = Mpp(
                methods=tempo_server.charge(),
                secret_key="test-secret",
            )
            assert srv.realm == "localhost"

    def test_create_auto_realm_hostname_does_not_shadow_platform_vars(self) -> None:
        env = {
            "HOSTNAME": "srv-abc123-7d9f8",
            "RENDER_EXTERNAL_HOSTNAME": "api.onrender.com",
        }
        with patch.dict(os.environ, env, clear=True):
            srv = Mpp(
                methods=tempo_server.charge(),
                secret_key="test-secret",
            )
            assert srv.realm == "api.onrender.com"

    def test_create_requires_secret_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Missing secret key"):
                Mpp(
                    methods=tempo_server.charge(),
                    realm="test.com",
                )

    def test_create_rejects_whitespace_secret_key(self) -> None:
        with patch.dict(os.environ, {"MPP_SECRET_KEY": "   "}, clear=True):
            with pytest.raises(ValueError, match="Missing secret key"):
                Mpp(
                    methods=tempo_server.charge(),
                    realm="test.com",
                )

    def test_create_auto_secret_key_from_env(self) -> None:
        with patch.dict(os.environ, {"MPP_SECRET_KEY": "env-secret"}):
            srv = Mpp(
                methods=tempo_server.charge(),
                realm="test.com",
            )
            assert srv.secret_key == "env-secret"

    def test_create_uses_explicit_secret_key(self) -> None:
        srv1 = Mpp(
            methods=tempo_server.charge(),
            realm="test.com",
            secret_key="test-secret",
        )
        srv2 = Mpp(
            methods=tempo_server.charge(),
            realm="test.com",
            secret_key="test-secret",
        )
        assert srv1.secret_key == srv2.secret_key


class TestMppCharge:
    @pytest.mark.asyncio
    async def test_charge_returns_challenge(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(amount="0.50")(http_request())
        result = challenge(result)
        assert result.method == "tempo"
        assert result.intent == "charge"
        assert result.request["amount"] == "500000"
        assert result.request["currency"] == "0x20c0000000000000000000000000000000000000"
        assert result.request["recipient"] == "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        assert result.expires is not None  # expires is a challenge-level auth-param

    @pytest.mark.asyncio
    async def test_charge_auto_expires_5_minutes(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        before = datetime.now(UTC)
        result = await srv.charge(amount="1.00")(http_request())
        after = datetime.now(UTC)

        result = challenge(result)
        assert result.expires is not None
        expires = datetime.fromisoformat(result.expires)
        assert expires > before + timedelta(minutes=4, seconds=59)
        assert expires < after + timedelta(minutes=5, seconds=1)

    @pytest.mark.asyncio
    async def test_charge_explicit_expires(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        exp = "2030-01-20T12:00:00+00:00"
        result = await srv.charge(amount="1.00", expires=exp)(http_request())
        result = challenge(result)
        assert result.expires == exp

    @pytest.mark.asyncio
    async def test_charge_non_string_expires_falls_back_to_default(self) -> None:
        """Non-string runtime expires values should not crash challenge creation."""
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )

        result = await srv.charge(
            amount="1.00",
            expires=datetime.now(UTC),  # type: ignore[arg-type]
        )(http_request())

        result = challenge(result)
        assert result.expires is not None

    @pytest.mark.asyncio
    async def test_charge_amount_conversion(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(amount="0.001")(http_request())
        result = challenge(result)
        assert result.request["amount"] == "1000"

    @pytest.mark.asyncio
    async def test_charge_whole_dollar_amount(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(amount="100")(http_request())
        result = challenge(result)
        assert result.request["amount"] == "100000000"

    @pytest.mark.asyncio
    async def test_charge_override_currency_recipient(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )
        result = await srv.charge(
            amount="1.00",
            currency="0x20c0000000000000000000000000000000000001",
            recipient="0x00000000000000000000000000000000000000aa",
        )(http_request())
        result = challenge(result)
        assert result.request["currency"] == "0x20c0000000000000000000000000000000000001"
        assert result.request["recipient"] == "0x00000000000000000000000000000000000000aa"

    @pytest.mark.asyncio
    async def test_charge_defaults_currency_to_usdc(self) -> None:
        """Currencies default to OUSD then USDC when chain_id defaults to mainnet (4217)."""
        from mpp.methods.tempo import OUSD, USDC

        methods = tempo_server.charge()
        assert [(method.defaults or {}).get("currency") for method in methods] == [OUSD, USDC]

    @pytest.mark.asyncio
    async def test_charge_defaults_currency_to_usdc_on_mainnet(self) -> None:
        """Currencies default to OUSD then USDC when chain_id is explicitly mainnet."""
        from mpp.methods.tempo import CHAIN_ID, OUSD, USDC

        methods = tempo_server.charge(chain_id=CHAIN_ID)
        assert [(method.defaults or {}).get("currency") for method in methods] == [OUSD, USDC]

    @pytest.mark.asyncio
    async def test_charge_missing_recipient_raises(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(currency="0xabc"),
            realm="test.com",
            secret_key="test-secret",
        )
        with pytest.raises(ValueError, match="recipient"):
            await srv.charge(amount="1.00")(http_request())

    @pytest.mark.asyncio
    async def test_charge_missing_currency_raises(self) -> None:
        [method] = tempo_server.charge(
            currency="0x20c0000000000000000000000000000000000000",
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        )
        srv = Mpp(
            methods=replace(method, defaults=None), realm="test.com", secret_key="test-secret"
        )
        with pytest.raises(ValueError, match="currency"):
            await srv.charge(amount="1.00")(http_request())

    @pytest.mark.asyncio
    async def test_charge_without_charge_intent_raises(self) -> None:
        with pytest.raises(ValueError, match="methods is required"):
            Mpp(methods=[], realm="test.com", secret_key="test-secret")

    @pytest.mark.asyncio
    async def test_charge_rejects_non_string_extra_values(self) -> None:
        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
            realm="test.com",
            secret_key="test-secret",
        )

        with pytest.raises(ValueError, match="extra"):
            await srv.charge(
                amount="1.00",
                extra={"attempts": "1", "invalid": 2},  # type: ignore[dict-item]
            )(http_request())

    @pytest.mark.asyncio
    async def test_charge_includes_extra_and_fee_payer(self) -> None:
        from mpp.methods.tempo import TempoAccount

        srv = Mpp(
            methods=tempo_server.charge(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                fee_payer=TempoAccount.from_key("0x" + "ab" * 32),
            ),
            realm="test.com",
            secret_key="test-secret",
        )

        result = await srv.charge(
            amount="1.00",
            fee_payer=True,
            extra={"plan": "pro"},
        )(http_request())

        result = challenge(result)
        assert result.request["extra"] == {"plan": "pro"}
        assert "memo" not in result.request["methodDetails"]
        assert result.request["methodDetails"]["feePayer"] is True

        with pytest.raises(ValueError, match="memo"):
            srv.charge(amount="1.00", memo="0x" + "ab" * 32)
