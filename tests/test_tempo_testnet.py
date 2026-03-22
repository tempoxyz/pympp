"""Tests for Tempo testnet utilities."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mpp.methods.tempo._defaults import CHAIN_ID
from mpp.methods.tempo.testnet import check_connection, fund_testnet_address


@pytest.mark.asyncio
async def test_fund_testnet_address_success() -> None:
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"result": "0x1"}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)
    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xDeadBeef")
    assert result is True


@pytest.mark.asyncio
async def test_fund_testnet_address_error_response() -> None:
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"error": {"code": -32000, "message": "rate limited"}}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)
    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xDeadBeef")
    assert result is False


@pytest.mark.asyncio
async def test_fund_testnet_address_network_error() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=Exception("connection refused"))
    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xDeadBeef")
    assert result is False


@pytest.mark.asyncio
async def test_check_connection_mainnet() -> None:
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.side_effect = [
        {"result": hex(9_000_000)},
        {"result": hex(CHAIN_ID)},
    ]
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)
    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        info = await check_connection(chain_id=CHAIN_ID)
    assert info["connected"] is True
    assert info["chain_id"] == CHAIN_ID
    assert info["block"] == 9_000_000


@pytest.mark.asyncio
async def test_check_connection_failure() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=Exception("timeout"))
    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        info = await check_connection()
    assert info["connected"] is False
    assert "error" in info
