"""Tests for Tempo testnet utilities."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from mpp.methods.tempo.testnet import (
    TEMPO_MAINNET_RPC,
    TEMPO_TESTNET_RPC,
    check_connection,
    fund_testnet_address,
)


def _make_response(json_data: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    return resp


async def test_fund_testnet_address_success() -> None:
    mock_resp = _make_response({"jsonrpc": "2.0", "result": "funded", "id": 1})
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xABCD1234")

    assert result is True
    mock_client.post.assert_awaited_once()
    call_kwargs = mock_client.post.call_args
    assert call_kwargs[0][0] == TEMPO_TESTNET_RPC
    assert call_kwargs[1]["json"]["method"] == "tempo_fundAddress"
    assert call_kwargs[1]["json"]["params"] == ["0xABCD1234"]


async def test_fund_testnet_address_rpc_error() -> None:
    error_body = {"jsonrpc": "2.0", "error": {"code": -32000, "message": "fail"}, "id": 1}
    mock_resp = _make_response(error_body)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xABCD1234")

    assert result is False


async def test_fund_testnet_address_network_error() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.post = AsyncMock(side_effect=Exception("connection refused"))

    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await fund_testnet_address("0xABCD1234")

    assert result is False


async def test_check_connection_success() -> None:
    block_resp = _make_response({"jsonrpc": "2.0", "result": "0x12d687", "id": 1})
    chain_resp = _make_response({"jsonrpc": "2.0", "result": "0x1079", "id": 2})

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.post = AsyncMock(side_effect=[block_resp, chain_resp])

    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await check_connection()

    assert result["connected"] is True
    assert result["chain_id"] == 0x1079  # 4217
    assert result["block"] == 0x12D687
    assert mock_client.post.call_count == 2
    first_call = mock_client.post.call_args_list[0]
    assert first_call[0][0] == TEMPO_MAINNET_RPC


async def test_check_connection_failure() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.post = AsyncMock(side_effect=Exception("timeout"))

    with patch("mpp.methods.tempo.testnet.httpx.AsyncClient", return_value=mock_client):
        result = await check_connection()

    assert result["connected"] is False
    assert "error" in result
    assert "timeout" in result["error"]
