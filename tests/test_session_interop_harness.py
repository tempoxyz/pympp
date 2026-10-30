"""The mppx session interop harness (tests/session_interop.py) against itself on localnet."""

from __future__ import annotations

import pytest

from tests import INTEGRATION
from tests.session_interop import mppx_session_server, run_mppx_session_client

pytestmark = [pytest.mark.integration, INTEGRATION]


async def test_mppx_client_pays_mppx_server_then_tops_up_and_closes(rpc_url, chain_id, currency):
    async with mppx_session_server(
        rpc_url=rpc_url, chain_id=chain_id, currency=currency, suggested_deposit="1"
    ) as server:
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            calls=3,
            top_up="0.5",
            close=True,
        )
    assert result.returncode == 0, result.stderr
    assert [call["status"] for call in result.calls] == [200, 200, 200]
    assert [call["receipt"]["acceptedCumulative"] for call in result.calls] == [
        "100",
        "200",
        "300",
    ]
    # Every paid call probes first: 402, then the credential (open, then vouchers).
    assert [[e["status"] for e in call["exchanges"]] for call in result.calls] == [[402, 200]] * 3
    assert [call["exchanges"][1]["action"] for call in result.calls] == [
        "open",
        "voucher",
        "voucher",
    ]
    assert result.top_up is not None and result.top_up["receipt"]["txHash"]
    assert result.close is not None and result.close["receipt"]["txHash"]
    assert result.final["opened"] is False
    assert [request["status"] for request in server.requests()][-2:] == [204, 204]
    assert any(event["trigger"] == "close" for event in server.settlements())
