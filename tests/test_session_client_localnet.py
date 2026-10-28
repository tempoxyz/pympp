"""The pympp session client paying an mppx session server on a Tempo localnet.

Runs tests/interop/mppx_session/server.mjs (mppx ``tempo.session``) against the localnet and
pays it with ``tempo.session`` through :class:`mpp.client.Mpp` and with the session manager,
then checks deposits, settlement and balances on chain.
"""

from __future__ import annotations

import os

import pytest

from mpp.client import Mpp
from mpp.methods.tempo.account import TempoAccount
from mpp.methods.tempo.client import session, session_manager
from mpp.methods.tempo.session import chain
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]
from tests.session_interop import MppxServer, mppx_session_server
from tests.test_session_chain_localnet import _balance  # pyright: ignore[reportPrivateUsage]

pytestmark = [pytest.mark.integration, INTEGRATION]

AMOUNT = 100  # 0.0001 at 6 decimals: the mppx server's default price per request


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


def _actions(server: MppxServer) -> list[tuple[str, str | None, int]]:
    return [
        (request["method"], request["action"], request["status"]) for request in server.requests()
    ]


async def test_many_sub_cent_calls_on_one_suggested_deposit(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payer = _new_account(rpc_url, currency)
    async with mppx_session_server(
        rpc_url=rpc_url, chain_id=chain_id, currency=currency, suggested_deposit="0.01"
    ) as server:
        method = session(account=payer, max_deposit="1", rpc_url=rpc_url)
        async with Mpp(methods=[method]) as mpp:
            for _ in range(20):
                response = await mpp.fetch(server.url)
                assert response.status_code == 200, response.text
                assert response.headers["payment-receipt"]
        paid = [action for _, action, _ in _actions(server) if action]
        assert paid == ["open"] + ["voucher"] * 19
        last = server.requests()[-1]["receipt"]
        assert last["acceptedCumulative"] == str(20 * AMOUNT)
        assert last["spent"] == str(20 * AMOUNT)
        state = await chain.get_channel_state(rpc_url, last["channelId"])
        assert state.deposit == 10_000
        assert state.close_requested_at == 0


async def test_tops_up_exact_shortfall_without_suggested_deposit(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payer = _new_account(rpc_url, currency)
    async with mppx_session_server(rpc_url=rpc_url, chain_id=chain_id, currency=currency) as server:
        method = session(account=payer, max_deposit="1", rpc_url=rpc_url)
        async with Mpp(methods=[method]) as mpp:
            for _ in range(3):
                assert (await mpp.fetch(server.url)).status_code == 200
        assert [(m, a, s) for m, a, s in _actions(server) if a] == [
            ("GET", "open", 200),
            ("POST", "topUp", 204),
            ("GET", "voucher", 200),
            ("POST", "topUp", 204),
            ("GET", "voucher", 200),
        ]
        channel_id = server.requests()[-1]["receipt"]["channelId"]
        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.deposit == 3 * AMOUNT


async def test_max_deposit_stops_payments(rpc_url: str, chain_id: int, currency: str) -> None:
    payer = _new_account(rpc_url, currency)
    async with mppx_session_server(
        rpc_url=rpc_url, chain_id=chain_id, currency=currency, suggested_deposit="1"
    ) as server:
        async with session_manager(account=payer, max_deposit="0.0002", rpc_url=rpc_url) as manager:
            await manager.fetch(server.url)
            await manager.fetch(server.url)
            assert manager.deposit == 2 * AMOUNT
            with pytest.raises(ValueError, match="exceeds local maxDeposit"):
                await manager.fetch(server.url)
            assert manager.cumulative == 2 * AMOUNT
        state = await chain.get_channel_state(rpc_url, manager.channel_id or "")
        assert state.deposit == 2 * AMOUNT


async def test_manager_top_up_and_close_settle_on_chain(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payer = _new_account(rpc_url, currency)
    async with mppx_session_server(
        rpc_url=rpc_url, chain_id=chain_id, currency=currency, suggested_deposit="0.001"
    ) as server:
        payee_before = _balance(rpc_url, currency, server.payee)
        async with session_manager(account=payer, max_deposit="1", rpc_url=rpc_url) as manager:
            for call in range(1, 6):
                response = await manager.fetch(server.url)
                assert response.status_code == 200
                assert response.receipt is not None
                assert response.receipt.spent == str(call * AMOUNT)
            assert manager.deposit == 1000
            channel_id = manager.channel_id
            assert channel_id is not None

            receipt = await manager.top_up("0.002")
            assert receipt is not None and receipt.tx_hash
            assert manager.deposit == 3000
            state = await chain.get_channel_state(rpc_url, channel_id)
            assert state.deposit == 3000

            closed = await manager.close()
            assert closed is not None and closed.tx_hash
            assert closed.accepted_cumulative == str(5 * AMOUNT)
            assert not manager.opened

        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.deposit == 0
        # The unsponsored payee pays the close transaction's fee out of what it captured.
        assert 0 < _balance(rpc_url, currency, server.payee) - payee_before <= 5 * AMOUNT
        assert server.settlements()[-1]["amount"] == str(5 * AMOUNT)
        assert [a for _, a, _ in _actions(server) if a][-2:] == ["topUp", "close"]


async def test_fee_sponsored_server(rpc_url: str, chain_id: int, currency: str) -> None:
    payer = _new_account(rpc_url, currency)
    fee_payer_key = "0x" + os.urandom(32).hex()
    async with mppx_session_server(
        rpc_url=rpc_url,
        chain_id=chain_id,
        currency=currency,
        fee_payer_key=fee_payer_key,
        suggested_deposit="0.01",
    ) as server:
        assert server.info["feePayer"]
        payer_before = _balance(rpc_url, currency, payer.address)
        payee_before = _balance(rpc_url, currency, server.payee)
        async with session_manager(account=payer, max_deposit="1", rpc_url=rpc_url) as manager:
            for _ in range(5):
                assert (await manager.fetch(server.url)).status_code == 200
            await manager.top_up("0.01")
            assert manager.deposit == 20_000
            closed = await manager.close()
            assert closed is not None and closed.spent == str(5 * AMOUNT)
        # The fee payer pays every fee: the payer loses exactly what it spent and the payee
        # gains exactly that.
        assert payer_before - _balance(rpc_url, currency, payer.address) == 5 * AMOUNT
        assert _balance(rpc_url, currency, server.payee) - payee_before == 5 * AMOUNT
