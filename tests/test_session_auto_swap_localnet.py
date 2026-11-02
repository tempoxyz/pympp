"""Session auto-swap on a Tempo localnet: a payer holding only AlphaUSD opens and tops up a
pathUSD session by buying pathUSD on the stablecoin DEX in the same transaction.

Covers the pympp client against the pympp server and the mppx server, both of which accept the
approve + swap prefix (mppx Chain.validateAutoSwapPrefix). The servers sponsor fees, since the
payer holds none of the session currency to pay them with.
"""

from __future__ import annotations

import os

import pytest
from pytempo import Call, TempoTransaction

from mpp.client import Mpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo._rpc import _rpc_call, get_tx_params  # pyright: ignore[reportPrivateUsage]
from mpp.methods.tempo.client import AutoSwap
from mpp.methods.tempo.session import _chain as chain
from tests import INTEGRATION
from tests.session_interop import mppx_session_server
from tests.test_session_e2e_localnet import (
    _balance,  # pyright: ignore[reportPrivateUsage]
    _calls,  # pyright: ignore[reportPrivateUsage]
    _new_account,  # pyright: ignore[reportPrivateUsage]
    _serve,  # pyright: ignore[reportPrivateUsage]
)
from tests.test_tempo_integration import _wait_for_receipt  # pyright: ignore[reportPrivateUsage]

pytestmark = [pytest.mark.integration, INTEGRATION]

# A second localnet TIP-20 token; the localnet DEX quotes it 1:1 against pathUSD.
ALPHA_USD = "0x20c0000000000000000000000000000000000001"
ALPHA_FUNDS = 1_000_000
AUTO_SWAP = AutoSwap(token_in=[ALPHA_USD])


async def _transfer(rpc_url: str, sender: TempoAccount, token: str, to: str, amount: int) -> None:
    """Send a TIP-20 transfer, with gas for a new sender and recipient."""
    chain_id, nonce, gas_price = await get_tx_params(rpc_url, sender.address)
    data = "0xa9059cbb" + to.removeprefix("0x").lower().zfill(64) + f"{amount:064x}"
    tx = TempoTransaction.create(
        chain_id=chain_id,
        gas_limit=2_000_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        fee_token=token,
        calls=(Call.create(to=token, value=0, data=data),),
    )
    raw = "0x" + tx.sign(sender.private_key).encode().hex()
    await _wait_for_receipt(rpc_url, await _rpc_call(rpc_url, "eth_sendRawTransaction", [raw]))


async def _alpha_only_payer(rpc_url: str, currency: str) -> TempoAccount:
    """A fresh payer holding only AlphaUSD, none of the session currency."""
    funder = _new_account(rpc_url, currency)
    payer = TempoAccount.from_key("0x" + os.urandom(32).hex())
    await _transfer(rpc_url, funder, ALPHA_USD, payer.address, ALPHA_FUNDS)
    assert await _balance(rpc_url, currency, payer.address) == 0
    assert await _balance(rpc_url, ALPHA_USD, payer.address) == ALPHA_FUNDS
    return payer


async def test_open_and_top_up_swap_into_the_session_currency(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    assert currency.lower() != ALPHA_USD
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    payer = await _alpha_only_payer(rpc_url, currency)
    async with _serve(
        rpc_url, chain_id, currency, payee, suggested_deposit="0.0001", fee_payer=sponsor
    ) as server:
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url, auto_swap=AUTO_SWAP
        ) as manager:
            await _calls(manager, server.url, 5)
            channel_id = manager.channel_id
            assert channel_id is not None
            assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == 100
            # The open bought exactly its deposit, so none is left to top up with.
            assert await _balance(rpc_url, currency, payer.address) == 0

            top_up = await manager.top_up("0.0001")
            assert top_up is not None and top_up.tx_hash
            assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == 200
            await _calls(manager, server.url, 5, first=6)
            closed = await manager.close()
            assert closed is not None and closed.spent == "100"
        # The close refunds the unspent deposit in the session currency.
        assert await _balance(rpc_url, currency, payer.address) == 100
        spent_alpha = ALPHA_FUNDS - await _balance(rpc_url, ALPHA_USD, payer.address)
        assert 200 <= spent_alpha <= 202


async def test_mppx_server_accepts_the_swap_prefix(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payer = await _alpha_only_payer(rpc_url, currency)
    async with mppx_session_server(
        rpc_url=rpc_url,
        chain_id=chain_id,
        currency=currency,
        fee_payer_key="0x" + os.urandom(32).hex(),
        suggested_deposit="0.001",
    ) as server:
        assert server.info["feePayer"]
        method = tempo_client.session(
            account=payer, max_deposit="1", rpc_url=rpc_url, auto_swap=AUTO_SWAP
        )
        async with Mpp(methods=[method]) as mpp:
            for _ in range(3):
                response = await mpp.fetch(server.url)
                assert response.status_code == 200, response.text
        paid = [request["action"] for request in server.requests() if request["action"]]
        assert paid == ["open", "voucher", "voucher"]
        channel_id = server.requests()[-1]["receipt"]["channelId"]
        assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == 1_000
        assert await _balance(rpc_url, currency, payer.address) == 0
        spent_alpha = ALPHA_FUNDS - await _balance(rpc_url, ALPHA_USD, payer.address)
        assert 1_000 <= spent_alpha <= 1_010
