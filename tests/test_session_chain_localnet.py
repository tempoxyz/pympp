"""TIP-1034 precompile flow on a Tempo localnet: open, top up, settle, close, request close.

Builds client transactions with the session chain helpers, broadcasts them as a
server would (unsponsored and through a fee-payer 0x78 envelope), and checks the
precompile agrees with the locally derived channel IDs and descriptors.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

from mpp.methods.tempo.account import TempoAccount
from mpp.methods.tempo.session import chain, voucher
from mpp.methods.tempo.session.channel import compute_channel_id
from mpp.methods.tempo.session.protocol import ESCROW_ADDRESS, ChannelDescriptor
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]

pytestmark = [pytest.mark.integration, INTEGRATION]


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


def _balance(rpc_url: str, token: str, address: str) -> int:
    data = "0x70a08231" + address.removeprefix("0x").lower().zfill(64)
    response = httpx.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": token, "data": data}, "latest"],
            "id": 1,
        },
        timeout=30,
    )
    return int(response.json()["result"], 16)


async def _open(
    rpc_url: str,
    chain_id: int,
    currency: str,
    payer: TempoAccount,
    payee: TempoAccount,
    *,
    deposit: int,
    sponsor: TempoAccount | None = None,
) -> tuple[ChannelDescriptor, str, chain.BroadcastOpenResult]:
    raw_tx, descriptor, channel_id = await chain.build_open_transaction(
        payer,
        rpc_url=rpc_url,
        payee=payee.address,
        token=currency,
        deposit=deposit,
        chain_id=chain_id,
        fee_payer=sponsor is not None,
    )
    assert raw_tx.startswith("0x78" if sponsor else "0x76")
    result = await chain.broadcast_open_transaction(
        rpc_url,
        serialized_transaction=raw_tx,
        chain_id=chain_id,
        escrow_contract=ESCROW_ADDRESS,
        expected_authorized_signer=payer.address,
        expected_channel_id=channel_id,
        expected_currency=currency,
        expected_expiring_nonce_hash=descriptor.expiring_nonce_hash,
        expected_operator=descriptor.operator,
        expected_payee=payee.address,
        expected_payer=payer.address,
        fee_payer=sponsor,
    )
    return descriptor, channel_id, result


async def _check_chain_agrees(
    rpc_url: str, chain_id: int, descriptor: ChannelDescriptor, channel_id: str
) -> chain.Channel:
    assert compute_channel_id(descriptor, chain_id=chain_id) == channel_id
    assert await chain.compute_channel_id_on_chain(rpc_url, descriptor) == channel_id
    on_chain = await chain.get_channel(rpc_url, descriptor)
    assert chain.same_channel_descriptor(on_chain.descriptor, descriptor)
    return on_chain


@pytest.mark.parametrize("sponsored", [False, True], ids=["unsponsored", "sponsored"])
async def test_open_top_up_settle_close(
    rpc_url: str, chain_id: int, currency: str, sponsored: bool
) -> None:
    payer = _new_account(rpc_url, currency)
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency) if sponsored else None

    payer_before = _balance(rpc_url, currency, payer.address)
    descriptor, channel_id, opened = await _open(
        rpc_url, chain_id, currency, payer, payee, deposit=1_000_000, sponsor=sponsor
    )
    assert chain.same_channel_descriptor(opened.descriptor, descriptor)
    assert opened.expiring_nonce_hash == descriptor.expiring_nonce_hash
    assert opened.state == chain.ChannelState(settled=0, deposit=1_000_000, close_requested_at=0)
    on_chain = await _check_chain_agrees(rpc_url, chain_id, descriptor, channel_id)
    assert on_chain.state.deposit == 1_000_000
    if sponsored:
        # The sponsor pays the gas: the payer only reserves the deposit.
        assert _balance(rpc_url, currency, payer.address) == payer_before - 1_000_000

    top_up_tx = await chain.build_top_up_transaction(
        payer, descriptor, 250_000, rpc_url=rpc_url, chain_id=chain_id, fee_payer=sponsored
    )
    topped_up = await chain.broadcast_top_up_transaction(
        rpc_url,
        serialized_transaction=top_up_tx,
        additional_deposit=250_000,
        chain_id=chain_id,
        descriptor=descriptor,
        escrow_contract=ESCROW_ADDRESS,
        expected_channel_id=channel_id,
        expected_currency=currency,
        fee_payer=sponsor,
    )
    assert topped_up.new_deposit == 1_250_000
    assert topped_up.state.deposit == 1_250_000

    # The payee settles a voucher, then closes with a later one, capturing part of it.
    settle_signature = voucher.sign_voucher(
        payer, channel_id=channel_id, cumulative_amount=300_000, chain_id=chain_id
    )
    settle_hash = await chain.settle_on_chain(
        rpc_url, payee, descriptor, 300_000, settle_signature, fee_payer=sponsor
    )
    receipt = await chain.wait_for_successful_receipt(rpc_url, settle_hash)
    settled = chain.get_channel_event(receipt, "Settled", channel_id, escrow=ESCROW_ADDRESS)
    assert (settled["deltaPaid"], settled["newSettled"]) == (300_000, 300_000)
    state = await chain.get_channel_state(rpc_url, channel_id)
    assert state.settled == 300_000

    payee_before = _balance(rpc_url, currency, payee.address)
    close_signature = voucher.sign_voucher(
        payer, channel_id=channel_id, cumulative_amount=500_000, chain_id=chain_id
    )
    close_hash = await chain.close_on_chain(
        rpc_url, payee, descriptor, 500_000, 450_000, close_signature, fee_payer=sponsor
    )
    receipt = await chain.wait_for_successful_receipt(rpc_url, close_hash)
    closed = chain.get_channel_event(receipt, "ChannelClosed", channel_id, escrow=ESCROW_ADDRESS)
    # settledToPayee is the total captured; only the part above settled moves now.
    assert closed["settledToPayee"] == 450_000
    assert closed["refundedToPayer"] == 1_250_000 - 450_000
    if sponsored:
        assert _balance(rpc_url, currency, payee.address) == payee_before + 150_000


async def test_payer_request_close(rpc_url: str, chain_id: int, currency: str) -> None:
    payer = _new_account(rpc_url, currency)
    payee = _new_account(rpc_url, currency)
    descriptor, channel_id, _ = await _open(
        rpc_url, chain_id, currency, payer, payee, deposit=100_000
    )
    tx_hash = await chain.request_close_on_chain(rpc_url, payer, descriptor)
    receipt = await chain.wait_for_successful_receipt(rpc_url, tx_hash)
    requested = chain.get_channel_event(receipt, "CloseRequested", channel_id)
    state = await chain.get_channel_state(rpc_url, channel_id)
    assert state.close_requested_at > 0
    assert requested["closeGraceEnd"] == state.close_requested_at + 900
    [batched] = await chain.get_channel_states_batch(rpc_url, [channel_id])
    assert batched == state


async def test_rejects_a_tampered_open_credential(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payer = _new_account(rpc_url, currency)
    payee = _new_account(rpc_url, currency)
    raw_tx, descriptor, channel_id = await chain.build_open_transaction(
        payer, rpc_url=rpc_url, payee=payee.address, token=currency, deposit=10_000
    )
    kwargs: dict[str, Any] = {
        "serialized_transaction": raw_tx,
        "chain_id": chain_id,
        "escrow_contract": ESCROW_ADDRESS,
        "expected_authorized_signer": payer.address,
        "expected_channel_id": channel_id,
        "expected_currency": currency,
        "expected_expiring_nonce_hash": descriptor.expiring_nonce_hash,
        "expected_operator": descriptor.operator,
        "expected_payee": payee.address,
        "expected_payer": payer.address,
    }
    chain.validate_open_credential_transaction(**kwargs)
    with pytest.raises(Exception, match="payee"):
        await chain.broadcast_open_transaction(
            rpc_url, **{**kwargs, "expected_payee": payer.address}
        )
    # Nothing was broadcast: the channel does not exist.
    state = await chain.get_channel_state(rpc_url, channel_id)
    assert state.deposit == 0
