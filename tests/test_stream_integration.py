from __future__ import annotations

import asyncio
import secrets
from datetime import UTC, datetime

import httpx
import pytest

from mpay import Credential
from mpay.methods.tempo import TempoAccount
from mpay.methods.tempo.intents import StreamIntent
from mpay.methods.tempo.stream.chain import (
    compute_channel_id,
    encode_approve_call,
    encode_open_call,
    get_on_chain_channel,
    get_tx_params,
)
from mpay.methods.tempo.stream.storage import ChannelState, MemoryStorage, SessionState
from mpay.methods.tempo.stream.types import SignedVoucher, Voucher
from mpay.methods.tempo.stream.voucher import sign_voucher
from tests.conftest import INTEGRATION

pytestmark = [pytest.mark.integration, INTEGRATION]

REQUIRES_ESCROW = pytest.mark.skipif(
    "not config.getfixturevalue('escrow_contract')",
    reason="No escrow contract deployed on this network",
)


@pytest.fixture(autouse=True)
def _skip_without_escrow(escrow_contract):
    if escrow_contract is None:
        pytest.skip("No escrow contract deployed on this network")


async def _open_channel(
    rpc_url: str,
    payer: TempoAccount,
    payee_address: str,
    currency: str,
    escrow_contract: str,
    deposit: int,
) -> str:
    from pytempo import Call, TempoTransaction

    salt = "0x" + secrets.token_hex(32)
    chain_id, nonce, gas_price = await get_tx_params(rpc_url, payer.address)

    channel_id = await compute_channel_id(
        rpc_url,
        escrow_contract,
        payer.address,
        payee_address,
        currency,
        deposit,
        salt,
        payer.address,
    )

    approve_data = encode_approve_call(escrow_contract, deposit)
    open_data = encode_open_call(payee_address, currency, deposit, salt, payer.address)

    tx = TempoTransaction.create(
        chain_id=chain_id,
        gas_limit=2_000_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        fee_token=currency,
        calls=(
            Call.create(to=currency, value=0, data=approve_data),
            Call.create(to=escrow_contract, value=0, data=open_data),
        ),
    )
    signed = tx.sign(payer.private_key)
    raw_tx = "0x" + signed.encode().hex()

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [raw_tx],
                "id": 1,
            },
        )
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"Open channel RPC error: {result['error']}")
        tx_hash = result["result"]

    await _wait_for_receipt(rpc_url, tx_hash)

    return channel_id


async def _wait_for_receipt(rpc_url: str, tx_hash: str, max_attempts: int = 30, delay: float = 1.0):
    async with httpx.AsyncClient(timeout=30) as client:
        for _ in range(max_attempts):
            resp = await client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1,
                },
            )
            result = resp.json().get("result")
            if result is not None:
                if result.get("status") != "0x1":
                    raise RuntimeError(f"Transaction reverted: {tx_hash}")
                return result
            await asyncio.sleep(delay)
    raise RuntimeError(f"Receipt not found: {tx_hash}")


def _make_challenge(
    *,
    challenge_id: str = "integration-challenge",
    currency: str,
    recipient: str,
    escrow_contract: str,
    chain_id: int,
):
    class MockChallenge:
        pass

    c = MockChallenge()
    c.id = challenge_id
    c.request = {
        "amount": "1000000",
        "unitType": "token",
        "currency": currency,
        "recipient": recipient,
        "methodDetails": {
            "escrowContract": escrow_contract,
            "chainId": chain_id,
        },
    }
    return c


class TestStreamIntegration:
    async def test_open_channel_on_chain(
        self,
        rpc_url,
        funded_payer,
        funded_recipient,
        currency,
        escrow_contract,
        chain_id,
    ):
        channel_id = await _open_channel(
            rpc_url,
            funded_payer,
            funded_recipient.address,
            currency,
            escrow_contract,
            10_000_000,
        )

        on_chain = await get_on_chain_channel(rpc_url, escrow_contract, channel_id)

        assert on_chain.deposit == 10_000_000
        assert on_chain.payer.lower() == funded_payer.address.lower()
        assert on_chain.payee.lower() == funded_recipient.address.lower()
        assert on_chain.finalized is False

    async def test_voucher_flow(
        self,
        rpc_url,
        funded_payer,
        funded_recipient,
        currency,
        escrow_contract,
        chain_id,
    ):
        channel_id = await _open_channel(
            rpc_url,
            funded_payer,
            funded_recipient.address,
            currency,
            escrow_contract,
            10_000_000,
        )

        storage = MemoryStorage()
        intent = StreamIntent(
            storage=storage,
            escrow_contract=escrow_contract,
            chain_id=chain_id,
            rpc_url=rpc_url,
        )

        on_chain = await get_on_chain_channel(rpc_url, escrow_contract, channel_id)

        initial_voucher = Voucher(channel_id=channel_id, cumulative_amount=0)
        initial_sig = sign_voucher(funded_payer, initial_voucher, escrow_contract, chain_id)

        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=on_chain.payer,
                payee=on_chain.payee,
                token=on_chain.token,
                authorized_signer=funded_payer.address,
                deposit=on_chain.deposit,
                settled_on_chain=0,
                highest_voucher_amount=0,
                highest_voucher=SignedVoucher(
                    channel_id=channel_id,
                    cumulative_amount=0,
                    signature=initial_sig,
                ),
                active_session_id="integration-challenge",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )
        await storage.update_session(
            "integration-challenge",
            lambda _: SessionState(
                challenge_id="integration-challenge",
                channel_id=channel_id,
                accepted_cumulative=0,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        voucher = Voucher(channel_id=channel_id, cumulative_amount=2_000_000)
        sig = sign_voucher(funded_payer, voucher, escrow_contract, chain_id)

        challenge = _make_challenge(
            currency=currency,
            recipient=funded_recipient.address,
            escrow_contract=escrow_contract,
            chain_id=chain_id,
        )

        credential = Credential(
            challenge=challenge,
            payload={
                "action": "voucher",
                "channelId": channel_id,
                "cumulativeAmount": "2000000",
                "signature": sig,
            },
        )

        receipt = await intent.verify(credential, {})

        assert receipt.status == "success"
        assert receipt.reference == channel_id

        ch = await storage.get_channel(channel_id)
        assert ch is not None
        assert ch.highest_voucher_amount == 2_000_000

    async def test_close_channel(
        self,
        rpc_url,
        funded_payer,
        funded_recipient,
        currency,
        escrow_contract,
        chain_id,
    ):
        channel_id = await _open_channel(
            rpc_url,
            funded_payer,
            funded_recipient.address,
            currency,
            escrow_contract,
            10_000_000,
        )

        storage = MemoryStorage()
        intent = StreamIntent(
            storage=storage,
            escrow_contract=escrow_contract,
            chain_id=chain_id,
            rpc_url=rpc_url,
        )

        on_chain = await get_on_chain_channel(rpc_url, escrow_contract, channel_id)

        initial_voucher = Voucher(channel_id=channel_id, cumulative_amount=0)
        initial_sig = sign_voucher(funded_payer, initial_voucher, escrow_contract, chain_id)

        await storage.update_channel(
            channel_id,
            lambda _: ChannelState(
                channel_id=channel_id,
                payer=on_chain.payer,
                payee=on_chain.payee,
                token=on_chain.token,
                authorized_signer=funded_payer.address,
                deposit=on_chain.deposit,
                settled_on_chain=0,
                highest_voucher_amount=0,
                highest_voucher=SignedVoucher(
                    channel_id=channel_id,
                    cumulative_amount=0,
                    signature=initial_sig,
                ),
                active_session_id="close-challenge",
                finalized=False,
                created_at=datetime.now(UTC),
            ),
        )
        await storage.update_session(
            "close-challenge",
            lambda _: SessionState(
                challenge_id="close-challenge",
                channel_id=channel_id,
                accepted_cumulative=0,
                spent=0,
                units=0,
                created_at=datetime.now(UTC),
            ),
        )

        voucher = Voucher(channel_id=channel_id, cumulative_amount=3_000_000)
        voucher_sig = sign_voucher(funded_payer, voucher, escrow_contract, chain_id)

        challenge_v = _make_challenge(
            challenge_id="close-challenge",
            currency=currency,
            recipient=funded_recipient.address,
            escrow_contract=escrow_contract,
            chain_id=chain_id,
        )
        credential_v = Credential(
            challenge=challenge_v,
            payload={
                "action": "voucher",
                "channelId": channel_id,
                "cumulativeAmount": "3000000",
                "signature": voucher_sig,
            },
        )
        await intent.verify(credential_v, {})

        close_voucher = Voucher(channel_id=channel_id, cumulative_amount=3_000_000)
        close_sig = sign_voucher(funded_payer, close_voucher, escrow_contract, chain_id)

        challenge_c = _make_challenge(
            challenge_id="close-challenge",
            currency=currency,
            recipient=funded_recipient.address,
            escrow_contract=escrow_contract,
            chain_id=chain_id,
        )
        credential_c = Credential(
            challenge=challenge_c,
            payload={
                "action": "close",
                "channelId": channel_id,
                "cumulativeAmount": "3000000",
                "signature": close_sig,
            },
        )
        receipt = await intent.verify(credential_c, {})

        assert receipt.status == "success"

        ch = await storage.get_channel(channel_id)
        assert ch is not None
        assert ch.finalized is True
        assert ch.highest_voucher_amount == 3_000_000

    async def test_get_on_chain_channel_reads_state(
        self,
        rpc_url,
        funded_payer,
        funded_recipient,
        currency,
        escrow_contract,
    ):
        channel_id = await _open_channel(
            rpc_url,
            funded_payer,
            funded_recipient.address,
            currency,
            escrow_contract,
            10_000_000,
        )

        on_chain = await get_on_chain_channel(rpc_url, escrow_contract, channel_id)

        assert on_chain.deposit == 10_000_000
        assert on_chain.settled == 0
        assert on_chain.finalized is False
        assert on_chain.payer.lower() == funded_payer.address.lower()
        assert on_chain.payee.lower() == funded_recipient.address.lower()
        assert on_chain.token.lower() == currency.lower()
        assert on_chain.close_requested_at == 0
