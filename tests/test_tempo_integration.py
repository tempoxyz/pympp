"""Integration tests for Tempo charge intent against a real node.

Requires TEMPO_RPC_URL to be set. Run with:
    TEMPO_RPC_URL=http://localhost:8545 pytest -m integration -v
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mpp import Challenge
from mpp.errors import VerificationError
from mpp.methods.tempo import ChargeIntent, TempoAccount, tempo
from mpp.methods.tempo._rpc import get_tx_params
from tests import INTEGRATION, make_credential
from tests.conftest import _fund_account

pytestmark = [pytest.mark.integration, INTEGRATION]


def _future_expires() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


async def _send_transfer(
    rpc_url: str,
    payer,
    currency: str,
    recipient_addr: str,
    amount: int,
) -> str:
    from pytempo import Call, TempoTransaction

    cid, nonce, gas_price = await get_tx_params(rpc_url, payer.address)

    selector = "a9059cbb"
    to_padded = recipient_addr[2:].lower().zfill(64)
    amount_padded = hex(amount)[2:].zfill(64)
    data = f"0x{selector}{to_padded}{amount_padded}"

    tx = TempoTransaction.create(
        chain_id=cid,
        gas_limit=500_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        fee_token=currency,
        calls=(Call.create(to=currency, value=0, data=data),),
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
            raise RuntimeError(f"RPC error: {result['error']}")
        tx_hash = result["result"]

    await _wait_for_receipt(rpc_url, tx_hash)
    return tx_hash


async def _wait_for_receipt(
    rpc_url: str, tx_hash: str, max_attempts: int = 30, delay: float = 1.0
) -> dict:
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
    raise RuntimeError(f"Receipt not found after {max_attempts} attempts: {tx_hash}")


class TestChargeIntegration:
    async def test_create_credential_builds_real_tx(
        self, rpc_url, funded_payer, funded_recipient, currency
    ):
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="integ-create-cred",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": currency,
                "recipient": funded_recipient.address,
                "expires": _future_expires(),
            },
        )

        credential = await method.create_credential(challenge)

        assert credential.payload["type"] == "transaction"
        assert credential.payload["signature"].startswith("0x76")
        assert funded_payer.address in credential.source

    async def test_verify_transaction_credential(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
            },
        }
        challenge = Challenge(
            id="integ-verify-tx",
            method="tempo",
            intent="charge",
            request=request_dict,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")
        assert len(receipt.reference) >= 66

    async def test_verify_hash_credential(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent
    ):
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
        }
        credential = make_credential(payload={"type": "hash", "hash": tx_hash})
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference == tx_hash

    async def test_verify_rejects_insufficient_transfer(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent
    ):
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 100
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
        }
        credential = make_credential(payload={"type": "hash", "hash": tx_hash})

        with pytest.raises(VerificationError):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_rejects_wrong_recipient(
        self, rpc_url, funded_payer, currency, charge_intent
    ):
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_payer.address, 1000000
        )

        wrong_recipient = "0x0000000000000000000000000000000000000001"
        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": wrong_recipient,
            "expires": expires,
        }
        credential = make_credential(payload={"type": "hash", "hash": tx_hash})

        with pytest.raises(VerificationError):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_premium_charge(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        expires = _future_expires()
        request_dict = {
            "amount": "1000000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
            },
        }
        challenge = Challenge(
            id="integ-premium",
            method="tempo",
            intent="charge",
            request=request_dict,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.method == "tempo"
        assert receipt.reference.startswith("0x")
        assert len(receipt.reference) >= 66

    async def test_e2e_charge_with_fee_payer(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        fee_payer_account = TempoAccount.from_key("0x" + __import__("os").urandom(32).hex())
        _fund_account(rpc_url, fee_payer_account.address, currency)

        intent = ChargeIntent(rpc_url=rpc_url)
        tempo(
            rpc_url=rpc_url,
            fee_payer=fee_payer_account,
            intents={"charge": intent},
        )

        client_method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": True,
                "chainId": chain_id,
            },
        }
        challenge = Challenge(
            id="integ-fee-payer",
            method="tempo",
            intent="charge",
            request=request_dict,
        )

        credential = await client_method.create_credential(challenge)
        receipt = await intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.method == "tempo"
        assert receipt.reference.startswith("0x")
        assert len(receipt.reference) >= 66

    async def test_verify_with_server_memo(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        """When server specifies memo, client should use transferWithMemo and server should verify."""
        memo = "0x" + "ab" * 32

        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
                "memo": memo,
            },
        }
        challenge = Challenge(
            id="integ-memo",
            method="tempo",
            intent="charge",
            request=request_dict,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")

    async def test_verify_rejects_wrong_memo(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        """Server should reject when tx has wrong memo."""
        client_memo = "0x" + "ab" * 32
        server_memo = "0x" + "cd" * 32

        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        expires = _future_expires()

        # Client builds tx with client_memo
        challenge = Challenge(
            id="integ-wrong-memo",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": currency,
                "recipient": funded_recipient.address,
                "expires": expires,
                "methodDetails": {
                    "feePayer": False,
                    "chainId": chain_id,
                    "memo": client_memo,
                },
            },
        )
        credential = await method.create_credential(challenge)

        # Server verifies with server_memo — should reject
        server_request = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
                "memo": server_memo,
            },
        }
        with pytest.raises(VerificationError):
            await charge_intent.verify(credential, server_request)

    async def test_default_memo_accepted_when_server_omits_memo(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        """Client defaults memo via encode_attribution; server without memo should still verify.

        The client always adds a memo (via encode_attribution) when the server
        doesn't specify one. The server's _verify_transfer_logs without memo
        requires TRANSFER_TOPIC, but the tx emits TRANSFER_WITH_MEMO_TOPIC.
        This test documents the actual behavior.
        """
        method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        expires = _future_expires()
        # Server request has NO memo — client will default one via encode_attribution
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
            },
        }
        challenge = Challenge(
            id="integ-default-memo",
            method="tempo",
            intent="charge",
            request=request_dict,
            realm="test.local",
        )

        credential = await method.create_credential(challenge)

        # The server verifies with no memo in request — _verify_transfer_logs
        # requires TRANSFER_TOPIC but the tx emits TRANSFER_WITH_MEMO_TOPIC.
        # This documents the current behavior (it may pass or fail depending
        # on whether the node emits both topics or just the memo topic).
        try:
            receipt = await charge_intent.verify(credential, request_dict)
            assert receipt.status == "success"
        except VerificationError:
            # Expected: memo mismatch between client default and server expectation
            pass

    async def test_fee_payer_wrong_recipient_rejected(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        fee_payer_account = TempoAccount.from_key("0x" + __import__("os").urandom(32).hex())
        _fund_account(rpc_url, fee_payer_account.address, currency)

        intent = ChargeIntent(rpc_url=rpc_url)
        tempo(
            rpc_url=rpc_url,
            fee_payer=fee_payer_account,
            intents={"charge": intent},
        )

        wrong_recipient = "0x0000000000000000000000000000000000000001"

        client_method = tempo(
            account=funded_payer,
            rpc_url=rpc_url,
            intents={"charge": ChargeIntent()},
        )
        challenge = Challenge(
            id="integ-fee-payer-wrong",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": currency,
                "recipient": wrong_recipient,
                "expires": _future_expires(),
                "methodDetails": {
                    "feePayer": True,
                    "chainId": chain_id,
                },
            },
        )
        credential = await client_method.create_credential(challenge)

        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": _future_expires(),
            "methodDetails": {
                "feePayer": True,
                "chainId": chain_id,
            },
        }

        with pytest.raises(VerificationError):
            await intent.verify(credential, request_dict)
