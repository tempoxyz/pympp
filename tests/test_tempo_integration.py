"""Integration tests for Tempo charge intent against a real node.

Requires a Tempo node (see tests/network.py). Run with:
    make node && TEMPO_NETWORK=localnet uv run pytest -m integration -v
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge
from mpp.errors import InternalPaymentError, VerificationError
from mpp.methods.tempo import ChargeIntent, TempoAccount
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._rpc import get_tx_params
from mpp.methods.tempo.client import _tempo_method
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC
from tests import INTEGRATION, TEST_REALM, internal_cause, make_credential
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
    memo: str | None = None,
) -> str:
    from pytempo import Call, TempoTransaction

    cid, nonce, gas_price = await get_tx_params(rpc_url, payer.address)

    to_padded = recipient_addr[2:].lower().zfill(64)
    amount_padded = hex(amount)[2:].zfill(64)
    if memo is not None:
        selector = "95777d59"
        memo_clean = memo[2:] if memo.startswith("0x") else memo
        data = f"0x{selector}{to_padded}{amount_padded}{memo_clean.lower()}"
    else:
        selector = "a9059cbb"
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
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
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
        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
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
            expires=expires,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")
        assert len(receipt.reference) >= 66

    async def test_verify_hash_credential(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        challenge_id = "test-hash-cred"
        memo = encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000, memo=memo
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference == tx_hash

    async def test_verify_hash_rejects_plain_transfer_without_challenge_bound_memo(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        challenge_id = "test-hash-no-memo"
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_hash_rejects_wrong_challenge_binding(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        challenge_id = "test-hash-wrong-binding"
        tx_hash = await _send_transfer(
            rpc_url,
            funded_payer,
            currency,
            funded_recipient.address,
            1000000,
            memo=encode_attribution(challenge_id="different-challenge", server_id=TEST_REALM),
        )

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )

        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_rejects_insufficient_transfer(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
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
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(payload={"type": "hash", "hash": tx_hash}, expires=expires)

        with pytest.raises(VerificationError):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_rejects_wrong_recipient(
        self, rpc_url, funded_payer, currency, charge_intent, chain_id
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
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(payload={"type": "hash", "hash": tx_hash}, expires=expires)

        with pytest.raises(VerificationError):
            await charge_intent.verify(credential, request_dict)

    async def test_verify_premium_charge(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        premium_amount = "900000000"
        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
        )
        expires = _future_expires()
        request_dict = {
            # Gas is paid in the same token, so leave headroom for settlement.
            "amount": premium_amount,
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
            expires=expires,
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

        intent = ChargeIntent(rpc_url=rpc_url, fee_payer=fee_payer_account)

        client_method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
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
            expires=expires,
        )

        # Spy on the simulate payload to catch request-shape regressions that
        # mocked-RPC unit tests cannot.
        captured: list[list[dict[str, Any]]] = []
        original_build = intent._build_simulate_payload

        def _spy(tx, sender):
            payload = original_build(tx, sender)
            captured.append(payload)
            return payload

        intent._build_simulate_payload = _spy  # type: ignore[method-assign]

        credential = await client_method.create_credential(challenge)
        receipt = await intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.method == "tempo"
        assert receipt.reference.startswith("0x")
        assert len(receipt.reference) >= 66

        # Both eth_call simulations ran against the node and carry the payment call.
        assert captured, "pre-broadcast simulation payload was never built"
        for request in captured[0]:
            assert request["calls"][-1]["to"].lower() == currency.lower()
            assert request["calls"][-1]["data"].startswith("0x")

    async def test_legacy_server_memo_uses_challenge_bound_attribution(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        """Legacy primary memos must not override the client's challenge binding."""
        memo = "0x" + "ab" * 32

        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
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
            expires=expires,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")

        tx_receipt = await _wait_for_receipt(rpc_url, receipt.reference)
        payment_memos = [
            log["topics"][3]
            for log in tx_receipt["logs"]
            if log["address"].lower() == currency.lower()
            and len(log.get("topics", [])) == 4
            and log["topics"][0] == TRANSFER_WITH_MEMO_TOPIC
        ]
        assert payment_memos == [
            encode_attribution(challenge_id=challenge.id, server_id=challenge.realm)
        ]

    @pytest.mark.parametrize("memo_kind", ["custom", "wrong_challenge", "wrong_realm"])
    async def test_legacy_server_memo_cannot_bypass_challenge_binding(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, memo_kind, chain_id
    ):
        """Matching a legacy memo is insufficient without challenge and realm binding."""
        challenge_id = "integ-unbound-legacy-memo"
        memo = {
            "custom": "0x" + "ab" * 32,
            "wrong_challenge": encode_attribution("different-challenge", TEST_REALM),
            "wrong_realm": encode_attribution(challenge_id, "different.example.com"),
        }[memo_kind]
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000, memo=memo
        )
        expires = _future_expires()
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )
        server_request = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"memo": memo, "chainId": chain_id},
        }
        with pytest.raises(VerificationError, match="memo is not bound to this challenge"):
            await charge_intent.verify(credential, server_request)

    async def test_default_memo_accepted_when_server_omits_memo(
        self, rpc_url, funded_payer, funded_recipient, currency, charge_intent, chain_id
    ):
        """Auto-generated attribution memos should still verify without a server memo."""
        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
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
            expires=expires,
        )

        credential = await method.create_credential(challenge)
        receipt = await charge_intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")

    async def test_verify_hash_replay_rejected_with_store(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        """Same hash submitted twice with a store should fail the second time."""
        from mpp.store import MemoryStore

        challenge_id = "test-hash-replay-store"
        memo = encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000, memo=memo
        )

        store = MemoryStore()
        intent = ChargeIntent(rpc_url=rpc_url, store=store)

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )

        receipt = await intent.verify(credential, request_dict)
        assert receipt.status == "success"

        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(credential, request_dict)

    async def test_verify_hash_replay_rejected_with_default_store(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        """The default replay store rejects a second fulfillment of the same payment."""
        challenge_id = "test-hash-replay-no-store"
        memo = encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000, memo=memo
        )

        intent = ChargeIntent(rpc_url=rpc_url)  # no store

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )

        receipt1 = await intent.verify(credential, request_dict)
        assert receipt1.status == "success"
        with pytest.raises(VerificationError, match="Transaction hash already used"):
            await intent.verify(credential, request_dict)

    async def test_verify_hash_store_records_on_success(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        """After successful verification, the hash should be recorded in the store."""
        from mpp.store import MemoryStore

        challenge_id = "test-hash-store-records"
        memo = encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)
        tx_hash = await _send_transfer(
            rpc_url, funded_payer, currency, funded_recipient.address, 1000000, memo=memo
        )

        store = MemoryStore()
        intent = ChargeIntent(rpc_url=rpc_url, store=store)

        store_key = f"mpp:charge:{tx_hash.lower()}"
        assert await store.get(store_key) is None

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(
            payload={"type": "hash", "hash": tx_hash},
            challenge_id=challenge_id,
            expires=expires,
        )
        await intent.verify(credential, request_dict)

        assert await store.get(store_key) is not None

    async def test_verify_hash_tx_not_found(
        self, rpc_url, funded_recipient, currency, charge_intent, chain_id
    ):
        """A hash with no receipt may still be pending, so it is not a 402."""
        bogus_hash = "0x" + "00" * 32

        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "methodDetails": {"chainId": chain_id},
        }
        credential = make_credential(payload={"type": "hash", "hash": bogus_hash}, expires=expires)

        with pytest.raises(InternalPaymentError) as raised:
            await charge_intent.verify(credential, request_dict)
        assert str(internal_cause(raised.value)) == "Transaction not found"

    async def test_verify_external_id_propagated(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        """externalId in request should be parseable and not break verification."""
        method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
        )
        expires = _future_expires()
        request_dict = {
            "amount": "1000000",
            "currency": currency,
            "recipient": funded_recipient.address,
            "expires": expires,
            "externalId": "order-42",
            "methodDetails": {
                "feePayer": False,
                "chainId": chain_id,
            },
        }
        challenge = Challenge(
            id="integ-ext-id",
            method="tempo",
            intent="charge",
            request=request_dict,
            expires=expires,
        )

        credential = await method.create_credential(challenge)
        intent = ChargeIntent(rpc_url=rpc_url)
        receipt = await intent.verify(credential, request_dict)

        assert receipt.status == "success"
        assert receipt.reference.startswith("0x")

    async def test_fee_payer_wrong_recipient_rejected(
        self, rpc_url, funded_payer, funded_recipient, currency, chain_id
    ):
        fee_payer_account = TempoAccount.from_key("0x" + __import__("os").urandom(32).hex())
        _fund_account(rpc_url, fee_payer_account.address, currency)

        intent = ChargeIntent(rpc_url=rpc_url, fee_payer=fee_payer_account)

        wrong_recipient = "0x0000000000000000000000000000000000000001"
        expires = _future_expires()

        client_method = _tempo_method(
            account=funded_payer,
            chain_id=chain_id,
            rpc_url=rpc_url,
        )
        challenge = Challenge(
            id="integ-fee-payer-wrong",
            method="tempo",
            intent="charge",
            request={
                "amount": "1000000",
                "currency": currency,
                "recipient": wrong_recipient,
                "expires": expires,
                "methodDetails": {
                    "feePayer": True,
                    "chainId": chain_id,
                },
            },
            expires=expires,
        )
        credential = await client_method.create_credential(challenge)

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

        with pytest.raises(VerificationError):
            await intent.verify(credential, request_dict)


class _P256Key:
    """A P256 key signing Tempo P256 and WebAuthn sender signatures, as passkey wallets do."""

    _N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        from eth_hash.auto import keccak

        self._key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.public_key = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
        self.address = "0x" + keccak(self.public_key)[-20:].hex()

    def _sign(self, digest: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        der = self._key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        s = min(s, self._N - s)  # Tempo requires low-s P256 signatures.
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def p256(self, digest: bytes) -> bytes:
        return b"\x01" + self._sign(digest) + self.public_key + b"\x00"

    def webauthn(self, digest: bytes) -> bytes:
        import base64
        import hashlib
        import json

        authenticator_data = hashlib.sha256(b"localhost").digest() + b"\x05" + bytes(4)
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": "http://localhost"},
            separators=(",", ":"),
        ).encode()
        signed = hashlib.sha256(authenticator_data + hashlib.sha256(client_data).digest())
        return (
            b"\x02"
            + authenticator_data
            + client_data
            + self._sign(signed.digest())
            + self.public_key
        )


class TestSponsoredSignatureKinds:
    """A local fee payer co-signs keychain, P256 and WebAuthn senders and key
    authorizations, as mppx does; each payment settles on chain."""

    AMOUNT = 10_000

    @staticmethod
    async def _unsigned_tx(
        rpc_url: str,
        currency: str,
        recipient: str,
        challenge_id: str,
        key_authorization: Any = None,
    ) -> Any:
        from pytempo import Call, TempoTransaction

        chain_id, _, gas_price = await get_tx_params(rpc_url, recipient)
        memo = encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)
        data = (
            "0x95777d59"
            + recipient[2:].lower().zfill(64)
            + hex(TestSponsoredSignatureKinds.AMOUNT)[2:].zfill(64)
            + memo[2:]
        )
        return TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=1_000_000,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=min(gas_price, 10_000_000_000),
            nonce=0,
            nonce_key=(1 << 256) - 1,
            awaiting_fee_payer=True,
            valid_before=int(datetime.now(UTC).timestamp()) + 120,
            calls=(Call.create(to=currency, value=0, data=data),),
            key_authorization=key_authorization,
        )

    @staticmethod
    def _request(currency: str, recipient: str, chain_id: int) -> dict[str, Any]:
        return {
            "amount": str(TestSponsoredSignatureKinds.AMOUNT),
            "currency": currency,
            "recipient": recipient,
            "methodDetails": {"feePayer": True, "chainId": chain_id},
        }

    async def _pay(
        self,
        intent: ChargeIntent,
        signed: Any,
        challenge_id: str,
        currency: str,
        recipient: str,
        chain_id: int,
    ) -> str:
        from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

        credential = make_credential(
            payload={
                "type": "transaction",
                "signature": "0x" + encode_fee_payer_envelope(signed).hex(),
            },
            challenge_id=challenge_id,
            expires=_future_expires(),
        )
        receipt = await intent.verify(credential, self._request(currency, recipient, chain_id))
        assert receipt.status == "success"
        return receipt.reference

    async def test_access_key_authorized_in_the_sponsored_transaction(
        self, rpc_url, funded_recipient, currency, chain_id
    ):
        import os

        from pytempo.keychain import KeyAuthorization

        sponsor = TempoAccount.from_key("0x" + os.urandom(32).hex())
        root = TempoAccount.from_key("0x" + os.urandom(32).hex())
        access = TempoAccount.from_key("0x" + os.urandom(32).hex())
        for account in (sponsor, root):
            _fund_account(rpc_url, account.address, currency)
        intent = ChargeIntent(rpc_url=rpc_url, fee_payer=sponsor)
        recipient = funded_recipient.address

        authorization = KeyAuthorization(key_id=access.address, chain_id=chain_id).sign(
            root.private_key
        )
        tx = await self._unsigned_tx(
            rpc_url, currency, recipient, "integ-key-auth", key_authorization=authorization
        )
        signed = tx.sign_access_key(access.private_key, root.address)
        reference = await self._pay(intent, signed, "integ-key-auth", currency, recipient, chain_id)
        receipt = await _wait_for_receipt(rpc_url, reference)
        assert receipt["from"].lower() == root.address.lower()

        # The authorized key now pays through pympp's access-key client.
        expires = _future_expires()
        challenge = Challenge(
            id="integ-access-key",
            method="tempo",
            intent="charge",
            realm=TEST_REALM,
            request=self._request(currency, recipient, chain_id),
            expires=expires,
        )
        method = _tempo_method(
            account=access, root_account=root.address, chain_id=chain_id, rpc_url=rpc_url
        )
        credential = await method.create_credential(challenge)
        receipt_ = await intent.verify(credential, self._request(currency, recipient, chain_id))
        assert receipt_.status == "success"

    @pytest.mark.parametrize("kind", ["p256", "webauthn"])
    async def test_passkey_sender(self, rpc_url, funded_recipient, currency, chain_id, kind):
        import os

        import attrs

        from mpp.methods.tempo._fee_payer import _RawSenderSignature

        sponsor = TempoAccount.from_key("0x" + os.urandom(32).hex())
        key = _P256Key()
        _fund_account(rpc_url, sponsor.address, currency)
        _fund_account(rpc_url, key.address, currency)
        intent = ChargeIntent(rpc_url=rpc_url, fee_payer=sponsor)
        recipient = funded_recipient.address

        tx = await self._unsigned_tx(rpc_url, currency, recipient, f"integ-{kind}")
        tx = attrs.evolve(tx, sender_address=key.address)
        digest = tx.get_signing_hash(for_fee_payer=False)
        signature = key.p256(digest) if kind == "p256" else key.webauthn(digest)
        signed = attrs.evolve(tx, sender_signature=_RawSenderSignature(signature))

        sponsor_before = await _tip20(rpc_url, currency, sponsor.address)
        reference = await self._pay(intent, signed, f"integ-{kind}", currency, recipient, chain_id)
        receipt = await _wait_for_receipt(rpc_url, reference)
        assert receipt["from"].lower() == key.address
        assert await _tip20(rpc_url, currency, sponsor.address) < sponsor_before


async def _tip20(rpc_url: str, token: str, address: str) -> int:
    from tests.conftest import _tip20_balance

    with httpx.Client(timeout=30) as client:
        return _tip20_balance(rpc_url, token, address, client)
