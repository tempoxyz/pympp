"""Zero-amount proof credential parity tests from mppx ``tempo/server/Charge.test.ts``."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from _charge_node import (
    REALM,
    SECRET_KEY,
    TESTNET_CHAIN_ID,
    build_transaction,
    credential,
    did,
    memo_for,
    other,
    payer,
    recipient,
    sign,
    transfer_call,
)
from _charge_setup import (
    challenge_of,
    charge_client,
    create_credential,
    funded_node,
    make_client,
    make_server,
    problem,
    request,
    server_method,
)

from mpp import store as _store
from mpp.credential import Credential
from mpp.errors import CredentialReplayedError
from mpp.server import Mpp
from mpp.tempo import proof
from mpp.tempo._internal.account import TempoAccount, secp256k1_account
from mpp.tempo._internal.charge import MismatchError
from mpp.tempo._internal.proof import legacy_v2_typed_data

pytestmark = pytest.mark.filterwarnings("ignore:tempo.charge\\(\\) has no `store`:UserWarning")


def proof_signature(
    account: TempoAccount,
    challenge: Any,
    *,
    bound_account: str | None = None,
    chain_id: int = TESTNET_CHAIN_ID,
    realm: str | None = None,
) -> str:
    return account.sign_typed_data(
        proof.typed_data(
            account=bound_account or account.address,
            chain_id=chain_id,
            challenge_id=challenge.id,
            realm=realm or challenge.realm,
        )
    )


def proof_credential(
    challenge: Any, signature: str, source: str | None = "auto", address: str | None = None
) -> str:
    return credential(
        challenge,
        {"signature": signature, "type": "proof"},
        did(address or payer().address) if source == "auto" else source,
    )


class TestProof:
    async def test_end_to_end_zero_dollar_auth(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="0", decimals=6)
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200
        # No transaction RPC: the client confirms its RPC client's chain (once, cached).
        assert node.methods == ["eth_chainId"]

    async def test_credential_contains_valid_source_did(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        value = Credential.deserialize(await create_credential(charge_client(node), challenge))
        assert value.payload["type"] == "proof"
        assert value.source == f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{payer().address}"
        assert (await request(handler, value.serialize())).status == 200

    async def test_reusable_until_expiry_without_store(self) -> None:
        node = funded_node()
        server = Mpp(methods=[server_method(node, store=None)], realm=REALM, secret_key=SECRET_KEY)
        handler = server.charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        value = proof_credential(challenge, proof_signature(payer(), challenge))
        assert (await request(handler, value)).status == 200
        assert (await request(handler, value)).status == 200

    async def test_rejects_replay_when_store_is_configured(self) -> None:
        node = funded_node()
        handler = make_server(node, store=_store.memory()).charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        value = proof_credential(challenge, proof_signature(payer(), challenge))
        assert (await request(handler, value)).status == 200
        replay = await request(handler, value)
        assert replay.status == 403
        assert "Proof credential has already been used" in (await problem(replay))["detail"]

    async def test_rejects_concurrent_replay(self) -> None:
        node = funded_node()
        server = make_server(node, store=_store.memory())
        challenge = await server.challenge.tempo.charge(amount="0", decimals=6)
        value = proof_credential(challenge, proof_signature(payer(), challenge))
        results = await asyncio.gather(
            server.verify_credential(value), server.verify_credential(value), return_exceptions=True
        )
        assert sum(isinstance(r, CredentialReplayedError) for r in results) == 1

    async def test_shared_store_rejects_replay_across_servers(self) -> None:
        node = funded_node()
        store = _store.memory()
        first, second = make_server(node, store=store), make_server(node, store=store)
        challenge = await first.challenge.tempo.charge(amount="0", decimals=6)
        value = proof_credential(challenge, proof_signature(payer(), challenge))
        await first.verify_credential(value)
        with pytest.raises(CredentialReplayedError):
            await second.verify_credential(value)

    async def test_store_keys_replay_protection_by_challenge_id(self) -> None:
        node = funded_node()
        store = _store.memory()
        server = make_server(node, store=store, store_key_prefix="tenant:")
        challenge1 = await server.challenge.tempo.charge(amount="0", decimals=6)
        challenge2 = await server.challenge.tempo.charge(amount="0", decimals=6)
        await server.verify_credential(
            proof_credential(challenge1, proof_signature(payer(), challenge1))
        )
        await server.verify_credential(
            proof_credential(challenge2, proof_signature(payer(), challenge2))
        )
        assert await store.get(f"tenant:mppx:charge:proof:{challenge1.id}") is not None
        assert await store.get(f"mppx:charge:proof:{challenge1.id}") is None

    async def test_receipt_reference_is_the_challenge_id(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="0", decimals=6)
        receipt = await server.verify_credential(
            proof_credential(challenge, proof_signature(payer(), challenge))
        )
        assert receipt.reference == challenge.id
        assert receipt.method == "tempo"

    @pytest.mark.parametrize(
        ("case", "message"),
        [
            ("wrong signer", "Proof signature does not match source."),
            ("no source", "Proof credential must include a source."),
            ("wrong chain domain", "Proof signature does not match source."),
            ("wrong realm", "Proof signature does not match source."),
            ("source chain mismatch", "Proof credential source is invalid."),
            ("malformed source", "Proof credential source is invalid."),
            ("v2 proof", "Proof signature does not match source."),
        ],
    )
    async def test_rejects_invalid_proofs(self, case: str, message: str) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        signature = proof_signature(payer(), challenge)
        source: str | None = "auto"
        match case:
            case "wrong signer":
                signature = proof_signature(other(), challenge, bound_account=payer().address)
            case "no source":
                source = None
            case "wrong chain domain":
                signature = proof_signature(payer(), challenge, chain_id=4217)
            case "wrong realm":
                signature = proof_signature(payer(), challenge, realm="other.example.com")
            case "source chain mismatch":
                source = did(payer().address, 4217)
            case "malformed source":
                source = "did:pkh:eip155:not-a-chain:0x123"
            case "v2 proof":
                signature = payer().sign_typed_data(
                    legacy_v2_typed_data(
                        chain_id=TESTNET_CHAIN_ID, challenge_id=challenge.id, realm=challenge.realm
                    )
                )
        response = await request(handler, proof_credential(challenge, signature, source))
        assert response.status == 402
        assert message in (await problem(response))["detail"]

    @pytest.mark.parametrize("payload_type", ["transaction", "hash"])
    async def test_rejects_non_proof_payloads_for_zero_amount(self, payload_type: str) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="0", decimals=6)
        payload = (
            {"hash": "0x" + "ab" * 32, "type": "hash"}
            if payload_type == "hash"
            else {
                "signature": sign(
                    payer(),
                    build_transaction(
                        [transfer_call(challenge.request["currency"], recipient().address, 0)]
                    ),
                ),
                "type": "transaction",
            }
        )
        with pytest.raises(
            MismatchError, match="Zero-amount challenges require a proof credential"
        ):
            await server.verify_credential(credential(challenge, payload))

    async def test_rejects_proof_for_non_zero_amount(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        with pytest.raises(MismatchError, match="only valid for zero-amount challenges"):
            await server.verify_credential(
                proof_credential(challenge, proof_signature(payer(), challenge))
            )


class TestAccessKeyProofs:
    @pytest.mark.parametrize(
        ("state", "expected"),
        [("authorized", 200), ("unauthorized", 402), ("revoked", 402), ("expired", 402)],
    )
    async def test_access_key_proofs(self, state: str, expected: int) -> None:
        node = funded_node()
        root = payer()
        access = secp256k1_account("0x" + "07" * 32, access=root.address)
        assert access.access_key_address is not None
        now = int(time.time())
        if state == "authorized":
            node.authorize_access_key(root.address, access.access_key_address, expiry=now + 3600)
        elif state == "revoked":
            node.access_keys[(root.address.lower(), access.access_key_address.lower())] = (
                0,
                now + 3600,
                True,
            )
        elif state == "expired":
            node.authorize_access_key(root.address, access.access_key_address, expiry=now - 5)
        handler = make_server(node).charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        response = await request(
            handler,
            proof_credential(
                challenge, proof_signature(access, challenge, bound_account=root.address)
            ),
        )
        assert response.status == expected
        if expected == 402:
            assert "Proof signature does not match source." in (await problem(response))["detail"]

    async def test_rejects_access_key_proof_replayed_across_co_authorized_account(self) -> None:
        node = funded_node()
        access = secp256k1_account("0x" + "07" * 32, access=payer().address)
        assert access.access_key_address is not None
        expiry = int(time.time()) + 3600
        node.authorize_access_key(payer().address, access.access_key_address, expiry=expiry)
        node.authorize_access_key(other().address, access.access_key_address, expiry=expiry)
        handler = make_server(node).charge(amount="0", decimals=6)
        challenge = await challenge_of(handler)
        signature = proof_signature(access, challenge, bound_account=payer().address)
        assert (await request(handler, proof_credential(challenge, signature))).status == 200
        stolen = await request(
            handler, proof_credential(challenge, signature, address=other().address)
        )
        assert stolen.status == 402
        assert "Proof signature does not match source." in (await problem(stolen))["detail"]


def test_memo_helper_is_challenge_bound() -> None:
    from mpp.challenge import Challenge

    challenge = Challenge(id="abc", realm=REALM, method="tempo", intent="charge", request={})
    assert memo_for(challenge).startswith("0x")
