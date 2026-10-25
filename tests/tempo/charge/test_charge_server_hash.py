"""Hash (push) credential parity tests from mppx ``tempo/server/Charge.test.ts``."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta

import pytest
from _charge_node import (
    CURRENCY,
    REALM,
    TESTNET_CHAIN_ID,
    build_transaction,
    credential,
    did,
    memo_for,
    other,
    payer,
    receipt_json,
    recipient,
    sign,
    transfer_call,
    transfer_logs,
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
)

from mpp import store as _store
from mpp.errors import CredentialReplayedError
from mpp.receipt import Receipt
from mpp.tempo._internal.charge import MismatchError
from mpp.tempo.server import ValidateSenderParams


def push(node, account, calls) -> str:  # type: ignore[no-untyped-def]
    return node.handle("eth_sendRawTransaction", [sign(account, build_transaction(calls))])


def pay_hash(node, challenge, *, account=None, memo=None, amount=None, to=None) -> str:  # type: ignore[no-untyped-def]
    return push(
        node,
        account or payer(),
        [
            transfer_call(
                challenge.request["currency"],
                to or challenge.request["recipient"],
                amount if amount is not None else int(challenge.request["amount"]),
                memo if memo is not None else memo_for(challenge),
            )
        ],
    )


class TestHashCredential:
    async def test_default(self) -> None:
        node = funded_node()
        server = make_server(node)
        handler = server.charge(amount="1", decimals=6)
        client = make_client(node, handler, mode="push")
        response = await client.fetch("https://api.example.com/paid")
        assert response.status_code == 200
        receipt = Receipt.from_headers(response.headers)
        assert receipt.to_dict() | {"reference": "[r]", "timestamp": "[t]"} == {
            "fundingCurrency": CURRENCY,
            "method": "tempo",
            "reference": "[r]",
            "status": "success",
            "timestamp": "[t]",
        }

    async def test_overrides(self) -> None:
        node = funded_node()
        server = make_server(node)
        expires = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
        handler = server.charge(
            amount="1", currency=CURRENCY, expires=expires, recipient=other().address
        )
        response = await make_client(node, handler, mode="push").fetch(
            "https://api.example.com/paid"
        )
        assert response.status_code == 200
        receipt = Receipt.from_headers(response.headers)
        assert receipt.funding_currency == CURRENCY
        assert node.balance(CURRENCY, other().address) == 1_000_000

    async def test_client_rejects_unsupported_explicit_push_mode(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="1", decimals=6, supported_modes=["pull"])
        challenge = await challenge_of(handler)
        with pytest.raises(ValueError, match=re.escape("Challenge does not support push mode.")):
            await create_credential(charge_client(node, mode="push"), challenge)

    async def test_falls_back_to_pull_when_push_is_not_advertised(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="1", decimals=6, supported_modes=["pull"])
        challenge = await challenge_of(handler)
        serialized = await create_credential(charge_client(node), challenge)
        from mpp.credential import Credential

        assert Credential.deserialize(serialized).payload["type"] == "transaction"
        assert (await request(handler, serialized)).status == 200

    async def test_rejects_hash_when_challenge_supports_only_pull(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="1", decimals=6, supported_modes=["pull"])
        challenge = await challenge_of(handler)
        tx_hash = pay_hash(node, challenge)
        response = await request(handler, credential(challenge, {"hash": tx_hash, "type": "hash"}))
        assert response.status == 402
        assert (
            "Hash credentials are not supported for this challenge."
            in (await problem(response))["detail"]
        )

    async def test_rejects_transaction_when_challenge_supports_only_push(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="1", decimals=6, supported_modes=["push"])
        challenge = await challenge_of(handler)
        signature = sign(
            payer(),
            build_transaction(
                [
                    transfer_call(
                        CURRENCY,
                        challenge.request["recipient"],
                        1_000_000,
                        memo_for(challenge),
                    )
                ]
            ),
        )
        response = await request(
            handler, credential(challenge, {"signature": signature, "type": "transaction"})
        )
        assert response.status == 402
        assert (
            "Transaction credentials are not supported for this challenge."
            in (await problem(response))["detail"]
        )

    @pytest.mark.parametrize("variant", ["same", "alternating-case"])
    async def test_rejects_replayed_transaction_hash(self, variant: str) -> None:
        node = funded_node()
        store = _store.memory()
        server = make_server(node, store=store, store_key_prefix="tenant:")
        handler = server.charge(amount="1", decimals=6)
        challenge = await challenge_of(handler)
        tx_hash = pay_hash(node, challenge)
        first = await request(handler, credential(challenge, {"hash": tx_hash, "type": "hash"}))
        assert first.status == 200
        assert await store.get(f"tenant:mppx:charge:{tx_hash}") is not None
        assert await store.get(f"mppx:charge:{tx_hash}") is None
        replayed = (
            tx_hash
            if variant == "same"
            else "0x" + "".join(c.upper() if i % 2 else c for i, c in enumerate(tx_hash[2:]))
        )
        second = await request(handler, credential(challenge, {"hash": replayed, "type": "hash"}))
        assert second.status == 403
        assert "www-authenticate" not in second.headers
        assert "Transaction hash has already been used." in (await problem(second))["detail"]

    async def test_rejects_replayed_hash_on_the_same_challenge(self) -> None:
        node = funded_node()
        server = make_server(node, store=_store.memory())
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        tx_hash = pay_hash(node, challenge)
        value = credential(challenge, {"hash": tx_hash, "type": "hash"})
        await server.verify_credential(value)
        upper = credential(challenge, {"hash": "0x" + tx_hash[2:].upper(), "type": "hash"})
        with pytest.raises(CredentialReplayedError, match="Transaction hash has already been used"):
            await server.verify_credential(upper)

    async def test_accepts_uppercase_hash_on_first_use(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        tx_hash = pay_hash(node, challenge)
        receipt = await server.verify_credential(
            credential(challenge, {"hash": "0x" + tx_hash[2:].upper(), "type": "hash"})
        )
        assert receipt.reference == tx_hash

    async def test_rejects_hash_with_non_matching_transfer_log(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        tx_hash = pay_hash(node, challenge, amount=1)
        with pytest.raises(MismatchError, match="no matching transfer found"):
            await server.verify_credential(credential(challenge, {"hash": tx_hash, "type": "hash"}))

    async def test_accepts_split_payments(self) -> None:
        node = funded_node()
        server = make_server(node)
        handler = server.charge(
            amount="1", decimals=6, splits=[{"amount": "0.25", "recipient": other().address}]
        )
        response = await make_client(node, handler, mode="push").fetch(
            "https://api.example.com/paid"
        )
        assert response.status_code == 200
        assert node.balance(CURRENCY, recipient().address) == 750_000
        assert node.balance(CURRENCY, other().address) == 250_000

    async def test_accepts_split_transfers_out_of_order(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(
            amount="1", decimals=6, splits=[{"amount": "0.25", "recipient": other().address}]
        )
        memo = memo_for(challenge)
        tx_hash = push(
            node,
            payer(),
            [
                transfer_call(CURRENCY, other().address, 250_000),
                transfer_call(CURRENCY, recipient().address, 750_000, memo),
            ],
        )
        receipt = await server.verify_credential(
            credential(challenge, {"hash": tx_hash, "type": "hash"})
        )
        assert receipt.status == "success"

    async def test_rejects_expired_request(self) -> None:
        node = funded_node()
        server = make_server(node)
        handler = server.charge(
            amount="1", expires=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        )
        response = await request(handler)
        assert response.status == 402
        from mpp.challenge import Challenge

        challenge = Challenge.deserialize(response.headers["www-authenticate"])
        tx_hash = pay_hash(node, challenge)
        rejected = await request(handler, credential(challenge, {"hash": tx_hash, "type": "hash"}))
        assert rejected.status == 402
        assert (await problem(rejected))["detail"].startswith("Payment expired at ")

    async def test_rejects_when_no_client_configured_for_chain(self) -> None:
        node = funded_node()
        rpc = node.client()

        def get_client(chain_id: int | None):  # type: ignore[no-untyped-def]
            if chain_id == TESTNET_CHAIN_ID:
                return rpc
            raise LookupError("not found")

        server = make_server(node, get_client=get_client)
        with pytest.raises(ValueError, match=r"^No client configured with chainId 123456\.$"):
            await request(server.charge(amount="1", chain_id=123456))


class TestPayer:
    @pytest.mark.parametrize("mode", ["push", "pull"])
    async def test_exposes_sender_on_payment_success(self, mode: str) -> None:
        node = funded_node()
        payers: list[str | None] = []
        server = make_server(node, on_payment_success=lambda ctx: payers.append(ctx.payer))
        server.on_payment_success(lambda event: payers.append(event.payer))
        handler = server.charge(amount="1", decimals=6)
        response = await make_client(node, handler, mode=mode).fetch("https://api.example.com/paid")
        assert response.status_code == 200
        assert [p.lower() if p else p for p in payers] == [payer().address.lower()] * 2

    @pytest.mark.parametrize(
        ("submitter", "senders", "expected"),
        [
            ("payer", ("payer", "payer"), "payer"),
            ("other", ("payer", "payer"), "payer"),
            ("payer", ("payer", "other"), None),
        ],
        ids=["direct", "relayed", "mixed-sender"],
    )
    async def test_reports_debited_account_for_hash_credentials(
        self, submitter: str, senders: tuple[str, str], expected: str | None
    ) -> None:
        accounts = {"payer": payer().address, "other": other().address}
        node = funded_node()
        tx_hash = "0x" + "ab" * 32
        server = make_server(node, validate_sender=lambda _: True)
        challenge = await server.challenge.tempo.charge(
            amount="1", decimals=6, splits=[{"amount": "0.2", "recipient": other().address}]
        )
        memo = memo_for(challenge)
        node.receipts[tx_hash] = receipt_json(
            transaction_hash=tx_hash,
            sender=accounts[submitter],
            logs=[
                *transfer_logs(
                    CURRENCY, accounts[senders[0]], recipient().address, 800_000, memo, 0
                ),
                *transfer_logs(CURRENCY, accounts[senders[1]], other().address, 200_000, memo, 2),
            ],
        )
        validation = await server.validate_credential(
            credential(challenge, {"hash": tx_hash, "type": "hash"})
        )
        assert validation.payer == (accounts[expected].lower() if expected else None)


class TestHashSource:
    """Attribution-memo source checks for hash credentials (mppx ``attribution memo`` block)."""

    @staticmethod
    async def relayed(
        *,
        source_account: str,
        transfer_sender: str,
        submitter: str,
        source: str | None = "auto",
        validate_sender=None,  # type: ignore[no-untyped-def]
        splits: bool = False,
    ):  # type: ignore[no-untyped-def]
        node = funded_node()
        tx_hash = "0x" + "cd" * 32
        server = make_server(node, validate_sender=validate_sender)
        options = {"splits": [{"amount": "0.2", "recipient": other().address}]} if splits else {}
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6, **options)
        memo = memo_for(challenge)
        logs = transfer_logs(
            CURRENCY,
            transfer_sender,
            recipient().address,
            800_000 if splits else 1_000_000,
            memo,
            0,
        )
        if splits:
            logs += transfer_logs(CURRENCY, transfer_sender, other().address, 200_000, None, 2)
        node.receipts[tx_hash] = receipt_json(transaction_hash=tx_hash, sender=submitter, logs=logs)
        value = credential(
            challenge,
            {"hash": tx_hash, "type": "hash"},
            did(source_account) if source == "auto" else source,
        )
        return node, server, value

    async def test_verifies_transfers_from_credential_source(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=payer().address,
        )
        assert (await server.verify_credential(value)).status == "success"

    async def test_verifies_transfers_from_receipt_sender_without_source(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=payer().address,
            source=None,
        )
        assert (await server.verify_credential(value)).status == "success"

    async def test_verifies_transfers_from_source_when_receipt_sender_differs(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=other().address,
        )
        validation = await server.validate_credential(value)
        assert validation.payer == payer().address.lower()
        assert (await server.verify_credential(value)).status == "success"

    async def test_rejects_transfers_from_a_different_source(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=other().address,
            submitter=other().address,
        )
        with pytest.raises(MismatchError, match="no matching transfer found"):
            await server.verify_credential(value)

    async def test_accepts_different_source_when_validate_sender_allows(self) -> None:
        seen: list[ValidateSenderParams] = []

        async def validate_sender(params: ValidateSenderParams) -> bool:
            seen.append(params)
            return True

        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=other().address,
            submitter=other().address,
            validate_sender=validate_sender,
        )
        assert (await server.verify_credential(value)).status == "success"
        assert seen[0].sender.lower() == other().address.lower()
        assert seen[0].expected_sender == payer().address
        assert seen[0].source is not None
        assert seen[0].source.chain_id == TESTNET_CHAIN_ID

    async def test_skips_validate_sender_when_source_matches(self) -> None:
        calls: list[ValidateSenderParams] = []
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=payer().address,
            validate_sender=lambda params: calls.append(params) or False,
        )
        assert (await server.verify_credential(value)).status == "success"
        assert calls == []

    async def test_rejects_malformed_source_without_consuming_hash(self) -> None:
        _node, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=payer().address,
            source="did:pkh:eip155:42431:not-an-address",
        )
        with pytest.raises(MismatchError, match=re.escape("Hash credential source is invalid.")):
            await server.verify_credential(value)
        from mpp.credential import Credential

        parsed = Credential.deserialize(value)
        retry = credential(parsed.challenge, parsed.payload, did(payer().address))
        assert (await server.verify_credential(retry)).status == "success"

    async def test_rejects_source_from_a_different_chain(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=payer().address,
            source=did(payer().address, 4217),
        )
        with pytest.raises(MismatchError, match=re.escape("Hash credential source is invalid.")):
            await server.verify_credential(value)

    async def test_verifies_split_transfers_from_source(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=payer().address,
            submitter=other().address,
            splits=True,
        )
        assert (await server.verify_credential(value)).status == "success"

    async def test_rejects_split_transfers_from_a_different_source(self) -> None:
        _, server, value = await self.relayed(
            source_account=payer().address,
            transfer_sender=other().address,
            submitter=other().address,
            splits=True,
        )
        with pytest.raises(MismatchError, match="no matching transfer found"):
            await server.verify_credential(value)

    async def test_rejects_one_transfer_with_memo_reused_for_duplicate_expected_transfers(
        self,
    ) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(
            amount="1", decimals=6, splits=[{"amount": "0.5", "recipient": recipient().address}]
        )
        tx_hash = pay_hash(node, challenge, amount=500_000)
        with pytest.raises(MismatchError, match="no matching transfer found"):
            await server.verify_credential(credential(challenge, {"hash": tx_hash, "type": "hash"}))


class TestHashMemoBinding:
    async def test_client_always_generates_attribution_memo(self) -> None:
        from mpp.tempo import attribution

        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = await create_credential(charge_client(node, mode="push"), challenge)
        from mpp.credential import Credential

        tx_hash = Credential.deserialize(value).payload["hash"]
        memo = node.receipts[tx_hash]["logs"][1]["topics"][3]
        assert attribution.is_mpp_memo(memo)
        assert attribution.verify_server(memo, REALM)
        assert attribution.verify_challenge_binding(memo, challenge.id)
        assert (await server.verify_credential(value)).status == "success"

    async def test_anonymous_client_generates_valid_memo(self) -> None:
        from mpp.tempo import attribution

        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = await create_credential(charge_client(node, mode="push"), challenge)
        from mpp.credential import Credential

        memo = node.receipts[Credential.deserialize(value).payload["hash"]]["logs"][1]["topics"][3]
        decoded = attribution.decode(memo)
        assert decoded is not None
        assert decoded.client_fingerprint is None

    @pytest.mark.parametrize(
        ("memo", "message"),
        [
            ("other-challenge", "memo is not bound to this challenge"),
            ("non-mpp", "memo is not bound to this challenge"),
            ("plain", "memo is not bound to this challenge"),
        ],
    )
    async def test_rejects_unbound_memos(self, memo: str, message: str) -> None:
        from mpp.tempo import attribution

        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        memo_value = {
            "other-challenge": attribution.encode(challenge_id="stolen", server_id=REALM),
            "non-mpp": "0x" + "ab" * 32,
            "plain": None,
        }[memo]
        if memo_value is None:
            tx_hash = push(node, payer(), [transfer_call(CURRENCY, recipient().address, 1_000_000)])
        else:
            tx_hash = pay_hash(node, challenge, memo=memo_value)
        with pytest.raises(CredentialReplayedError, match=message):
            await server.verify_credential(credential(challenge, {"hash": tx_hash, "type": "hash"}))

    async def test_rejects_challenge_nonce_on_dust_transfer(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        tx_hash = push(
            node,
            payer(),
            [
                transfer_call(CURRENCY, recipient().address, 1_000_000, "0x" + "ab" * 32),
                transfer_call(CURRENCY, recipient().address, 1, memo_for(challenge)),
            ],
        )
        with pytest.raises(CredentialReplayedError, match="memo is not bound to this challenge"):
            await server.verify_credential(credential(challenge, {"hash": tx_hash, "type": "hash"}))


class TestConcurrentHashReplay:
    async def test_rejects_concurrent_replay_of_the_same_transaction_hash(self) -> None:
        node = funded_node()
        server = make_server(node, store=_store.memory())
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = credential(challenge, {"hash": pay_hash(node, challenge), "type": "hash"})
        results = await asyncio.gather(
            server.verify_credential(value), server.verify_credential(value), return_exceptions=True
        )
        assert sum(isinstance(r, Receipt) for r in results) == 1
        assert sum(isinstance(r, CredentialReplayedError) for r in results) == 1
