"""Transaction (pull) credential parity tests from mppx ``tempo/server/Charge.test.ts``."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import pytest
from _charge_node import (
    CURRENCY,
    DEFAULT,
    FakeTempoNode,
    build_transaction,
    credential,
    did,
    memo_for,
    other,
    payer,
    recipient,
    sign,
    sponsor,
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
from pytempo import Call

from mpp.credential import Credential
from mpp.errors import CredentialReplayedError
from mpp.receipt import Receipt
from mpp.tempo._internal import abi
from mpp.tempo._internal.account import secp256k1_account
from mpp.tempo._internal.charge import MismatchError
from mpp.tempo._internal.fee_payer import FeePayerValidationError
from mpp.tempo._internal.hexutil import keccak256, rlp_decode, rlp_encode, to_bytes, to_hex
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer
from mpp.tempo._internal.rpc import RpcError
from mpp.tempo.assets import PATH_USD_ADDRESS


def keccak(serialized: str) -> str:
    return to_hex(keccak256(to_bytes(serialized)))


def signed_payment(
    challenge: Any, *, account: Any = None, fee_payer: bool = False, **kw: Any
) -> str:
    calls = kw.pop("calls", None) or [
        transfer_call(
            challenge.request["currency"],
            challenge.request["recipient"],
            int(challenge.request["amount"]),
            memo_for(challenge),
        )
    ]
    return sign(account or payer(), build_transaction(calls, fee_payer=fee_payer, **kw))


def with_fee_token(serialized: str, fee_token: str) -> str:
    """Re-encodes a ``0x78`` sender envelope committing to ``fee_token`` (ox ``format: feePayer``)."""
    fields = rlp_decode(to_bytes(serialized)[1:])
    fields[10] = to_bytes(fee_token)
    return "0x78" + rlp_encode(fields).hex()


def as_awaiting_0x76(serialized: str) -> str:
    """The ``0x76`` form of a ``0x78`` sender envelope awaiting its fee payer (ox ``0x00`` slot)."""
    fields = rlp_decode(to_bytes(serialized)[1:])
    fields[11] = b"\x00"
    return "0x76" + rlp_encode(fields).hex()


def tx_credential(challenge: Any, signature: str, source: str | None = None) -> str:
    return credential(challenge, {"signature": signature, "type": "transaction"}, source)


class TestTransactionCredential:
    @pytest.mark.parametrize("wait", [True, False], ids=["confirmed", "optimistic"])
    async def test_default(self, wait: bool) -> None:
        node = funded_node()
        server = make_server(node, wait_for_confirmation=wait)
        handler = server.charge(amount="1", decimals=6)
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200
        receipt = Receipt.from_headers(response.headers)
        assert receipt.status == "success"
        assert receipt.funding_currency == CURRENCY
        assert node.count("eth_sendRawTransactionSync" if wait else "eth_sendRawTransaction") == 1
        assert node.balance(CURRENCY, recipient().address) == 1_000_000

    @pytest.mark.parametrize(
        ("rpc_method", "wait"),
        [("eth_sendRawTransactionSync", True), ("eth_sendRawTransaction", False)],
    )
    async def test_canonicalizes_raw_recovery_ids(self, rpc_method: str, wait: bool) -> None:
        node = funded_node()
        server = make_server(node, wait_for_confirmation=wait)
        handler = server.charge(amount="1", currency=CURRENCY, recipient=recipient().address)
        challenge = await challenge_of(handler)
        canonical_credential = await create_credential(charge_client(node), challenge)
        canonical = Credential.deserialize(canonical_credential).payload["signature"]
        # Electrum-encoded recovery ID (27/28) -> raw recovery ID (0/1).
        assert canonical[-2:] in ("1b", "1c")
        raw = canonical[:-2] + ("00" if canonical.endswith("1b") else "01")
        assert keccak(raw) != keccak(canonical)
        response = await request(handler, tx_credential(challenge, raw))
        assert response.status == 200
        broadcasts = [params[0] for method, params in node.requests if method == rpc_method]
        assert broadcasts == [canonical]
        assert Receipt.from_headers(response.headers).reference == keccak(canonical)
        replay = await request(handler, canonical_credential)
        assert replay.status == 403
        assert "www-authenticate" not in replay.headers

    @pytest.mark.parametrize("wait", [True, False], ids=["confirmed", "optimistic"])
    async def test_rechecks_expiry_before_broadcast(
        self, wait: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # pympp#319 / mppx#1078: a challenge that expires during simulation is not settled.
        from mpp import expires

        node = funded_node()
        handler = make_server(node, wait_for_confirmation=wait).charge(
            amount="1", currency=CURRENCY, recipient=recipient().address
        )
        challenge = await challenge_of(handler)
        signed = await create_credential(charge_client(node), challenge)
        expected_calls = node.count("eth_call")
        dry_run = funded_node()
        dry_handler = make_server(dry_run, wait_for_confirmation=wait).charge(
            amount="1", currency=CURRENCY, recipient=recipient().address
        )
        dry_challenge = await challenge_of(dry_handler)
        dry_credential = await create_credential(charge_client(dry_run), dry_challenge)
        before = dry_run.count("eth_call")
        assert (await request(dry_handler, dry_credential)).status == 200
        settle_calls = dry_run.count("eth_call") - before

        real_now = expires.now
        seen = 0

        def last_simulation_expires(_: list[Any]) -> Any:
            nonlocal seen
            seen += 1
            if seen == settle_calls:
                parsed = expires.parse(challenge.expires)
                assert parsed is not None
                monkeypatch.setattr(expires, "now", lambda: parsed)
            return DEFAULT

        node.on("eth_call", last_simulation_expires)
        response = await request(handler, signed)
        assert response.status == 402
        assert "expired" in (await problem(response))["type"]
        assert node.count("eth_sendRawTransactionSync") + node.count("eth_sendRawTransaction") == 0
        assert node.count("eth_call") == expected_calls + settle_calls
        # The hash claim was released, so the signed transaction settles before expiry.
        monkeypatch.setattr(expires, "now", real_now)
        node.overrides.clear()
        assert (await request(handler, signed)).status == 200

    async def test_rejects_pull_then_push_replay(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(
            amount="1", currency=CURRENCY, recipient=recipient().address
        )
        challenge = await challenge_of(handler)
        pulled = await create_credential(charge_client(node, mode="pull"), challenge)
        response = await request(handler, pulled)
        assert response.status == 200
        reference = Receipt.from_headers(response.headers).reference
        replay = await request(handler, credential(challenge, {"hash": reference, "type": "hash"}))
        assert replay.status == 403
        assert "www-authenticate" not in replay.headers
        assert "Transaction hash has already been used." in (await problem(replay))["detail"]

    async def test_rejects_concurrent_replay_of_the_same_serialized_transaction(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(
            amount="1", currency=CURRENCY, recipient=recipient().address
        )
        first, second = await asyncio.gather(challenge_of(handler), challenge_of(handler))
        credential1 = await create_credential(charge_client(node), first)
        credential2 = credential(second, Credential.deserialize(credential1).payload)
        responses = await asyncio.gather(
            request(handler, credential1), request(handler, credential2)
        )
        assert sorted(r.status for r in responses) == [200, 402]

    async def test_rejects_concurrent_replay_of_the_same_credential(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = tx_credential(challenge, signed_payment(challenge))
        results = await asyncio.gather(
            server.verify_credential(value), server.verify_credential(value), return_exceptions=True
        )
        assert sum(isinstance(r, Receipt) for r in results) == 1
        assert sum(isinstance(r, CredentialReplayedError) for r in results) == 1

    async def test_rejects_malleable_fee_payer_variants(self) -> None:
        node = funded_node()
        server = make_server(node)
        handler = server.charge(
            fee_payer=sponsor(), amount="1", currency=CURRENCY, recipient=recipient().address
        )
        first, second = await challenge_of(handler), await challenge_of(handler)
        credential1 = await create_credential(charge_client(node), first)
        assert (await request(handler, credential1)).status == 200
        serialized = Credential.deserialize(credential1).payload["signature"]
        assert serialized.startswith("0x78")
        variant = as_awaiting_0x76(serialized)
        assert variant != serialized
        response = await request(handler, tx_credential(second, variant))
        assert response.status == 402

    async def test_rejects_non_tempo_transaction_type(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        with pytest.raises(MismatchError, match=r"Only Tempo \(0x76/0x78\) transactions"):
            await server.verify_credential(tx_credential(challenge, "0x02f86c0180"))

    async def test_rejects_unsigned_transaction(self) -> None:
        node = funded_node()
        server = make_server(node, fee_payer=sponsor())
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        # ox serializes an unsigned sponsored transaction as its signing preimage.
        unsigned = to_hex(
            build_transaction(
                [transfer_call(CURRENCY, recipient().address, 1_000_000, memo_for(challenge))],
                fee_payer=True,
            ).encode_for_signing()
        )
        with pytest.raises(MismatchError, match="must be signed by the sender"):
            await server.verify_credential(tx_credential(challenge, unsigned))

    async def test_rejects_credential_that_claims_a_different_source(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = tx_credential(challenge, signed_payment(challenge), did(other().address))
        with pytest.raises(MismatchError, match="source does not match the sender"):
            await server.verify_credential(value)
        bad_chain = tx_credential(challenge, signed_payment(challenge), did(payer().address, 4217))
        with pytest.raises(
            MismatchError, match=re.escape("Transaction credential source is invalid.")
        ):
            await server.verify_credential(bad_chain)

    @pytest.mark.parametrize("wait", [True, False], ids=["confirmed", "optimistic"])
    async def test_rejects_wrong_challenge_nonce(self, wait: bool) -> None:
        node = funded_node()
        server = make_server(node, wait_for_confirmation=wait)
        stolen = await server.challenge.tempo.charge(amount="1", decimals=6)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        with pytest.raises(MismatchError, match="memo is not bound to this challenge"):
            await server.verify_credential(tx_credential(challenge, signed_payment(stolen)))
        assert node.count("eth_sendRawTransactionSync") + node.count("eth_sendRawTransaction") == 0

    async def test_rejects_plain_transfer_without_bound_memo(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        signature = sign(
            payer(), build_transaction([transfer_call(CURRENCY, recipient().address, 1_000_000)])
        )
        with pytest.raises(MismatchError, match="memo is not bound to this challenge"):
            await server.verify_credential(tx_credential(challenge, signature))

    async def test_rejects_pull_transaction_when_receipt_has_no_transfer_log(self) -> None:
        node = funded_node()
        original = node.handle

        def without_logs(params: list[Any]) -> Any:
            receipt = original("eth_sendRawTransactionSync", params)
            receipt = {**receipt, "logs": []}
            node.receipts[receipt["transactionHash"]] = receipt
            return receipt

        node.on("eth_sendRawTransactionSync", without_logs)
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        with pytest.raises(MismatchError, match="no matching transfer found"):
            await server.verify_credential(tx_credential(challenge, signed_payment(challenge)))

    async def test_accepts_split_transaction_out_of_order(self) -> None:
        node = funded_node()
        server = make_server(node)
        challenge = await server.challenge.tempo.charge(
            amount="1", decimals=6, splits=[{"amount": "0.25", "recipient": other().address}]
        )
        signature = sign(
            payer(),
            build_transaction(
                [
                    transfer_call(CURRENCY, other().address, 250_000),
                    transfer_call(CURRENCY, recipient().address, 750_000, memo_for(challenge)),
                ]
            ),
        )
        receipt = await server.verify_credential(tx_credential(challenge, signature))
        assert receipt.status == "success"

    async def test_rejects_invalid_payload_schema(self) -> None:
        node = funded_node()
        handler = make_server(node).charge(amount="1", decimals=6)
        challenge = await challenge_of(handler)
        response = await request(handler, credential(challenge, {"type": "unknown"}))
        assert response.status == 402

    async def test_access_keys(self) -> None:
        node = funded_node()
        access = secp256k1_account("0x" + "05" * 32, access=payer().address)
        handler = make_server(node).charge(amount="1", decimals=6)
        response = await make_client(node, handler, account=access).fetch(
            "https://api.example.com/paid"
        )
        assert response.status_code == 200
        assert node.balance(CURRENCY, recipient().address) == 1_000_000


class TestFeePayer:
    async def test_fee_payer(self) -> None:
        node = funded_node()
        handler = make_server(node, fee_payer=sponsor()).charge(amount="1", decimals=6)
        challenge = await challenge_of(handler)
        assert challenge.request["methodDetails"]["feePayer"] is True
        value = await create_credential(charge_client(node), challenge)
        assert Credential.deserialize(value).payload["signature"].startswith("0x78")
        response = await request(handler, value)
        assert response.status == 200
        (receipt,) = node.receipts.values()
        assert receipt["feeToken"].lower() == PATH_USD_ADDRESS

    async def test_fee_payer_hoisted_account(self) -> None:
        node = funded_node()
        handler = make_server(node, account=recipient(), fee_payer=True).charge(
            amount="1", decimals=6
        )
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200

    async def test_fee_payer_with_splits(self) -> None:
        node = funded_node()
        handler = make_server(node, fee_payer=sponsor()).charge(
            amount="1", decimals=6, splits=[{"amount": "0.25", "recipient": other().address}]
        )
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200
        assert node.balance(CURRENCY, other().address) == 250_000

    @pytest.mark.parametrize(
        ("allowed", "fee_token", "accepted"),
        [
            (None, None, True),
            ([CURRENCY], CURRENCY, True),
            (None, CURRENCY, False),
            ([CURRENCY], PATH_USD_ADDRESS, False),
        ],
    )
    async def test_credential_fee_token_policy(
        self, allowed: list[str] | None, fee_token: str | None, accepted: bool
    ) -> None:
        node = funded_node()
        node.fund(CURRENCY, sponsor().address, 100_000_000)
        server = make_server(node, allowed_fee_tokens=allowed, fee_payer=sponsor())
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = await create_credential(charge_client(node), challenge)
        if fee_token:
            signature = Credential.deserialize(value).payload["signature"]
            value = tx_credential(challenge, with_fee_token(signature, fee_token))
        if not accepted:
            with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
                await server.validate_credential(value)
            with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
                await server.verify_credential(value)
            return
        validation = await server.validate_credential(value)
        assert validation.details.mode == "pull"
        assert validation.details.sender.lower() == payer().address.lower()
        assert (await server.verify_credential(value)).status == "success"

    @pytest.mark.parametrize(
        ("allowed", "fee_token", "expected", "remote", "incoming"),
        [
            (None, None, PATH_USD_ADDRESS, False, None),
            ([CURRENCY], None, CURRENCY, False, None),
            ([CURRENCY, PATH_USD_ADDRESS], None, CURRENCY, False, None),
            ([CURRENCY], PATH_USD_ADDRESS, None, False, None),
            ([CURRENCY, PATH_USD_ADDRESS], PATH_USD_ADDRESS, PATH_USD_ADDRESS, False, None),
            (None, CURRENCY, None, False, None),
            (None, None, PATH_USD_ADDRESS, True, None),
            ([CURRENCY], None, CURRENCY, True, None),
            (None, None, None, True, CURRENCY),
        ],
    )
    async def test_local_fee_token_configuration(
        self,
        allowed: list[str] | None,
        fee_token: str | None,
        expected: str | None,
        remote: bool,
        incoming: str | None,
    ) -> None:
        node = funded_node()
        node.fund(CURRENCY, sponsor().address, 100_000_000)
        parameters: dict[str, Any] = {"allowed_fee_tokens": allowed}
        if remote:
            parameters["fee_payer"] = "https://fee-payer.example"
        else:
            parameters["fee_token"] = fee_token
        if remote and fee_token:
            pytest.skip("fee_token cannot be combined with a remote fee payer")
        server = make_server(node, **parameters)
        handler = server.charge(
            fee_payer=sponsor(), amount="1", currency=CURRENCY, recipient=recipient().address
        )
        challenge = await challenge_of(handler)
        value = await create_credential(charge_client(node), challenge)
        if incoming:
            signature = Credential.deserialize(value).payload["signature"]
            value = tx_credential(challenge, with_fee_token(signature, incoming))
        node.requests.clear()
        response = await request(handler, value)
        calls = [params[0] for method, params in node.requests if method == "eth_call"]
        calls = [c for c in calls if "calls" in c]
        if expected is None:
            assert response.status != 200
            assert len(calls) < 2
            return
        assert response.status == 200
        assert len(calls) == 2
        assert "feePayer" not in calls[0]
        assert calls[1]["feePayer"].lower() == sponsor().address.lower()
        assert calls[1]["feeToken"].lower() == expected.lower()
        assert calls[1]["from"].lower() == payer().address.lower()
        assert calls[1]["calls"]

    def test_rejects_fee_token_with_remote_fee_payer(self) -> None:
        with pytest.raises(ValueError, match="`feeToken` can only be configured for a local"):
            server_method(funded_node(), fee_payer="https://fee-payer.example", fee_token=CURRENCY)

    async def test_simulates_before_broadcasting(self) -> None:
        node = funded_node()
        handler = make_server(node, fee_payer=sponsor()).charge(amount="1", decimals=6)
        challenge = await challenge_of(handler)
        value = await create_credential(charge_client(node), challenge)
        node.methods.clear()
        assert (await request(handler, value)).status == 200
        sends = node.methods.index("eth_sendRawTransactionSync")
        assert node.methods[:sends].count("eth_call") >= 2

    @pytest.mark.parametrize("failing_simulation", [1, 2])
    @pytest.mark.parametrize("wait", [True, False])
    async def test_fails_closed_when_simulation_reverts(
        self, failing_simulation: int, wait: bool
    ) -> None:
        node = funded_node()
        simulations = 0

        def call(params: list[Any]) -> Any:
            nonlocal simulations
            if "calls" not in params[0]:
                return DEFAULT
            simulations += 1
            if simulations >= failing_simulation:
                raise RpcError(3, "execution reverted: simulation fixture")
            return DEFAULT

        handler = make_server(node, fee_payer=sponsor(), wait_for_confirmation=wait).charge(
            amount="1", decimals=6
        )
        challenge = await challenge_of(handler)
        value = await create_credential(charge_client(node), challenge)
        node.on("eth_call", call)
        node.methods.clear()
        response = await request(handler, value)
        assert response.status != 200
        assert "eth_call" in node.methods
        assert "eth_sendRawTransactionSync" not in node.methods
        assert "eth_sendRawTransaction" not in node.methods

    async def test_rejects_unauthorized_calls(self) -> None:
        node = funded_node()
        server = make_server(node, fee_payer=sponsor())
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        calls = [
            transfer_call(CURRENCY, recipient().address, 1_000_000, memo_for(challenge)),
            transfer_call(CURRENCY, other().address, 5_000_000),
        ]
        signature = signed_payment(challenge, calls=calls, fee_payer=True)
        with pytest.raises(MismatchError, match="no matching payment call found"):
            await server.verify_credential(tx_credential(challenge, signature))
        approve = Call(to=CURRENCY, data=abi.APPROVE.encode(other().address, 10**9))
        signature = signed_payment(
            challenge,
            calls=[
                approve,
                transfer_call(CURRENCY, recipient().address, 1_000_000, memo_for(challenge)),
            ],
            fee_payer=True,
        )
        with pytest.raises(MismatchError, match="no matching payment call found"):
            await server.verify_credential(tx_credential(challenge, signature))

    async def test_access_key_fee_payer(self) -> None:
        node = funded_node()
        access = secp256k1_account("0x" + "05" * 32, access=payer().address)
        handler = make_server(node, fee_payer=sponsor()).charge(amount="1", decimals=6)
        response = await make_client(node, handler, account=access).fetch(
            "https://api.example.com/paid"
        )
        assert response.status_code == 200

    async def test_request_level_fee_payer_false_disables_sponsorship(self) -> None:
        node = funded_node()
        server = make_server(node, fee_payer=sponsor())
        handler = server.charge(amount="1", decimals=6, fee_payer=False)
        challenge = await challenge_of(handler)
        assert "feePayer" not in (challenge.request.get("methodDetails") or {})
        response = await request(handler, await create_credential(charge_client(node), challenge))
        assert response.status == 200
        (receipt,) = node.receipts.values()
        assert receipt["feeToken"] is None or receipt["feeToken"].lower() != PATH_USD_ADDRESS


class TestRemoteFeePayer:
    async def test_hosted_fee_payer_url(self) -> None:
        import httpx

        node = funded_node()
        hosted = FakeTempoNode(hosted_fee_payer=sponsor(), hosted_fee_token=PATH_USD_ADDRESS)
        remote = RemoteFeePayer(
            url="https://fee-payer.example",
            headers={"authorization": "Bearer secret", "content-type": "text/plain"},
            http=httpx.AsyncClient(transport=hosted.transport()),
        )
        seen: list[httpx.Headers] = []
        original = hosted._handle_http

        async def capture(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers)
            return await original(request)

        hosted._handle_http = capture  # type: ignore[method-assign]
        remote = RemoteFeePayer(
            url=remote.url,
            headers=remote.headers,
            http=httpx.AsyncClient(transport=httpx.MockTransport(capture)),
        )
        handler = make_server(node, fee_payer=remote).charge(amount="1", decimals=6)
        challenge = await challenge_of(handler)
        assert challenge.request["methodDetails"]["feePayer"] is True
        response = await request(handler, await create_credential(charge_client(node), challenge))
        assert response.status == 200
        assert hosted.methods == ["eth_fillTransaction"]
        assert seen[0]["authorization"] == "Bearer secret"
        assert seen[0]["content-type"] == "application/json"
        (receipt,) = node.receipts.values()
        assert receipt["feeToken"].lower() == PATH_USD_ADDRESS

    @pytest.mark.parametrize(
        ("allowed", "accepted"), [([CURRENCY], False), ([PATH_USD_ADDRESS], True)]
    )
    async def test_hosted_fee_token_allowlist(self, allowed: list[str], accepted: bool) -> None:
        import httpx

        node = funded_node()
        hosted = FakeTempoNode(hosted_fee_payer=sponsor(), hosted_fee_token=PATH_USD_ADDRESS)
        remote = RemoteFeePayer(
            url="https://fee-payer.example", http=httpx.AsyncClient(transport=hosted.transport())
        )
        server = make_server(node, fee_payer=remote, allowed_fee_tokens=allowed)
        challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
        value = await create_credential(charge_client(node), challenge)
        if accepted:
            assert (await server.verify_credential(value)).status == "success"
        else:
            with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
                await server.verify_credential(value)
            assert node.count("eth_sendRawTransactionSync") == 0
