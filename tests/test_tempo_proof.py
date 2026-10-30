"""Zero-amount Tempo proof credentials and `supportedModes`, as mppx."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from eth_abi.abi import encode
from eth_account.messages import encode_typed_data
from eth_hash.auto import keccak
from pydantic import ValidationError

from mpp import Challenge
from mpp.errors import CredentialReplayedError, VerificationError
from mpp.methods.tempo import PATH_USD, TempoAccount
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._proof import (
    proof_hash,
    proof_source,
    recover_proof_signer,
    sign_proof,
    typed_data,
)
from mpp.methods.tempo.client import TransactionError, _tempo_method
from mpp.methods.tempo.intents import ACCOUNT_KEYCHAIN, GET_KEY_SELECTOR, ChargeIntent
from mpp.methods.tempo.schemas import ChargeInput
from mpp.server import Mpp
from mpp.server.http import PaymentVerified
from mpp.store import MemoryStore
from tests import challenge, challenges, http_request, make_credential

ROOT_KEY = "0x" + "11" * 32
ACCESS_KEY = "0x" + "22" * 32
OTHER_KEY = "0x" + "33" * 32
CHAIN = 42431
CHALLENGE_ID = "kM9xPqWvT2nJrHsY4aDfEb"
REALM = "api.example.com"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
ROOT = TempoAccount.from_key(ROOT_KEY)
ACCESS = TempoAccount.from_key(ACCESS_KEY)
OTHER = TempoAccount.from_key(OTHER_KEY)

# Computed with viem 2.57.1 (mppx's pinned version) from mppx's
# src/tempo/internal/proof.ts typedData({account: ROOT.address, chainId: CHAIN,
# challengeId: CHALLENGE_ID, realm: REALM}): hashTypedData, then signTypedData by
# privateKeyToAccount(ROOT_KEY), and by viem/tempo
# Account.fromSecp256k1(ACCESS_KEY, {access: ROOT.address}) (a Keychain V2 envelope).
VIEM_PROOF_HASH = "0x2db9f3ad46355ef4479f0b322396221c624618117d42cfa3ddcce707682ab155"
VIEM_SIGNATURE = (
    "0x3baf02ba159042829a9bcaa17774cecb25b0194cccff0dd076db7474befcaa2b"
    "26592fc409ed59c24888f9d3b276debe61696c86793e9a35632cbff79c3496d01c"
)
VIEM_KEYCHAIN_SIGNATURE = (
    "0x0419e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
    "a64ad10a15b8ed2c208c147daf58f5ec3989b4de18173565f10d3acad84fc1cf"
    "3ccc20181099d57723b7b9f9ed3821442c44f641e0eb4e8a4f2965d15be9e8621c"
)
PROOF = {"account": ROOT.address, "chain_id": CHAIN, "challenge_id": CHALLENGE_ID, "realm": REALM}


def _expires(seconds: int = 3600) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _request(amount: str = "0", **details: Any) -> dict[str, Any]:
    return {
        "amount": amount,
        "currency": PATH_USD,
        "recipient": RECIPIENT,
        "methodDetails": {"chainId": CHAIN, **details},
    }


def _challenge(amount: str = "0", **details: Any) -> Challenge:
    return Challenge(
        id=CHALLENGE_ID,
        method="tempo",
        intent="charge",
        realm=REALM,
        request=_request(amount, **details),
        expires=_expires(),
    )


def _proof_credential(
    signature: str, source: str | None = proof_source(ROOT.address, CHAIN), **kwargs: Any
) -> Any:
    return make_credential(
        {"type": "proof", "signature": signature},
        challenge_id=CHALLENGE_ID,
        realm=REALM,
        source=source,
        expires=_expires(),
        **kwargs,
    )


def _intent(**kwargs: Any) -> ChargeIntent:
    return ChargeIntent(chain_id=CHAIN, rpc_url="https://rpc.test", **kwargs)


def _keychain_rpc(intent: ChargeIntent, *, expiry: int, revoked: bool = False) -> list[dict]:
    """Answer the intent's AccountKeychain `getKey` lookups; returns the eth_calls made."""
    calls: list[dict] = []

    async def post(url: str, *, json: dict) -> httpx.Response:
        if json["method"] == "eth_chainId":
            result = hex(CHAIN)
        else:
            assert json["method"] == "eth_call"
            calls.append(json["params"][0])
            words = encode(
                ["uint8", "address", "uint64", "bool", "bool"],
                [0, ACCESS.address, expiry, False, revoked],
            )
            result = "0x" + words.hex()
        request = httpx.Request("POST", url)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": result}, request=request
        )

    intent._http_client = AsyncMock(post=AsyncMock(side_effect=post))
    return calls


class TestProofTypedData:
    """pympp signs the exact EIP-712 typed data mppx's proof.ts defines."""

    def test_typed_data_reproduces_mppx(self) -> None:
        assert typed_data(**PROOF) == {
            "domain": {"name": "MPP", "version": "3", "chainId": CHAIN},
            "types": {
                "Proof": [
                    {"name": "account", "type": "address"},
                    {"name": "challengeId", "type": "string"},
                    {"name": "realm", "type": "string"},
                ]
            },
            "primaryType": "Proof",
            "message": {"account": ROOT.address, "challengeId": CHALLENGE_ID, "realm": REALM},
        }

    def test_hash_matches_viem_and_eth_account(self) -> None:
        data = typed_data(**PROOF)
        domain_type = [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ]
        signable = encode_typed_data(
            full_message={**data, "types": {**data["types"], "EIP712Domain": domain_type}}
        )
        eth_account_hash = keccak(b"\x19" + signable.version + signable.header + signable.body)
        assert "0x" + proof_hash(**PROOF).hex() == VIEM_PROOF_HASH
        assert "0x" + eth_account_hash.hex() == VIEM_PROOF_HASH

    def test_signatures_match_viem(self) -> None:
        assert sign_proof(ROOT, **PROOF) == VIEM_SIGNATURE
        assert sign_proof(ACCESS, **PROOF) == VIEM_KEYCHAIN_SIGNATURE

    def test_recovers_viem_signatures(self) -> None:
        digest = bytes.fromhex(VIEM_PROOF_HASH[2:])
        plain = recover_proof_signer(VIEM_SIGNATURE, account=ROOT.address, digest=digest)
        keychain = recover_proof_signer(
            VIEM_KEYCHAIN_SIGNATURE, account=ROOT.address, digest=digest
        )
        assert plain is not None and (plain.address, plain.keychain) == (ROOT.address, False)
        assert keychain is not None
        assert (keychain.address, keychain.keychain) == (ACCESS.address, True)
        # A Keychain envelope must name the proof's account as its user.
        assert (
            recover_proof_signer(VIEM_KEYCHAIN_SIGNATURE, account=OTHER.address, digest=digest)
            is None
        )

    def test_recovers_keychain_v1(self) -> None:
        digest = proof_hash(**PROOF)
        v1 = "0x03" + ROOT.address[2:].lower() + ACCESS.sign_hash(digest).hex()
        signer = recover_proof_signer(v1, account=ROOT.address, digest=digest)
        assert signer is not None and (signer.address, signer.keychain) == (ACCESS.address, True)


class TestZeroAmountClient:
    """Zero-amount charges are paid with a proof, not a transaction (mppx client/Charge.ts)."""

    async def test_signs_proof_without_transaction(self) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        build = AsyncMock(side_effect=AssertionError("no transaction for a zero amount"))
        with patch.object(method, "_build_tempo_transfer", build):
            credential = await method.create_credential(_challenge())

        assert credential.payload == {"type": "proof", "signature": VIEM_SIGNATURE}
        assert credential.source == f"did:pkh:eip155:{CHAIN}:{ROOT.address}"

    async def test_access_key_signs_keychain_proof_for_root(self) -> None:
        method = _tempo_method(account=ACCESS, chain_id=CHAIN, root_account=ROOT.address)
        credential = await method.create_credential(_challenge())

        assert credential.payload == {"type": "proof", "signature": VIEM_KEYCHAIN_SIGNATURE}
        assert credential.source == f"did:pkh:eip155:{CHAIN}:{ROOT.address}"

    async def test_mode_does_not_apply_to_zero_amount(self) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN, mode="push")
        credential = await method.create_credential(_challenge(supportedModes=["pull"]))
        assert credential.payload["type"] == "proof"


class TestProofVerification:
    """The server verifies proofs as mppx's server/Charge.ts does."""

    async def test_valid_proof(self) -> None:
        intent = _intent()
        credential = _proof_credential(VIEM_SIGNATURE)

        validation = await intent.validate(credential, _request())
        receipt = await intent.broadcast(credential, _request())

        assert validation.payer == ROOT.address.lower()
        assert validation.details == {"mode": "proof"}
        assert receipt.reference == CHALLENGE_ID
        assert receipt.payer == ROOT.address.lower()

    async def test_proof_requires_zero_amount(self) -> None:
        with pytest.raises(VerificationError, match="only valid for zero-amount"):
            await _intent().validate(_proof_credential(VIEM_SIGNATURE), _request("1000"))

    @pytest.mark.parametrize(
        "payload",
        [{"type": "hash", "hash": "0x" + "ab" * 32}, {"type": "transaction", "signature": "0x76"}],
    )
    async def test_zero_amount_requires_proof(self, payload: dict) -> None:
        credential = make_credential(payload, CHALLENGE_ID, REALM, expires=_expires())
        with pytest.raises(VerificationError, match="require a proof credential"):
            await _intent().broadcast(credential, _request())

    @pytest.mark.parametrize(
        ("source", "match"),
        [
            (None, "must include a source"),
            (proof_source(ROOT.address, 4217), "source is invalid"),
            ("did:pkh:eip155:42431:0xnot-an-address", "source is invalid"),
        ],
    )
    async def test_invalid_source(self, source: str | None, match: str) -> None:
        with pytest.raises(VerificationError, match=match):
            await _intent().validate(_proof_credential(VIEM_SIGNATURE, source=source), _request())

    async def test_proof_is_bound_to_challenge_and_realm(self) -> None:
        intent = _intent()
        _keychain_rpc(intent, expiry=0)
        other_realm = sign_proof(ROOT, **{**PROOF, "realm": "other.example"})
        other_id = sign_proof(ROOT, **{**PROOF, "challenge_id": "other"})
        for signature in (other_realm, other_id):
            with pytest.raises(VerificationError, match="does not match source"):
                await intent.validate(_proof_credential(signature), _request())

    async def test_proof_for_another_account_is_rejected(self) -> None:
        intent = _intent()
        calls = _keychain_rpc(intent, expiry=0)
        # Signed by ROOT but claiming OTHER as the payer.
        signature = sign_proof(ROOT, **{**PROOF, "account": OTHER.address})
        with pytest.raises(VerificationError, match="does not match source"):
            await intent.validate(
                _proof_credential(signature, source=proof_source(OTHER.address, CHAIN)), _request()
            )
        # The signer is looked up as one of OTHER's access keys, and isn't one.
        assert len(calls) == 1

    async def test_keychain_for_another_account_is_rejected(self) -> None:
        intent = _intent()
        calls = _keychain_rpc(intent, expiry=2**63)
        signature = sign_proof(ACCESS, **{**PROOF, "account": OTHER.address})
        with pytest.raises(VerificationError, match="does not match source"):
            await intent.validate(_proof_credential(signature), _request())
        assert calls == []

    @pytest.mark.parametrize("keychain", [True, False], ids=["keychain-v2", "bare"])
    async def test_active_access_key(self, keychain: bool) -> None:
        intent = _intent()
        calls = _keychain_rpc(intent, expiry=2**63)
        digest = proof_hash(**PROOF)
        signature = VIEM_KEYCHAIN_SIGNATURE if keychain else "0x" + ACCESS.sign_hash(digest).hex()

        validation = await intent.validate(_proof_credential(signature), _request())

        assert validation.payer == ROOT.address.lower()
        [call] = calls
        assert call["to"] == ACCOUNT_KEYCHAIN
        assert call["data"] == (
            "0x"
            + GET_KEY_SELECTOR
            + ROOT.address[2:].lower().zfill(64)
            + ACCESS.address[2:].lower().zfill(64)
        )

    @pytest.mark.parametrize(("expiry", "revoked"), [(2**63, True), (1, False), (0, False)])
    async def test_inactive_access_key(self, expiry: int, revoked: bool) -> None:
        intent = _intent()
        _keychain_rpc(intent, expiry=expiry, revoked=revoked)
        with pytest.raises(VerificationError, match="does not match source"):
            await intent.validate(_proof_credential(VIEM_KEYCHAIN_SIGNATURE), _request())

    async def test_configured_store_claims_proof_once(self) -> None:
        store = MemoryStore()
        intent = _intent(store=store)
        credential = _proof_credential(VIEM_SIGNATURE)

        await intent.broadcast(credential, _request())

        assert await store.get(f"mpp:charge:proof:{CHALLENGE_ID}") is not None
        with pytest.raises(CredentialReplayedError, match="already been used"):
            await intent.validate(credential, _request())
        with pytest.raises(CredentialReplayedError, match="already been used"):
            await intent.broadcast(credential, _request())

    async def test_proof_claim_outlives_challenge_expiry(self) -> None:
        from mpp.methods.tempo.intents import _PROOF_CLAIM_GRACE

        store = MemoryStore()
        intent = _intent(store=store)
        credential = _proof_credential(VIEM_SIGNATURE)

        await intent.broadcast(credential, _request())

        deadline = store._expiry_deadlines[f"mpp:charge:proof:{CHALLENGE_ID}"]
        expires = datetime.fromisoformat(credential.challenge.expires.replace("Z", "+00:00"))
        assert deadline == expires.timestamp() + _PROOF_CLAIM_GRACE

    async def test_without_store_proof_stays_reusable(self) -> None:
        # As mppx: replay protection for proofs needs an explicitly configured store.
        intent = _intent()
        credential = _proof_credential(VIEM_SIGNATURE)
        await intent.broadcast(credential, _request())
        await intent.broadcast(credential, _request())

    async def test_mpp_round_trip_with_shared_store(self) -> None:
        server = Mpp(
            methods=tempo_server.charge(
                recipient=RECIPIENT,
                chain_id=CHAIN,
                rpc_url="https://rpc.test",
                currencies=[PATH_USD],
            ),
            realm=REALM,
            secret_key="test-secret",
            store=MemoryStore(),
        )
        handler = server.charge(amount="0")
        issued = challenge(await handler(http_request()))
        assert issued.request["amount"] == "0"

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        credential = await method.create_credential(issued)
        authorization = credential.to_authorization()
        paid = await handler(http_request(authorization))

        assert isinstance(paid, PaymentVerified)
        assert paid.receipt.reference == issued.id
        assert paid.receipt.payer == ROOT.address.lower()
        replayed = await handler(http_request(authorization))
        assert not isinstance(replayed, PaymentVerified)
        assert b"already been used" in replayed.challenge.body


class TestSupportedModes:
    """`methodDetails.supportedModes` (mppx Methods.ts) picks push or pull."""

    def test_charge_input_serializes_supported_modes(self) -> None:
        wire = ChargeInput(
            amount="1", currency=PATH_USD, recipient=RECIPIENT, supportedModes=["push"]
        ).model_dump()
        assert wire["methodDetails"] == {"supportedModes": ["push"]}
        with pytest.raises(ValidationError):
            ChargeInput(amount="1", currency=PATH_USD, recipient=RECIPIENT, supportedModes=[])

    async def test_server_advertises_supported_modes(self) -> None:
        server = Mpp(
            methods=tempo_server.charge(
                recipient=RECIPIENT,
                chain_id=CHAIN,
                rpc_url="https://rpc.test",
                currencies=[PATH_USD],
                supported_modes=["push"],
            ),
            realm=REALM,
            secret_key="test-secret",
        )
        default = challenge(await server.charge(amount="1")(http_request()))
        route = challenge(
            await server.charge(amount="1", supported_modes=["pull", "push"])(http_request())
        )
        assert default.request["methodDetails"]["supportedModes"] == ["push"]
        assert route.request["methodDetails"]["supportedModes"] == ["pull", "push"]

    @pytest.mark.parametrize("modes", [[], "push", ["fast"]])
    def test_server_rejects_invalid_supported_modes(self, modes: Any) -> None:
        with pytest.raises(ValueError, match="supported_modes|mode"):
            tempo_server.charge(recipient=RECIPIENT, supported_modes=modes)

    async def test_push_only_sponsored_challenge_skips_lifetime_floor(self) -> None:
        server = Mpp(
            methods=tempo_server.charge(
                recipient=RECIPIENT,
                chain_id=CHAIN,
                rpc_url="https://rpc.test",
                currencies=[PATH_USD],
                fee_payer=OTHER,
            ),
            realm=REALM,
            secret_key="test-secret",
        )
        expires = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
        for options in ({"amount": "0"}, {"amount": "1", "supported_modes": ["push"]}):
            result = await server.charge(fee_payer=True, expires=expires, **options)(http_request())
            assert challenges(result)

    @pytest.mark.parametrize(
        ("modes", "payload", "match"),
        [
            (["push"], {"type": "transaction", "signature": "0x76"}, "Transaction credentials"),
            (["pull"], {"type": "hash", "hash": "0x" + "ab" * 32}, "Hash credentials"),
        ],
    )
    async def test_server_rejects_unsupported_mode(
        self, modes: list[str], payload: dict, match: str
    ) -> None:
        credential = make_credential(payload, CHALLENGE_ID, REALM, expires=_expires())
        with pytest.raises(VerificationError, match=match):
            await _intent().validate(credential, _request("1000", supportedModes=modes))

    @staticmethod
    def _push_rpc(status: str = "0x1") -> AsyncMock:
        async def rpc(url: str, method: str, params: list[Any], **_: Any) -> Any:
            assert (method, params) == ("eth_sendRawTransactionSync", ["0x76signed"])
            return {"transactionHash": "0x" + "cd" * 32, "status": status}

        return AsyncMock(side_effect=rpc)

    @pytest.mark.parametrize(
        ("mode", "details"),
        [(None, {"supportedModes": ["push"], "feePayer": True}), ("push", {})],
        ids=["push-only-challenge", "explicit-push"],
    )
    async def test_client_pushes(self, mode: Any, details: dict) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN, mode=mode)
        build = AsyncMock(return_value=("0x76signed", CHAIN))
        with (
            patch.object(method, "_build_tempo_transfer", build),
            patch("mpp.methods.tempo.client._rpc_call", self._push_rpc()),
        ):
            credential = await method.create_credential(_challenge("1000", **details))

        assert credential.payload == {"type": "hash", "hash": "0x" + "cd" * 32}
        assert credential.source == f"did:pkh:eip155:{CHAIN}:{ROOT.address}"
        # The client pays its own fees when it broadcasts.
        assert build.await_args is not None
        assert build.await_args.kwargs["awaiting_fee_payer"] is False

    async def test_client_reports_reverted_push(self) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        with (
            patch.object(
                method, "_build_tempo_transfer", AsyncMock(return_value=("0x76signed", CHAIN))
            ),
            patch("mpp.methods.tempo.client._rpc_call", self._push_rpc(status="0x0")),
            pytest.raises(TransactionError, match="reverted"),
        ):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))

    @pytest.mark.parametrize(
        "rpc_error",
        [
            {"code": 4, "message": "transaction pooled but not yet confirmed"},
            {"code": -32000, "message": "already known"},
        ],
    )
    async def test_client_reports_pooled_push_as_unknown(self, rpc_error: dict) -> None:
        from mpp.errors import PaymentOutcomeUnknownError
        from mpp.methods.tempo._rpc import RpcError

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        rpc = AsyncMock(side_effect=RpcError({"jsonrpc": "2.0", "id": 1, "error": rpc_error}))
        with (
            patch.object(
                method, "_build_tempo_transfer", AsyncMock(return_value=("0x76ab", CHAIN))
            ),
            patch("mpp.methods.tempo.client._rpc_call", rpc),
            pytest.raises(PaymentOutcomeUnknownError) as raised,
        ):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))
        assert raised.value.transaction_hash is not None

    async def test_client_reports_refused_push_as_failed(self) -> None:
        from mpp.methods.tempo._rpc import RpcError

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        error = {"code": -32000, "message": "insufficient funds for gas"}
        rpc = AsyncMock(side_effect=RpcError({"jsonrpc": "2.0", "id": 1, "error": error}))
        with (
            patch.object(
                method, "_build_tempo_transfer", AsyncMock(return_value=("0x76signed", CHAIN))
            ),
            patch("mpp.methods.tempo.client._rpc_call", rpc),
            pytest.raises(TransactionError, match="insufficient funds"),
        ):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))

    @pytest.mark.parametrize("details", [{}, {"supportedModes": ["push", "pull"]}])
    async def test_client_pulls_by_default(self, details: dict) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        with patch.object(
            method, "_build_tempo_transfer", AsyncMock(return_value=("0x76signed", CHAIN))
        ):
            credential = await method.create_credential(_challenge("1000", **details))
        assert credential.payload == {"type": "transaction", "signature": "0x76signed"}

    async def test_client_rejects_unsupported_explicit_mode(self) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN, mode="pull")
        with pytest.raises(ValueError, match="does not support pull mode"):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))

    def test_client_rejects_invalid_mode(self) -> None:
        with pytest.raises(ValueError, match="Invalid Tempo charge mode"):
            _tempo_method(account=ROOT, chain_id=CHAIN, mode="fast")  # pyright: ignore[reportArgumentType]


class TestPushSafety:
    """Push payments are on chain once broadcast: never pay twice, never lose the hash."""

    async def test_lost_broadcast_response_is_an_unknown_outcome_with_the_hash(self) -> None:
        import httpx
        from eth_hash.auto import keccak

        from mpp.errors import PaymentOutcomeUnknownError

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        raw = "0x76" + "ab" * 40
        with (
            patch.object(method, "_build_tempo_transfer", AsyncMock(return_value=(raw, CHAIN))),
            patch(
                "mpp.methods.tempo.client._rpc_call",
                AsyncMock(side_effect=httpx.ReadTimeout("lost")),
            ),
            pytest.raises(PaymentOutcomeUnknownError) as raised,
        ):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))
        assert raised.value.transaction_hash == "0x" + keccak(bytes.fromhex(raw[2:])).hex()

    async def test_node_rejection_is_a_plain_transaction_error(self) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        with (
            patch.object(
                method, "_build_tempo_transfer", AsyncMock(return_value=("0x76signed", CHAIN))
            ),
            patch(
                "mpp.methods.tempo.client._rpc_call",
                AsyncMock(side_effect=RuntimeError("RPC error: nonce too low")),
            ),
            pytest.raises(TransactionError, match="nonce too low"),
        ):
            await method.create_credential(_challenge("1000", supportedModes=["push"]))

    def test_transaction_hash_reads_hash_credentials(self) -> None:
        from mpp import Credential

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        tx_hash = "0x" + "cd" * 32
        credential = Credential(
            challenge=_challenge("1000").to_echo(), payload={"type": "hash", "hash": tx_hash}
        )
        assert method.transaction_hash(credential) == tx_hash

    @pytest.mark.parametrize(
        ("mode", "details", "payable"),
        [
            ("pull", {"supportedModes": ["push"]}, False),
            ("push", {"supportedModes": ["pull"]}, False),
            ("pull", {"supportedModes": ["push", "pull"]}, True),
            ("pull", {}, True),
        ],
    )
    def test_selection_skips_offers_without_the_client_mode(
        self, mode: Any, details: dict, payable: bool
    ) -> None:
        method = _tempo_method(account=ROOT, chain_id=CHAIN, mode=mode)
        assert method.can_handle_challenge(_challenge("1000", **details)) is payable
        # A zero amount pays with a proof, whatever the modes.
        assert method.can_handle_challenge(_challenge("0", **details))


class TestZeroAmountSplits:
    def test_routes_reject_splits_that_leave_nothing(self) -> None:
        from mpp.methods.tempo.schemas import ChargeInput

        def charge(amount: str, split_amount: str = "1") -> ChargeInput:
            return ChargeInput.model_validate(
                {
                    "amount": amount,
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": ROOT.address,
                    "splits": [{"amount": split_amount, "recipient": "0x" + "11" * 20}],
                }
            )

        for amount, split_amount in (("0", "1"), ("0.000001", "1"), ("1", "0")):
            with pytest.raises(ValueError, match="Invalid splits"):
                charge(amount, split_amount)
        assert charge("0.000002")

    async def test_proof_on_a_wire_request_with_splits_is_rejected(self) -> None:
        credential = make_credential(
            {"type": "proof", "signature": "0x" + "00" * 65},
            CHALLENGE_ID,
            REALM,
            expires=_expires(),
            source=f"did:pkh:eip155:{CHAIN}:{ROOT.address}",
        )
        request = _request("0", splits=[{"amount": "1", "recipient": "0x" + "11" * 20}])
        with pytest.raises(VerificationError, match="Invalid splits"):
            await _intent().validate(credential, request)


class TestPushCancellation:
    async def test_push_is_not_broadcast_after_every_caller_is_cancelled(self) -> None:
        import asyncio

        method = _tempo_method(account=ROOT, chain_id=CHAIN)
        built = asyncio.Event()
        release = asyncio.Event()

        async def build(**_: Any) -> tuple[str, int]:
            built.set()
            await release.wait()
            return ("0x76signed", CHAIN)

        rpc = AsyncMock()
        with (
            patch.object(method, "_build_tempo_transfer", build),
            patch("mpp.methods.tempo.client._rpc_call", rpc),
        ):
            caller = asyncio.ensure_future(
                method.create_credential(_challenge("1000", supportedModes=["push"]))
            )
            await built.wait()
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller
            release.set()
            for _ in range(5):
                await asyncio.sleep(0)

        rpc.assert_not_awaited()


class TestP256AndWebAuthnProofs:
    """P256 and WebAuthn proof signatures, verified as Tempo verifies them."""

    @staticmethod
    def _key() -> tuple[int, bytes, str]:
        from Crypto.PublicKey import ECC
        from eth_hash.auto import keccak

        key = ECC.generate(curve="P-256")
        public = int(key.pointQ.x).to_bytes(32, "big") + int(key.pointQ.y).to_bytes(32, "big")
        return int(key.d), public, "0x" + keccak(public)[12:].hex()

    @staticmethod
    def _sign(d: int, public: bytes, digest: bytes) -> bytes:
        import secrets

        from Crypto.PublicKey import ECC

        from mpp.methods.tempo._proof import _P256_GX, _P256_GY, _P256_ORDER

        n = _P256_ORDER
        z = int.from_bytes(digest, "big") % n
        while True:
            k = secrets.randbelow(n - 1) + 1
            point = ECC.EccPoint(_P256_GX, _P256_GY, "P-256") * k
            r = int(point.x) % n
            s = pow(k, -1, n) * (z + r * d) % n
            if r and s:
                break
        s = min(s, n - s)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + public

    def _p256(self, d: int, public: bytes, digest: bytes, pre_hash: bool = False) -> bytes:
        import hashlib

        message = hashlib.sha256(digest).digest() if pre_hash else digest
        return bytes([0x01]) + self._sign(d, public, message) + bytes([int(pre_hash)])

    def _webauthn(self, d: int, public: bytes, digest: bytes, kind: str = "webauthn.get") -> bytes:
        import base64
        import hashlib
        import json

        authenticator_data = bytes(32) + bytes([0x05]) + bytes([0, 0, 0, 1])
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        client_data = json.dumps({"type": kind, "challenge": challenge}).encode()
        message = hashlib.sha256(authenticator_data + hashlib.sha256(client_data).digest()).digest()
        return bytes([0x02]) + authenticator_data + client_data + self._sign(d, public, message)

    @pytest.mark.parametrize("kind", ["p256", "p256-prehash", "webauthn"])
    def test_access_key_proofs_recover_their_key(self, kind: str) -> None:
        from eth_hash.auto import keccak

        from mpp.methods.tempo._proof import proof_hash, recover_proof_signer

        d, public, address = self._key()
        digest = proof_hash(
            account=ROOT.address, chain_id=CHAIN, challenge_id=CHALLENGE_ID, realm=REALM
        )
        wrapped = keccak(bytes([0x04]) + digest + bytes.fromhex(ROOT.address[2:]))
        inner = (
            self._webauthn(d, public, wrapped)
            if kind == "webauthn"
            else self._p256(d, public, wrapped, pre_hash=kind == "p256-prehash")
        )
        envelope = "0x" + (bytes([0x04]) + bytes.fromhex(ROOT.address[2:]) + inner).hex()

        signer = recover_proof_signer(envelope, account=ROOT.address, digest=digest)

        assert signer is not None and signer.keychain
        assert signer.address == address
        assert recover_proof_signer(envelope, account=ACCESS.address, digest=digest) is None
        assert recover_proof_signer(envelope, account=ROOT.address, digest=bytes(32)) is None

    def test_rejects_high_s_and_registration_assertions(self) -> None:
        from mpp.methods.tempo._proof import _P256_ORDER, _recover_primitive

        d, public, _ = self._key()
        digest = bytes(range(32))
        signature = bytearray(self._p256(d, public, digest))
        s = int.from_bytes(signature[33:65], "big")
        signature[33:65] = (_P256_ORDER - s).to_bytes(32, "big")
        assert _recover_primitive(bytes(signature), digest) is None
        assert (
            _recover_primitive(self._webauthn(d, public, digest, "webauthn.create"), digest) is None
        )
