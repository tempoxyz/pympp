"""Port of mppx ``tempo/client/Charge.test.ts`` plus client-side mode behavior."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import attrs
import httpx
import pytest
from _charge_node import (
    TESTNET_CHAIN_ID,
    FakeTempoNode,
    payer,
    sponsor,
)
from pytempo import Call, TempoTransaction

from mpp.challenge import Challenge
from mpp.client import Mpp as ClientMppx
from mpp.credential import Credential
from mpp.errors import PaymentExpiredError
from mpp.method import CredentialParams
from mpp.tempo import attribution, methods, proof
from mpp.tempo._internal import abi
from mpp.tempo._internal.account import TempoAccount, secp256k1_account
from mpp.tempo._internal.envelope import (
    call_target,
    deserialize,
    fee_token,
    sender,
    serialize,
    serialize_for_fee_payer,
)
from mpp.tempo._internal.hexutil import keccak256, rlp_decode, rlp_encode, to_bytes, to_hex
from mpp.tempo._internal.rpc import RpcError
from mpp.tempo._internal.signature import Signature
from mpp.tempo.assets import MACH_ADDRESS, PATH_USD_ADDRESS
from mpp.tempo.client import (
    ExecuteCalls,
    ResolveAccountInfo,
    SignPaymentProof,
    charge,
    transaction_hash,
)
from mpp.tempo.client._charge import _valid_before

ACCOUNT_KEY = "0x" + "00" * 31 + "01"
CURRENCY = "0x3333333333333333333333333333333333333333"
RECIPIENT = "0x2222222222222222222222222222222222222222"
OTHER_CURRENCY = "0x4444444444444444444444444444444444444444"


def account() -> TempoAccount:
    return secp256k1_account(ACCOUNT_KEY)


def create_challenge(challenge_id: str = "test-challenge-id", **overrides: Any) -> Challenge:
    request = methods.charge.normalize_request(
        {"amount": "0", "currency": CURRENCY, "decimals": 6, "recipient": RECIPIENT, **overrides}
    )
    return Challenge(
        id=challenge_id, intent="charge", method="tempo", realm="api.example.com", request=request
    )


def funded(chain_id: int = TESTNET_CHAIN_ID) -> FakeTempoNode:
    node = FakeTempoNode(chain_id=chain_id)
    node.fund(CURRENCY, account().address, 10**12)
    node.fund(PATH_USD_ADDRESS, account().address, 10**12)
    return node


def client_method(node: FakeTempoNode, **parameters: Any) -> Any:
    rpc = node.client()
    requested: list[int | None] = []

    def get_client(chain_id: int | None) -> Any:
        requested.append(chain_id)
        return rpc

    return Probe(
        charge(**{"account": account(), "get_client": get_client, **parameters}), requested
    )


class Probe:
    """A client method plus the chain IDs its ``get_client`` was asked for."""

    def __init__(self, method: Any, requested: list[int | None]) -> None:
        self.method = method
        self.context = method.context
        self.create_credential = method.create_credential
        self.requested = requested


async def create(method: Any, challenge: Challenge, context: dict[str, Any] | None = None) -> str:
    parsed = method.context.model_validate(context) if context is not None else None
    return await method.create_credential(CredentialParams(challenge=challenge, context=parsed))


def fill_requests(node: FakeTempoNode) -> list[dict[str, Any]]:
    return [params[0] for method, params in node.requests if method == "eth_fillTransaction"]


def signed_transaction(value: str) -> TempoTransaction:
    return deserialize(Credential.deserialize(value).payload["signature"])


class TestTempoChargeClient:
    async def test_mach_challenges_use_stablecoin_fee_token(self) -> None:
        node = funded()
        node.fund(MACH_ADDRESS, account().address, 10**12)
        value = await create(
            client_method(node),
            create_challenge(
                amount="1", chainId=TESTNET_CHAIN_ID, currency=MACH_ADDRESS, supportedModes=["pull"]
            ),
        )
        assert fill_requests(node)[0]["feeToken"].lower() == PATH_USD_ADDRESS
        assert (fee_token(signed_transaction(value)) or "").lower() == PATH_USD_ADDRESS

    async def test_uses_client_chain_when_challenge_omits_chain_id(self) -> None:
        node = funded(chain_id=1337)
        value = Credential.deserialize(await create(client_method(node), create_challenge()))
        assert value.source == f"did:pkh:eip155:1337:{account().address}"

    async def test_uses_challenge_chain_for_client_resolution_and_proof_source(self) -> None:
        node = funded()
        method = client_method(node)
        value = Credential.deserialize(
            await create(method, create_challenge(chainId=TESTNET_CHAIN_ID))
        )
        assert method.requested == [TESTNET_CHAIN_ID]
        assert value.source == f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{account().address}"

    async def test_builds_transfer_calls(self) -> None:
        node = funded()
        challenge = create_challenge(amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["pull"])
        value = await create(client_method(node), challenge)
        (call,) = signed_transaction(value).calls
        assert call_target(call) == CURRENCY
        recipient, amount, memo = abi.TRANSFER_WITH_MEMO.decode_input(call.data)
        assert (recipient.lower(), amount) == (RECIPIENT, 1_000_000)
        assert to_hex(memo) == attribution.encode(
            challenge_id=challenge.id, server_id=challenge.realm
        )

    @pytest.mark.parametrize("fixed_memo", [None, "0x" + "dd" * 32])
    async def test_split_binds_each_unfixed_leg(self, fixed_memo: str | None) -> None:
        # pympp#313: legs without a fixed memo carry the challenge memo, so no leg can be
        # shared with another challenge in a batched payment.
        node = funded()
        split: dict[str, Any] = {"recipient": OTHER_CURRENCY, "amount": "0.25"}
        if fixed_memo is not None:
            split["memo"] = fixed_memo
        challenge = create_challenge(
            amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["pull"], splits=[split]
        )
        value = await create(client_method(node), challenge)
        bound = attribution.encode(challenge_id=challenge.id, server_id=challenge.realm)
        legs = [
            abi.TRANSFER_WITH_MEMO.decode_input(call.data)
            for call in signed_transaction(value).calls
        ]
        assert [(recipient.lower(), amount, to_hex(memo)) for recipient, amount, memo in legs] == [
            (RECIPIENT, 750_000, bound),
            (OTHER_CURRENCY, 250_000, fixed_memo or bound),
        ]

    async def test_refuses_fixed_attribution_split_memo(self) -> None:
        # pympp#325: such a split leg could also pay the challenge its memo names.
        node = funded()
        method = client_method(node)
        challenge = create_challenge(
            amount="1",
            chainId=TESTNET_CHAIN_ID,
            splits=[{"recipient": OTHER_CURRENCY, "amount": "0.25"}],
        )
        challenge.request["methodDetails"]["splits"][0]["memo"] = attribution.encode(
            challenge_id="other-challenge", server_id=challenge.realm
        )
        assert not method.method.can_handle_challenge(challenge)
        with pytest.raises(ValueError, match="Fixed split memos must not use MPP attribution"):
            await create(method, challenge)
        assert node.count("eth_fillTransaction") == 0

    async def test_client_id_is_fingerprinted_into_the_memo(self) -> None:
        node = funded()
        challenge = create_challenge(amount="1", chainId=TESTNET_CHAIN_ID)
        value = await create(client_method(node, client_id="my-app"), challenge)
        (call,) = signed_transaction(value).calls
        memo = to_hex(abi.TRANSFER_WITH_MEMO.decode_input(call.data)[2])
        assert memo == attribution.encode(
            challenge_id=challenge.id, server_id=challenge.realm, client_id="my-app"
        )

    async def test_resolve_account_selects_account_from_executable_calls(self) -> None:
        node = funded()
        selected = secp256k1_account("0x" + "00" * 31 + "02")
        node.fund(CURRENCY, selected.address, 10**12)
        calls: list[ResolveAccountInfo] = []

        def resolve_account(info: ResolveAccountInfo) -> TempoAccount:
            calls.append(info)
            return selected

        value = await create(
            client_method(node, resolve_account=resolve_account),
            create_challenge(amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["pull"]),
        )
        (info,) = calls
        assert info.account.address == account().address
        assert info.chain_id == TESTNET_CHAIN_ID
        assert isinstance(info.operation, ExecuteCalls)
        assert info.operation.kind == "executeCalls"
        assert info.operation.calls is not None
        assert len(info.operation.calls) == 1
        assert call_target(info.operation.calls[0]) == CURRENCY
        assert Credential.deserialize(value).source == f"did:pkh:eip155:42431:{selected.address}"
        assert sender(signed_transaction(value)) == selected.address

    async def test_zero_amount_proof_binds_to_root_payer_for_access_key(self) -> None:
        node = funded()
        root = account()
        access = secp256k1_account("0x" + "0a" * 32, access=root.address)
        selected_root = secp256k1_account("0x" + "00" * 31 + "02")
        selected = secp256k1_account("0x" + "0b" * 32, access=selected_root.address)
        seen: list[ResolveAccountInfo] = []

        def resolve_account(info: ResolveAccountInfo) -> TempoAccount:
            seen.append(info)
            return selected

        challenge = create_challenge(chainId=TESTNET_CHAIN_ID)
        value = Credential.deserialize(
            await create(
                client_method(node, account=access, resolve_account=resolve_account), challenge
            )
        )
        (info,) = seen
        assert info.account is access
        assert info.chain_id == TESTNET_CHAIN_ID
        assert isinstance(info.operation, SignPaymentProof)
        assert value.payload["type"] == "proof"
        assert value.source == f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{selected_root.address}"
        from mpp.tempo._internal.proof import recover_authorized_proof_signer

        signer = recover_authorized_proof_signer(
            chain_id=TESTNET_CHAIN_ID,
            challenge_id=challenge.id,
            realm=challenge.realm,
            signature=value.payload["signature"],
            source_address=selected_root.address,
        )
        assert signer == selected.access_key_address

    async def test_normalizes_sponsored_pull_transactions_before_signing(self) -> None:
        node = funded()
        node.gas = 100
        original = node.handle

        def fill(params: list[Any]) -> Any:
            result = original("eth_fillTransaction", params)
            result["tx"] |= {
                "feePayerSignature": {"r": "0x1", "s": "0x2", "yParity": "0x0"},
                "feeToken": CURRENCY,
            }
            return result

        node.on("eth_fillTransaction", fill)
        value = await create(
            client_method(node),
            create_challenge(
                amount="1", chainId=TESTNET_CHAIN_ID, feePayer=True, supportedModes=["pull"]
            ),
        )
        assert "feePayer" not in fill_requests(node)[0]
        serialized = Credential.deserialize(value).payload["signature"]
        assert serialized.startswith("0x78")
        transaction = deserialize(serialized)
        assert transaction.awaiting_fee_payer is True
        assert transaction.fee_payer_signature is None
        assert transaction.fee_token is None
        assert transaction.gas_limit == 5_100

    async def test_unsponsored_transactions_add_gas_buffer_and_expiring_nonce(self) -> None:
        node = funded()
        value = await create(
            client_method(node), create_challenge(amount="1", chainId=TESTNET_CHAIN_ID)
        )
        transaction = signed_transaction(value)
        assert transaction.gas_limit == node.gas + 5_000
        assert transaction.nonce_key == 2**256 - 1
        assert transaction.nonce == 0
        assert transaction.max_fee_per_gas == node.max_fee_per_gas * 12 // 10
        assert transaction.valid_after is not None
        assert sender(transaction) == account().address

    async def test_falls_back_to_estimate_without_fill_transaction(self) -> None:
        node = funded()

        def unsupported(_: list[Any]) -> Any:
            raise RpcError(-32601, "the method eth_fillTransaction does not exist")

        node.on("eth_fillTransaction", unsupported)
        value = await create(
            client_method(node), create_challenge(amount="1", chainId=TESTNET_CHAIN_ID)
        )
        transaction = signed_transaction(value)
        assert transaction.gas_limit == node.gas + 5_000
        assert transaction.max_priority_fee_per_gas == node.max_priority_fee_per_gas
        assert "eth_estimateGas" in node.methods


class TestModes:
    async def test_push_mode_broadcasts_and_sends_hash(self) -> None:
        node = funded()
        value = Credential.deserialize(
            await create(
                client_method(node, mode="push"),
                create_challenge(amount="1", chainId=TESTNET_CHAIN_ID),
            )
        )
        assert value.payload["type"] == "hash"
        assert value.payload["hash"] in node.receipts

    async def test_context_mode_overrides_parameters(self) -> None:
        node = funded()
        value = Credential.deserialize(
            await create(
                client_method(node, mode="pull"),
                create_challenge(amount="1", chainId=TESTNET_CHAIN_ID),
                {"mode": "push"},
            )
        )
        assert value.payload["type"] == "hash"

    async def test_defaults_to_pull_and_falls_back_to_first_supported(self) -> None:
        node = funded()
        pulled = Credential.deserialize(
            await create(
                client_method(node), create_challenge(amount="1", chainId=TESTNET_CHAIN_ID)
            )
        )
        assert pulled.payload["type"] == "transaction"
        pushed = Credential.deserialize(
            await create(
                client_method(node),
                create_challenge(
                    "push-only", amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["push"]
                ),
            )
        )
        assert pushed.payload["type"] == "hash"

    async def test_rejects_unsupported_explicit_mode(self) -> None:
        node = funded()
        with pytest.raises(ValueError, match=r"Challenge does not support push mode\."):
            await create(
                client_method(node, mode="push"),
                create_challenge(amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["pull"]),
            )

    async def test_requires_an_account(self) -> None:
        node = funded()
        with pytest.raises(ValueError, match="No `account` provided"):
            await create(
                client_method(node, account=None),
                create_challenge(amount="1", chainId=TESTNET_CHAIN_ID),
            )

    async def test_context_account_overrides_parameters(self) -> None:
        node = funded()
        other = secp256k1_account("0x" + "00" * 31 + "02")
        node.fund(CURRENCY, other.address, 10**12)
        value = await create(
            client_method(node),
            create_challenge(amount="1", chainId=TESTNET_CHAIN_ID),
            {"account": other},
        )
        assert sender(signed_transaction(value)) == other.address


class TestValidBefore:
    BASE = 1_800_000_000

    @staticmethod
    def at(seconds: float) -> str:
        return (
            datetime.fromtimestamp(seconds, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    @pytest.mark.parametrize(
        ("now", "expires", "expected"),
        [
            (0, None, 60),
            (0, 90, 60),
            (0, 10, 11),
            (0, 10.5, 11),
            (0.2, 0.5, 1),
            (0.5, 0.5, 1),
            (0, 0, 1),
            (0.998, 0.999, 1),
        ],
        ids=[
            "no challenge expiry",
            "expiry after the window",
            "expiry inside the window",
            "fractional expiry",
            "sub-second expiry",
            "expiry is now",
            "whole-second expiry is now",
            "millisecond expiry",
        ],
    )
    def test_caps_at_the_challenge_expiry(
        self, now: float, expires: float | None, expected: int
    ) -> None:
        expiry = None if expires is None else self.at(self.BASE + expires)
        valid_before = _valid_before(expiry, now=self.BASE + now)
        assert valid_before == self.BASE + expected
        assert valid_before > self.BASE + now


class TestInFlightSigning:
    @pytest.mark.parametrize(
        ("concurrent", "other_id", "signings"),
        [(True, "shared", 1), (False, "shared", 2), (True, "other", 2)],
        ids=["concurrent, same challenge", "sequential, same challenge", "concurrent, other"],
    )
    async def test_signings(self, concurrent: bool, other_id: str, signings: int) -> None:
        node = funded()
        method = client_method(node)

        def make(challenge_id: str) -> Any:
            return create(
                method, create_challenge(challenge_id, amount="1", chainId=TESTNET_CHAIN_ID)
            )

        if concurrent:
            first, second = await asyncio.gather(make("shared"), make(other_id))
        else:
            first, second = await make("shared"), await make(other_id)
        assert node.count("eth_fillTransaction") == signings
        assert (first == second) == (signings == 1)

    async def test_does_not_share_a_failed_signing(self) -> None:
        node = funded()
        failures = [RpcError(-32000, "rpc down")]

        def fill(params: list[Any]) -> Any:
            if failures:
                raise failures.pop()
            return node.handle("eth_fillTransaction", params)

        node.on("eth_fillTransaction", fill)
        method = client_method(node)
        challenge = create_challenge("shared", amount="1", chainId=TESTNET_CHAIN_ID)
        with pytest.raises(RpcError, match="rpc down"):
            await create(method, challenge)
        await create(method, challenge)
        assert node.count("eth_fillTransaction") == 2

    async def test_enforces_policy_when_joining_a_signing(self) -> None:
        node = funded()
        method = client_method(node, expected_recipients=[RECIPIENT])
        allowed = create_challenge("shared", amount="1", chainId=TESTNET_CHAIN_ID)
        disallowed = create_challenge(
            "shared", amount="1", chainId=TESTNET_CHAIN_ID, recipient=OTHER_CURRENCY
        )
        first, second = await asyncio.gather(
            create(method, allowed), create(method, disallowed), return_exceptions=True
        )
        assert isinstance(first, str)
        assert isinstance(second, ValueError)
        assert "recipient" in str(second)
        assert node.count("eth_fillTransaction") == 1


class TestTransactionHash:
    @staticmethod
    def envelopes() -> dict[str, Any]:
        signer = account()
        transaction = TempoTransaction(
            chain_id=TESTNET_CHAIN_ID,
            calls=(Call(to=RECIPIENT, data="0x"),),
            gas_limit=100_000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
        )
        signed = signer.sign_transaction(transaction)
        unsponsored = serialize(signed)
        signature = signed.sender_signature
        assert isinstance(signature, Signature)
        cosigned = serialize(attrs.evolve(signed, fee_payer_signature=signature))
        awaiting = signer.sign_transaction(attrs.evolve(transaction, awaiting_fee_payer=True))
        # ox's 0x76 forms without a fee-payer or sender signature: the signing preimage
        # (plus the sender signature), which pytempo does not serialize.
        awaiting_0x76 = (
            "0x76"
            + rlp_encode(
                [*rlp_decode(awaiting.encode_for_signing()[1:]), signature.to_bytes()]
            ).hex()
        )
        unsigned = to_hex(transaction.encode_for_signing())
        return {
            "unsponsored": ({"signature": unsponsored, "type": "transaction"}, unsponsored),
            "fee payer co-signed": ({"signature": cosigned, "type": "transaction"}, cosigned),
            "sponsored envelope": (
                {"signature": serialize_for_fee_payer(awaiting), "type": "transaction"},
                None,
            ),
            "awaiting fee payer": ({"signature": awaiting_0x76, "type": "transaction"}, None),
            "unsigned": ({"signature": unsigned, "type": "transaction"}, None),
            "trailing bytes": ({"signature": unsponsored + "00", "type": "transaction"}, None),
            "malformed": ({"signature": "0x76ff", "type": "transaction"}, None),
            "non-Tempo": ({"signature": "0x02c0", "type": "transaction"}, None),
            "push": ({"hash": "0x" + "ab" * 32, "type": "hash"}, "push"),
            "malformed push": ({"hash": "0xabc", "type": "hash"}, None),
            "proof": ({"signature": "0x01", "type": "proof"}, None),
        }

    @pytest.mark.parametrize(
        "name",
        [
            "unsponsored",
            "fee payer co-signed",
            "sponsored envelope",
            "awaiting fee payer",
            "unsigned",
            "trailing bytes",
            "malformed",
            "non-Tempo",
            "push",
            "malformed push",
            "proof",
        ],
    )
    def test_derives_credential_hashes(self, name: str) -> None:
        payload, expected = self.envelopes()[name]
        value = Credential(challenge=create_challenge(), payload=payload).serialize()
        if expected == "push":
            expected = payload["hash"]
        elif expected is not None:
            expected = to_hex(keccak256(to_bytes(expected)))
        assert transaction_hash(value) == expected
        assert charge().transaction_hash is transaction_hash


class TestChainPinning:
    async def test_rejects_resolved_client_whose_chain_conflicts_with_pin(self) -> None:
        node = funded()
        with pytest.raises(ValueError, match=r"Chain ID mismatch: expected 4217, got 42431\."):
            await create(client_method(node, expected_chain_id=4217), create_challenge())

    async def test_rejects_challenge_chain_conflicting_with_pin(self) -> None:
        node = funded()
        method = client_method(node, expected_chain_id=TESTNET_CHAIN_ID)
        with pytest.raises(ValueError, match=r"Chain ID mismatch: expected 42431, got 1\."):
            await create(method, create_challenge(chainId=1))
        assert method.requested == []

    async def test_accepts_matching_challenge(self) -> None:
        node = funded()
        value = Credential.deserialize(
            await create(
                client_method(node, expected_chain_id=TESTNET_CHAIN_ID),
                create_challenge(chainId=TESTNET_CHAIN_ID),
            )
        )
        assert value.source == f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{account().address}"

    async def test_signs_on_pin_when_challenge_omits_chain(self) -> None:
        node = funded()
        method = client_method(node, expected_chain_id=TESTNET_CHAIN_ID)
        value = Credential.deserialize(await create(method, create_challenge()))
        assert method.requested == [TESTNET_CHAIN_ID]
        assert value.source == f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{account().address}"

    async def test_unpinned_client_rejects_resolved_client_on_another_chain(self) -> None:
        node = funded()
        with pytest.raises(ValueError, match=r"Chain ID mismatch: expected 1, got 42431\."):
            await create(client_method(node), create_challenge(chainId=1))


@pytest.mark.parametrize(
    ("allowed", "advertised", "resolved", "pin", "accepted"),
    [
        ([4217, 42431], 4217, 4217, None, True),
        ([4217, 42431], 42431, 42431, None, True),
        ([4217, 42431], None, 42431, None, True),
        ([42431], None, 42431, None, True),
        ([4217, 42431], None, 1, None, False),
        ([], None, 42431, None, False),
        ([], 42431, 42431, None, False),
        ([4217], None, 42431, 42431, False),
        ([4217, 42431], 1, 1, None, False),
    ],
)
async def test_charge_chain_allowlists(
    allowed: list[int], advertised: int | None, resolved: int, pin: int | None, accepted: bool
) -> None:
    node = funded(chain_id=resolved)
    method = client_method(node, allowed_chain_ids=allowed, expected_chain_id=pin)
    overrides = {} if advertised is None else {"chainId": advertised}
    if accepted:
        value = Credential.deserialize(await create(method, create_challenge(**overrides)))
        assert value.source == f"did:pkh:eip155:{resolved}:{account().address}"
    else:
        with pytest.raises(ValueError, match="Chain ID not allowed"):
            await create(method, create_challenge(**overrides))
        if advertised is not None or not allowed:
            assert method.requested == []


class TestRecipientAllowlist:
    @pytest.mark.parametrize("splits", [None, [{"recipient": CURRENCY, "amount": "0.1"}]])
    async def test_rejects_unlisted_primary_recipient(self, splits: Any) -> None:
        node = funded()
        resolved: list[Any] = []
        method = client_method(
            node, expected_recipients=[CURRENCY], resolve_account=lambda i: resolved.append(i)
        )
        overrides = {"splits": splits} if splits else {}
        with pytest.raises(ValueError, match=f"Unexpected primary recipient: {RECIPIENT}"):
            await create(method, create_challenge(amount="1", **overrides))
        assert resolved == []

    @pytest.mark.parametrize(
        ("allowed", "splits", "error"),
        [
            ([RECIPIENT, CURRENCY], [{"recipient": CURRENCY, "amount": "0.1"}], None),
            (
                [RECIPIENT],
                [{"recipient": CURRENCY, "amount": "0.1"}],
                f"Unexpected split recipient: {CURRENCY}",
            ),
            ([], None, f"Unexpected primary recipient: {RECIPIENT}"),
            (None, None, None),
        ],
        ids=["matching recipients", "unlisted split", "empty allowlist", "no allowlist"],
    )
    async def test_recipient_policy(
        self, allowed: list[str] | None, splits: Any, error: str | None
    ) -> None:
        node = funded()
        method = client_method(node, expected_recipients=allowed)
        challenge = create_challenge(
            amount="1",
            chainId=TESTNET_CHAIN_ID,
            supportedModes=["pull"],
            **({"splits": splits} if splits else {}),
        )
        if error:
            with pytest.raises(ValueError, match=error):
                await create(method, challenge)
            assert node.count("eth_fillTransaction") == 0
        else:
            value = Credential.deserialize(await create(method, challenge))
            assert value.payload["type"] == "transaction"


class TestAmountCap:
    ATOMIC = "Tempo charge amount exceeds maxAtomicAmount."
    DISPLAY = "Tempo charge amount exceeds maxAmount."

    @pytest.mark.parametrize(
        ("options", "error"),
        [
            ({"max_atomic_amount": "1000001"}, None),
            ({"max_atomic_amount": "1000000"}, None),
            ({"max_atomic_amount": "999999"}, ATOMIC),
            ({"max_atomic_amount": "0"}, ATOMIC),
            ({"decimals": 6, "max_amount": "1.000001"}, None),
            ({"decimals": 6, "max_amount": "1"}, None),
            ({"decimals": 6, "max_amount": "0.999999"}, DISPLAY),
            ({"decimals": 6, "max_amount": "2", "max_atomic_amount": "999999"}, ATOMIC),
            ({}, None),
            (
                {"currencies": [OTHER_CURRENCY]},
                f"Tempo charge currency is not allowed: {CURRENCY}.",
            ),
        ],
    )
    async def test_caps(self, options: dict[str, Any], error: str | None) -> None:
        node = funded()
        resolved: list[Any] = []
        method = client_method(
            node,
            **{"currencies": [CURRENCY], **options},
            resolve_account=lambda info: resolved.append(info),
        )
        challenge = create_challenge(
            amount="1",
            chainId=TESTNET_CHAIN_ID,
            splits=[{"recipient": CURRENCY, "amount": "0.4"}],
            supportedModes=["pull"],
        )
        if error:
            import re

            with pytest.raises(ValueError, match=re.escape(error)):
                await create(method, challenge)
            assert resolved == []
            assert node.count("eth_fillTransaction") == 0
        else:
            value = Credential.deserialize(await create(method, challenge))
            assert value.payload["type"] == "transaction"

    @pytest.mark.parametrize(
        ("options", "error"),
        [
            (
                {"currencies": None, "max_atomic_amount": "1"},
                "Tempo charge maxAmount and maxAtomicAmount require currencies.",
            ),
            (
                {"currencies": None, "decimals": 6, "max_amount": "1"},
                "Tempo charge maxAmount and maxAtomicAmount require currencies.",
            ),
            ({"max_amount": "2"}, "Tempo charge maxAmount requires currency decimals."),
            (
                {"decimals": 6, "max_amount": "1.0000005"},
                "Tempo charge maxAmount 1.0000005 has more fractional digits than 6 decimals allow.",
            ),
            ({"decimals": 6, "max_amount": "1.0000000"}, None),
        ],
    )
    def test_config_time_validation(self, options: dict[str, Any], error: str | None) -> None:
        import re

        parameters = {"account": account(), "currencies": [CURRENCY], **options}
        if error:
            with pytest.raises(ValueError, match=re.escape(error)):
                charge(**parameters)
        else:
            charge(**parameters)

    async def test_accepts_zero_amount_proofs_under_zero_cap(self) -> None:
        node = funded()
        value = await create(
            client_method(node, currencies=[CURRENCY], max_atomic_amount="0"), create_challenge()
        )
        assert Credential.deserialize(value).payload["type"] == "proof"


@pytest.mark.parametrize(
    ("options", "offers", "selected"),
    [
        (
            {"currencies": [CURRENCY], "max_atomic_amount": "1000000"},
            [{"amount": "2"}, {"amount": "0.5"}],
            1,
        ),
        (
            {"currencies": [CURRENCY], "max_atomic_amount": "1000000"},
            [{"amount": "2"}, {"amount": "3"}],
            None,
        ),
        (
            {"currencies": [CURRENCY], "decimals": 6, "max_amount": "1"},
            [{"amount": "2"}, {"amount": "0.5"}],
            1,
        ),
        (
            {"currencies": [CURRENCY], "decimals": 6, "max_amount": "1"},
            [{"amount": "2"}, {"amount": "3"}],
            None,
        ),
        (
            {"currencies": [CURRENCY], "max_atomic_amount": "1000000"},
            [
                {"amount": "0.5", "currency": OTHER_CURRENCY},
                {"amount": "0.5", "currency": CURRENCY},
            ],
            1,
        ),
        (
            {"currencies": [CURRENCY], "max_atomic_amount": "1000000"},
            [
                {"amount": "0.5", "currency": OTHER_CURRENCY},
                {"amount": "0.5", "currency": OTHER_CURRENCY},
            ],
            None,
        ),
        (
            {"expected_recipients": [RECIPIENT]},
            [{"recipient": CURRENCY}, {"recipient": RECIPIENT}],
            1,
        ),
        (
            {"expected_recipients": [RECIPIENT]},
            [
                {"amount": "1", "splits": [{"recipient": CURRENCY, "amount": "0.1"}]},
                {"amount": "1"},
            ],
            1,
        ),
        (
            {"expected_recipients": [RECIPIENT]},
            [{"recipient": CURRENCY}, {"recipient": CURRENCY}],
            None,
        ),
        ({"expected_chain_id": 42431}, [{"chainId": 4217}, {"chainId": 42431}], 1),
        ({"allowed_chain_ids": [4217]}, [{"chainId": 42431}, {"chainId": 1}], None),
    ],
)
async def test_challenge_selection_policy(
    options: dict[str, Any], offers: list[dict[str, Any]], selected: int | None
) -> None:
    mppx = ClientMppx(methods=[charge(account=account(), **options)])
    challenges = [create_challenge(f"offer-{i}", **offer) for i, offer in enumerate(offers)]
    response = httpx.Response(
        402, headers={"WWW-Authenticate": ", ".join(c.serialize() for c in challenges)}
    )
    request = httpx.Request("GET", "https://api.example.com")
    if selected is None:
        with pytest.raises(ValueError, match="No method found for challenges"):
            await mppx.prepare_payment(response, request=request)
    else:
        prepared = await mppx.prepare_payment(response, request=request)
        assert prepared.challenge.id == f"offer-{selected}"


@pytest.mark.parametrize("allowed", [[], [CURRENCY], [RECIPIENT]])
async def test_zero_amount_recipient_policy(allowed: list[str]) -> None:
    node = funded()
    method = client_method(node, expected_recipients=allowed)
    if RECIPIENT in allowed:
        value = await create(method, create_challenge())
        assert Credential.deserialize(value).payload["type"] == "proof"
    else:
        with pytest.raises(ValueError, match="Unexpected primary recipient"):
            await create(method, create_challenge())


async def test_proof_signature_verifies_for_the_payer() -> None:
    node = funded()
    challenge = create_challenge(chainId=TESTNET_CHAIN_ID)
    value = Credential.deserialize(await create(client_method(node), challenge))
    from mpp.tempo._internal.proof import hash_typed_data
    from mpp.tempo._internal.signature import deserialize as deserialize_signature
    from mpp.tempo._internal.signature import verify

    digest = hash_typed_data(
        proof.typed_data(
            account=account().address,
            chain_id=TESTNET_CHAIN_ID,
            challenge_id=challenge.id,
            realm=challenge.realm,
        )
    )
    assert verify(
        deserialize_signature(value.payload["signature"]), payload=digest, address=account().address
    )


def test_sponsor_fixture_is_distinct() -> None:
    assert sponsor().address != payer().address


class TestPaymentOutcomeUnknown:
    """A paid request failing without a response reports ``PaymentOutcomeUnknownError``
    (via ``payment.failed``) carrying the hash the payment settles with, when derivable."""

    @staticmethod
    def flaky_server(challenge: Challenge) -> httpx.MockTransport:
        def app(request: httpx.Request) -> httpx.Response:
            if "authorization" in request.headers:
                raise httpx.ReadError("connection reset after credential was sent", request=request)
            return httpx.Response(402, headers={"WWW-Authenticate": challenge.serialize()})

        return httpx.MockTransport(app)

    @pytest.mark.parametrize(
        ("overrides", "mode", "expected"),
        [({}, "pull", "keccak"), ({}, "push", "hash"), ({"feePayer": True}, "pull", None)],
        ids=["pull", "push", "sponsored"],
    )
    async def test_reports_the_settling_transaction_hash(
        self, overrides: dict[str, Any], mode: str, expected: str | None
    ) -> None:
        from mpp.errors import PaymentOutcomeUnknownError

        node = funded()
        rpc = node.client()
        challenge = create_challenge(amount="1", chainId=TESTNET_CHAIN_ID, **overrides)
        mppx = ClientMppx(
            methods=[charge(account=account(), get_client=lambda _: rpc, mode=mode)],
            inner=self.flaky_server(challenge),
        )
        failures: list[Any] = []
        mppx.on_payment_failed(lambda event: failures.append(event.error))
        with pytest.raises(httpx.ReadError):
            await mppx.fetch("https://api.example.com/paid")
        (error,) = failures
        assert isinstance(error, PaymentOutcomeUnknownError)
        assert error.challenge == challenge
        payload = Credential.deserialize(error.credential).payload
        if expected == "keccak":
            assert error.transaction_hash == to_hex(keccak256(to_bytes(payload["signature"])))
        elif expected == "hash":
            assert error.transaction_hash == payload["hash"]
        else:
            assert error.transaction_hash is None
        assert isinstance(error.__cause__, httpx.ReadError)


class TestSponsoredValidityWindow:
    # pympp#318: sponsored transactions need 15 s of validity left when the server cosigns.
    @pytest.mark.parametrize("seconds_left", [0.5, 10, 14.9])
    async def test_sponsored_challenge_near_expiry_is_refused(self, seconds_left: float) -> None:
        node = funded()
        expires = datetime.fromtimestamp(time.time() + seconds_left, UTC).isoformat()
        challenge = create_challenge(
            amount="1",
            chainId=TESTNET_CHAIN_ID,
            feePayer=True,
            supportedModes=["pull"],
        )
        challenge = Challenge(**{**challenge.to_dict(), "expires": expires.replace("+00:00", "Z")})
        with pytest.raises(PaymentExpiredError):
            await create(client_method(node), challenge)
        assert node.count("eth_fillTransaction") == 0

    async def test_unsponsored_challenge_near_expiry_still_signs(self) -> None:
        node = funded()
        expires = datetime.fromtimestamp(time.time() + 10, UTC).isoformat()
        challenge = create_challenge(amount="1", chainId=TESTNET_CHAIN_ID, supportedModes=["pull"])
        challenge = Challenge(**{**challenge.to_dict(), "expires": expires.replace("+00:00", "Z")})
        value = Credential.deserialize(await create(client_method(node), challenge))
        assert value.payload["type"] == "transaction"
