"""Edge cases of TIP-1166 configurable account signatures and opening commitments."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from mpp.errors import VerificationFailedError
from mpp.methods.tempo import _rlp as rlp
from mpp.methods.tempo._rpc import RpcError as NodeRpcError
from mpp.methods.tempo.session import _abi as abi
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._configurable import (
    MAX_OWNERS,
    ConfigurableAccount,
    ConfigurableAccountOwner,
    ConfigurableAccountSignature,
    configurable_account_digest,
    verify_configurable_signature,
)
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS
from mpp.methods.tempo.session._voucher import (
    _verify_signer_signature,  # pyright: ignore[reportPrivateUsage]
    sign_voucher,
)
from tests.test_session_chain import DESCRIPTOR, PAYER, RPC, FakeRpc
from tests.test_session_configurable import (
    ACCOUNT,
    CHANNEL_ID,
    COMMITMENT,
    CONFIG,
    KEYS,
    PAYLOAD,
    ROTATED,
    SALT,
    ZERO,
    commitment_log,
    configurable,
)

ZERO_ADDRESS = "0x" + "00" * 20


def owner_address(index: int) -> str:
    return "0x" + f"{index:040x}"


def body(signature: ConfigurableAccountSignature) -> list[Any]:
    return rlp.decode(signature.encode()[1:])


def envelope(items: Any) -> bytes:
    return b"\x05" + rlp.encode(items)


def signed() -> ConfigurableAccountSignature:
    return ConfigurableAccountSignature.decode(configurable().sign_hash(PAYLOAD))


class TestConfigValidation:
    @pytest.mark.parametrize(
        ("changes", "message"),
        [
            ({"salt": "0x" + "zz" * 32}, "invalid salt"),
            ({"salt": "ab" * 32}, "invalid salt"),
            ({"version": -1}, "version out of range"),
            ({"version": 2**64}, "version out of range"),
            ({"owners": ()}, "no owners"),
            (
                {
                    "owners": tuple(
                        ConfigurableAccountOwner(owner_address(i + 1), 1)
                        for i in range(MAX_OWNERS + 1)
                    )
                },
                "too many owners",
            ),
            ({"threshold": 0}, "threshold must be 1 to 255"),
            (
                {"owners": (ConfigurableAccountOwner(ZERO_ADDRESS, 1), *CONFIG.owners[1:])},
                "zero address",
            ),
            (
                {"owners": (replace(CONFIG.owners[0], weight=0), *CONFIG.owners[1:])},
                "weight must be 1 to 255",
            ),
            ({"owners": (CONFIG.owners[1], CONFIG.owners[0])}, "distinct and ascending"),
            (
                {
                    "threshold": 1,
                    "owners": (
                        ConfigurableAccountOwner(owner_address(1), 200),
                        ConfigurableAccountOwner(owner_address(2), 200),
                    ),
                },
                "total weight exceeds 255",
            ),
            ({"threshold": 4}, "weight 8 approvals can reach"),
        ],
    )
    def test_rejects_invalid_configs(self, changes: dict[str, Any], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            replace(CONFIG, **changes).validate()

    def test_initial_config_cannot_own_its_account(self) -> None:
        owner = CONFIG.owners[0].owner
        with pytest.raises(ValueError, match="cannot own itself"):
            CONFIG.validate(owner)
        # A later version may list the account among its owners.
        replace(CONFIG, version=1).validate(owner)

    def test_digest_needs_a_32_byte_inner_digest(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            configurable_account_digest(b"\x01" * 31, ACCOUNT, 0)


class TestDecode:
    def test_rejects_malformed_envelopes(self) -> None:
        items = body(signed())
        config = items[1]
        cases: list[tuple[bytes, str]] = [
            (b"\x05", "not a configurable account signature"),
            (b"\x01" + rlp.encode(items), "not a configurable account signature"),
            (b"\x05\xff", "malformed configurable account signature"),
            (envelope(b"\x01\x02"), "malformed configurable account signature"),
            (envelope(items[:2]), "malformed configurable account signature"),
            (envelope([b"\x01" * 19, config, items[2]]), "malformed configurable account address"),
            (envelope([items[0], config[:3], items[2]]), "malformed configurable account config"),
            (envelope([items[0], config, []]), "1 to 8 approvals"),
            (envelope([items[0], config, [items[2][0]] * 9]), "1 to 8 approvals"),
            (envelope([b"\x00" * 20, config, items[2]]), "zero address"),
            (
                envelope([items[0], [*config[:2], b"\x00\x02", config[3]], items[2]]),
                "invalid RLP integer",
            ),
            (
                envelope([items[0], [*config[:2], b"\x01\x02", config[3]], items[2]]),
                "invalid RLP integer",
            ),
        ]
        for raw, message in cases:
            with pytest.raises(ValueError, match=message):
                ConfigurableAccountSignature.decode(raw)

    def test_rejects_a_non_canonical_envelope(self) -> None:
        # The same list with its length in a longer header than it needs.
        payload = rlp.encode(body(signed()))
        assert payload[0] == 0xF9
        padded = b"\x05\xfa\x00" + payload[1:]
        with pytest.raises(ValueError, match="configurable account signature"):
            ConfigurableAccountSignature.decode(padded)


class TestApprovals:
    def test_rejects_unusable_approvals(self) -> None:
        parsed = signed()
        good = parsed.approvals
        assert parsed.verify_approvals(PAYLOAD)
        first = good[0]
        high_s = first[:32] + (2**256 - 1).to_bytes(32, "big") + first[64:]
        bad_v = first[:64] + bytes([29])
        zero_r = b"\x00" * 32 + (1).to_bytes(32, "big") + bytes([27])
        for approval in (first[:64], high_s, bad_v, zero_r):
            tampered = replace(parsed, approvals=(approval, *good[1:]))
            assert not tampered.verify_approvals(PAYLOAD)
        # Approvals in descending owner order fail, as do duplicate approvals.
        assert not replace(parsed, approvals=tuple(reversed(good))).verify_approvals(PAYLOAD)
        assert not replace(parsed, approvals=(good[0], good[0])).verify_approvals(PAYLOAD)

    def test_accepts_a_zero_or_one_recovery_id(self) -> None:
        parsed = signed()
        approvals = tuple(a[:64] + bytes([a[64] - 27]) for a in parsed.approvals)
        assert replace(parsed, approvals=approvals).verify_approvals(PAYLOAD)

    def test_verify_rejects_garbage_and_mismatched_configs(self) -> None:
        signature = "0x" + configurable().sign_hash(PAYLOAD).hex()
        assert verify_configurable_signature(signature, PAYLOAD, ACCOUNT)
        assert not verify_configurable_signature("0x05zz", PAYLOAD, ACCOUNT)
        assert not verify_configurable_signature(signature, PAYLOAD, PAYER.address)
        assert not verify_configurable_signature(signature, PAYLOAD, ACCOUNT, SALT)
        rotated = "0x" + configurable(ROTATED).sign_hash(PAYLOAD).hex()
        assert not verify_configurable_signature(rotated, PAYLOAD, ACCOUNT, ZERO)

    def test_voucher_rule_rejects_a_bad_digest(self) -> None:
        signature = "0x" + configurable().sign_hash(PAYLOAD).hex()
        assert not _verify_signer_signature(
            signature, "0xzz", ACCOUNT, configurable=True, opening_commitment=None
        )
        assert not _verify_signer_signature(
            signature, "0x" + PAYLOAD.hex(), ACCOUNT, configurable=False, opening_commitment=None
        )


class _NonSecpOwner:
    def __init__(self, address: str) -> None:
        self.address = address

    def sign_hash(self, msg_hash: bytes) -> bytes:
        return b"\x01" * 64


class TestConfigurableAccount:
    def test_owners_must_sign_with_secp256k1(self) -> None:
        owners = [_NonSecpOwner(o.owner) for o in CONFIG.owners]
        account = ConfigurableAccount(address=ACCOUNT, config=CONFIG, owners=owners)
        with pytest.raises(ValueError, match="secp256k1"):
            account.sign_hash(PAYLOAD)

    def test_owners_must_reach_the_threshold(self) -> None:
        with pytest.raises(ValueError, match="cannot reach"):
            ConfigurableAccount(address=ACCOUNT, config=CONFIG, owners=KEYS[:1])

    def test_root_key_must_be_the_account(self) -> None:
        with pytest.raises(ValueError, match="root_key"):
            ConfigurableAccount(address=ACCOUNT, config=CONFIG, owners=KEYS, root_key=KEYS[0])

    def test_from_initial_config_needs_version_zero(self) -> None:
        with pytest.raises(ValueError, match="version 0"):
            ConfigurableAccount.from_initial_config(ROTATED, KEYS)
        assert ConfigurableAccount.from_initial_config(CONFIG, KEYS).address == ACCOUNT

    def test_rotated_account_without_root_key_signs_every_channel(self) -> None:
        account = configurable(ROTATED)
        assert account.channel_signer(ZERO) is account
        assert account.channel_signer(account.commitment) is account


class TestChainOpeningCommitments:
    def test_skips_unusable_logs(self) -> None:
        descriptor = replace(DESCRIPTOR, authorized_signer=ACCOUNT, salt=COMMITMENT)
        log = commitment_log(CHANNEL_ID, ACCOUNT, COMMITMENT)
        receipt = {"logs": ["not a log", {**log, "topics": []}, log]}
        assert chain.get_opening_commitment(receipt, descriptor, CHANNEL_ID) == COMMITMENT
        assert chain.get_opening_commitment({"logs": None}, descriptor, CHANNEL_ID) is None

    def test_an_undecodable_opening_commitment_event_fails(self) -> None:
        # Skipping it could read a nonzero opening commitment as zero.
        descriptor = replace(DESCRIPTOR, authorized_signer=ACCOUNT, salt=COMMITMENT)
        log = commitment_log(CHANNEL_ID, ACCOUNT, COMMITMENT)
        for broken in ({**log, "data": "0x1234"}, {**log, "topics": log["topics"][:2]}):
            with pytest.raises(VerificationFailedError, match="undecodable"):
                chain.get_opening_commitment({"logs": [broken, log]}, descriptor, CHANNEL_ID)

    def test_zero_authorized_signer_means_the_payer(self) -> None:
        descriptor = replace(DESCRIPTOR, authorized_signer=ZERO_ADDRESS, salt=COMMITMENT)
        receipt = {"logs": [commitment_log(CHANNEL_ID, PAYER.address, COMMITMENT)]}
        assert chain.get_opening_commitment(receipt, descriptor, CHANNEL_ID) == COMMITMENT

    async def test_config_commitment_results(self) -> None:
        rpc = FakeRpc()
        rpc.overrides["eth_call"] = lambda params: "0x"
        assert await chain.get_config_commitment(RPC, ACCOUNT, client=rpc.client) == ZERO
        rpc.overrides["eth_call"] = lambda params: "0x1234"
        with pytest.raises(ValueError, match="getConfigCommitment"):
            await chain.get_config_commitment(RPC, ACCOUNT, client=rpc.client)

    async def test_verify_voucher_on_chain_asks_the_escrow(self) -> None:
        rpc = FakeRpc()
        descriptor = replace(DESCRIPTOR, authorized_signer=ZERO_ADDRESS)
        channel_id = compute_channel_id(descriptor, chain_id=rpc.chain_id)
        signed = sign_voucher(
            PAYER, channel_id=channel_id, cumulative_amount=100, chain_id=rpc.chain_id
        )

        async def verify() -> bool:
            return await chain.verify_voucher_on_chain(
                RPC, descriptor, 100, signed, escrow=ESCROW_ADDRESS, client=rpc.client
            )

        assert await verify()
        rpc.opening_commitments[channel_id.lower()] = COMMITMENT
        assert not await verify()
        rpc.overrides["eth_call"] = lambda params: "0x1234"
        with pytest.raises(Exception):  # noqa: B017
            await verify()

    def test_signer_config_error_reads_nested_revert_data(self) -> None:
        selector = abi.ERROR_SELECTORS["RootKeyRetired"]
        data = "0x" + (selector + b"\x00" * 12 + bytes.fromhex(ACCOUNT[2:])).hex()
        error = chain.signer_config_error(
            NodeRpcError({"error": {"code": 3, "data": {"data": data}}})
        )
        assert error is not None
        assert error.reason == "RootKeyRetired"
        assert error.signer == ACCOUNT
        assert chain.signer_config_error(NodeRpcError({"error": {"data": "0x1234"}})) is None
