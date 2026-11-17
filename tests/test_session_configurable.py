"""TIP-1166 configurable account voucher signers (T15): 0x05 vouchers, signer snapshots, salts.

Encodings are checked against a vector computed with ox's tempo AccountConfig and
SignatureEnvelope (ox 1.8.16), which match tempo-primitives' configurable account code.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from eth_abi.abi import encode

from mpp.errors import VerificationFailedError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo._rpc import RpcError as NodeRpcError
from mpp.methods.tempo.session import _abi as abi
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._configurable import (
    CONFIGURABLE_ACCOUNT_ADDRESS,
    ConfigurableAccount,
    ConfigurableAccountConfig,
    ConfigurableAccountOwner,
    ConfigurableAccountSignature,
    ConfigurableVouchersUnsupportedError,
    SignerConfigChangedError,
    configurable_account_digest,
    verify_configurable_signature,
)
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS, ChannelDescriptor, SignedVoucher
from mpp.methods.tempo.session._voucher import (
    sign_close_authorization,
    sign_voucher,
    verify_close_authorization,
    verify_voucher,
)
from mpp.methods.tempo.session.client import _ops as ops
from mpp.methods.tempo.session.server import _request_state as request_state
from mpp.methods.tempo.session.server import _verification as verification
from mpp.methods.tempo.session.server._store import (
    InvalidSignatureError,
    channel_state_from_json,
    channel_state_to_json,
)
from tests.session_helpers import Lifecycle, make_challenge
from tests.test_session_chain import (
    CHAIN_ID,
    CURRENCY,
    DEPOSIT,
    DESCRIPTOR,
    PAYEE,
    PAYER,
    RPC,
    FakeRpc,
    opened_log,
    topic,
)

# ox: AccountConfig.from({salt: 0xab..ab, threshold: 2, owners: three keys of weight 1}).
KEYS = [TempoAccount.from_key("0x" + byte * 32) for byte in ("22", "11", "33")]
SALT = "0x" + "ab" * 32
ACCOUNT = "0x4398f1ac3c453e752a1078053e09402aff14d706"
COMMITMENT = "0xa531fbe0df1d4cf1890bd2b1fcb3aac31f9e2dda5e63416f69eae4fba6e192c2"
ROTATED_COMMITMENT = "0xa2877e60b9f9988a7f58a0e2f2a0bc323f99fb1871475b6992176621c257c2c8"
ZERO = "0x" + "00" * 32
PAYLOAD = bytes.fromhex("5a" * 32)
SIGN_PAYLOAD = "0xfd20f2b267e3084c3b54c7e01f7a3e7434f9ed6b6c26d2fa1f1e90b3225d3158"
ENVELOPE = (
    "0x05f90109944398f1ac3c453e752a1078053e09402aff14d706f86aa0abababababababababababababab"
    "abababababababababababababababababab8002f845d6941563915e194d8cfba1943570603f7606a31155"
    "0801d69419e7e376e7c213b7e7e7e46cc70a5dd086daff2a01d6945cbdd86a2fa8dc4bddd8a8f69dba4857"
    "2eec07fb01f886b8419684fc73356fac40a37a204c7ae30fb3c3eacdd8b90319698790d547f4b350a143fa"
    "2c04b6339cb8c3ee59a40a62198cca05a8601911f26f64f927ea9faf54121cb841a8199f0a3fa11c0096b7"
    "eee657c20c127979834d4608c2b9e12659b2d5eaef804f04e43c2bf74ed3e32df4959f06502aa26032ff76"
    "d3b389de057274f0d160c71b"
)

CONFIG = ConfigurableAccountConfig(
    salt=SALT,
    threshold=2,
    owners=tuple(
        ConfigurableAccountOwner(address, 1)
        for address in sorted((k.address.lower() for k in KEYS), key=lambda a: int(a, 16))
    ),
)
# ox: AccountConfig.update(config, {threshold: 1, owners: [lowest owner]}).
ROTATED = ConfigurableAccountConfig(salt=SALT, threshold=1, owners=(CONFIG.owners[0],), version=1)
CHANNEL_ID = "0x" + "c1" * 32


def configurable(config: ConfigurableAccountConfig = CONFIG) -> ConfigurableAccount:
    return ConfigurableAccount(address=ACCOUNT, config=config, owners=KEYS)


def voucher(signer: Any, amount: int = 100, channel_id: str = CHANNEL_ID) -> SignedVoucher:
    signature = sign_voucher(
        signer, channel_id=channel_id, cumulative_amount=amount, chain_id=CHAIN_ID
    )
    return SignedVoucher(channel_id=channel_id, cumulative_amount=amount, signature=signature)


def check(signed: SignedVoucher, signer: str = ACCOUNT, **options: Any) -> bool:
    return verify_voucher(ESCROW_ADDRESS, CHAIN_ID, signed, signer, **options)


def snapshot_log(channel_id: str, signer: str, commitment: str) -> dict[str, Any]:
    return {
        "address": ESCROW_ADDRESS,
        "topics": [abi.EVENT_TOPICS["SignerSnapshotCached"], channel_id, topic(signer)],
        "data": "0x" + encode(["bytes32"], [bytes.fromhex(commitment[2:])]).hex(),
    }


def with_commitment(rpc: FakeRpc, commitment: str) -> None:
    """Answer the configurable account precompile's getConfigCommitment with commitment."""
    original = rpc._call  # pyright: ignore[reportPrivateUsage]

    def call(params: list[Any]) -> Any:
        if str(params[0].get("to", "")).lower() == CONFIGURABLE_ACCOUNT_ADDRESS.lower():
            return commitment
        return original(params)

    rpc.overrides["eth_call"] = call


async def build_open(rpc: FakeRpc, **kwargs: Any) -> tuple[str, ChannelDescriptor, str]:
    return await chain.build_open_transaction(
        PAYER,
        rpc_url=RPC,
        payee=PAYEE.address,
        token=CURRENCY,
        deposit=DEPOSIT,
        client=rpc.client,
        **kwargs,
    )


class TestEncodings:
    def test_matches_ox(self) -> None:
        assert CONFIG.derive_address() == ACCOUNT
        assert CONFIG.commitment() == COMMITMENT
        assert ROTATED.commitment() == ROTATED_COMMITMENT
        assert "0x" + configurable_account_digest(PAYLOAD, ACCOUNT, 0).hex() == SIGN_PAYLOAD
        assert "0x" + configurable().sign_hash(PAYLOAD).hex() == ENVELOPE
        assert configurable().commitment == COMMITMENT

    def test_decodes_and_reencodes_the_envelope(self) -> None:
        parsed = ConfigurableAccountSignature.decode(bytes.fromhex(ENVELOPE[2:]))
        assert parsed.account == ACCOUNT and parsed.config == CONFIG
        assert "0x" + parsed.encode().hex() == ENVELOPE

    def test_from_initial_config_derives_the_account(self) -> None:
        assert ConfigurableAccount.from_initial_config(CONFIG, KEYS).address == ACCOUNT
        with pytest.raises(ValueError, match="version 0"):
            ConfigurableAccount.from_initial_config(ROTATED, KEYS)

    @pytest.mark.parametrize(
        "config",
        [
            replace(CONFIG, owners=CONFIG.owners[::-1]),
            replace(CONFIG, owners=(CONFIG.owners[0], CONFIG.owners[0])),
            replace(CONFIG, threshold=4),
            replace(CONFIG, threshold=0),
            replace(CONFIG, owners=()),
            replace(CONFIG, salt="0x01"),
        ],
    )
    def test_rejects_invalid_configs(self, config: ConfigurableAccountConfig) -> None:
        with pytest.raises(ValueError):
            config.validate()

    def test_rejects_owners_that_cannot_reach_the_threshold(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            ConfigurableAccount(address=ACCOUNT, config=CONFIG, owners=KEYS[:1])


class TestVerifyVoucher:
    def test_defaults_reject_configurable_vouchers(self) -> None:
        signed = voucher(configurable())
        assert signed.signature.startswith("0x05")
        assert not check(signed)
        assert not check(signed, signer_snapshot=COMMITMENT)

    def test_primitive_vouchers_are_unchanged(self) -> None:
        signed = voucher(PAYER)
        assert check(signed, PAYER.address)
        assert check(signed, PAYER.address, configurable=True)
        assert check(signed, PAYER.address, configurable=True, signer_snapshot=ZERO)

    def test_accepts_a_configurable_voucher_under_its_snapshot(self) -> None:
        assert check(voucher(configurable()), configurable=True, signer_snapshot=COMMITMENT)

    def test_rejects_a_voucher_under_a_rotated_config(self) -> None:
        rotated = voucher(configurable(ROTATED))
        assert check(rotated, configurable=True, signer_snapshot=ROTATED_COMMITMENT)
        assert not check(rotated, configurable=True, signer_snapshot=COMMITMENT)
        original = voucher(configurable())
        assert not check(original, configurable=True, signer_snapshot=ROTATED_COMMITMENT)

    def test_rejects_a_primitive_voucher_when_the_snapshot_is_nonzero(self) -> None:
        signed = voucher(PAYER)
        assert not check(signed, PAYER.address, signer_snapshot=COMMITMENT)
        assert not check(signed, PAYER.address, configurable=True, signer_snapshot=COMMITMENT)

    def test_zero_snapshot_needs_the_version_zero_config_that_derives_the_signer(self) -> None:
        assert check(voucher(configurable()), configurable=True)
        assert check(voucher(configurable()), configurable=True, signer_snapshot=ZERO)
        # A later config version cannot prove the address without a snapshot.
        assert not check(voucher(configurable(ROTATED)), configurable=True)
        # A version-zero config that derives another address.
        stranger = "0x" + "77" * 20
        other = ConfigurableAccount(address=stranger, config=CONFIG, owners=KEYS)
        assert not check(voucher(other), stranger, configurable=True)

    def test_rejects_a_voucher_for_another_signer_or_amount(self) -> None:
        signed = voucher(configurable())
        assert not check(signed, PAYER.address, configurable=True)
        moved = replace(signed, cumulative_amount=101)
        assert not check(moved, configurable=True, signer_snapshot=COMMITMENT)

    def test_rejects_approvals_below_threshold_out_of_order_or_unneeded(self) -> None:
        digest = configurable_account_digest(PAYLOAD, ACCOUNT, 0)
        by_owner = {key.address.lower(): key.sign_hash(digest) for key in KEYS}
        ordered = [by_owner[owner.owner] for owner in CONFIG.owners]

        def verify(approvals: list[bytes]) -> bool:
            signature = ConfigurableAccountSignature(ACCOUNT, CONFIG, tuple(approvals))
            envelope = "0x" + signature.encode().hex()
            return verify_configurable_signature(envelope, PAYLOAD, ACCOUNT, COMMITMENT)

        assert verify(ordered[:2])
        assert not verify(ordered[:1])  # below the threshold
        assert not verify(ordered[:2][::-1])  # not in ascending owner order
        assert not verify([ordered[0], ordered[0]])  # the same owner twice
        assert not verify(ordered)  # an approval the threshold does not need
        stranger = TempoAccount.from_key("0x" + "55" * 32)
        assert not verify([ordered[0], stranger.sign_hash(digest)])

    def test_rejects_malformed_envelopes(self) -> None:
        assert not verify_configurable_signature("0x05", PAYLOAD, ACCOUNT)
        assert not verify_configurable_signature("0x05c0", PAYLOAD, ACCOUNT)
        assert not verify_configurable_signature(ENVELOPE + "00", PAYLOAD, ACCOUNT)
        assert not check(
            SignedVoucher(channel_id=CHANNEL_ID, cumulative_amount=100, signature="0x05zz"),
            configurable=True,
        )

    def test_close_authorization_follows_the_same_rules(self) -> None:
        signature = sign_close_authorization(
            configurable(), channel_id=CHANNEL_ID, cumulative_amount=100, chain_id=CHAIN_ID
        )
        signed = SignedVoucher(channel_id=CHANNEL_ID, cumulative_amount=100, signature=signature)

        def verify(**options: Any) -> bool:
            return verify_close_authorization(
                ESCROW_ADDRESS, CHAIN_ID, signed, [PAYER.address, ACCOUNT], **options
            )

        assert not verify()
        assert verify(configurable=True, signer_snapshot=COMMITMENT)
        assert not verify(configurable=True, signer_snapshot=ROTATED_COMMITMENT)


class TestChain:
    def test_reads_the_signer_snapshot_from_the_open_receipt(self) -> None:
        descriptor = replace(DESCRIPTOR, authorized_signer=ACCOUNT, salt=COMMITMENT)
        receipt = {"logs": [snapshot_log(CHANNEL_ID, ACCOUNT, COMMITMENT)]}
        assert chain.get_signer_snapshot(receipt, descriptor, CHANNEL_ID) == COMMITMENT
        assert chain.get_signer_snapshot({"logs": []}, descriptor, CHANNEL_ID) is None
        assert chain.get_signer_snapshot(receipt, descriptor, "0x" + "d2" * 32) is None
        assert (
            chain.get_signer_snapshot(receipt, descriptor, CHANNEL_ID, escrow=PAYEE.address) is None
        )
        with pytest.raises(VerificationFailedError, match="salt"):
            chain.get_signer_snapshot(receipt, replace(descriptor, salt=SALT), CHANNEL_ID)
        wrong = {"logs": [snapshot_log(CHANNEL_ID, PAYEE.address, COMMITMENT)]}
        with pytest.raises(VerificationFailedError, match="signer"):
            chain.get_signer_snapshot(wrong, descriptor, CHANNEL_ID)
        twice = {"logs": receipt["logs"] * 2}
        with pytest.raises(VerificationFailedError, match="at most one"):
            chain.get_signer_snapshot(twice, descriptor, CHANNEL_ID)

    async def test_open_salt_defaults_to_the_signer_commitment(self) -> None:
        rpc = FakeRpc()
        with_commitment(rpc, COMMITMENT)
        _, descriptor, _ = await build_open(rpc, voucher_signer=configurable())
        assert descriptor.salt == COMMITMENT
        assert descriptor.authorized_signer.lower() == ACCOUNT

    async def test_explicit_salt_wins(self) -> None:
        rpc = FakeRpc()
        with_commitment(rpc, COMMITMENT)
        salt = "0x" + "01" * 32
        _, descriptor, _ = await build_open(rpc, voucher_signer=configurable(), salt=salt)
        assert descriptor.salt == salt

    async def test_unregistered_signer_keeps_a_random_salt(self) -> None:
        rpc = FakeRpc()
        with_commitment(rpc, ZERO)
        _, descriptor, _ = await build_open(rpc, voucher_signer=configurable())
        assert descriptor.salt not in (COMMITMENT, ZERO)
        with pytest.raises(ValueError, match="version-zero"):
            await build_open(rpc, voucher_signer=configurable(ROTATED))

    async def test_stale_config_fails_before_signing(self) -> None:
        rpc = FakeRpc()
        with_commitment(rpc, ROTATED_COMMITMENT)
        with pytest.raises(ValueError, match="on-chain commitment"):
            await build_open(rpc, voucher_signer=configurable())
        assert not rpc.methods("eth_estimateGas")

    async def test_no_commitment_read_without_a_configurable_signer(self) -> None:
        rpc = FakeRpc()
        await build_open(rpc)
        assert all(
            str(params[0].get("to", "")).lower() != CONFIGURABLE_ACCOUNT_ADDRESS.lower()
            for params in rpc.methods("eth_call")
        )

    @pytest.mark.parametrize("reason", ["SignerConfigChanged", "RootKeyRetired"])
    async def test_top_up_surfaces_signer_config_changes(
        self, reason: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rpc = FakeRpc()
        data = "0x" + (abi.ERROR_SELECTORS[reason] + bytes(12) + bytes.fromhex(ACCOUNT[2:])).hex()
        original = chain._rpc  # pyright: ignore[reportPrivateUsage]

        async def node(rpc_url: str, method: str, params: list[Any], client: Any) -> Any:
            if method == "eth_estimateGas":
                raise NodeRpcError({"error": {"code": 3, "message": "reverted", "data": data}})
            return await original(rpc_url, method, params, client)

        monkeypatch.setattr(chain, "_rpc", node)
        descriptor = replace(DESCRIPTOR, authorized_signer=ACCOUNT, salt=COMMITMENT)
        with pytest.raises(SignerConfigChangedError) as caught:
            await chain.build_top_up_transaction(
                PAYER, descriptor, 500, rpc_url=RPC, chain_id=CHAIN_ID, client=rpc.client
            )
        assert (caught.value.reason, caught.value.signer) == (reason, ACCOUNT)
        assert caught.value.channel_id is not None

    def test_other_rpc_errors_are_not_mapped(self) -> None:
        assert chain.signer_config_error(NodeRpcError({"error": "boom"})) is None
        assert chain.signer_config_error(NodeRpcError({"error": {"data": "0xzz"}})) is None
        assert chain.signer_config_error(RuntimeError("boom")) is None


class TestServer:
    async def _life(self) -> Lifecycle:
        life = Lifecycle()
        with_commitment(life.rpc, COMMITMENT)
        return await life.build(voucher_signer=configurable())

    async def _open(self, life: Lifecycle, cached: str = COMMITMENT, **overrides: Any) -> None:
        signed = voucher(configurable(), 100, life.channel_id)
        life.rpc.logs = [
            opened_log(life.descriptor, life.channel_id),
            snapshot_log(life.channel_id, ACCOUNT, cached),
        ]
        await verification.broadcast_credential_payload(
            life.context(life.open_payload(signature=signed.signature), **overrides)
        )

    async def test_accepts_configurable_vouchers_when_enabled(self) -> None:
        life = await self._life()
        await self._open(life, configurable_vouchers=True)
        assert (await life.channel()).signer_snapshot == COMMITMENT
        signed = voucher(configurable(), 300, life.channel_id)
        receipt = await life.accept(
            life.voucher_payload(300, signature=signed.signature), configurable_vouchers=True
        )
        assert receipt.accepted_cumulative == "300"
        rotated = voucher(configurable(ROTATED), 400, life.channel_id)
        with pytest.raises(InvalidSignatureError):
            await life.accept(
                life.voucher_payload(400, signature=rotated.signature), configurable_vouchers=True
            )

    async def test_rejects_configurable_vouchers_by_default(self) -> None:
        life = await self._life()
        with pytest.raises(InvalidSignatureError):
            await self._open(life)
        assert not life.rpc.sent

    async def test_rejects_an_open_whose_receipt_caches_another_snapshot(self) -> None:
        life = await self._life()
        with pytest.raises(VerificationFailedError):
            await self._open(life, ROTATED_COMMITMENT, configurable_vouchers=True)

    async def test_primitive_opens_store_a_zero_snapshot(self) -> None:
        life = await Lifecycle().build()
        await life.open(configurable_vouchers=True)
        channel = await life.channel()
        assert channel.signer_snapshot == ZERO
        assert channel_state_from_json(channel_state_to_json(channel)).signer_snapshot == ZERO
        # Records written before the field existed load as unknown.
        legacy = channel_state_to_json(replace(channel, signer_snapshot=None))
        assert "signerSnapshot" not in legacy
        assert channel_state_from_json(legacy).signer_snapshot is None
        cached = channel_state_to_json(replace(channel, signer_snapshot=COMMITMENT))
        assert cached["signerSnapshot"] == COMMITMENT
        assert channel_state_from_json(cached).signer_snapshot == COMMITMENT

    async def test_accepts_configurable_vouchers_in_one_store_update(self) -> None:
        life = await self._life()
        await self._open(life, configurable_vouchers=True)
        signed = voucher(configurable(), 300, life.channel_id)
        receipt = await life.accept(
            life.voucher_payload(300, signature=signed.signature),
            configurable_vouchers=True,
            voucher_state_max_age=60_000,
        )
        assert receipt.accepted_cumulative == "300"
        primitive = life.voucher_payload(400)
        with pytest.raises(InvalidSignatureError):
            await life.accept(primitive, configurable_vouchers=True, voucher_state_max_age=60_000)

    async def test_rejects_a_primitive_open_voucher_once_the_escrow_cached_a_commitment(
        self,
    ) -> None:
        # Such as an EOA that adopted a configuration (TIP-1113): its old key still signs.
        life = await Lifecycle().build(salt=COMMITMENT)
        life.rpc.logs = [
            opened_log(life.descriptor, life.channel_id),
            snapshot_log(life.channel_id, PAYER.address, COMMITMENT),
        ]
        with pytest.raises(InvalidSignatureError):
            await verification.broadcast_credential_payload(life.context(life.open_payload()))


class TestUnknownSnapshot:
    """A channel stored without a snapshot is looked up on chain once, never assumed zero."""

    async def _life(self, *, commitment: str | None, logged: bool) -> Lifecycle:
        life = await Lifecycle().build(salt=COMMITMENT)
        await life.open()
        await life.update(signer_snapshot=None)
        if commitment is not None:
            life.rpc.commitments[PAYER.address.lower()] = commitment
        if logged:
            life.rpc.chain_logs = [snapshot_log(life.channel_id, PAYER.address, COMMITMENT)]
        return life

    async def test_a_logged_snapshot_rejects_primitive_vouchers(self) -> None:
        life = await self._life(commitment=ROTATED_COMMITMENT, logged=True)
        snapshots: dict[str, str] = {}
        for amount in (200, 300):
            with pytest.raises(InvalidSignatureError):
                await life.accept(life.voucher_payload(amount), signer_snapshots=snapshots)
        assert (await life.channel()).signer_snapshot == COMMITMENT
        assert len(life.rpc.methods("eth_getLogs")) == 1

    async def test_the_one_store_update_path_also_waits_for_the_lookup(self) -> None:
        life = await self._life(commitment=COMMITMENT, logged=True)
        with pytest.raises(InvalidSignatureError):
            await life.accept(life.voucher_payload(200), voucher_state_max_age=60_000)
        assert (await life.channel()).signer_snapshot == COMMITMENT

    async def test_no_log_means_zero_rules(self) -> None:
        life = await self._life(commitment=COMMITMENT, logged=False)
        receipt = await life.accept(life.voucher_payload(200))
        assert receipt.accepted_cumulative == "200"
        assert (await life.channel()).signer_snapshot == ZERO

    async def test_a_signer_without_a_commitment_skips_the_log_search(self) -> None:
        life = await self._life(commitment=None, logged=False)
        receipt = await life.accept(life.voucher_payload(200))
        assert receipt.accepted_cumulative == "200"
        assert not life.rpc.methods("eth_getLogs")
        assert (await life.channel()).signer_snapshot == ZERO

    async def test_close_looks_the_snapshot_up_too(self) -> None:
        life = await self._life(commitment=COMMITMENT, logged=True)
        with pytest.raises(InvalidSignatureError):
            await life.accept(life.close_payload(100))

    def test_challenge_advertises_configurable_vouchers_only_when_enabled(self) -> None:
        def resolve(**options: Any) -> dict[str, Any]:
            return request_state.resolve_session_payment_request(
                request={"amount": "1", "currency": CURRENCY, "recipient": PAYEE.address},
                chain_id=CHAIN_ID,
                default_fee_payer=None,
                parameter_escrow_contract=None,
                fee_token=None,
                **options,
            )

        assert "configurable_vouchers" not in resolve()
        assert resolve(configurable_vouchers=True)["configurable_vouchers"] is True


class TestChannelSigner:
    def test_signs_0x05_for_a_channel_salted_with_its_commitment(self) -> None:
        assert configurable().channel_signer(COMMITMENT) is not None
        account = configurable(ROTATED)
        assert account.channel_signer(ROTATED_COMMITMENT) is account

    def test_zero_snapshot_channels_use_the_version_zero_config_that_derives_the_address(
        self,
    ) -> None:
        account = configurable()
        assert account.channel_signer(SALT) is account
        signed = voucher(account.channel_signer(SALT))
        assert check(signed, configurable=True, signer_snapshot=ZERO)

    def test_zero_snapshot_channels_fall_back_to_the_root_key(self) -> None:
        # An EOA that adopted a configuration (TIP-1113): its v0 config does not derive it.
        root = PAYER
        config = replace(ROTATED, version=0)
        account = ConfigurableAccount(
            address=root.address, config=config, owners=KEYS, root_key=root
        )
        assert account.channel_signer(SALT) is root
        assert account.channel_signer(config.commitment()) is account
        signed = voucher(account.channel_signer(SALT))
        assert check(signed, root.address, signer_snapshot=ZERO)
        with pytest.raises(ValueError, match="own key"):
            ConfigurableAccount(address=ACCOUNT, config=CONFIG, owners=KEYS, root_key=root)


class TestClient:
    async def test_open_fails_fast_without_server_support(self) -> None:
        rpc = FakeRpc()
        for advertised in (None, False):
            with pytest.raises(ConfigurableVouchersUnsupportedError):
                await ops.create_open_payload(
                    PAYER,
                    rpc_url=RPC,
                    chain_id=CHAIN_ID,
                    deposit=DEPOSIT,
                    initial_amount=100,
                    payee=PAYEE.address,
                    token=CURRENCY,
                    client=rpc.client,
                    voucher_signer=configurable(),
                    configurable_vouchers=advertised,
                )
        assert not rpc.requests

    async def test_open_signs_configurable_vouchers_when_supported(self) -> None:
        rpc = FakeRpc()
        with_commitment(rpc, COMMITMENT)
        payload = await ops.create_open_payload(
            PAYER,
            rpc_url=RPC,
            chain_id=CHAIN_ID,
            deposit=DEPOSIT,
            initial_amount=100,
            payee=PAYEE.address,
            token=CURRENCY,
            client=rpc.client,
            voucher_signer=configurable(),
            configurable_vouchers=True,
        )
        assert payload.descriptor is not None and payload.descriptor["salt"] == COMMITMENT
        assert payload.signature.startswith("0x05")
        signed = SignedVoucher(
            channel_id=payload.channel_id, cumulative_amount=100, signature=payload.signature
        )
        assert check(signed, configurable=True, signer_snapshot=COMMITMENT)

    async def test_reads_configurable_vouchers_from_the_challenge(self) -> None:
        from tests.test_session_client import resolved_for

        assert not (await resolved_for(make_challenge())).configurable_vouchers
        enabled = await resolved_for(make_challenge(configurableVouchers=True))
        assert enabled.configurable_vouchers
