"""Sponsorship limits on fee-payer-sponsored opens and top-ups.

Ports mppx server/SponsorshipLimit.test.ts, plus the limit applied through tempo.session().
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import rlp  # pyright: ignore[reportMissingTypeStubs]
from Crypto.PublicKey import ECC
from eth_account import Account
from eth_hash.auto import keccak
from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]
from pytempo.keychain import KeyAuthorization  # pyright: ignore[reportMissingTypeStubs]

from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope
from mpp.methods.tempo.session._protocol import OpenPayload, VoucherPayload
from mpp.methods.tempo.session.server import SponsorshipLimit
from mpp.methods.tempo.session.server import _sponsorship_limit as limits
from mpp.server import PaymentRequired, PaymentVerified, Request
from mpp.store import MemoryStore
from tests.session_helpers import Lifecycle, authorize, challenge_for
from tests.test_session_chain import CHAIN_ID, SPONSOR, opened_log
from tests.test_session_server import URL, BytesCasStore, DictStore, make_server

PAYER_KEY = "0x" + "ab" * 32
PAYER = Account.from_key(PAYER_KEY)
ACCESS_KEY = "0x" + "cd" * 32
ACCESS = Account.from_key(ACCESS_KEY)
VICTIM = "0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141"

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def unsigned(**fields: Any) -> Any:
    return TempoTransaction.create(
        chain_id=4217,
        gas_limit=100_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        calls=(Call.create(to="0x" + "00" * 19 + "01", value=0, data=b""),),
        **fields,
    )


def with_signature(tx: Any, signature: bytes) -> str:
    """The 0x76 encoding of ``tx`` with a raw sender signature in its last field."""
    fields = rlp.decode(tx.sign(PAYER_KEY).encode()[1:])
    return "0x" + (b"\x76" + rlp.encode([*fields[:-1], signature])).hex()


def p256_key() -> Any:
    return ECC.generate(curve="P-256")


def p256_sign(key: Any, digest: bytes) -> tuple[int, int]:
    d = int(key.d)
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = int((ECC.EccPoint(*_generator(), curve="p256") * k).x) % N
        s = pow(k, -1, N) * (int.from_bytes(digest, "big") + r * d) % N
        if r and s:
            return r, min(s, N - s)


def _generator() -> tuple[int, int]:
    return (
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    )


def public(key: Any) -> bytes:
    return int(key.pointQ.x).to_bytes(32, "big") + int(key.pointQ.y).to_bytes(32, "big")


def key_address(key: Any) -> str:
    return "0x" + keccak(public(key))[-20:].hex()


def p256_signature(key: Any, payload: bytes, *, prehash: bool) -> bytes:
    digest = hashlib.sha256(payload).digest() if prehash else payload
    r, s = p256_sign(key, digest)
    return (
        b"\x01"
        + r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
        + public(key)
        + (b"\x01" if prehash else b"\x00")
    )


def webauthn_signature(
    key: Any, payload: bytes, *, flags: int = 0x05, kind: str = "webauthn.get", **client: Any
) -> bytes:
    authenticator_data = b"\x11" * 32 + bytes([flags]) + b"\x00\x00\x00\x01"
    challenge = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    client_data = json.dumps({"type": kind, "challenge": challenge, **client}).encode()
    signed = authenticator_data + hashlib.sha256(client_data).digest()
    r, s = p256_sign(key, hashlib.sha256(signed).digest())
    return (
        b"\x02"
        + authenticator_data
        + client_data
        + r.to_bytes(32, "big")
        + s.to_bytes(32, "big")
        + public(key)
    )


def keychain_signature(payload: bytes, *, user: str = VICTIM, version: int = 3) -> bytes:
    user_bytes = bytes.fromhex(user[2:])
    signed = payload if version == 3 else keccak(b"\x04" + payload + user_bytes)
    inner = Account._sign_hash(signed, ACCESS_KEY)  # pyright: ignore[reportPrivateUsage]
    return bytes([version]) + user_bytes + bytes(inner.signature)


async def read(store: Any, key: str) -> str:
    raw = await store.get(key)
    assert raw is not None
    return raw


def open_payload(transaction: str) -> OpenPayload:
    return OpenPayload.model_validate(
        {
            "action": "open",
            "type": "transaction",
            "channelId": "0x" + "11" * 32,
            "transaction": transaction,
            "signature": "0x1234",
            "descriptor": {
                "payer": VICTIM,
                "payee": "0x" + "00" * 19 + "02",
                "operator": "0x" + "00" * 20,
                "token": "0x" + "00" * 19 + "03",
                "salt": "0x" + "33" * 32,
                "authorizedSigner": PAYER.address,
                "expiringNonceHash": "0x" + "22" * 32,
            },
            "cumulativeAmount": "1",
        }
    )


class TestVerifiedPayer:
    def test_keys_on_the_recovered_transaction_signer(self) -> None:
        raw = "0x" + unsigned().sign(PAYER_KEY).encode().hex()
        assert limits.verified_payer(raw) == PAYER.address.lower()

    def test_ignores_a_victim_in_the_0x78_sender_slot(self) -> None:
        signed = unsigned(awaiting_fee_payer=True).sign(PAYER_KEY)
        envelope = encode_fee_payer_envelope(signed)
        fields = rlp.decode(envelope[1:])
        fields[11] = bytes.fromhex(VICTIM[2:])
        spoofed = "0x" + (b"\x78" + rlp.encode(fields)).hex()
        assert limits.verified_payer(spoofed) == PAYER.address.lower()

    @pytest.mark.parametrize("prehash", [False, True])
    def test_keys_a_passkey_on_its_verified_signer_and_refuses_a_forgery(
        self, prehash: bool
    ) -> None:
        key = p256_key()
        tx = unsigned()
        signature = p256_signature(key, tx.get_signing_hash(), prehash=prehash)
        assert limits.verified_payer(with_signature(tx, signature)) == key_address(key)
        forged = p256_signature(key, b"\x00" * 32, prehash=prehash)
        assert limits.verified_payer(with_signature(tx, forged)) is None
        high_s = bytearray(signature)
        s = int.from_bytes(signature[33:65], "big")
        high_s[33:65] = (N - s).to_bytes(32, "big")
        assert limits.verified_payer(with_signature(tx, bytes(high_s))) is None
        off_curve = signature[:65] + b"\x00" * 31 + b"\x01" + signature[97:]
        assert limits.verified_payer(with_signature(tx, off_curve)) is None

    def test_keys_a_webauthn_assertion_on_its_verified_signer(self) -> None:
        key = p256_key()
        tx = unsigned()
        payload = tx.get_signing_hash()
        valid = webauthn_signature(key, payload, origin="https://wallet.test")
        assert limits.verified_payer(with_signature(tx, valid)) == key_address(key)
        for refused in (
            webauthn_signature(key, b"\x00" * 32),
            webauthn_signature(key, payload, flags=0x04),
            webauthn_signature(key, payload, flags=0x15),
            webauthn_signature(key, payload, kind="webauthn.create"),
        ):
            assert limits.verified_payer(with_signature(tx, refused)) is None
        tampered = bytearray(valid)
        tampered[-65] ^= 1
        assert limits.verified_payer(with_signature(tx, bytes(tampered))) is None

    def test_rejects_webauthn_metadata_it_cannot_parse(self) -> None:
        payload = b"\x01" * 32
        tail = b"\x00" * 128

        def verify(client_data: bytes) -> str | None:
            return limits._verified_webauthn_signer(  # pyright: ignore[reportPrivateUsage]
                payload, b"\x11" * 32 + b"\x05" + b"\x00" * 4 + client_data + tail
            )

        assert verify(b"no json") is None
        assert verify(b"{not json}") is None
        assert verify(json.dumps({"type": "webauthn.get", "challenge": "!!"}).encode()) is None
        assert verify(json.dumps({"type": "webauthn.get"}).encode()) is None

    @pytest.mark.parametrize("version", [3, 4])
    def test_keys_an_access_key_on_the_key_not_the_claimed_account(self, version: int) -> None:
        tx = unsigned()
        signature = keychain_signature(tx.get_signing_hash(), version=version)
        assert limits.verified_payer(with_signature(tx, signature)) == ACCESS.address.lower()

    def test_keys_an_inline_access_key_authorization_on_the_authorizing_account(self) -> None:
        authorization = KeyAuthorization(key_id=ACCESS.address, chain_id=4217).sign(PAYER_KEY)
        tx = unsigned(key_authorization=authorization)
        signature = keychain_signature(tx.get_signing_hash())
        assert limits.verified_payer(with_signature(tx, signature)) == PAYER.address.lower()
        # An authorization for another key proves nothing about this signer.
        other = KeyAuthorization(key_id=VICTIM, chain_id=4217).sign(PAYER_KEY)
        tx = unsigned(key_authorization=other)
        signature = keychain_signature(tx.get_signing_hash())
        assert limits.verified_payer(with_signature(tx, signature)) is None

    def test_unprovable_keychain_signatures(self) -> None:
        tx = unsigned()
        multisig_inner = b"\x03" + bytes.fromhex(VICTIM[2:]) + b"\x05\x00"
        short = b"\x03" + b"\x01" * 10
        for signature in (multisig_inner, short, b"\x05" + b"\x00" * 30):
            assert limits.verified_payer(with_signature(tx, signature)) is None
        # A keychain signature by an unrecoverable access key.
        bad = b"\x03" + bytes.fromhex(VICTIM[2:]) + b"\x00" * 65
        assert limits.verified_payer(with_signature(tx, bad)) is None

    def test_malformed_key_authorizations(self) -> None:
        authorization = KeyAuthorization(key_id=ACCESS.address, chain_id=4217).sign(PAYER_KEY)
        tx = unsigned(key_authorization=authorization)
        signature = keychain_signature(tx.get_signing_hash())
        fields = rlp.decode(bytes.fromhex(with_signature(tx, signature)[4:]))
        for auth in ([fields[13][0]], [fields[13][0], b""], [b"x", fields[13][1]]):
            raw = "0x" + (b"\x76" + rlp.encode([*fields[:13], auth, fields[14]])).hex()
            assert limits.verified_payer(raw) is None

    @pytest.mark.parametrize(
        "transaction",
        [
            "",
            "not-hex",
            "0x76deadbeef",
            "0x76" + rlp.encode([b"\x01"] * 3).hex(),
            "0x76" + rlp.encode([b"\x01"] * 14).hex(),
            "0x76" + rlp.encode([*[b"\x01"] * 13, b""]).hex(),
        ],
    )
    def test_returns_no_payer_for(self, transaction: str) -> None:
        assert limits.verified_payer(transaction) is None

    def test_an_unrecoverable_secp256k1_signature(self) -> None:
        assert limits.verified_payer(with_signature(unsigned(), b"\x00" * 65)) is None


NOW = datetime(2026, 10, 20, 12, tzinfo=UTC)


class TestReserve:
    async def test_allows_the_default_five_sponsored_opens_per_payer_per_utc_day(self) -> None:
        store = MemoryStore()

        async def reserve(now: datetime = NOW) -> bool:
            return await limits.reserve(store, action="open", chain_id=4217, payer=VICTIM, now=now)

        assert [await reserve() for _ in range(6)].count(True) == 5
        assert await reserve(datetime(2026, 10, 21, tzinfo=UTC)) is True

    async def test_concurrent_reservations_respect_the_limit(self) -> None:
        import asyncio

        store = MemoryStore()
        results = await asyncio.gather(
            *(
                limits.reserve(store, action="open", chain_id=4217, payer=VICTIM, now=NOW)
                for _ in range(8)
            )
        )
        assert results.count(True) == 5

    async def test_counts_top_ups_chains_and_payers_separately(self) -> None:
        store = MemoryStore()

        async def reserve(action: Any, chain_id: int, payer: str) -> bool:
            return await limits.reserve(
                store, action=action, chain_id=chain_id, payer=payer, per_day=1, now=NOW
            )

        assert await reserve("open", 4217, VICTIM) is True
        assert await reserve("open", 4217, VICTIM.upper().replace("0X", "0x")) is False
        assert await reserve("topUp", 4217, VICTIM) is True
        assert await reserve("open", 42431, VICTIM) is True
        assert await reserve("open", 4217, PAYER.address) is True
        assert json.loads(await read(store, f"mppx:session:sponsorship:4217:{VICTIM}")) == {
            "day": "2026-10-20",
            "open": 1,
            "topUp": 1,
        }

    async def test_bytes_stores_and_unreadable_records(self) -> None:
        store = BytesCasStore()
        key = f"mppx:session:sponsorship:4217:{VICTIM}"
        await store.put(key, "not json")
        assert await limits.reserve(store, action="open", chain_id=4217, payer=VICTIM, now=NOW)
        assert await limits.reserve(store, action="open", chain_id=4217, payer=VICTIM, now=NOW)
        assert json.loads(await read(store, key))["open"] == 2

    async def test_retries_a_lost_compare_and_set(self) -> None:
        class ContendedStore(MemoryStore):
            lost = False

            async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
                if not self.lost:
                    # Another instance reserved first.
                    self.lost = True
                    await self.put(key, json.dumps({"day": "2026-10-20", "open": 1, "topUp": 0}))
                    return False
                return await super().compare_and_set(key, expected, value)

        store = ContendedStore()
        assert await limits.reserve(
            store, action="open", chain_id=4217, payer=VICTIM, per_day=2, now=NOW
        )
        assert not await limits.reserve(
            store, action="open", chain_id=4217, payer=VICTIM, per_day=2, now=NOW
        )


class TestLimitFeePayer:
    async def test_stops_sponsoring_a_payer_that_used_its_daily_opens(self) -> None:
        limit = SponsorshipLimit(store=MemoryStore(), per_day=2)
        payload = open_payload("0x" + unsigned().sign(PAYER_KEY).encode().hex())

        async def limit_fee_payer() -> Any:
            return await limits.limit_fee_payer(
                chain_id=4217, fee_payer=SPONSOR, limit=limit, payload=payload
            )

        assert await limit_fee_payer() is SPONSOR
        assert await limit_fee_payer() is SPONSOR
        assert await limit_fee_payer() is None

    async def test_does_not_spend_the_quota_of_the_descriptor_payer(self) -> None:
        store = MemoryStore()
        await limits.limit_fee_payer(
            chain_id=4217,
            fee_payer=SPONSOR,
            limit=SponsorshipLimit(store=store, per_day=1),
            payload=open_payload("0x" + unsigned().sign(PAYER_KEY).encode().hex()),
        )
        assert await limits.reserve(store, action="open", chain_id=4217, payer=VICTIM, per_day=1)

    async def test_does_not_sponsor_a_transaction_whose_signatures_prove_no_payer(self) -> None:
        assert (
            await limits.limit_fee_payer(
                chain_id=4217,
                fee_payer=SPONSOR,
                limit=SponsorshipLimit(store=MemoryStore()),
                payload=open_payload("0x76deadbeef"),
            )
            is None
        )

    async def test_leaves_vouchers_unsponsored_requests_and_unlimited_servers_alone(
        self,
    ) -> None:
        limit = SponsorshipLimit(store=MemoryStore(), per_day=0)
        voucher = VoucherPayload.model_validate(
            {
                "action": "voucher",
                "channelId": "0x" + "11" * 32,
                "descriptor": open_payload("0x76").descriptor,
                "cumulativeAmount": "1",
                "signature": "0x1234",
            }
        )
        assert (
            await limits.limit_fee_payer(
                chain_id=4217, fee_payer=SPONSOR, limit=limit, payload=voucher
            )
            is SPONSOR
        )
        payload = open_payload("0x" + unsigned().sign(PAYER_KEY).encode().hex())
        assert (
            await limits.limit_fee_payer(
                chain_id=4217, fee_payer=None, limit=limit, payload=payload
            )
            is None
        )
        assert (
            await limits.limit_fee_payer(
                chain_id=4217, fee_payer=SPONSOR, limit=None, payload=payload
            )
            is SPONSOR
        )

    def test_validates_its_parameters(self) -> None:
        for per_day in (-1, 1.5, True):
            with pytest.raises(ValueError, match="per_day"):
                SponsorshipLimit(store=MemoryStore(), per_day=per_day)  # pyright: ignore[reportArgumentType]
        with pytest.raises(TypeError, match="compare_and_set"):
            SponsorshipLimit(store=cast(Any, DictStore()))


class TestThroughTheSessionMethod:
    @pytest.mark.parametrize("per_day", [1, 0])
    async def test_sponsors_opens_within_the_limit(self, per_day: int) -> None:
        life = await Lifecycle().build(fee_payer=True)
        usage = MemoryStore()
        server = make_server(
            life,
            chain_id=CHAIN_ID,
            fee_payer=SPONSOR,
            sponsorship_limit=SponsorshipLimit(store=usage, per_day=per_day),
        )
        handler = server.session(amount="0.0001", unit_type="request")
        challenge = await challenge_for(handler, Request("GET", URL))
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await handler(
            Request("GET", URL, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        payer = limits.verified_payer(life.transaction)
        assert payer is not None
        if per_day:
            assert isinstance(result, PaymentVerified), result
            assert life.rpc.sent[0].startswith("0x76")
            record = json.loads(await read(usage, f"mppx:session:sponsorship:{CHAIN_ID}:{payer}"))
            assert record["open"] == 1
        else:
            # Over the limit the sponsor does not co-sign, so the sponsored open cannot land.
            assert isinstance(result, PaymentRequired)
            assert not life.rpc.sent
