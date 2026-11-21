"""Opening credential sources are bound to the payer the signed transaction authenticates.

Ports mppx session/server/CredentialVerification.test.ts ("open source transaction
authentication") and the open source binding case from Session.test.ts.
"""

from __future__ import annotations

from typing import Any

import pytest
import rlp  # pyright: ignore[reportMissingTypeStubs]
from eth_abi.abi import encode
from pytempo.keychain import KeyAuthorization  # pyright: ignore[reportMissingTypeStubs]

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session.server import _verification as verification
from tests.session_helpers import Lifecycle
from tests.test_session_chain import CHAIN_ID as LIFECYCLE_CHAIN_ID
from tests.test_session_chain import PAYEE
from tests.test_session_sponsorship_limit import (
    ACCESS,
    ACCESS_KEY,
    PAYER,
    PAYER_KEY,
    keychain_signature,
    unsigned,
    with_signature,
)

CHAIN_ID = 4217
SOURCE = f"did:pkh:eip155:{CHAIN_ID}:{PAYER.address}"
RPC_URL = "http://rpc.invalid"
NOT_AUTHENTICATED = "credential source is not authenticated by transaction signature"


def keychain(tx: Any) -> str:
    return with_signature(tx, keychain_signature(tx.get_signing_hash(), user=PAYER.address))


def inline(chain_id: int = CHAIN_ID, expiry: int | None = None) -> str:
    authorization = KeyAuthorization(key_id=ACCESS.address, chain_id=chain_id, expiry=expiry)
    return keychain(unsigned(key_authorization=authorization.sign(PAYER_KEY)))


def forged_sender() -> str:
    signed = unsigned(awaiting_fee_payer=True).sign(ACCESS_KEY)
    fields = rlp.decode(encode_fee_payer_envelope(signed)[1:])
    fields[11] = bytes.fromhex(PAYER.address[2:])
    return "0x" + (b"\x78" + rlp.encode(fields)).hex()


TRANSACTIONS: dict[str, Any] = {
    "direct": lambda: "0x" + unsigned().sign(PAYER_KEY).encode().hex(),
    "unsigned": lambda: "0x" + unsigned().encode().hex(),
    "forged sender": forged_sender,
    "active key": lambda: keychain(unsigned()),
    "revoked key": lambda: keychain(unsigned()),
    "expired key": lambda: keychain(unsigned()),
    "unknown key": lambda: keychain(unsigned()),
    "inline key": lambda: inline(),
    "wrong chain": lambda: inline(chain_id=999),
    "expired authorization": lambda: inline(expiry=1),
    # mppx's verifiedPayer cannot prove a multisig signer either.
    "multisig": lambda: with_signature(
        unsigned(), b"\x05" + rlp.encode([bytes.fromhex(PAYER.address[2:]), [], []])
    ),
}


@pytest.mark.parametrize("kind", list(TRANSACTIONS))
async def test_open_source_transaction_authentication(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[Any]] = []

    async def rpc(url: str, method: str, params: list[Any], client: Any) -> str:
        if method == "eth_chainId":
            return hex(CHAIN_ID)
        calls.append(params)
        if kind == "unknown key":
            raise RuntimeError("unavailable")
        expiry = 1 if kind == "expired key" else 9_999_999_999
        result = encode(
            ["uint8", "address", "uint64", "bool", "bool"],
            [0, ACCESS.address, expiry, False, kind == "revoked key"],
        )
        return "0x" + result.hex()

    monkeypatch.setattr(chain, "_rpc", rpc)
    check = verification.assert_credential_source_is_payer(
        source=SOURCE,
        chain_id=CHAIN_ID,
        payer=PAYER.address,
        serialized_transaction=TRANSACTIONS[kind](),
        rpc_url=RPC_URL,
    )
    if kind in ("direct", "active key", "inline key"):
        await check
    else:
        with pytest.raises(VerificationFailedError, match=NOT_AUTHENTICATED):
            await check
    if kind in ("active key", "inline key"):
        assert len(calls) == 1


def key_state(*, expiry: int = 9_999_999_999, revoked: bool = False) -> str:
    result = encode(
        ["uint8", "address", "uint64", "bool", "bool"],
        [0, ACCESS.address, expiry, False, revoked],
    )
    return "0x" + result.hex()


async def check_source(transaction: str) -> None:
    await verification.assert_credential_source_is_payer(
        source=SOURCE,
        chain_id=CHAIN_ID,
        payer=PAYER.address,
        serialized_transaction=transaction,
        rpc_url=RPC_URL,
    )


async def test_open_source_rejects_an_inline_authorization_for_a_revoked_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def rpc(url: str, method: str, params: list[Any], client: Any) -> str:
        return hex(CHAIN_ID) if method == "eth_chainId" else key_state(revoked=True)

    monkeypatch.setattr(chain, "_rpc", rpc)
    with pytest.raises(VerificationFailedError, match=NOT_AUTHENTICATED):
        await check_source(inline())


@pytest.mark.parametrize("kind", ["active key", "inline key"])
async def test_open_source_rejects_a_key_read_from_another_chain(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def rpc(url: str, method: str, params: list[Any], client: Any) -> str:
        return hex(CHAIN_ID + 1) if method == "eth_chainId" else key_state()

    monkeypatch.setattr(chain, "_rpc", rpc)
    with pytest.raises(VerificationFailedError, match=NOT_AUTHENTICATED):
        await check_source(TRANSACTIONS[kind]())


async def test_open_source_rejects_a_key_that_expires_while_it_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1_000.0]
    monkeypatch.setattr(verification.time, "time", lambda: clock[0])

    async def rpc(url: str, method: str, params: list[Any], client: Any) -> str:
        if method == "eth_chainId":
            return hex(CHAIN_ID)
        clock[0] = 2_000.0
        return key_state(expiry=1_500)

    monkeypatch.setattr(chain, "_rpc", rpc)
    with pytest.raises(VerificationFailedError, match=NOT_AUTHENTICATED):
        await check_source(keychain(unsigned()))


async def test_open_source_must_name_the_transaction_payer() -> None:
    with pytest.raises(VerificationFailedError, match="does not match transaction payer"):
        await verification.assert_credential_source_is_payer(
            source=f"did:pkh:eip155:{CHAIN_ID}:{ACCESS.address}",
            chain_id=CHAIN_ID,
            payer=PAYER.address,
            serialized_transaction="0x" + unsigned().sign(PAYER_KEY).encode().hex(),
            rpc_url=RPC_URL,
        )


@pytest.mark.parametrize(
    "source",
    [
        f"did:pkh:eip155:1:{PAYER.address}",
        "",
        "did:web:payer.test",
        f"did:pkh:eip155:{CHAIN_ID}:0x12",
    ],
)
async def test_open_source_errors_name_the_transaction_payer(source: str) -> None:
    with pytest.raises(VerificationFailedError, match="does not match transaction payer"):
        await verification.assert_credential_source_is_payer(
            source=source,
            chain_id=CHAIN_ID,
            payer=PAYER.address,
            serialized_transaction="0x" + unsigned().sign(PAYER_KEY).encode().hex(),
            rpc_url=RPC_URL,
        )


async def test_open_without_a_source_is_not_bound() -> None:
    await verification.assert_credential_source_is_payer(
        source=None,
        chain_id=CHAIN_ID,
        payer=PAYER.address,
        serialized_transaction="0x",
        rpc_url=RPC_URL,
    )


async def test_open_rejects_a_source_that_is_not_the_payer() -> None:
    life = await Lifecycle().build()
    source = f"did:pkh:eip155:{LIFECYCLE_CHAIN_ID}:{PAYEE.address}"
    with pytest.raises(VerificationFailedError, match="does not match transaction payer"):
        await life.open(credential_source=source)
    assert await life.store.get_channel(life.channel_id) is None
    receipt = await life.open()
    assert receipt.channel_id == life.channel_id
