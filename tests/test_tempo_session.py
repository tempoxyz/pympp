"""Focused client tests for Tempo TIP-1034 sessions."""

from __future__ import annotations

from typing import Any, cast

import pytest
import rlp
from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp import Challenge, MemoryStore
from mpp.methods.tempo import (
    TIP20_CHANNEL_ESCROW,
    TempoAccount,
    TempoSessionMethod,
    tempo_session,
)
from mpp.methods.tempo import session as session_module

PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CHAIN_ID = 42431
RPC_URL = "https://rpc.test"
TOKEN = "0x20c0000000000000000000000000000000000001"
PAYEE = "0x0000000000000000000000000000000000000002"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
SALT = bytes.fromhex("11" * 32)
CHANNEL_ID = "0xf8e4ab2eca9ec42f2cb0478ba074a76fa803607cacae5e557171f6679924fcf9"
PREIMAGE = (
    "76f9012582a5bf0202831e8480f8def8dc944d5050000000000000000000000000000000000080b8"
    "c4edc53b000000000000000000000000000000000000000000000000000000000000000002000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0020c000000000000000000000000000000000000100000000000000000000000000000000000000"
    "00000000000000000000000032111111111111111111111111111111111111111111111111111111"
    "1111111111000000000000000000000000fcad0b19bb29d4674531d6f115237e16afce377cc0a001"
    + "11" * 31
    + "8080809420c000000000000000000000000000000000000180c0"
)


@pytest.fixture
def account() -> TempoAccount:
    return TempoAccount.from_key(PRIVATE_KEY)


def challenge(
    *,
    amount: str = "10",
    suggested_deposit: str | None = "50",
    min_voucher_delta: str | None = "25",
    snapshot: dict[str, Any] | None = None,
    method: str = "tempo",
    intent: str = "session",
    protocol: str = "v2",
    chain_id: int = CHAIN_ID,
    escrow: str = TIP20_CHANNEL_ESCROW,
    operator: str | None = None,
) -> Challenge:
    details: dict[str, Any] = {
        "sessionProtocol": protocol,
        "chainId": chain_id,
        "escrowContract": escrow,
    }
    if min_voucher_delta is not None:
        details["minVoucherDelta"] = min_voucher_delta
    if snapshot is not None:
        details["sessionSnapshot"] = snapshot
    if operator is not None:
        details["operator"] = operator
    request: dict[str, Any] = {
        "amount": amount,
        "currency": TOKEN,
        "recipient": PAYEE,
        "methodDetails": details,
    }
    if suggested_deposit is not None:
        request["suggestedDeposit"] = suggested_deposit
    return Challenge(
        id="challenge-1",
        realm="example.com",
        method=method,
        intent=intent,
        request=request,
    )


def method(
    account: TempoAccount,
    *,
    max_deposit: int = 50,
    store: MemoryStore | None = None,
) -> TempoSessionMethod:
    return tempo_session(
        account=account,
        max_deposit=max_deposit,
        rpc_url=RPC_URL,
        chain_id=CHAIN_ID,
        channel_store=store,
    )


def deterministic_transactions(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    async def get_tx_params(rpc_url: str, address: str) -> tuple[int, int, int]:
        calls.append((rpc_url, address))
        return CHAIN_ID, 7, 2

    async def lane_nonce(self: TempoSessionMethod, nonce_key: int) -> int:
        return 0

    def urandom(length: int) -> bytes:
        assert length == 32
        return SALT

    monkeypatch.setattr(session_module, "get_tx_params", get_tx_params)
    monkeypatch.setattr(TempoSessionMethod, "_lane_nonce", lane_nonce)
    monkeypatch.setattr(session_module.os, "urandom", urandom)
    return calls


def transaction_fields(payload: dict[str, Any]) -> list[Any]:
    raw = bytes.fromhex(cast("str", payload["transaction"])[2:])
    return cast("list[Any]", rlp.decode(raw[1:]))


def test_public_factory(account: TempoAccount) -> None:
    store = MemoryStore()
    result = method(account, store=store)

    assert isinstance(result, TempoSessionMethod)
    assert result.intents.keys() == {"session"}
    assert result.channel_store is store
    assert result.max_deposit == 50
    with pytest.raises(TypeError, match="max_deposit must be an integer"):
        tempo_session(account=account, max_deposit=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="greater than zero"):
        tempo_session(account=account, max_deposit=0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("invalid", "message"),
    [
        (challenge(method="stripe"), "only handles tempo/session"),
        (challenge(intent="charge"), "only handles tempo/session"),
        (challenge(protocol="v1"), "sessionProtocol v2"),
        (challenge(chain_id=1), "restricted to 42431"),
        (
            challenge(escrow="0x0000000000000000000000000000000000000003"),
            "escrow is outside local policy",
        ),
        (
            challenge(operator="0x0000000000000000000000000000000000000004"),
            "only accepts the zero operator",
        ),
    ],
)
async def test_challenge_policy(account: TempoAccount, invalid: Challenge, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await method(account).create_credential(invalid)


@pytest.mark.asyncio
async def test_open_payload_is_deterministic(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    rpc_calls = deterministic_transactions(monkeypatch)

    credential = await method(account).create_credential(challenge())
    payload = credential.payload
    descriptor = cast("dict[str, str]", payload["descriptor"])

    assert set(payload) == {
        "action",
        "type",
        "channelId",
        "transaction",
        "descriptor",
        "cumulativeAmount",
        "signature",
        "authorizedSigner",
    }
    assert payload["action"] == "open"
    assert payload["type"] == "transaction"
    assert payload["channelId"] == CHANNEL_ID
    assert payload["cumulativeAmount"] == "10"
    assert payload["signature"] == (
        "0xf6bd824d8f1a27b12d052aa2ce30564a35f2d53b506a9cd2260fdcf01f326494"
        "59f288db3c39792f338bccea830456b325f6587f5aaf0a79a29a2bb0c879a6231c"
    )
    assert descriptor == {
        "payer": account.address.lower(),
        "payee": PAYEE,
        "operator": ZERO_ADDRESS,
        "token": TOKEN,
        "salt": "0x" + SALT.hex(),
        "authorizedSigner": account.address.lower(),
        "expiringNonceHash": ("0xd6d945c2cf976d050b069e8281c9272222ad96d23b82f4d87dc40266fe800315"),
    }
    assert payload["authorizedSigner"] == account.address.lower()
    assert credential.source == f"did:pkh:eip155:{CHAIN_ID}:{account.address.lower()}"

    raw = bytes.fromhex(cast("str", payload["transaction"])[2:])
    fields = transaction_fields(payload)
    call = cast("list[bytes]", fields[4][0])
    assert raw[0] == 0x76
    assert keccak(raw).hex() == "6fa21191db73f670fa853d94ea4e26297575668dae41b17ecdb15482b3684686"
    assert [int.from_bytes(cast("bytes", value)) for value in fields[:4]] == [
        CHAIN_ID,
        2,
        2,
        2_000_000,
    ]
    assert int.from_bytes(cast("bytes", fields[6])) == int.from_bytes(b"\x01" + SALT[1:])
    assert fields[7] == b""
    assert call[0] == bytes.fromhex(TIP20_CHANNEL_ESCROW[2:])
    assert call[1] == b""
    assert call[2][:4].hex() == "edc53b00"
    decoded = decode(
        ["address", "address", "address", "uint96", "bytes32", "address"],
        call[2][4:],
    )
    assert decoded == (PAYEE, ZERO_ADDRESS, TOKEN, 50, SALT, account.address.lower())
    preimage = b"\x76" + rlp.encode(fields[:13])
    assert preimage.hex() == PREIMAGE
    assert (
        "0x" + keccak(preimage + bytes.fromhex(account.address[2:])).hex()
        == descriptor["expiringNonceHash"]
    )
    assert rpc_calls == [(RPC_URL, account.address)]


@pytest.mark.asyncio
async def test_persisted_voucher_honors_delta_and_cap(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    store = MemoryStore()
    opened = await method(account, store=store).create_credential(challenge())
    snapshot = {
        "channelId": opened.payload["channelId"],
        "descriptor": opened.payload["descriptor"],
        "escrow": TIP20_CHANNEL_ESCROW,
        "chainId": CHAIN_ID,
        "deposit": "50",
        "acceptedCumulative": "10",
        "spent": "10",
        "settled": "0",
        "requiredCumulative": "26",
    }
    restarted = method(account, store=store)

    voucher = await restarted.create_credential(challenge(amount="5", snapshot=snapshot))

    assert voucher.payload["action"] == "voucher"
    assert voucher.payload["channelId"] == opened.payload["channelId"]
    assert voucher.payload["cumulativeAmount"] == "35"
    snapshot["acceptedCumulative"] = "35"
    snapshot["requiredCumulative"] = "36"
    with pytest.raises(ValueError, match="voucher exceeds max_deposit"):
        await restarted.create_credential(
            challenge(
                amount="1",
                suggested_deposit=None,
                min_voucher_delta="25",
                snapshot=snapshot,
            )
        )


@pytest.mark.asyncio
async def test_snapshot_recovery_reads_channel_state(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    opened = await method(account, max_deposit=100).create_credential(
        challenge(suggested_deposit="100", min_voucher_delta="0")
    )
    snapshot = {
        "channelId": opened.payload["channelId"],
        "descriptor": opened.payload["descriptor"],
        "escrow": TIP20_CHANNEL_ESCROW,
        "chainId": CHAIN_ID,
        "deposit": "100",
        "acceptedCumulative": "10",
        "spent": "8",
        "settled": "5",
        "requiredCumulative": "20",
    }
    calls: list[tuple[str, str, list[object]]] = []

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        calls.append((rpc_url, rpc_method, params))
        return "0x" + encode(["uint96", "uint96", "uint32"], [5, 100, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)

    voucher = await method(account, max_deposit=100, store=MemoryStore()).create_credential(
        challenge(
            amount="5",
            suggested_deposit=None,
            min_voucher_delta="0",
            snapshot=snapshot,
        )
    )

    assert voucher.payload["action"] == "voucher"
    assert voucher.payload["cumulativeAmount"] == "20"
    assert calls == [
        (
            RPC_URL,
            "eth_call",
            [
                {
                    "to": TIP20_CHANNEL_ESCROW,
                    "data": "0xd18da8b1" + cast("str", opened.payload["channelId"])[2:],
                },
                "latest",
            ],
        )
    ]

    async def oversized_deposit(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        return "0x" + encode(["uint96", "uint96", "uint32"], [5, 101, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", oversized_deposit)
    with pytest.raises(ValueError, match="channel deposit exceeds max_deposit"):
        await method(account, max_deposit=100, store=MemoryStore()).create_credential(
            challenge(
                amount="5",
                suggested_deposit=None,
                min_voucher_delta="0",
                snapshot=snapshot,
            )
        )


@pytest.mark.asyncio
async def test_pending_open_and_voucher_are_retried_without_advancing(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    rpc_calls = deterministic_transactions(monkeypatch)
    store = MemoryStore()
    payment_method = method(account, store=store)

    opened = await payment_method.create_credential(challenge(min_voucher_delta="0"))
    retried_open = await payment_method.create_credential(challenge(min_voucher_delta="0"))

    assert retried_open.payload == opened.payload
    assert len(rpc_calls) == 1

    snapshot = {
        "channelId": opened.payload["channelId"],
        "descriptor": opened.payload["descriptor"],
        "escrow": TIP20_CHANNEL_ESCROW,
        "chainId": CHAIN_ID,
        "deposit": "50",
        "acceptedCumulative": "10",
        "spent": "10",
        "settled": "0",
        "requiredCumulative": "15",
    }
    voucher = await payment_method.create_credential(
        challenge(amount="5", min_voucher_delta="0", snapshot=snapshot)
    )
    retried_voucher = await payment_method.create_credential(
        challenge(amount="5", min_voucher_delta="0")
    )

    assert voucher.payload["action"] == "voucher"
    assert voucher.payload["cumulativeAmount"] == "15"
    assert retried_voucher.payload == voucher.payload


@pytest.mark.asyncio
async def test_channel_nonce_lane_reads_pending_state(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str, list[object]]] = []

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        calls.append((rpc_url, rpc_method, params))
        return "0x" + encode(["uint64"], [7]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)
    nonce_key = int.from_bytes(b"\x01" + SALT[1:])

    assert await method(account)._lane_nonce(nonce_key) == 7
    data = keccak(b"getNonce(address,uint256)")[:4] + encode(
        ["address", "uint256"], [account.address, nonce_key]
    )
    assert calls == [
        (
            RPC_URL,
            "eth_call",
            [
                {
                    "to": session_module.NONCE_PRECOMPILE,
                    "data": "0x" + data.hex(),
                },
                "pending",
            ],
        )
    ]


@pytest.mark.asyncio
async def test_advertised_deposit_rollback_uses_onchain_state(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    payment_method = method(account)
    opened = await payment_method.create_credential(challenge())
    snapshot = {
        "channelId": opened.payload["channelId"],
        "descriptor": opened.payload["descriptor"],
        "escrow": TIP20_CHANNEL_ESCROW,
        "chainId": CHAIN_ID,
        "deposit": "0",
        "acceptedCumulative": "10",
        "spent": "10",
        "settled": "0",
        "requiredCumulative": "26",
    }

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        return "0x" + encode(["uint96", "uint96", "uint32"], [0, 50, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)

    credential = await payment_method.create_credential(challenge(snapshot=snapshot))

    assert credential.payload["action"] == "voucher"
    assert credential.payload["cumulativeAmount"] == "35"


@pytest.mark.asyncio
async def test_required_above_deposit_selects_top_up(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    rpc_calls = deterministic_transactions(monkeypatch)
    store = MemoryStore()
    payment_method = method(account, store=store)
    opened = await payment_method.create_credential(
        challenge(suggested_deposit="20", min_voucher_delta="0")
    )
    snapshot = {
        "channelId": opened.payload["channelId"],
        "descriptor": opened.payload["descriptor"],
        "escrow": TIP20_CHANNEL_ESCROW,
        "chainId": CHAIN_ID,
        "deposit": "20",
        "acceptedCumulative": "10",
        "spent": "10",
        "settled": "0",
        "requiredCumulative": "25",
    }

    top_up = await payment_method.create_credential(
        challenge(
            amount="15",
            suggested_deposit=None,
            min_voucher_delta="0",
            snapshot=snapshot,
        )
    )

    assert top_up.payload["action"] == "topUp"
    assert top_up.payload["channelId"] == opened.payload["channelId"]
    assert top_up.payload["additionalDeposit"] == "5"
    assert transaction_fields(top_up.payload)[4][0][2][:4].hex() == "dc48471e"
    assert transaction_fields(top_up.payload)[6] == transaction_fields(opened.payload)[6]

    retried = await payment_method.create_credential(
        challenge(amount="15", suggested_deposit=None, min_voucher_delta="0")
    )
    assert retried.payload == top_up.payload
    assert len(rpc_calls) == 2

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        return "0x" + encode(["uint96", "uint96", "uint32"], [0, 25, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)
    snapshot["deposit"] = "25"
    confirmed = await payment_method.create_credential(
        challenge(
            amount="15",
            suggested_deposit=None,
            min_voucher_delta="0",
            snapshot=snapshot,
        )
    )
    assert confirmed.payload["action"] == "voucher"
    assert confirmed.payload["cumulativeAmount"] == "25"
    assert len(rpc_calls) == 2
