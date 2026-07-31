"""Focused client tests for Tempo TIP-1034 sessions."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
import rlp
from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp import Challenge, Credential, MemoryStore
from mpp.client import PaymentTransport
from mpp.methods.tempo import (
    TIP20_CHANNEL_ESCROW,
    TempoAccount,
    TempoSessionMethod,
    tempo_session,
)
from mpp.methods.tempo import session as session_module
from mpp.methods.tempo._defaults import TESTNET_RPC_URL
from mpp.runtime import PaymentRuntime

PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CHAIN_ID = 42431
RPC_URL = "https://rpc.test"
TOKEN = "0x20c0000000000000000000000000000000000001"
PAYEE = "0x0000000000000000000000000000000000000002"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
OPERATOR = "0x0000000000000000000000000000000000000004"
SALT = bytes.fromhex("11" * 32)
CHANNEL_ID = "0x4abd2d2c950ccef5f29dfc1fa3a83ae4dffbf34efcb72666140785b42064f4e5"
FINALIZED_HASH = "0x" + "ab" * 32
PREIMAGE = (
    "76f9012782a5bf0202831e8480f8def8dc944d5050000000000000000000000000000000000080b8"
    "c4edc53b000000000000000000000000000000000000000000000000000000000000000002000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0020c000000000000000000000000000000000000100000000000000000000000000000000000000"
    "00000000000000000000000032111111111111111111111111111111111111111111111111111111"
    "1111111111000000000000000000000000fcad0b19bb29d4674531d6f115237e16afce377cc0a0ff"
    + "ff" * 31
    + "80820401809420c000000000000000000000000000000000000180c0"
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
    fee_payer: bool = False,
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
    if fee_payer:
        details["feePayer"] = True
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

    def urandom(length: int) -> bytes:
        if length == 32:
            return SALT
        assert length == 8
        return (1).to_bytes(8)

    monkeypatch.setattr(session_module, "get_tx_params", get_tx_params)
    monkeypatch.setattr(session_module.os, "urandom", urandom)
    monkeypatch.setattr(session_module.time, "time", lambda: 1_000)
    return calls


def deterministic_expiring_transactions(
    monkeypatch: pytest.MonkeyPatch, now: list[int]
) -> list[tuple[str, str]]:
    calls = deterministic_transactions(monkeypatch)
    random_value = 0

    def urandom(length: int) -> bytes:
        nonlocal random_value
        if length == 32:
            return SALT
        assert length == 8
        random_value += 1
        return random_value.to_bytes(8)

    monkeypatch.setattr(session_module.os, "urandom", urandom)
    monkeypatch.setattr(session_module.time, "time", lambda: now[0])
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
    assert (
        tempo_session(
            account=account,
            max_deposit=50,
            chain_id=CHAIN_ID,
        ).rpc_url
        == TESTNET_RPC_URL
    )
    with pytest.raises(TypeError, match="max_deposit must be an integer"):
        tempo_session(account=account, max_deposit=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="greater than zero"):
        tempo_session(account=account, max_deposit=0)


def test_runtime_skips_unsupported_session_protocol(account: TempoAccount) -> None:
    payment_method = method(account)
    supported = challenge(protocol="v2")

    assert PaymentRuntime([payment_method]).match_challenge(
        [
            challenge(protocol="v1"),
            challenge(chain_id=1),
            challenge(escrow="0x0000000000000000000000000000000000000003"),
            supported,
        ]
    ) == (supported, payment_method)


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
    ],
)
async def test_challenge_policy(account: TempoAccount, invalid: Challenge, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await method(account).create_credential(invalid)


@pytest.mark.asyncio
async def test_native_client_drives_open_top_up_and_voucher(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    actions: list[str] = []
    inherited_headers: list[tuple[str | None, str | None]] = []
    channel_id: str | None = None
    descriptor: dict[str, object] | None = None
    topped_up = False

    async def server(request: httpx.Request) -> httpx.Response:
        nonlocal channel_id, descriptor, topped_up
        inherited_headers.append(
            (request.headers.get("x-client-default"), request.headers.get("cookie"))
        )
        authorization = request.headers.get("authorization")
        if authorization is None:
            snapshot = None
            if channel_id is not None and descriptor is not None:
                snapshot = {
                    "channelId": channel_id,
                    "descriptor": descriptor,
                    "escrow": TIP20_CHANNEL_ESCROW,
                    "chainId": CHAIN_ID,
                    "deposit": "8" if topped_up else "5",
                    "acceptedCumulative": "2",
                    "spent": "2",
                    "settled": "0",
                    "requiredCumulative": "8",
                }
            offered = challenge(
                amount="2",
                suggested_deposit="5",
                min_voucher_delta="0",
                snapshot=snapshot,
            )
            return httpx.Response(
                402,
                headers={"www-authenticate": offered.to_www_authenticate("example.com")},
            )

        payload = Credential.from_authorization(authorization).payload
        action = str(payload["action"])
        actions.append(action)
        channel_id = str(payload["channelId"])
        if action == "open":
            descriptor = cast("dict[str, object]", payload["descriptor"])
        elif action == "topUp":
            topped_up = True
        return httpx.Response(204 if action == "topUp" else 200, json={"paid": True})

    transport = PaymentTransport(
        methods=[method(account, max_deposit=10)],
        inner=httpx.MockTransport(server),
    )
    async with httpx.AsyncClient(
        transport=transport,
        headers={"x-client-default": "keep"},
        cookies={"session": "keep"},
    ) as client:
        response = await client.get(
            "https://example.com/resource",
            headers={"accept": "text/event-stream"},
        )

    assert response.json() == {"paid": True}
    assert actions == ["open", "topUp", "voucher"]
    assert inherited_headers
    assert set(inherited_headers) == {("keep", "session=keep")}


@pytest.mark.asyncio
async def test_native_client_drives_sse_and_refreshes_management_challenge(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    actions: list[str] = []
    inherited_headers: list[tuple[str | None, str | None]] = []
    management_idempotency: list[str | None] = []
    refreshed = False
    offered = challenge(amount="2", suggested_deposit="5", min_voucher_delta="0")

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            need = {
                "channelId": channel_id,
                "requiredCumulative": "8",
                "acceptedCumulative": "2",
                "deposit": "5",
            }
            yield b"data: first\n\n"
            yield f"event: payment-need-voucher\ndata: {json.dumps(need)}\n\n".encode()
            yield b"data: second\n\n"

    channel_id: str | None = None

    async def server(request: httpx.Request) -> httpx.Response:
        nonlocal channel_id, refreshed
        inherited_headers.append(
            (request.headers.get("x-client-default"), request.headers.get("cookie"))
        )
        if request.method == "POST":
            management_idempotency.append(request.headers.get("idempotency-key"))
        authorization = request.headers.get("authorization")
        if authorization is None:
            return httpx.Response(
                402,
                headers={"www-authenticate": offered.to_www_authenticate("example.com")},
            )

        credential = Credential.from_authorization(authorization)
        action = str(credential.payload["action"])
        actions.append(action)
        channel_id = str(credential.payload["channelId"])
        if action == "open":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=Stream(),
            )
        if action == "topUp" and not refreshed:
            refreshed = True
            replacement = replace(offered, id="challenge-refreshed")
            return httpx.Response(
                402,
                headers={"www-authenticate": replacement.to_www_authenticate("example.com")},
            )
        return httpx.Response(204)

    transport = PaymentTransport(
        methods=[method(account, max_deposit=10)],
        inner=httpx.MockTransport(server),
    )
    async with httpx.AsyncClient(
        transport=transport,
        headers={"idempotency-key": "original", "x-client-default": "keep"},
        cookies={"session": "keep"},
    ) as client:
        response = await client.get("https://example.com/stream")

    assert response.content == b"data: first\n\ndata: second\n\n"
    assert actions == ["open", "topUp", "topUp", "voucher"]
    assert set(inherited_headers) == {("keep", "session=keep")}
    assert management_idempotency == [None, None, None]


@pytest.mark.asyncio
async def test_open_accepts_nonzero_operator(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)

    payload = (await method(account).create_credential(challenge(operator=OPERATOR))).payload
    call = cast("list[bytes]", transaction_fields(payload)[4][0])
    decoded = decode(["address", "address", "address", "uint96", "bytes32", "address"], call[2][4:])

    assert cast("dict[str, str]", payload["descriptor"])["operator"] == OPERATOR
    assert decoded[1] == OPERATOR


@pytest.mark.asyncio
async def test_open_rejects_zero_deposit(account: TempoAccount) -> None:
    with pytest.raises(ValueError, match="deposit must be greater than zero"):
        await method(account).create_credential(
            challenge(amount="0", suggested_deposit=None, min_voucher_delta="0")
        )


@pytest.mark.asyncio
async def test_concurrent_requests_reuse_one_open(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    transactions = deterministic_transactions(monkeypatch)
    payment_method = method(account)

    first, second = await asyncio.gather(
        payment_method.create_credential(challenge()),
        payment_method.create_credential(challenge()),
    )

    assert first.payload == second.payload
    assert len(transactions) == 1


@pytest.mark.asyncio
async def test_stored_channel_rejects_zero_deposit(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    deterministic_transactions(monkeypatch)
    store = MemoryStore()
    payment_method = method(account, store=store)
    await payment_method.create_credential(challenge())
    key, raw = next(iter(store._data.items()))
    value = json.loads(cast("str", raw))
    value.update(deposit="0", cumulative="0", accepted="0")
    await store.put(key, json.dumps(value))

    with pytest.raises(ValueError, match="stored Tempo session deposit must be greater than zero"):
        await payment_method.create_credential(challenge())


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
        "0xe6b57dfde28cd529af8539b0a0f4e5350603b6fa5222d93775fcd8ae1b18e341"
        "647d8405382acb3ca4e3b9dbdd0ff77413c5232cd3cac370b367dae7dd0c7ea01c"
    )
    assert descriptor == {
        "payer": account.address.lower(),
        "payee": PAYEE,
        "operator": ZERO_ADDRESS,
        "token": TOKEN,
        "salt": "0x" + SALT.hex(),
        "authorizedSigner": account.address.lower(),
        "expiringNonceHash": ("0x554c8fa3daa204868a30bf1fa6b444aa7cca09dffc2900ce5eaf1eb0e43ad19e"),
    }
    assert payload["authorizedSigner"] == account.address.lower()
    assert credential.source == f"did:pkh:eip155:{CHAIN_ID}:{account.address.lower()}"

    raw = bytes.fromhex(cast("str", payload["transaction"])[2:])
    fields = transaction_fields(payload)
    call = cast("list[bytes]", fields[4][0])
    assert raw[0] == 0x76
    assert keccak(raw).hex() == "f82b3056b5f40a9c67c8c18c948f5afdb57c571085d64e6d22f841c63ebe2c4c"
    assert [int.from_bytes(cast("bytes", value)) for value in fields[:4]] == [
        CHAIN_ID,
        2,
        2,
        2_000_000,
    ]
    assert int.from_bytes(cast("bytes", fields[6])) == (1 << 256) - 1
    assert fields[7] == b""
    assert int.from_bytes(cast("bytes", fields[8])) == 1_025
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
        "highestVoucher": {
            "channelId": opened.payload["channelId"],
            "cumulativeAmount": "10",
            "signature": opened.payload["signature"],
        },
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
async def test_snapshot_recovery_requires_valid_signed_voucher(
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
    rpc = AsyncMock()
    monkeypatch.setattr(session_module, "_rpc_call", rpc)

    with pytest.raises(ValueError, match="missing its highest signed voucher"):
        await method(account, max_deposit=100).create_credential(
            challenge(snapshot=snapshot, min_voucher_delta="0")
        )

    snapshot["highestVoucher"] = {
        "channelId": opened.payload["channelId"],
        "cumulativeAmount": "10",
        "signature": "0x" + "00" * 65,
    }
    with pytest.raises(ValueError, match="highest voucher signature is invalid"):
        await method(account, max_deposit=100).create_credential(
            challenge(snapshot=snapshot, min_voucher_delta="0")
        )

    rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejected_snapshot_recovery_does_not_poison_store(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    tx_calls = deterministic_transactions(monkeypatch)
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
        "highestVoucher": {
            "channelId": opened.payload["channelId"],
            "cumulativeAmount": "10",
            "signature": opened.payload["signature"],
        },
        "spent": "90",
        "settled": "0",
        "requiredCumulative": "20",
    }
    rpc_calls: list[str] = []

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> str:
        rpc_calls.append(rpc_method)
        return "0x" + encode(["uint96", "uint96", "uint32"], [0, 100, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)
    store = MemoryStore()
    payment_method = method(account, max_deposit=100, store=store)

    with pytest.raises(ValueError, match="snapshot amounts are inconsistent"):
        await payment_method.create_credential(
            challenge(amount="5", min_voucher_delta="0", snapshot=snapshot)
        )

    assert store._data == {}
    assert rpc_calls == []
    fresh = await payment_method.create_credential(
        challenge(amount="5", suggested_deposit="20", min_voucher_delta="0")
    )
    assert fresh.payload["action"] == "open"
    assert fresh.payload["cumulativeAmount"] == "5"
    assert len(tx_calls) == 2


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
@pytest.mark.parametrize("onchain_deposit", [0, 50])
@pytest.mark.parametrize("fee_payer", [False, True])
async def test_expired_open_reconciles_before_replacement(
    account: TempoAccount,
    monkeypatch: pytest.MonkeyPatch,
    onchain_deposit: int,
    fee_payer: bool,
) -> None:
    now = [1_000]
    chain_time = [1_024]
    tx_calls = deterministic_expiring_transactions(monkeypatch, now)
    rpc_calls: list[str] = []
    state_blocks: list[object] = []

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> object:
        rpc_calls.append(rpc_method)
        if rpc_method == "eth_getBlockByNumber":
            assert params == ["finalized", False]
            return {"hash": FINALIZED_HASH, "timestamp": hex(chain_time[0])}
        state_blocks.append(params[1])
        return "0x" + encode(["uint96", "uint96", "uint32"], [0, onchain_deposit, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)
    payment_method = method(account)
    request = challenge(fee_payer=fee_payer, min_voucher_delta="0")
    opened = await payment_method.create_credential(request)

    now[0] = 1_024
    assert (await payment_method.create_credential(request)).payload == opened.payload
    assert rpc_calls == []

    now[0] = 1_025
    lagged = await payment_method.create_credential(request)
    assert lagged.payload == opened.payload
    assert rpc_calls == ["eth_getBlockByNumber"]

    chain_time[0] = 1_025
    replacement = await payment_method.create_credential(request)

    assert replacement.payload["action"] == ("voucher" if onchain_deposit else "open")
    if onchain_deposit:
        assert "transaction" not in replacement.payload
        assert replacement.payload["channelId"] == opened.payload["channelId"]
    else:
        assert replacement.payload["transaction"] != opened.payload["transaction"]
        assert replacement.payload["channelId"] != opened.payload["channelId"]
    assert rpc_calls == ["eth_getBlockByNumber", "eth_getBlockByNumber", "eth_call"]
    assert state_blocks == [{"blockHash": FINALIZED_HASH, "requireCanonical": True}]
    assert len(tx_calls) == (1 if onchain_deposit else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [{"timestamp": "0x1"}, {"hash": "0x12", "timestamp": "0x1"}])
async def test_expiry_block_requires_valid_hash(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch, block: dict[str, str]
) -> None:
    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> object:
        assert (rpc_method, params) == ("eth_getBlockByNumber", ["finalized", False])
        return block

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)

    with pytest.raises(ValueError, match="finalized block hash"):
        await method(account)._expiry_block()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("onchain_deposit", "reconnect_time"), [(20, 1_025), (25, 1_024), (25, 1_025)]
)
@pytest.mark.parametrize("fee_payer", [False, True])
async def test_sse_reconnect_reconciles_pending_top_up(
    account: TempoAccount,
    monkeypatch: pytest.MonkeyPatch,
    onchain_deposit: int,
    reconnect_time: int,
    fee_payer: bool,
) -> None:
    now = [1_000]
    tx_calls = deterministic_expiring_transactions(monkeypatch, now)
    rpc_calls: list[str] = []
    state_blocks: list[object] = []

    async def rpc_call(rpc_url: str, rpc_method: str, params: list[object]) -> object:
        rpc_calls.append(rpc_method)
        if rpc_method == "eth_getBlockByNumber":
            assert params == ["finalized", False]
            return {"hash": FINALIZED_HASH, "timestamp": hex(now[0])}
        state_blocks.append(params[1])
        return "0x" + encode(["uint96", "uint96", "uint32"], [0, onchain_deposit, 0]).hex()

    monkeypatch.setattr(session_module, "_rpc_call", rpc_call)
    payment_method = method(account)
    opened = await payment_method.create_credential(
        challenge(fee_payer=fee_payer, suggested_deposit="20", min_voucher_delta="0")
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
    request = challenge(
        amount="15",
        fee_payer=fee_payer,
        suggested_deposit=None,
        min_voucher_delta="0",
        snapshot=snapshot,
    )
    top_up = await payment_method.create_credential(request)

    now[0] = 1_024
    retry = await payment_method.create_credential(
        challenge(amount="15", fee_payer=True, suggested_deposit=None, min_voucher_delta="0")
    )
    assert retry.payload == top_up.payload
    assert rpc_calls == []

    now[0] = reconnect_time
    reconnect = challenge(
        amount="15", fee_payer=fee_payer, suggested_deposit=None, min_voucher_delta="0"
    )
    channel, target = await payment_method._prepare_voucher(
        payment_method._resolve(reconnect),
        {
            "channelId": opened.payload["channelId"],
            "deposit": str(onchain_deposit),
            "requiredCumulative": "25",
            "acceptedCumulative": "10",
        },
    )
    action = "voucher" if onchain_deposit == 25 else "topUp"
    context = {"action": action, "channelId": channel.channel_id}
    if action == "voucher":
        context["cumulativeAmount"] = str(target)
    else:
        context["additionalDeposit"] = str(target - channel.deposit)
    replacement = await payment_method.create_credential(reconnect, context=context)

    assert replacement.payload["action"] == action
    if onchain_deposit == 25:
        assert "transaction" not in replacement.payload
    else:
        assert replacement.payload["additionalDeposit"] == "5"
        assert replacement.payload["transaction"] != top_up.payload["transaction"]
    expired = reconnect_time == 1_025
    assert rpc_calls == (["eth_getBlockByNumber", "eth_call"] if expired else ["eth_call"])
    assert state_blocks == (
        [{"blockHash": FINALIZED_HASH, "requireCanonical": True}] if expired else ["latest"]
    )
    assert len(tx_calls) == (2 if onchain_deposit == 25 else 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("fee_payer", [False, True])
async def test_top_ups_are_unique_within_one_second(
    account: TempoAccount, monkeypatch: pytest.MonkeyPatch, fee_payer: bool
) -> None:
    now = [1_000]
    deterministic_expiring_transactions(monkeypatch, now)

    async def create_top_up() -> dict[str, Any]:
        payment_method = method(account)
        opened = await payment_method.create_credential(
            challenge(fee_payer=fee_payer, suggested_deposit="20", min_voucher_delta="0")
        )
        return (
            await payment_method.create_credential(
                challenge(
                    amount="15",
                    fee_payer=fee_payer,
                    suggested_deposit=None,
                    min_voucher_delta="0",
                    snapshot={
                        "channelId": opened.payload["channelId"],
                        "descriptor": opened.payload["descriptor"],
                        "escrow": TIP20_CHANNEL_ESCROW,
                        "chainId": CHAIN_ID,
                        "deposit": "20",
                        "acceptedCumulative": "10",
                        "spent": "10",
                        "settled": "0",
                        "requiredCumulative": "25",
                    },
                )
            )
        ).payload

    first = await create_top_up()
    second = await create_top_up()
    first_fields = transaction_fields(first)
    second_fields = transaction_fields(second)

    assert first_fields[8] == second_fields[8]
    assert first_fields[9] != second_fields[9]
    assert first_fields[9] and second_fields[9]
    assert first["transaction"] != second["transaction"]


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
