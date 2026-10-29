"""End-to-end TIP-1034 sessions: the pympp client paying a live pympp server on a Tempo localnet.

A Starlette app protected with `mpp.server.pay` and `tempo.session(...)` runs on uvicorn over real
HTTP; the pympp session manager and `mpp.client.Mpp` with `tempo.session` pay it. Covers many
sub-cent calls on one deposit with exact receipts and on-chain close amounts, top-up, scheduled
settlement, fee sponsorship, adversarial credentials, concurrency, restarts on a persistent store
and the close supervisor.

Run with TEMPO_NETWORK=localnet (docker compose up -d tempo redis):
    TEMPO_NETWORK=localnet REDIS_URL=redis://localhost:6379 uv run pytest \
        tests/test_session_e2e_localnet.py -v
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp.client import Mpp as ClientMpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session import _voucher as voucher
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ChannelDescriptor,
    deserialize_session_receipt,
)
from mpp.methods.tempo.session.client import SessionManager
from mpp.methods.tempo.session.server import SettlementSchedule, supervise_closes
from mpp.methods.tempo.session.server._settlement import (
    SessionSettlementContext,
    SessionSettlementFailureContext,
)
from mpp.methods.tempo.session.server._store import ChannelState, from_store
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from mpp.stores.sqlite import SQLiteStore
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]

pytestmark = [pytest.mark.integration, INTEGRATION]

SECRET_KEY = "session-e2e-localnet-secret"
REALM = "session-e2e.test"
PRICE = "0.00001"
UNIT = 10  # PRICE in base units (6 decimals)
REDIS_URL = os.environ.get("REDIS_URL")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
PROBLEMS = "https://paymentauth.org/problems"


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


async def _rpc(rpc_url: str, method: str, params: list[Any]) -> Any:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            rpc_url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        )
    body = response.json()
    assert "error" not in body, body
    return body["result"]


async def _balance(rpc_url: str, token: str, address: str) -> int:
    data = "0x70a08231" + address.removeprefix("0x").lower().zfill(64)
    return int(await _rpc(rpc_url, "eth_call", [{"to": token, "data": data}, "latest"]), 16)


def _topic_address(topic: str) -> str:
    return "0x" + topic[-40:].lower()


async def _transfers(rpc_url: str, tx_hash: str, token: str) -> list[tuple[str, str, int]]:
    """The token's Transfer events in a mined transaction, as (from, to, value)."""
    receipt = await _rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash])
    assert receipt is not None and receipt["status"] == "0x1", receipt
    return [
        (_topic_address(log["topics"][1]), _topic_address(log["topics"][2]), int(log["data"], 16))
        for log in receipt["logs"]
        if log["address"].lower() == token.lower()
        and log["topics"]
        and log["topics"][0].lower() == TRANSFER_TOPIC
    ]


def _paid(transfers: list[tuple[str, str, int]], sender: str, recipient: str) -> int:
    return sum(v for f, t, v in transfers if f == sender.lower() and t == recipient.lower())


def _paid_out(transfers: list[tuple[str, str, int]], sender: str) -> int:
    return sum(v for f, _, v in transfers if f == sender.lower())


@dataclass
class SessionServer:
    url: str
    store: Any
    payee: TempoAccount
    settlements: list[SessionSettlementContext] = field(
        default_factory=list[SessionSettlementContext]
    )
    failures: list[SessionSettlementFailureContext] = field(
        default_factory=list[SessionSettlementFailureContext]
    )

    async def channel(self, channel_id: str) -> ChannelState:
        state = await from_store(self.store).get_channel(channel_id)
        assert state is not None, channel_id
        return state


@contextlib.asynccontextmanager
async def _serve(
    rpc_url: str,
    chain_id: int,
    currency: str,
    payee: TempoAccount,
    *,
    store: Any | None = None,
    amount: str = PRICE,
    suggested_deposit: str | None = None,
    fee_payer: TempoAccount | None = None,
    settlement_schedule: SettlementSchedule | None = None,
) -> AsyncIterator[SessionServer]:
    """Serve `GET /paid` behind `pay(mpp.session(...))` on a fresh uvicorn instance."""
    store = store if store is not None else MemoryStore()
    state = SessionServer(url="", store=store, payee=payee)
    mpp = Mpp(
        methods=[
            tempo_server.session(
                account=payee,
                currency=currency,
                chain_id=chain_id,
                rpc_url=rpc_url,
                store=store,
                fee_payer=fee_payer,
                settlement_schedule=settlement_schedule,
                on_session_settlement=state.settlements.append,
                on_session_settlement_failure=state.failures.append,
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )
    options: dict[str, Any] = {"amount": amount, "unit_type": "request"}
    if suggested_deposit is not None:
        options["suggested_deposit"] = suggested_deposit

    @pay(mpp.session(**options))
    async def paid(request: Request, credential: Credential, receipt: Receipt) -> Any:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/paid", paid, methods=["GET", "POST"])])
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(500):
            if server.started:
                break
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("uvicorn did not start")
        port = server.servers[0].sockets[0].getsockname()[1]
        state.url = f"http://127.0.0.1:{port}/paid"
        yield state
    finally:
        server.should_exit = True
        await task


def _manager(payer: TempoAccount, rpc_url: str, **options: Any) -> SessionManager:
    return tempo_client.session_manager(
        account=payer, max_deposit=options.pop("max_deposit", "1"), rpc_url=rpc_url, **options
    )


async def _calls(manager: SessionManager, url: str, count: int, *, first: int = 1) -> None:
    """Make `count` paid calls and check each receipt pays exactly one more unit."""
    for n in range(first, first + count):
        response = await manager.fetch(url)
        assert response.status_code == 200, response.text
        receipt = response.receipt
        assert receipt is not None
        assert receipt.spent == str(n * UNIT)
        assert receipt.accepted_cumulative == str(n * UNIT)
        assert receipt.units == n
        assert receipt.channel_id == manager.channel_id


async def _assert_closed(
    rpc_url: str,
    currency: str,
    server: SessionServer,
    channel_id: str,
    *,
    payer: str,
    tx_hash: str,
    deposit: int,
    spent: int,
) -> None:
    """The close paid the payee exactly the spend and refunded the payer the rest, on-chain."""
    state = await chain.get_channel_state(rpc_url, channel_id)
    assert state.deposit == 0
    channel = await server.channel(channel_id)
    assert channel.finalized and channel.spent == spent
    transfers = await _transfers(rpc_url, tx_hash, currency)
    assert _paid(transfers, ESCROW_ADDRESS, server.payee.address) == spent
    assert _paid(transfers, ESCROW_ADDRESS, payer) == deposit - spent


def _source(chain_id: int, account: TempoAccount) -> str:
    return f"did:pkh:eip155:{chain_id}:{account.address}"


async def _challenge(client: httpx.AsyncClient, url: str) -> Challenge:
    response = await client.get(url)
    assert response.status_code == 402
    return Challenge.from_www_authenticate(response.headers["www-authenticate"])


async def test_200_sub_cent_calls_on_one_deposit_then_close(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """200 calls at 0.00001 on one suggested deposit, exact receipts, settled exactly on close."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.01") as server:
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 200)
            assert manager.deposit == 10_000
            channel_id = manager.channel_id
            assert channel_id is not None
            channel = await server.channel(channel_id)
            assert (channel.spent, channel.units, channel.highest_voucher_amount) == (
                2000,
                200,
                2000,
            )
            state = await chain.get_channel_state(rpc_url, channel_id)
            assert (state.deposit, state.settled) == (10_000, 0)

            payer_before = await _balance(rpc_url, currency, payer.address)
            closed = await manager.close()
            assert closed is not None and closed.tx_hash
            assert closed.spent == "2000"
            assert not manager.opened
        assert [(s.trigger, s.amount) for s in server.settlements] == [("close", 2000)]
        await _assert_closed(
            rpc_url,
            currency,
            server,
            channel_id,
            payer=payer.address,
            tx_hash=closed.tx_hash,
            deposit=10_000,
            spent=2000,
        )
        # The server sent the close, so the payer only received its refund.
        assert await _balance(rpc_url, currency, payer.address) - payer_before == 8000


async def test_mpp_client_tops_up_mid_session(rpc_url: str, chain_id: int, currency: str) -> None:
    """mpp.client.Mpp with tempo.session tops up when the deposit runs out, mid-session."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.00005") as server:
        method = tempo_client.session(
            account=payer, max_deposit="1", top_up_amount="0.0001", rpc_url=rpc_url
        )
        channel_ids: set[str] = set()
        async with ClientMpp(methods=[method]) as mpp:
            for n in range(1, 13):
                response = await mpp.fetch(server.url)
                assert response.status_code == 200, response.text
                receipt = deserialize_session_receipt(response.headers["payment-receipt"])
                assert (receipt.spent, receipt.accepted_cumulative, receipt.units) == (
                    str(n * UNIT),
                    str(n * UNIT),
                    n,
                )
                channel_ids.add(receipt.channel_id)
        assert len(channel_ids) == 1
        channel_id = channel_ids.pop()
        # 50 opened, then one 100 top-up when call 6 found the deposit spent: 120 <= 150.
        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.deposit == 150
        channel = await server.channel(channel_id)
        assert (channel.deposit, channel.spent, channel.units) == (150, 120, 12)


async def test_manager_top_up_mid_session_then_close(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.0001") as server:
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 5)
            top_up = await manager.top_up("0.0002")
            assert top_up is not None and top_up.tx_hash
            assert manager.deposit == 300
            channel_id = manager.channel_id
            assert channel_id is not None
            assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == 300
            assert (await server.channel(channel_id)).deposit == 300
            await _calls(manager, server.url, 20, first=6)
            closed = await manager.close()
            assert closed is not None and closed.tx_hash and closed.spent == "250"
        await _assert_closed(
            rpc_url,
            currency,
            server,
            channel_id,
            payer=payer.address,
            tx_hash=closed.tx_hash,
            deposit=300,
            spent=250,
        )


async def test_settlement_schedule_settles_mid_session(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(
        rpc_url,
        chain_id,
        currency,
        payee,
        suggested_deposit="0.01",
        settlement_schedule=SettlementSchedule(units=3),
    ) as server:
        async with _manager(payer, rpc_url) as manager:
            tx_hashes: list[bool] = []
            for n in range(1, 8):
                response = await manager.fetch(server.url)
                assert response.status_code == 200
                assert response.receipt is not None and response.receipt.spent == str(n * UNIT)
                tx_hashes.append(bool(response.receipt.tx_hash))
            channel_id = manager.channel_id
            assert channel_id is not None
        scheduled = [s for s in server.settlements if s.trigger == "scheduled"]
        assert [(s.amount, s.delta) for s in scheduled] == [(30, 30), (60, 30)]
        assert not server.failures
        # The open and the settling requests carry a transaction hash.
        assert tx_hashes == [True, False, True, False, False, True, False]
        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.settled == 60
        for settlement in scheduled:
            transfers = await _transfers(rpc_url, settlement.tx_hash, currency)
            assert _paid(transfers, ESCROW_ADDRESS, payee.address) == settlement.delta
        channel = await server.channel(channel_id)
        assert (channel.spent, channel.settled_on_chain) == (70, 60)


async def test_fee_sponsored_server_open_top_up_close(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """With a fee payer, payer and payee balances move by exactly the spend."""
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(
        rpc_url, chain_id, currency, payee, suggested_deposit="0.0001", fee_payer=sponsor
    ) as server:
        payer_before = await _balance(rpc_url, currency, payer.address)
        payee_before = await _balance(rpc_url, currency, payee.address)
        sponsor_before = await _balance(rpc_url, currency, sponsor.address)
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 5)
            top_up = await manager.top_up("0.0001")
            assert top_up is not None and top_up.tx_hash
            await _calls(manager, server.url, 10, first=6)
            channel_id = manager.channel_id
            assert channel_id is not None
            closed = await manager.close()
            assert closed is not None and closed.tx_hash and closed.spent == "150"
        await _assert_closed(
            rpc_url,
            currency,
            server,
            channel_id,
            payer=payer.address,
            tx_hash=closed.tx_hash,
            deposit=200,
            spent=150,
        )
        assert payer_before - await _balance(rpc_url, currency, payer.address) == 150
        assert await _balance(rpc_url, currency, payee.address) - payee_before == 150
        assert await _balance(rpc_url, currency, sponsor.address) < sponsor_before


async def test_adversarial_credentials_are_rejected_without_charging(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    attacker = TempoAccount.from_key("0x" + os.urandom(32).hex())
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.0001") as server:
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 3)
            channel_id = manager.channel_id
            entry = manager.channel
            assert channel_id is not None and entry is not None
            descriptor = entry.descriptor
            before = await server.channel(channel_id)
            assert (before.spent, before.highest_voucher_amount) == (30, 30)

            async with httpx.AsyncClient(timeout=30) as client:

                async def send(payload: dict[str, Any]) -> httpx.Response:
                    challenge = await _challenge(client, server.url)
                    credential = Credential(
                        challenge=challenge.to_echo(),
                        payload=payload,
                        source=_source(chain_id, payer),
                    )
                    return await client.get(
                        server.url, headers={"Authorization": credential.to_authorization()}
                    )

                def voucher_payload(
                    cumulative: int,
                    *,
                    signer: TempoAccount = payer,
                    channel: str = channel_id,
                    wire: ChannelDescriptor = descriptor,
                ) -> dict[str, Any]:
                    return {
                        "action": "voucher",
                        "channelId": channel,
                        "descriptor": wire.to_wire(),
                        "cumulativeAmount": str(cumulative),
                        "signature": voucher.sign_voucher(
                            signer,
                            channel_id=channel,
                            cumulative_amount=cumulative,
                            chain_id=chain_id,
                        ),
                    }

                unknown = ChannelDescriptor(
                    payer=descriptor.payer,
                    payee=descriptor.payee,
                    operator=descriptor.operator,
                    token=descriptor.token,
                    salt="0x" + os.urandom(32).hex(),
                    authorized_signer=descriptor.authorized_signer,
                    expiring_nonce_hash="0x" + os.urandom(32).hex(),
                )
                unknown_id = compute_channel_id(unknown, chain_id=chain_id)
                bad_close = {
                    "action": "close",
                    "channelId": channel_id,
                    "descriptor": descriptor.to_wire(),
                    "cumulativeAmount": "30",
                    "signature": voucher.sign_voucher(
                        payer, channel_id=channel_id, cumulative_amount=30, chain_id=chain_id
                    ),
                    # A voucher signature where the close authorization belongs.
                    "closeSignature": voucher.sign_voucher(
                        payer, channel_id=channel_id, cumulative_amount=30, chain_id=chain_id
                    ),
                }
                cases: list[tuple[str, dict[str, Any], int, str]] = [
                    ("stale voucher", voucher_payload(20), 402, "verification-failed"),
                    ("replayed voucher", voucher_payload(30), 402, "session/delta-too-small"),
                    (
                        "voucher above deposit",
                        voucher_payload(101),
                        402,
                        "session/amount-exceeds-deposit",
                    ),
                    (
                        "voucher signed by another key",
                        voucher_payload(40, signer=attacker),
                        402,
                        "session/invalid-signature",
                    ),
                    (
                        "voucher for an unknown channel",
                        voucher_payload(40, channel=unknown_id, wire=unknown),
                        410,
                        "session/channel-not-found",
                    ),
                    (
                        "close with a bad close signature",
                        bad_close,
                        402,
                        "session/invalid-signature",
                    ),
                ]
                for name, payload, status, problem in cases:
                    response = await send(payload)
                    assert response.status_code == status, (name, response.text)
                    assert response.json()["type"] == f"{PROBLEMS}/{problem}", (name, response.text)
                    assert "payment-receipt" not in response.headers, name
                    after = await server.channel(channel_id)
                    assert (after.spent, after.units, after.highest_voucher_amount) == (
                        30,
                        3,
                        30,
                    ), name
                    assert not after.finalized, name
                assert await from_store(server.store).get_channel(unknown_id) is None
            state = await chain.get_channel_state(rpc_url, channel_id)
            assert (state.deposit, state.settled, state.close_requested_at) == (100, 0, 0)
            assert not server.settlements
            # The honest client carries on from where it was.
            await _calls(manager, server.url, 2, first=4)


async def test_concurrent_clients_on_separate_channels(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """20 calls from 4 independent clients at once, each on its own channel."""
    payee = _new_account(rpc_url, currency)
    payers = [_new_account(rpc_url, currency) for _ in range(4)]
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.0001") as server:
        managers = [_manager(payer, rpc_url) for payer in payers]
        try:
            await asyncio.gather(*(_calls(m, server.url, 5) for m in managers))
            channel_ids = [m.channel_id for m in managers]
            assert len({c for c in channel_ids if c}) == 4
            for channel_id in channel_ids:
                assert channel_id is not None
                channel = await server.channel(channel_id)
                assert (channel.spent, channel.units, channel.highest_voucher_amount) == (50, 5, 50)
            closes = await asyncio.gather(*(m.close() for m in managers))
            assert all(c is not None and c.spent == "50" for c in closes)
        finally:
            await asyncio.gather(*(m.aclose() for m in managers))
        assert sorted(s.amount for s in server.settlements) == [50] * 4


async def test_concurrent_vouchers_on_one_channel(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """Concurrent raw voucher credentials on one channel: each success charges exactly once."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.001") as server:
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 1)
            channel_id = manager.channel_id
            entry = manager.channel
            assert channel_id is not None and entry is not None
        descriptor = entry.descriptor.to_wire()

        async with httpx.AsyncClient(timeout=60) as client:
            challenges = [await _challenge(client, server.url) for _ in range(20)]

            async def pay_with(challenge: Challenge, cumulative: int) -> httpx.Response:
                credential = Credential(
                    challenge=challenge.to_echo(),
                    payload={
                        "action": "voucher",
                        "channelId": channel_id,
                        "descriptor": descriptor,
                        "cumulativeAmount": str(cumulative),
                        "signature": voucher.sign_voucher(
                            payer,
                            channel_id=channel_id,
                            cumulative_amount=cumulative,
                            chain_id=chain_id,
                        ),
                    },
                    source=_source(chain_id, payer),
                )
                return await client.get(
                    server.url, headers={"Authorization": credential.to_authorization()}
                )

            responses = await asyncio.gather(
                *(pay_with(c, UNIT * (n + 2)) for n, c in enumerate(challenges))
            )
        succeeded = [r for r in responses if r.status_code == 200]
        assert succeeded
        for response in responses:
            if response.status_code != 200:
                assert response.status_code == 402, response.text
                assert response.json()["type"] in (
                    f"{PROBLEMS}/session/delta-too-small",
                    f"{PROBLEMS}/verification-failed",
                ), response.text
                assert "payment-receipt" not in response.headers
        channel = await server.channel(channel_id)
        assert channel.units == 1 + len(succeeded)
        assert channel.spent == UNIT * channel.units
        assert channel.spent <= channel.highest_voucher_amount
        spent = sorted(
            int(deserialize_session_receipt(r.headers["payment-receipt"]).spent) for r in succeeded
        )
        assert spent == [UNIT * (i + 2) for i in range(len(succeeded))]


StoreFactory = Callable[[], Awaitable[tuple[Any, Callable[[], Awaitable[None]]]]]


@contextlib.asynccontextmanager
async def _sqlite_stores(tmp_path: Path) -> AsyncIterator[StoreFactory]:
    path = str(tmp_path / "sessions.db")

    async def open_store() -> tuple[Any, Callable[[], Awaitable[None]]]:
        store = await SQLiteStore.create(path)
        return store, store.close

    yield open_store


@contextlib.asynccontextmanager
async def _redis_stores(tmp_path: Path) -> AsyncIterator[StoreFactory]:
    from redis.asyncio import from_url

    from mpp.stores.redis import RedisStore

    assert REDIS_URL is not None
    url = REDIS_URL
    prefix = f"test:session-e2e:{uuid.uuid4().hex[:8]}:"

    async def open_store() -> tuple[Any, Callable[[], Awaitable[None]]]:
        client = from_url(url)
        return RedisStore(client, key_prefix=prefix), client.aclose

    try:
        yield open_store
    finally:
        client = from_url(url)
        try:
            keys = [key async for key in client.scan_iter(f"{prefix}*")]
            if keys:
                await client.delete(*keys)
        finally:
            await client.aclose()


@pytest.mark.parametrize(
    "backend",
    [
        "sqlite",
        pytest.param(
            "redis",
            marks=[
                pytest.mark.redis,
                pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
            ],
        ),
    ],
)
async def test_restart_on_persistent_store_keeps_the_channel(
    rpc_url: str, chain_id: int, currency: str, tmp_path: Path, backend: str
) -> None:
    """A new server instance on the same store accepts the channel's next vouchers and closes it."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    stores = _sqlite_stores(tmp_path) if backend == "sqlite" else _redis_stores(tmp_path)
    async with stores as open_store, _manager(payer, rpc_url) as manager:
        store, close_store = await open_store()
        try:
            async with _serve(
                rpc_url, chain_id, currency, payee, store=store, suggested_deposit="0.001"
            ) as first:
                await _calls(manager, first.url, 3)
        finally:
            await close_store()
        channel_id = manager.channel_id
        assert channel_id is not None

        store, close_store = await open_store()
        try:
            async with _serve(
                rpc_url, chain_id, currency, payee, store=store, suggested_deposit="0.001"
            ) as second:
                channel = await second.channel(channel_id)
                assert (channel.spent, channel.units) == (30, 3)
                await _calls(manager, second.url, 4, first=4)
                closed = await manager.close()
                assert closed is not None and closed.tx_hash and closed.spent == "70"
                assert [(s.trigger, s.amount) for s in second.settlements] == [("close", 70)]
                await _assert_closed(
                    rpc_url,
                    currency,
                    second,
                    channel_id,
                    payer=payer.address,
                    tx_hash=closed.tx_hash,
                    deposit=1000,
                    spent=70,
                )
        finally:
            await close_store()


async def test_close_supervisor_closes_a_requested_channel(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """The payer requests a close on-chain; supervise_closes captures the spend before the grace."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.001") as server:
        async with _manager(payer, rpc_url) as manager:
            await _calls(manager, server.url, 4)
            channel_id = manager.channel_id
            entry = manager.channel
            assert channel_id is not None and entry is not None

        await chain.request_close_on_chain(rpc_url, payer, entry.descriptor)
        requested = await chain.get_channel_state(rpc_url, channel_id)
        assert requested.close_requested_at != 0 and requested.deposit == 1000

        supervision = await supervise_closes(
            channel_ids=[channel_id],
            store=server.store,
            rpc_url=rpc_url,
            account=payee,
            on_session_settlement=server.settlements.append,
        )
        assert supervision.complete
        assert supervision.closed == 1 and supervision.failed == 0
        [supervised] = supervision.channels
        assert supervised.outcome == "closed", supervised.error
        assert supervised.tx_hash
        assert [(s.trigger, s.amount) for s in server.settlements] == [("close", 40)]
        await _assert_closed(
            rpc_url,
            currency,
            server,
            channel_id,
            payer=payer.address,
            tx_hash=supervised.tx_hash,
            deposit=1000,
            spent=40,
        )
        # A second run has nothing left to do.
        again = await supervise_closes(
            channel_ids=[channel_id], store=server.store, rpc_url=rpc_url, account=payee
        )
        assert [c.outcome for c in again.channels] == ["finalized"]
