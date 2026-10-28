"""TIP-1034 session server against a Tempo localnet, paid by mppx's session client.

A Starlette app protected with `mpp.server.pay` and `tempo.session(...)` runs on uvicorn;
tests/interop/mppx_session/client.mjs (mppx `tempo.session` and its session manager) pays it.
Covers many sub-cent calls on one deposit, top-up, close with on-chain settlement amounts,
scheduled settlement mid-session, fee-sponsored open/top-up, voucher replay and concurrent calls.

Run with TEMPO_NETWORK=localnet (docker compose up -d tempo) and the harness's npm deps:
    uv run pytest tests/test_session_server_localnet.py -m integration -v
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session import _voucher as voucher
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS
from mpp.methods.tempo.session.server import SettlementSchedule
from mpp.methods.tempo.session.server._settlement import (
    SessionSettlementContext,
    SessionSettlementFailureContext,
)
from mpp.methods.tempo.session.server._store import from_store
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]
from tests.session_interop import run_mppx_session_client

pytestmark = [pytest.mark.integration, INTEGRATION]

SECRET_KEY = "session-server-localnet-secret"
REALM = "session.test"


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


def _balance(rpc_url: str, token: str, address: str) -> int:
    data = "0x70a08231" + address.removeprefix("0x").lower().zfill(64)
    response = httpx.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": token, "data": data}, "latest"],
            "id": 1,
        },
        timeout=30,
    )
    return int(response.json()["result"], 16)


@dataclass
class SessionServer:
    url: str
    store: MemoryStore
    payee: TempoAccount
    settlements: list[SessionSettlementContext] = field(
        default_factory=list[SessionSettlementContext]
    )
    failures: list[SessionSettlementFailureContext] = field(
        default_factory=list[SessionSettlementFailureContext]
    )

    async def channel(self, channel_id: str) -> Any:
        return await from_store(self.store).get_channel(channel_id)


@contextlib.asynccontextmanager
async def _serve(
    rpc_url: str,
    chain_id: int,
    currency: str,
    payee: TempoAccount,
    *,
    amount: str = "0.0001",
    suggested_deposit: str | None = None,
    fee_payer: TempoAccount | None = None,
    settlement_schedule: SettlementSchedule | None = None,
) -> AsyncIterator[SessionServer]:
    store = MemoryStore()
    server_state = SessionServer(url="", store=store, payee=payee)
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
                on_session_settlement=server_state.settlements.append,
                on_session_settlement_failure=server_state.failures.append,
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
        return JSONResponse({"ok": True, "spent": (receipt.extensions or {}).get("spent")})

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
        server_state.url = f"http://127.0.0.1:{port}/paid"
        yield server_state
    finally:
        server.should_exit = True
        await task


def _decode_receipt(header: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))


def _assert_ok(result: Any) -> None:
    assert result.returncode == 0, (result.lines, result.stderr)
    assert result.final["ok"], result.lines


async def test_sub_cent_calls_on_one_sponsored_deposit_then_close(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """Twenty-five 0.0001 calls on one fee-sponsored deposit, then a cooperative close."""
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(
        rpc_url, chain_id, currency, payee, suggested_deposit="0.01", fee_payer=sponsor
    ) as server:
        payee_before = _balance(rpc_url, currency, payee.address)
        payer_before = _balance(rpc_url, currency, payer.address)
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            payer_key=_key(payer),
            calls=25,
            max_deposit="1",
            close=True,
            fund=False,
        )
        _assert_ok(result)
        calls = result.calls
        assert [call["status"] for call in calls] == [200] * 25
        # Every call paid exactly one route amount (100 base units) on one channel.
        assert [int(call["receipt"]["spent"]) for call in calls] == [
            100 * (i + 1) for i in range(25)
        ]
        assert {call["receipt"]["channelId"] for call in calls} == {result.final["channelId"]}
        assert [call["receipt"]["units"] for call in calls] == list(range(1, 26))
        # One open, then vouchers only: the suggested deposit covers every call.
        actions = [e["action"] for call in calls for e in call["exchanges"] if e["action"]]
        assert actions[0] == "open"
        assert set(actions[1:]) == {"voucher"}
        close = result.close
        assert close is not None and close["receipt"] is not None
        assert close["receipt"]["txHash"]
        channel_id = result.final["channelId"]
        channel = await server.channel(channel_id)
        assert channel is not None and channel.finalized
        assert channel.spent == 2500
        # The close paid the payee exactly the spend and refunded the rest of the deposit.
        assert [(s.trigger, s.amount) for s in server.settlements] == [("close", 2500)]
        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.deposit == 0
        assert _balance(rpc_url, currency, payee.address) - payee_before == 2500
        assert payer_before - _balance(rpc_url, currency, payer.address) == 2500


async def test_unsponsored_tiny_calls_top_up_shortfall_and_close(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """0.00001 calls without a suggested deposit: the client tops up each shortfall."""
    payee = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, amount="0.00001") as server:
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            calls=4,
            top_up="0.001",
            close=True,
        )
        _assert_ok(result)
        top_up = result.top_up
        assert top_up is not None and top_up["receipt"] is not None
        assert top_up["receipt"]["txHash"]
        assert [int(call["receipt"]["spent"]) for call in result.calls] == [10, 20, 30, 40]
        actions = [e["action"] for call in result.calls for e in call["exchanges"] if e["action"]]
        assert actions[0] == "open"
        assert "topUp" in actions
        assert [(s.trigger, s.amount) for s in server.settlements] == [("close", 40)]
        channel = await server.channel(result.final["channelId"])
        assert channel is not None and channel.finalized and channel.settled_on_chain == 40


async def test_settlement_schedule_settles_mid_session(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    async with _serve(
        rpc_url,
        chain_id,
        currency,
        payee,
        suggested_deposit="0.01",
        fee_payer=sponsor,
        settlement_schedule=SettlementSchedule(units=3),
    ) as server:
        payee_before = _balance(rpc_url, currency, payee.address)
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            calls=7,
            mode="fetch",
        )
        _assert_ok(result)
        scheduled = [s for s in server.settlements if s.trigger == "scheduled"]
        assert [s.amount for s in scheduled] == [300, 600]
        assert not server.failures
        # The settling requests' receipts carry the settlement transaction.
        assert [bool(call["receipt"].get("txHash")) for call in result.calls] == [
            True,  # open
            False,
            True,
            False,
            False,
            True,
            False,
        ]
        channel_id = result.final["channelId"]
        state = await chain.get_channel_state(rpc_url, channel_id)
        assert state.settled == 600
        assert _balance(rpc_url, currency, payee.address) - payee_before == 600
        channel = await server.channel(channel_id)
        assert channel is not None and channel.spent == 700 and channel.settled_on_chain == 600


async def test_replayed_voucher_is_rejected(rpc_url: str, chain_id: int, currency: str) -> None:
    payee = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.01") as server:
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            calls=3,
            mode="fetch",
            trace=True,
        )
        _assert_ok(result)
        vouchers = [e for e in result.http if e["action"] == "voucher" and e["status"] == 200]
        assert vouchers
        authorization = vouchers[-1]["requestHeaders"]["authorization"]
        channel_id = result.final["channelId"]
        before = await server.channel(channel_id)
        async with httpx.AsyncClient(timeout=30) as client:
            replay = await client.get(server.url, headers={"Authorization": authorization})
        assert replay.status_code == 402, replay.text
        assert replay.json()["type"].endswith("/delta-too-small")
        after = await server.channel(channel_id)
        assert after.spent == before.spent == 300


async def test_concurrent_vouchers_on_one_channel_charge_each_success_once(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(rpc_url, chain_id, currency, payee, suggested_deposit="0.01") as server:
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            payer_key=_key(payer),
            calls=1,
            mode="fetch",
            trace=True,
            fund=False,
        )
        _assert_ok(result)
        channel_id = result.final["channelId"]
        opened = next(e for e in result.http if e["action"] == "open")
        descriptor = _credential_payload(opened["requestHeaders"]["authorization"])["descriptor"]

        async with httpx.AsyncClient(timeout=60) as client:

            async def pay_with(cumulative: int) -> httpx.Response:
                challenge_response = await client.get(server.url)
                challenge = Challenge.from_www_authenticate(
                    challenge_response.headers["www-authenticate"]
                )
                signature = voucher.sign_voucher(
                    payer,
                    channel_id=channel_id,
                    cumulative_amount=cumulative,
                    escrow=ESCROW_ADDRESS,
                    chain_id=chain_id,
                )
                credential = Credential(
                    challenge=challenge.to_echo(),
                    payload={
                        "action": "voucher",
                        "channelId": channel_id,
                        "descriptor": descriptor,
                        "cumulativeAmount": str(cumulative),
                        "signature": signature,
                    },
                    source=f"did:pkh:eip155:{chain_id}:{payer.address}",
                )
                return await client.get(
                    server.url, headers={"Authorization": credential.to_authorization()}
                )

            # Distinct vouchers for calls 2..9, sent at once.
            responses = await asyncio.gather(*(pay_with(100 * n) for n in range(2, 10)))
        succeeded = [r for r in responses if r.status_code == 200]
        assert succeeded
        for response in responses:
            if response.status_code != 200:
                assert response.json()["type"].endswith("/delta-too-small"), response.text
        channel = await server.channel(channel_id)
        # Each accepted voucher paid exactly one request; spend never exceeds the vouchers.
        assert channel.units == 1 + len(succeeded)
        assert channel.spent == 100 * channel.units
        assert channel.spent <= channel.highest_voucher_amount
        spent = sorted(
            int(_decode_receipt(r.headers["payment-receipt"])["spent"]) for r in succeeded
        )
        assert spent == [100 * (i + 2) for i in range(len(succeeded))]


def _key(account: TempoAccount) -> str:
    key = account.private_key
    return key if key.startswith("0x") else "0x" + key


def _credential_payload(authorization: str) -> dict[str, Any]:
    encoded = authorization.split(" ", 1)[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))["payload"]


async def test_fee_sponsored_top_up(rpc_url: str, chain_id: int, currency: str) -> None:
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    async with _serve(
        rpc_url, chain_id, currency, payee, suggested_deposit="0.01", fee_payer=sponsor
    ) as server:
        payer_before = _balance(rpc_url, currency, payer.address)
        result = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            payer_key=_key(payer),
            calls=2,
            top_up="0.005",
            close=True,
            fund=False,
        )
        _assert_ok(result)
        assert result.top_up is not None and result.top_up["receipt"]["txHash"]
        channel = await server.channel(result.final["channelId"])
        assert channel is not None and channel.finalized and channel.deposit == 0
        # The sponsor paid every fee: the payer lost exactly the spend.
        assert payer_before - _balance(rpc_url, currency, payer.address) == 200
