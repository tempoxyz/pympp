"""tempo.session() acceptance options on a Tempo localnet, paid by mppx's session client.

``voucher_state_max_age`` accepts vouchers against recently verified channel state, so a run
of vouchers reads the escrow far less often; ``charge_on_acceptance`` charges each request in the
update that accepts its voucher; ``sponsorship_limit`` stops sponsoring a payer's opens past its
daily quota.

Run with TEMPO_NETWORK=localnet (docker compose up -d tempo) and the harness's npm deps:
    uv run pytest tests/test_session_acceptance_localnet.py -m integration -v
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Credential, Receipt
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session._abi import SELECTORS
from mpp.methods.tempo.session.server import SponsorshipLimit
from mpp.methods.tempo.session.server._store import from_store
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]
from tests.session_interop import run_mppx_session_client

pytestmark = [pytest.mark.integration, INTEGRATION]


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


def _key(account: TempoAccount) -> str:
    key = account.private_key
    return key if key.startswith("0x") else "0x" + key


class ReadCounter:
    """Counts the escrow's getChannelState reads made through one HTTP client."""

    def __init__(self) -> None:
        self.reads = 0
        self.client = httpx.AsyncClient(timeout=30, event_hooks={"request": [self.count]})

    async def count(self, request: httpx.Request) -> None:
        with contextlib.suppress(ValueError):
            body = json.loads(request.content)
            calls = body if isinstance(body, list) else [body]
            for call in calls:
                if call.get("method") != "eth_call":
                    continue
                data = str(call["params"][0].get("data") or call["params"][0].get("input") or "")
                if data.startswith("0x" + SELECTORS["getChannelState"].hex()):
                    self.reads += 1


@contextlib.asynccontextmanager
async def _serve(
    rpc_url: str, chain_id: int, currency: str, payee: TempoAccount, **options: Any
) -> AsyncIterator[tuple[str, MemoryStore, ReadCounter]]:
    store = MemoryStore()
    counter = ReadCounter()
    mpp = Mpp(
        methods=[
            tempo_server.session(
                account=payee,
                currency=currency,
                chain_id=chain_id,
                rpc_url=rpc_url,
                store=store,
                http_client=counter.client,
                **options,
            )
        ],
        realm="session.test",
        secret_key="session-acceptance-localnet",
    )

    @pay(mpp.session(amount="0.0001", unit_type="request", suggested_deposit="0.01"))
    async def paid(request: Request, credential: Credential, receipt: Receipt) -> Any:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/paid", paid, methods=["GET", "POST"])])
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
    )
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(500):
            if server.started:
                break
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/paid", store, counter
    finally:
        server.should_exit = True
        await task
        await counter.client.aclose()


async def _run(url: str, rpc_url: str, chain_id: int, currency: str, **options: Any) -> Any:
    return await run_mppx_session_client(
        url, rpc_url=rpc_url, chain_id=chain_id, currency=currency, max_deposit="1", **options
    )


async def test_recent_state_reads_the_escrow_less_and_charges_on_acceptance(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """Twenty vouchers each: a fresh escrow read per voucher, or reads only as state ages."""
    reads: dict[int, int] = {}
    for max_age in (0, 60_000):
        payee = _new_account(rpc_url, currency)
        async with _serve(
            rpc_url,
            chain_id,
            currency,
            payee,
            voucher_state_max_age=max_age,
            charge_on_acceptance=True,
        ) as (url, store, counter):
            result = await _run(url, rpc_url, chain_id, currency, calls=21, close=True)
            assert result.returncode == 0, (result.lines, result.stderr)
            assert [int(call["receipt"]["spent"]) for call in result.calls] == [
                100 * (i + 1) for i in range(21)
            ]
            channel = await from_store(store).get_channel(result.final["channelId"])
            assert channel is not None and channel.finalized and channel.spent == 2_100
            reads[max_age] = counter.reads
    # Without a max age every one of the twenty vouchers waits for its own read.
    assert reads[0] >= 20
    assert reads[60_000] <= reads[0] // 2, reads


async def test_sponsorship_limit_stops_sponsoring_a_payer_past_its_quota(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    sponsor = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    usage = MemoryStore()
    async with _serve(
        rpc_url,
        chain_id,
        currency,
        payee,
        fee_payer=sponsor,
        sponsorship_limit=SponsorshipLimit(store=usage, per_day=1),
    ) as (url, _, _):
        first = await _run(
            url, rpc_url, chain_id, currency, payer_key=_key(payer), calls=1, fund=False
        )
        assert first.returncode == 0, (first.lines, first.stderr)
        key = f"mppx:session:sponsorship:{chain_id}:{payer.address.lower()}"
        assert json.loads(str(await usage.get(key)))["open"] == 1
        # A second channel by the same payer is past the quota: the sponsor does not co-sign.
        second = await _run(
            url, rpc_url, chain_id, currency, payer_key=_key(payer), calls=1, fund=False
        )
        assert second.returncode != 0 or not second.final.get("ok"), second.lines
        assert json.loads(str(await usage.get(key)))["open"] == 1
