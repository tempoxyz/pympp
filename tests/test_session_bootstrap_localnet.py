"""Session bootstrap on a Tempo localnet: a fresh pympp client recovers its channel via ``HEAD``.

A Starlette app behind ``pay(mpp.session(...))`` runs ``tempo.session(bootstrap=True,
resolve_channel_id=...)`` on uvicorn. A first manager opens a channel and pays; a second manager
with an empty channel store bootstraps (zero-amount proof, then the server's snapshot), validates
the snapshot against the chain and keeps paying on the same channel without opening another.

Run with TEMPO_NETWORK=localnet (docker compose up -d tempo):
    TEMPO_NETWORK=localnet uv run pytest tests/test_session_bootstrap_localnet.py -v
"""

from __future__ import annotations

import asyncio
import contextlib
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

from mpp import Challenge, Credential, Receipt
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._snapshot import deserialize_snapshot
from mpp.methods.tempo.session.server import ResolveSessionChannelIdParameters
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from tests import INTEGRATION
from tests.conftest import _fund_account  # pyright: ignore[reportPrivateUsage]
from tests.session_interop import mppx_session_server, run_mppx_session_client

pytestmark = [pytest.mark.integration, INTEGRATION]

SECRET_KEY = "session-bootstrap-localnet-secret"
REALM = "session-bootstrap.test"
PRICE = "0.00001"
UNIT = 10


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


@contextlib.asynccontextmanager
async def _serve(
    rpc_url: str, chain_id: int, currency: str, payee: TempoAccount, channels: dict[str, str]
) -> AsyncIterator[str]:
    """Serve ``GET /paid`` with bootstrap; ``channels`` maps payer DIDs to their channel IDs."""
    sources: list[str | None] = []

    def resolve_channel_id(params: ResolveSessionChannelIdParameters) -> str | None:
        sources.append(params.source)
        return channels.get(params.source.lower()) if params.source else None

    mpp = Mpp(
        methods=[
            tempo_server.session(
                account=payee,
                currency=currency,
                chain_id=chain_id,
                rpc_url=rpc_url,
                store=MemoryStore(),
                bootstrap=True,
                resolve_channel_id=resolve_channel_id,
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )

    @pay(mpp.session(amount=PRICE, unit_type="request", suggested_deposit="0.01"))
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
        yield f"http://127.0.0.1:{port}/paid"
    finally:
        server.should_exit = True
        await task


def _origin(url: str) -> str:
    parsed = httpx.URL(url)
    return f"{parsed.scheme}://{parsed.host}:{parsed.port}"


async def test_fresh_client_recovers_its_channel_via_head_bootstrap(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    did = f"did:pkh:eip155:{chain_id}:{payer.address}".lower()
    channels: dict[str, str] = {}
    async with _serve(rpc_url, chain_id, currency, payee, channels) as url:
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url
        ) as first:
            for n in range(1, 4):
                response = await first.fetch(url)
                assert response.status_code == 200, response.text
                assert response.receipt is not None and response.receipt.spent == str(n * UNIT)
            channel_id = first.channel_id
            assert channel_id is not None
        channels[did] = channel_id
        deposit = (await chain.get_channel_state(rpc_url, channel_id)).deposit

        async with httpx.AsyncClient() as client:
            # The unauthenticated HEAD gets a zero-amount identity challenge, not a snapshot.
            head = await client.head(url)
            assert head.status_code == 402
            challenge = Challenge.from_www_authenticate(head.headers["www-authenticate"])
            assert (challenge.method, challenge.intent) == ("tempo", "charge")
            assert challenge.request["amount"] == "0"

        async with tempo_client.session_manager(
            account=payer,
            max_deposit="1",
            rpc_url=rpc_url,
            bootstrap=True,
            trusted_tempo_realms={_origin(url): REALM},
        ) as fresh:
            response = await fresh.fetch(url)
            assert response.status_code == 200, response.text
            receipt = response.receipt
            assert receipt is not None
            # The recovered channel paid the fourth unit: no new channel was opened.
            assert receipt.channel_id == channel_id == fresh.channel_id
            assert (receipt.spent, receipt.accepted_cumulative) == (str(4 * UNIT), str(4 * UNIT))
            for n in range(5, 8):
                response = await fresh.fetch(url)
                assert response.status_code == 200, response.text
                assert response.receipt is not None
                assert response.receipt.spent == str(n * UNIT)
            assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == deposit
            closed = await fresh.close()
            assert closed is not None and closed.tx_hash and closed.spent == str(7 * UNIT)
        assert (await chain.get_channel_state(rpc_url, channel_id)).deposit == 0


async def test_bootstrap_without_a_trusted_realm_opens_a_new_channel(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """A realm the request origin doesn't own gets no proof, so the client opens a channel."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    channels: dict[str, str] = {}
    async with _serve(rpc_url, chain_id, currency, payee, channels) as url:
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url
        ) as first:
            assert (await first.fetch(url)).status_code == 200
            assert first.channel_id is not None
            channels[f"did:pkh:eip155:{chain_id}:{payer.address}".lower()] = first.channel_id
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url, bootstrap=True
        ) as fresh:
            response = await fresh.fetch(url)
            assert response.status_code == 200, response.text
            assert fresh.channel_id is not None and fresh.channel_id != first.channel_id


async def test_bootstrap_snapshot_header_matches_the_server_channel(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """The 204 bootstrap response carries Payment-Session and a decodable snapshot."""
    from mpp.methods.tempo.session._proof import proof_source, sign_proof

    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    channels: dict[str, str] = {}
    async with _serve(rpc_url, chain_id, currency, payee, channels) as url:
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url
        ) as first:
            assert (await first.fetch(url)).status_code == 200
            assert first.channel_id is not None
            channel_id = first.channel_id
        channels[f"did:pkh:eip155:{chain_id}:{payer.address}".lower()] = channel_id
        async with httpx.AsyncClient() as client:
            head = await client.head(url)
            challenge = Challenge.from_www_authenticate(head.headers["www-authenticate"])
            signature = sign_proof(
                payer, chain_id=chain_id, challenge_id=challenge.id, realm=challenge.realm
            )
            credential = Credential(
                challenge=challenge.to_echo(),
                payload={"signature": signature, "type": "proof"},
                source=proof_source(payer.address, chain_id),
            ).to_authorization()
            proved = await client.head(url, headers={"Authorization": credential})
            assert proved.status_code == 204
            assert proved.headers["payment-session"] == channel_id
            snapshot = deserialize_snapshot(proved.headers["payment-session-snapshot"])
            assert (snapshot.channel_id, snapshot.spent, snapshot.accepted_cumulative) == (
                channel_id,
                UNIT,
                UNIT,
            )
            # A proof is accepted once.
            replayed = await client.head(url, headers={"Authorization": credential})
            assert replayed.status_code == 403


def _key(account: TempoAccount) -> str:
    key = account.private_key
    return key if key.startswith("0x") else "0x" + key


async def test_mppx_client_recovers_a_pympp_channel_via_head_bootstrap(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """mppx's session manager (bootstrap: true) resumes a channel a pympp client opened."""
    payee = _new_account(rpc_url, currency)
    payer = _new_account(rpc_url, currency)
    channels: dict[str, str] = {}
    async with _serve(rpc_url, chain_id, currency, payee, channels) as url:
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url
        ) as first:
            for _ in range(2):
                assert (await first.fetch(url)).status_code == 200
            channel_id = first.channel_id
            assert channel_id is not None
        channels[f"did:pkh:eip155:{chain_id}:{payer.address}".lower()] = channel_id
        result = await run_mppx_session_client(
            url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            payer_key=_key(payer),
            calls=2,
            fund=False,
            bootstrap=True,
            trusted_realms={_origin(url): REALM},
        )
        assert result.returncode == 0, result.stderr
        calls = result.calls
        assert [call["status"] for call in calls] == [200, 200], calls
        assert [call["receipt"]["channelId"] for call in calls] == [channel_id] * 2
        assert [int(call["receipt"]["spent"]) for call in calls] == [3 * UNIT, 4 * UNIT]
        exchanges = [e for call in calls for e in call["exchanges"]]
        # HEAD challenge, HEAD with the proof (204), then vouchers on the recovered channel.
        assert [(e["method"], e["status"]) for e in exchanges[:2]] == [("HEAD", 402), ("HEAD", 204)]
        assert {e["action"] for e in exchanges if e["action"]} == {"voucher"}


async def test_pympp_client_recovers_an_mppx_channel_via_head_bootstrap(
    rpc_url: str, chain_id: int, currency: str
) -> None:
    """pympp's session manager (bootstrap=True) resumes a channel on an mppx bootstrap server."""
    payer = _new_account(rpc_url, currency)
    async with mppx_session_server(
        rpc_url=rpc_url, chain_id=chain_id, currency=currency, bootstrap=True
    ) as server:
        opened = await run_mppx_session_client(
            server.url,
            rpc_url=rpc_url,
            chain_id=chain_id,
            currency=currency,
            payer_key=_key(payer),
            calls=2,
            fund=False,
        )
        assert opened.returncode == 0, opened.stderr
        channel_id = opened.calls[-1]["receipt"]["channelId"]
        async with tempo_client.session_manager(
            account=payer, max_deposit="1", rpc_url=rpc_url, bootstrap=True
        ) as fresh:
            response = await fresh.fetch(server.url)
            assert response.status_code == 200, response.text
            receipt = response.receipt
            assert receipt is not None
            assert receipt.channel_id.lower() == channel_id.lower() == str(fresh.channel_id)
            assert receipt.spent == "300"
            closed = await fresh.close()
            assert closed is not None and closed.tx_hash and closed.spent == "300"
        requests = server.requests()
        heads = [r["status"] for r in requests if r["method"] == "HEAD"]
        assert heads == [402, 204], requests
        assert [r["action"] for r in requests if r["action"]].count("open") == 1
