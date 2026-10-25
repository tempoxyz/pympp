"""End-to-end tests for the Mpp engine against a real Tempo node.

A Starlette app protected with mpp.server.pay runs on uvicorn, and
mpp.client.Mpp pays it over real HTTP. Every payment settles on the localnet:
pull (signed transaction), push (transaction hash), fee-sponsored, splits, a
zero-amount charge, a composed two-currency offer, Payment-Authorization with
requires_auth, and replay rejection across two engines sharing one Redis store.

Requires TEMPO_RPC_URL (and REDIS_URL for the shared-store test). Run with:
    TEMPO_RPC_URL=http://localhost:8545 REDIS_URL=redis://localhost:6379 \
        uv run pytest tests/test_engine_integration.py -m "integration or redis" -v
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp.client import Mpp as MppClient
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.server import ComposedHandler, Mpp, pay
from mpp.store import Store
from tests import INTEGRATION
from tests.conftest import _fund_account, _tip20_balance
from tests.test_tempo_integration import _send_transfer

pytestmark = [pytest.mark.integration, INTEGRATION]

REDIS_URL = os.environ.get("REDIS_URL")
SECRET_KEY = "engine-integration-secret-key"
REALM = "engine.test"
# A second localnet TIP-20 token (AlphaUSD); tempo_fundAddress funds it too.
ALPHA_USD = "0x20c0000000000000000000000000000000000001"


def _new_account(rpc_url: str, currency: str) -> TempoAccount:
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


def _balance(rpc_url: str, token: str, address: str) -> int:
    with httpx.Client(timeout=30) as client:
        return _tip20_balance(rpc_url, token, address, client)


@contextlib.asynccontextmanager
async def _serve(routes: dict[str, ComposedHandler]) -> AsyncIterator[str]:
    """Serve one paid route per handler with uvicorn and yield the base URL.

    Paid responses echo the request's credential headers, since the client
    retries inside its transport and the response keeps the unpaid request.
    """

    def endpoint(handler: ComposedHandler) -> Callable[..., Any]:
        @pay(handler)
        async def paid(request: Request, credential: Credential, receipt: Receipt) -> Any:
            return JSONResponse(
                {
                    "authorization": request.headers.get("authorization"),
                    "payer": credential.source,
                    "payment_authorization": request.headers.get("payment-authorization"),
                    "reference": receipt.reference,
                }
            )

        return paid

    app = Starlette(routes=[Route(path, endpoint(handler)) for path, handler in routes.items()])
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
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


def _server(
    rpc_url: str,
    chain_id: int,
    recipient: str,
    currency: str,
    *,
    requires_auth: bool = False,
    store: Store | None = None,
    **options: Any,
) -> Mpp:
    return Mpp(
        methods=tempo_server.charge(
            recipient=recipient,
            chain_id=chain_id,
            rpc_url=rpc_url,
            currencies=[currency],
            **options,
        ),
        realm=REALM,
        secret_key=SECRET_KEY,
        requires_auth=requires_auth,
        store=store,
    )


def _client(account: TempoAccount, rpc_url: str, **options: Any) -> MppClient:
    return MppClient(methods=[tempo_client.charge(account=account, rpc_url=rpc_url, **options)])


def _receipt(response: httpx.Response) -> Receipt:
    assert response.status_code == 200, response.text
    receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
    assert receipt.status == "success"
    assert receipt.method == "tempo"
    assert receipt.reference == response.json()["reference"]
    return receipt


async def _push(
    http: httpx.AsyncClient,
    url: str,
    rpc_url: str,
    chain_id: int,
    currency: str,
    payer: TempoAccount,
    recipient: str,
) -> tuple[dict[str, str], str]:
    """Pay the route's challenge by broadcasting a transfer; return the hash credential."""
    unpaid = await http.get(url)
    assert unpaid.status_code == 402
    challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
    memo = encode_attribution(challenge_id=challenge.id, server_id=challenge.realm)
    tx_hash = await _send_transfer(
        rpc_url, payer, currency, recipient, int(challenge.request["amount"]), memo=memo
    )
    credential = Credential(
        challenge=challenge.to_echo(),
        payload={"type": "hash", "hash": tx_hash},
        source=f"did:pkh:eip155:{chain_id}:{payer.address}",
    )
    return {"Authorization": credential.to_authorization()}, tx_hash


def _refused(response: httpx.Response) -> None:
    assert response.status_code in (402, 403), response.text
    assert "Payment-Receipt" not in response.headers


class TestEngineCharge:
    async def test_pull_charge_settles_and_replay_is_refused(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, currency)
        async with _serve({"/paid": server.charge(amount="0.25")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            assert unpaid.status_code == 402
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.request["amount"] == "250000"
            assert challenge.request["methodDetails"]["chainId"] == chain_id

            before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                response = await client.fetch(f"{url}/paid")
            _receipt(response)
            assert response.json()["payer"].endswith(funded_payer.address)
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 250_000

            # The credential the client sent is spent: replaying it is refused.
            headers = {"Authorization": response.json()["authorization"]}
            async with httpx.AsyncClient(timeout=30) as http:
                _refused(await http.get(f"{url}/paid", headers=headers))
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 250_000

    async def test_push_hash_credential_settles_once(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, currency)
        async with _serve({"/paid": server.charge(amount="0.1")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                headers, tx_hash = await _push(
                    http,
                    f"{url}/paid",
                    rpc_url,
                    chain_id,
                    currency,
                    funded_payer,
                    funded_recipient.address,
                )
                assert _receipt(await http.get(f"{url}/paid", headers=headers)).reference == tx_hash
                _refused(await http.get(f"{url}/paid", headers=headers))

    async def test_fee_sponsored_charge(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        sponsor = _new_account(rpc_url, currency)
        server = _server(rpc_url, chain_id, funded_recipient.address, currency, fee_payer=sponsor)
        async with _serve({"/paid": server.charge(amount="0.5", fee_payer=True)}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.request["methodDetails"]["feePayer"] is True

            payer_before = _balance(rpc_url, currency, funded_payer.address)
            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            sponsor_before = _balance(rpc_url, currency, sponsor.address)
            async with _client(funded_payer, rpc_url) as client:
                _receipt(await client.fetch(f"{url}/paid"))

        # The payer pays exactly the amount; the sponsor pays the gas.
        assert _balance(rpc_url, currency, funded_payer.address) == payer_before - 500_000
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before + 500_000
        assert _balance(rpc_url, currency, sponsor.address) < sponsor_before

    async def test_split_charge_pays_every_recipient(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        partner = TempoAccount.from_key("0x" + os.urandom(32).hex())
        server = _server(rpc_url, chain_id, funded_recipient.address, currency)
        splits = [{"amount": "150000", "recipient": partner.address}]
        async with _serve({"/paid": server.charge(amount="1", splits=splits)}) as url:
            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                _receipt(await client.fetch(f"{url}/paid"))

        assert _balance(rpc_url, currency, partner.address) == 150_000
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before + 850_000

    async def test_zero_amount_charge(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, currency)
        async with _serve({"/paid": server.charge(amount="0")}) as url:
            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            client = MppClient(
                methods=[tempo_client.charge(account=funded_payer, rpc_url=rpc_url)],
                trusted_tempo_realms={url: REALM},
            )
            async with client:
                response = await client.fetch(f"{url}/paid")
            _receipt(response)
            assert response.json()["payer"].endswith(funded_payer.address)
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before

    async def test_composed_two_currency_offer(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        methods = tempo_server.charge(
            recipient=funded_recipient.address,
            chain_id=chain_id,
            rpc_url=rpc_url,
            currencies=[ALPHA_USD, currency],
        )
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET_KEY)
        handler = server.compose(
            (methods[0], {"amount": "0.2"}),
            (methods[1], {"amount": "0.3"}),
        )
        async with _serve({"/paid": handler}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            offers = [
                Challenge.from_www_authenticate(value)
                for value in unpaid.headers.get_list("WWW-Authenticate")
            ]
            assert [(o.request["currency"], o.request["amount"]) for o in offers] == [
                (ALPHA_USD, "200000"),
                (currency, "300000"),
            ]

            alpha_before = _balance(rpc_url, ALPHA_USD, funded_recipient.address)
            before = _balance(rpc_url, currency, funded_recipient.address)
            # A client pinned to the second currency skips the first offer.
            async with _client(funded_payer, rpc_url, currencies=[currency]) as client:
                _receipt(await client.fetch(f"{url}/paid"))
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 300_000
            assert _balance(rpc_url, ALPHA_USD, funded_recipient.address) == alpha_before

            # An unpinned client takes the first offer.
            async with _client(funded_payer, rpc_url) as client:
                _receipt(await client.fetch(f"{url}/paid"))
            assert _balance(rpc_url, ALPHA_USD, funded_recipient.address) == alpha_before + 200_000

    async def test_requires_auth_reads_payment_authorization(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, currency, requires_auth=True)
        async with _serve({"/paid": server.charge(amount="0.05")}) as url:
            async with _client(funded_payer, rpc_url) as client:
                response = await client.fetch(
                    f"{url}/paid", headers={"Authorization": "Bearer app-token"}
                )
            _receipt(response)
            # The server sees the application token untouched beside the credential.
            assert response.json()["authorization"] == "Bearer app-token"
            assert response.json()["payment_authorization"].startswith("Payment ")


@pytest.mark.redis
@pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)")
async def test_shared_redis_store_refuses_replay_across_engines(
    rpc_url, chain_id, currency, funded_payer, funded_recipient
):
    from redis.asyncio import from_url

    from mpp.stores import RedisStore

    assert REDIS_URL is not None
    redis = from_url(REDIS_URL)
    prefix = f"test:engine:{uuid.uuid4().hex[:8]}:"

    def engine() -> Mpp:
        store = RedisStore(redis, key_prefix=prefix)
        return _server(rpc_url, chain_id, funded_recipient.address, currency, store=store)

    first, second = engine(), engine()
    try:
        async with (
            _serve({"/paid": first.charge(amount="0.07")}) as first_url,
            _serve({"/paid": second.charge(amount="0.07")}) as second_url,
            httpx.AsyncClient(timeout=30) as http,
        ):
            # The first engine issues the challenge; the second, sharing its key,
            # realm and store, accepts the credential once.
            headers, tx_hash = await _push(
                http,
                f"{first_url}/paid",
                rpc_url,
                chain_id,
                currency,
                funded_payer,
                funded_recipient.address,
            )
            paid = await http.get(f"{second_url}/paid", headers=headers)
            assert _receipt(paid).reference == tx_hash
            _refused(await http.get(f"{first_url}/paid", headers=headers))
            assert await redis.keys(f"{prefix}*")
    finally:
        keys = await redis.keys(f"{prefix}*")
        if keys:
            await redis.delete(*keys)
        await redis.aclose()
