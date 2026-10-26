"""Concurrency stress tests for the payment engine, replay stores and client transport.

Settlement must be exactly-once under contention: many parallel replays of one
credential settle once, distinct payments all settle, replay-store claims have one
winner per key across connections, and the client transport never sends one
request's credential with another. The Tempo RPC is an in-process fake.

The default runs stay small. Heavier variants are marked ``stress`` and run with:

    MPP_STRESS=1 uv run pytest -m stress -v

Redis variants run when REDIS_URL is set.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import anyio
import httpx
import pytest

from mpp import Challenge, Credential, Receipt
from mpp.client import PaymentTransport
from mpp.methods import Method
from mpp.methods.tempo import CHAIN_ID
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC
from mpp.runtime import ClientMethod, CredentialParams
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request
from mpp.store import MemoryStore
from mpp.stores.sqlite import SQLiteStore
from tests import http_request, server_method

REALM = "api.example.com"
SECRET = "stress-secret"
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
PAYER = "0x1234567890123456789012345678901234567890"
REDIS_URL = os.environ.get("REDIS_URL")

STRESS = [
    pytest.mark.stress,
    pytest.mark.skipif(not os.environ.get("MPP_STRESS"), reason="MPP_STRESS not set"),
]
# (default runs, stress runs) of parallel requests.
SIZES = [pytest.param(50, id="50"), pytest.param(1000, id="1000", marks=STRESS)]


StoreFactory = Callable[[], Awaitable[Any]]


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param(
            "redis",
            marks=[
                pytest.mark.redis,
                pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)"),
            ],
        ),
    ]
)
async def stores(request: pytest.FixtureRequest, tmp_path: Any) -> AsyncIterator[StoreFactory]:
    """Open stores on one shared backend: every call is a new connection to it.

    Memory has no connections, so every call returns the same store.
    """
    cleanups: list[Callable[[], Awaitable[Any]]] = []
    name: str = request.param
    if name == "memory":
        shared = MemoryStore()

        async def make() -> Any:
            return shared

    elif name == "sqlite":
        path = str(tmp_path / "stress.db")

        async def make() -> Any:
            store = await SQLiteStore.create(path)
            cleanups.append(store.close)
            return store

    else:
        from redis.asyncio import BlockingConnectionPool, Redis

        from mpp.stores.redis import RedisStore

        url = REDIS_URL
        assert url is not None
        prefix = f"stress:{uuid.uuid4().hex[:8]}:"

        async def make() -> Any:
            # redis-py's default pool raises past 100 connections instead of waiting.
            pool = BlockingConnectionPool.from_url(url, decode_responses=True)
            client = Redis(connection_pool=pool)
            cleanups.append(client.aclose)
            return RedisStore(client, key_prefix=prefix)

    yield make
    for cleanup in reversed(cleanups):
        await cleanup()


class TempoRoute:
    """A Tempo charge route whose fake RPC mines one receipt per transaction hash.

    Each receipt pays the challenge its hash was bound to by :meth:``credential``.
    """

    def __init__(self, store: Any) -> None:
        self.bound: dict[str, str] = {}
        self.successes: list[Any] = []
        server = Mpp(
            methods=tempo.charge(
                rpc_url="https://rpc.test",
                store=store,
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(self._rpc)),
                currencies=[CURRENCY],
                recipient=RECIPIENT,
            ),
            realm=REALM,
            secret_key=SECRET,
        )
        server.on_payment_success(self.successes.append)
        self.handler = server.charge(amount="0.001")

    async def credential(self, tx_hash: str) -> str:
        issued = _challenge(await self.handler(http_request()))
        self.bound[tx_hash] = issued.id
        payload = {"type": "hash", "hash": tx_hash}
        return Credential(challenge=issued.to_echo(), payload=payload).to_authorization()

    async def pay(self, authorization: str) -> Any:
        return await self.handler(http_request(authorization))

    async def _rpc(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body["params"]
        # Yield so concurrent verifications interleave at every RPC.
        await anyio.sleep(0)
        if method == "eth_chainId":
            result: Any = hex(CHAIN_ID)
        elif method == "eth_getTransactionReceipt":
            result = self._receipt(params[0].lower())
        else:
            result = None
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    def _receipt(self, tx_hash: str) -> dict[str, Any]:
        memo = encode_attribution(challenge_id=self.bound[tx_hash], server_id=REALM)
        return {
            "status": "0x1",
            "transactionHash": tx_hash,
            "logs": [
                {
                    "address": CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + PAYER[2:].lower().zfill(64),
                        "0x" + RECIPIENT[2:].lower().zfill(64),
                        memo,
                    ],
                    "data": "0x" + hex(1000)[2:].zfill(64),
                }
            ],
        }


def _challenge(result: Any) -> Challenge:
    assert isinstance(result, PaymentRequired), result
    [value] = result.challenge.headers.get_list("www-authenticate")
    return Challenge.from_www_authenticate(value)


def _tx_hash(index: int) -> str:
    return "0x" + f"{index + 1:064x}"


class TestTempoSettlement:
    @pytest.mark.parametrize("replays", SIZES)
    async def test_parallel_replays_settle_once(self, stores: StoreFactory, replays: int) -> None:
        route = TempoRoute(await stores())
        authorization = await route.credential(_tx_hash(1))

        results = await asyncio.gather(*(route.pay(authorization) for _ in range(replays)))

        paid = [result for result in results if isinstance(result, PaymentVerified)]
        assert len(paid) == 1
        assert paid[0].receipt.reference == _tx_hash(1)
        rejected = [result for result in results if not isinstance(result, PaymentVerified)]
        assert {result.status for result in rejected} == {403}
        assert len(route.successes) == 1

    @pytest.mark.parametrize("payments", SIZES)
    async def test_parallel_distinct_payments_all_settle(
        self, stores: StoreFactory, payments: int
    ) -> None:
        route = TempoRoute(await stores())
        hashes = [_tx_hash(index) for index in range(payments)]
        authorizations = [await route.credential(tx_hash) for tx_hash in hashes]

        results = await asyncio.gather(*(route.pay(value) for value in authorizations))

        assert all(isinstance(result, PaymentVerified) for result in results), results
        assert [result.receipt.reference for result in results] == hashes
        assert len(route.successes) == payments

    async def test_replicas_sharing_a_store_settle_once(self, stores: StoreFactory) -> None:
        """Replicas with their own engine and store connection share one replay backend."""
        replicas = [TempoRoute(await stores()) for _ in range(4)]
        authorization = await replicas[0].credential(_tx_hash(7))
        for replica in replicas[1:]:
            replica.bound = replicas[0].bound

        results = await asyncio.gather(
            *(replicas[index % len(replicas)].pay(authorization) for index in range(40))
        )

        assert sum(isinstance(result, PaymentVerified) for result in results) == 1
        assert sum(len(replica.successes) for replica in replicas) == 1


class TestReplayClaims:
    @pytest.mark.parametrize("claimants", [pytest.param(200, id="200"), *SIZES[1:]])
    async def test_one_winner_per_key_across_connections(
        self, stores: StoreFactory, claimants: int
    ) -> None:
        connections = [await stores() for _ in range(3)]
        keys = [f"claim:{index}" for index in range(20)]

        async def claim(index: int) -> tuple[str, str, bool]:
            key, value = keys[index % len(keys)], f"claimant-{index}"
            won = await connections[index % len(connections)].put_if_absent(key, value)
            return key, value, won

        results = await asyncio.gather(*(claim(index) for index in range(claimants)))

        winners = {key: value for key, value, won in results if won}
        assert sum(won for _, _, won in results) == len(keys)
        assert sorted(winners) == sorted(keys)
        for connection in connections:
            assert {key: await connection.get(key) for key in keys} == winners


# trio --------------------------------------------------------------------------
#
# The engine, MemoryStore and the client transport also run under trio. The SQLite
# (aiosqlite) and Redis (redis.asyncio) drivers are asyncio-only.

BACKENDS = ["asyncio", "trio"]


async def _gather(calls: list[Callable[[], Awaitable[Any]]]) -> list[Any]:
    """Run calls concurrently on any anyio backend, keeping their order."""
    results: list[Any] = [None] * len(calls)

    async def run(index: int) -> None:
        results[index] = await calls[index]()

    async with anyio.create_task_group() as group:
        for index in range(len(calls)):
            group.start_soon(run, index)
    return results


class TestTrio:
    def test_replays_settle_once(self) -> None:
        async def run() -> None:
            route = TempoRoute(MemoryStore())
            authorization = await route.credential(_tx_hash(1))

            results = await _gather([lambda: route.pay(authorization)] * 50)

            assert sum(isinstance(result, PaymentVerified) for result in results) == 1
            assert len(route.successes) == 1

        anyio.run(run, backend="trio")

    def test_distinct_payments_all_settle(self) -> None:
        async def run() -> None:
            route = TempoRoute(MemoryStore())
            hashes = [_tx_hash(index) for index in range(50)]
            authorizations = [await route.credential(tx_hash) for tx_hash in hashes]

            results = await _gather(
                [lambda value=value: route.pay(value) for value in authorizations]
            )

            assert [result.receipt.reference for result in results] == hashes

        anyio.run(run, backend="trio")


# Client transport --------------------------------------------------------------


REQUEST_ID = "X-Request-Id"


class EngineServer(httpx.AsyncBaseTransport):
    """Serves an engine route in-process and checks each paid retry's credential.

    A retry must echo the challenge issued to the request carrying the same
    ``X-Request-Id``, so a credential crossed between concurrent requests fails.
    """

    def __init__(self, seed: int) -> None:
        self.random = random.Random(seed)
        self.issued: dict[str, str] = {}
        self.crossed: list[str] = []
        self.settled: list[str] = []
        self.server = Mpp(
            methods=server_method(verify=self._verify), realm=REALM, secret_key=SECRET
        )

    async def _verify(self, context: Any) -> Receipt:
        await anyio.sleep(self.random.random() / 1000)
        self.settled.append(context.challenge.id)
        return Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference=context.credential.payload["request_id"],
            method="tempo",
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await anyio.sleep(self.random.random() / 1000)
        request_id = request.headers[REQUEST_ID]
        authorization = request.headers.get("authorization")
        if authorization is not None:
            echoed = Credential.from_authorization(authorization).challenge.id
            if echoed != self.issued[request_id]:
                self.crossed.append(request_id)
        result = await self.server.charge(amount="1", meta={"request_id": request_id})(
            Request(
                request.method,
                str(request.url),
                headers=request.headers.multi_items(),
                body=await request.aread(),
            )
        )
        if isinstance(result, PaymentVerified):
            return httpx.Response(200, json={"reference": result.receipt.reference})
        response = result.challenge
        if response.status == 402:
            self.issued[request_id] = _challenge(result).id
        return httpx.Response(
            response.status, headers=response.headers.multi_items(), content=response.body
        )


def _client_method(seed: int) -> ClientMethod:
    rng = random.Random(seed)

    async def create_credential(params: CredentialParams) -> str:
        # Interleave credential creation with the other in-flight requests.
        await anyio.sleep(rng.random() / 1000)
        challenge = params.challenge
        assert challenge.opaque is not None
        payload = {"request_id": challenge.opaque["request_id"]}
        return Credential(challenge=challenge.to_echo(), payload=payload).to_authorization()

    return ClientMethod(
        method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
        create_credential=create_credential,
    )


class TestClientTransport:
    @pytest.mark.parametrize("backend", BACKENDS)
    @pytest.mark.parametrize("requests", SIZES)
    def test_concurrent_fetches_keep_their_own_credentials(
        self, backend: str, requests: int
    ) -> None:
        server = EngineServer(seed=requests)
        transport = PaymentTransport(methods=[_client_method(requests)], inner=server)

        async def run() -> list[httpx.Response]:
            async with httpx.AsyncClient(
                transport=transport, base_url="https://api.example.com"
            ) as client:
                return await _gather(
                    [
                        lambda index=index: client.get(
                            "/resource", headers={REQUEST_ID: f"request-{index}"}
                        )
                        for index in range(requests)
                    ]
                )

        responses = anyio.run(run, backend=backend)

        assert [response.status_code for response in responses] == [200] * requests
        assert [response.json()["reference"] for response in responses] == [
            f"request-{index}" for index in range(requests)
        ]
        assert server.crossed == []
        assert len(server.settled) == len(set(server.settled)) == requests
