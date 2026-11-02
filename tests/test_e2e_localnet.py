"""End-to-end payments over real HTTP against a Tempo localnet.

A Starlette app protected with `mpp.server.pay` runs on uvicorn, and
`mpp.client.Mpp` pays it. Every payment settles on chain: pull (signed
transaction), push (transaction hash), fee-sponsored, splits, a zero-amount
charge paid with a proof, a two-currency offer paid by a pinned client, requires_auth with
Payment-Authorization, replay rejection, and replay rejection across two
servers sharing one Redis store.

These tests pinned 0.15 behaviour before the engine refactor and are ported to
the Mpp engine API unchanged in intent.

Run with TEMPO_NETWORK=localnet and REDIS_URL=redis://localhost:6379:
    uv run pytest tests/test_e2e_localnet.py -m "integration or redis" -v
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp.client import Mpp as Client
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._rpc import _rpc_call
from mpp.methods.tempo.client import EXPIRING_NONCE_KEY, _tempo_method
from mpp.server import ComposedHandler, Mpp, pay
from mpp.store import Store
from tests import INTEGRATION
from tests.conftest import _fund_account, _tip20_balance
from tests.test_tempo_integration import _send_transfer

pytestmark = [pytest.mark.integration, INTEGRATION]

REDIS_URL = os.environ.get("REDIS_URL")
SECRET_KEY = "e2e-localnet-secret-key"
REALM = "e2e.test"
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
    """Serve one paid route per route handler with uvicorn; yield the base URL.

    Paid responses carry the Payment-Receipt header and echo the request's
    credential headers, since the client retries inside its transport.
    """

    def endpoint(handler: ComposedHandler) -> Callable[..., Awaitable[Any]]:
        @pay(handler)
        async def paid(request: Request, credential: Credential, receipt: Receipt) -> Any:
            return JSONResponse(
                {
                    "authorization": request.headers.get("authorization"),
                    "payer": credential.source,
                    "payment_authorization": request.headers.get("payment-authorization"),
                    "reference": receipt.reference,
                },
                headers={"Payment-Receipt": receipt.to_payment_receipt()},
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
    currencies: list[str],
    *,
    fee_payer: TempoAccount | None = None,
    requires_auth: bool = False,
    store: Store | None = None,
) -> Mpp:
    return Mpp(
        methods=tempo_server.charge(
            recipient=recipient,
            chain_id=chain_id,
            rpc_url=rpc_url,
            currencies=currencies,
            fee_payer=fee_payer,
        ),
        realm=REALM,
        secret_key=SECRET_KEY,
        store=store,
        requires_auth=requires_auth,
    )


def _client(account: TempoAccount, rpc_url: str, **options: Any) -> Client:
    return Client(methods=[tempo_client.charge(account=account, rpc_url=rpc_url, **options)])


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
    """A spent credential is refused with 403 and no receipt."""
    assert response.status_code == 403, response.text
    assert "Payment-Receipt" not in response.headers


class TestE2ECharge:
    async def test_pull_charge_settles_and_replay_is_refused(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        async with _serve({"/paid": server.charge(amount="0.25")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            assert unpaid.status_code == 402
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.realm == REALM
            assert challenge.request["amount"] == "250000"
            assert challenge.request["currency"] == currency
            assert challenge.request["methodDetails"]["chainId"] == chain_id

            before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                response = await client.fetch(f"{url}/paid")
            _receipt(response)
            assert response.json()["payer"].endswith(funded_payer.address)
            assert response.json()["authorization"].startswith("Payment ")
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 250_000

            # The credential the client sent is spent: replaying it is refused.
            headers = {"Authorization": response.json()["authorization"]}
            async with httpx.AsyncClient(timeout=30) as http:
                _refused(await http.get(f"{url}/paid", headers=headers))
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 250_000

    async def test_push_hash_credential_settles_once(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        async with _serve({"/paid": server.charge(amount="0.1")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                before = _balance(rpc_url, currency, funded_recipient.address)
                headers, tx_hash = await _push(
                    http,
                    f"{url}/paid",
                    rpc_url,
                    chain_id,
                    currency,
                    funded_payer,
                    funded_recipient.address,
                )
                assert _balance(rpc_url, currency, funded_recipient.address) == before + 100_000
                paid = await http.get(f"{url}/paid", headers=headers)
                assert _receipt(paid).reference == tx_hash
                _refused(await http.get(f"{url}/paid", headers=headers))

    async def test_push_only_route_is_paid_by_a_client_broadcast(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        async with _serve({"/paid": server.charge(amount="0.1", supported_modes=["push"])}) as url:
            before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                response = await client.fetch(f"{url}/paid")
            receipt = _receipt(response)
            credential = Credential.from_authorization(response.json()["authorization"])
            assert credential.payload == {"type": "hash", "hash": receipt.reference}
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 100_000

    async def test_fee_sponsored_charge(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        sponsor = _new_account(rpc_url, currency)
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency], fee_payer=sponsor)
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

    async def test_fee_payer_sponsors_split_routes_by_default(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        # As mppx: a configured fee payer sponsors routes that don't opt out, splits included.
        sponsor = _new_account(rpc_url, currency)
        partner = TempoAccount.from_key("0x" + os.urandom(32).hex())
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency], fee_payer=sponsor)
        splits = [{"amount": "150000", "recipient": partner.address}]
        async with _serve({"/paid": server.charge(amount="1", splits=splits)}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.request["methodDetails"]["feePayer"] is True
            assert challenge.request["methodDetails"]["splits"] == splits

            payer_before = _balance(rpc_url, currency, funded_payer.address)
            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            sponsor_before = _balance(rpc_url, currency, sponsor.address)
            async with _client(funded_payer, rpc_url) as client:
                _receipt(await client.fetch(f"{url}/paid"))

        assert _balance(rpc_url, currency, funded_payer.address) == payer_before - 1_000_000
        assert _balance(rpc_url, currency, partner.address) == 150_000
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before + 850_000
        assert _balance(rpc_url, currency, sponsor.address) < sponsor_before

    async def test_split_charge_pays_every_recipient(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        partner = TempoAccount.from_key("0x" + os.urandom(32).hex())
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        splits = [{"amount": "150000", "recipient": partner.address}]
        async with _serve({"/paid": server.charge(amount="1", splits=splits)}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.request["amount"] == "1000000"
            assert challenge.request["methodDetails"]["splits"] == splits

            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                _receipt(await client.fetch(f"{url}/paid"))

        assert _balance(rpc_url, currency, partner.address) == 150_000
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before + 850_000

    async def test_zero_amount_charge_needs_a_trusted_realm(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        async with _serve({"/paid": server.charge(amount="0")}) as url:
            # The realm differs from the request host, so an unpinned client refuses.
            async with _client(funded_payer, rpc_url) as client:
                with pytest.raises(Exception, match="trusted_tempo_realms"):
                    await client.fetch(f"{url}/paid")

            recipient_before = _balance(rpc_url, currency, funded_recipient.address)
            payer_before = _balance(rpc_url, currency, funded_payer.address)
            method = tempo_client.charge(account=funded_payer, rpc_url=rpc_url)
            async with Client(methods=[method], trusted_tempo_realms={url: REALM}) as client:
                response = await client.fetch(f"{url}/paid")
            _receipt(response)
            assert response.json()["payer"].endswith(funded_payer.address)
        assert _balance(rpc_url, currency, funded_recipient.address) == recipient_before
        assert _balance(rpc_url, currency, funded_payer.address) <= payer_before

    async def test_zero_amount_proof_signed_by_an_access_key(
        self, rpc_url, chain_id, currency, funded_recipient
    ):
        from pytempo import Call, TempoTransaction
        from pytempo.keychain import KeyAuthorization

        root = _new_account(rpc_url, currency)
        access_key = TempoAccount.from_key("0x" + os.urandom(32).hex())
        stranger = TempoAccount.from_key("0x" + os.urandom(32).hex())
        # The root account authorizes the access key in a 1-unit self-transfer.
        authorization = KeyAuthorization(key_id=access_key.address, chain_id=chain_id)
        gas_price = int(await _rpc_call(rpc_url, "eth_gasPrice", []), 16)
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=2_000_000,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=gas_price,
            nonce=0,
            nonce_key=EXPIRING_NONCE_KEY,
            valid_before=int(time.time()) + 25,
            fee_token=currency,
            calls=(
                Call.create(
                    to=currency,
                    value=0,
                    data="0xa9059cbb" + root.address[2:].lower().zfill(64) + "1".zfill(64),
                ),
            ),
            key_authorization=authorization.sign(root.private_key),
        ).sign(root.private_key)
        raw = "0x" + tx.encode().hex()
        receipt = await _rpc_call(rpc_url, "eth_sendRawTransactionSync", [raw])
        assert receipt["status"] == "0x1"

        server = _server(rpc_url, chain_id, funded_recipient.address, [currency])
        async with _serve({"/paid": server.charge(amount="0")}) as url:
            method = tempo_client.charge(
                account=access_key, rpc_url=rpc_url, root_account=root.address
            )
            async with Client(methods=[method], trusted_tempo_realms={url: REALM}) as client:
                response = await client.fetch(f"{url}/paid")
            _receipt(response)
            credential = Credential.from_authorization(response.json()["authorization"])
            assert credential.payload["signature"].startswith("0x04")
            assert credential.source == f"did:pkh:eip155:{chain_id}:{root.address}"

            # A key the root account never authorized cannot prove for it.
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
                challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
                forged = await _tempo_method(
                    account=stranger, rpc_url=rpc_url, root_account=root.address
                ).create_credential(challenge)
                headers = {"Authorization": forged.to_authorization()}
                refused = await http.get(f"{url}/paid", headers=headers)
            assert refused.status_code == 402
            assert refused.json()["detail"] == "Proof signature does not match source."

    async def test_two_currency_offer_paid_by_a_pinned_client(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [ALPHA_USD, currency])
        handler = server.compose(
            ("tempo/charge", {"amount": "0.2", "currency": ALPHA_USD}),
            ("tempo/charge", {"amount": "0.3", "currency": currency}),
        )
        async with _serve({"/paid": handler}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            assert unpaid.status_code == 402
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

    async def test_multi_currency_method_offers_every_currency_in_order(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(rpc_url, chain_id, funded_recipient.address, [currency, ALPHA_USD])
        async with _serve({"/paid": server.charge(amount="0.01")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            offers = [
                Challenge.from_www_authenticate(value)
                for value in unpaid.headers.get_list("WWW-Authenticate")
            ]
            assert [o.request["currency"] for o in offers] == [currency, ALPHA_USD]
            alpha_before = _balance(rpc_url, ALPHA_USD, funded_recipient.address)
            async with _client(funded_payer, rpc_url, currencies=[ALPHA_USD]) as client:
                _receipt(await client.fetch(f"{url}/paid"))
            assert _balance(rpc_url, ALPHA_USD, funded_recipient.address) == alpha_before + 10_000

    async def test_requires_auth_reads_payment_authorization(
        self, rpc_url, chain_id, currency, funded_payer, funded_recipient
    ):
        server = _server(
            rpc_url, chain_id, funded_recipient.address, [currency], requires_auth=True
        )
        async with _serve({"/paid": server.charge(amount="0.05")}) as url:
            async with httpx.AsyncClient(timeout=30) as http:
                unpaid = await http.get(f"{url}/paid")
            challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
            assert challenge.credential_header == "Payment-Authorization"

            before = _balance(rpc_url, currency, funded_recipient.address)
            async with _client(funded_payer, rpc_url) as client:
                response = await client.fetch(
                    f"{url}/paid", headers={"Authorization": "Bearer app-token"}
                )
            _receipt(response)
            # The server sees the application token untouched beside the credential.
            assert response.json()["authorization"] == "Bearer app-token"
            assert response.json()["payment_authorization"].startswith("Payment ")
            assert _balance(rpc_url, currency, funded_recipient.address) == before + 50_000

            # The credential in Authorization is not read when requires_auth is set.
            spent = {"Authorization": response.json()["payment_authorization"]}
            async with httpx.AsyncClient(timeout=30) as http:
                assert (await http.get(f"{url}/paid", headers=spent)).status_code == 402


@pytest.mark.redis
@pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set (no Redis instance)")
async def test_shared_redis_store_refuses_replay_across_servers(
    rpc_url, chain_id, currency, funded_payer, funded_recipient
):
    from redis.asyncio import from_url

    from mpp.stores import RedisStore

    assert REDIS_URL is not None
    redis = from_url(REDIS_URL)
    prefix = f"test:e2e:{uuid.uuid4().hex[:8]}:"

    def make_server() -> Mpp:
        store = RedisStore(redis, key_prefix=prefix)
        return _server(rpc_url, chain_id, funded_recipient.address, [currency], store=store)

    first, second = make_server(), make_server()
    try:
        async with (
            _serve({"/paid": first.charge(amount="0.07")}) as first_url,
            _serve({"/paid": second.charge(amount="0.07")}) as second_url,
            httpx.AsyncClient(timeout=30) as http,
        ):
            # The first server issues the challenge; the second, sharing its key,
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
            _refused(await http.get(f"{second_url}/paid", headers=headers))
            assert await redis.keys(f"{prefix}*")
    finally:
        keys = await redis.keys(f"{prefix}*")
        if keys:
            await redis.delete(*keys)
        await redis.aclose()
