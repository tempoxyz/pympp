"""pympp's x402 client against mppx's x402 server, the reference, over HTTP.

The server is mppx's ``evm.charge`` with an x402 facilitator, run under Node
from ``tests/fixtures/x402/mppx-server`` (see its ``server.mjs``). It offers a
native ``evm/charge`` challenge in ``WWW-Authenticate`` and an x402 ``exact``
offer in ``PAYMENT-REQUIRED`` on the same route, as the server in mppx's
``src/x402/Exact.e2e.test.ts`` does. mppx has no x402-only route, so tests that
pay the x402 offer drop ``WWW-Authenticate`` on the client side, which is what
a server that only speaks x402 looks like to pympp.

Needs Node and the fixture's dependencies:
    npm ci --ignore-scripts --prefix tests/fixtures/x402/mppx-server

The tests skip without them unless X402_MPPX_SERVER=1 (CI's integration job),
which makes a missing server a failure. The on-chain test also needs
X402_ANVIL_RPC_URL, like ``tests/test_x402_localnet.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from web3 import Web3
from x402 import x402FacilitatorSync
from x402.mechanisms.evm import FacilitatorWeb3Signer
from x402.mechanisms.evm.exact import register_exact_evm_facilitator
from x402.schemas import PaymentPayload, PaymentRequirements

from mpp.client import PaymentTransport
from mpp.methods.evm import EvmAsset
from mpp.methods.evm import client as evm
from mpp.methods.evm._eip3009 import authorization_domain, sign_authorization
from mpp.x402 import (
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_signature,
    encode_payment_signature,
    payment_response,
    route_nonce,
)
from tests.x402_harness import StubFacilitator, hd_account, serve_in_thread

FIXTURE = Path(__file__).parent / "fixtures" / "x402" / "mppx-server"
ARTIFACT = Path(__file__).parent / "fixtures" / "x402" / "TestUSDC.json"
NODE = shutil.which("node")
RPC_URL = os.environ.get("X402_ANVIL_RPC_URL")
CHAIN_ID = 31337

if NODE is None or not (FIXTURE / "node_modules" / "mppx").is_dir():
    _reason = (
        "mppx server fixture unavailable: needs node and "
        "npm ci --ignore-scripts --prefix tests/fixtures/x402/mppx-server"
    )
    if os.environ.get("X402_MPPX_SERVER") == "1":
        raise RuntimeError(f"X402_MPPX_SERVER=1 but the {_reason}")
    pytest.skip(_reason, allow_module_level=True)

payer = hd_account(0)
recipient = hd_account(1)

# No chain behind the stub facilitator, so any address names the token.
STUB_ASSET = EvmAsset(
    address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
    decimals=6,
    chain_id=CHAIN_ID,
    name="USDC",
    version="2",
)


@contextlib.asynccontextmanager
async def mppx_server(
    *,
    facilitator: str,
    asset: EvmAsset = STUB_ASSET,
    route_binding: str = "required",
    payee: str = recipient.address,
) -> AsyncIterator[str]:
    """Run the fixture's mppx server under Node and yield its base URL."""
    assert NODE is not None
    env = {
        **os.environ,
        "MPPX_FACILITATOR_URL": facilitator,
        "MPPX_TOKEN": asset.address,
        "MPPX_RECIPIENT": payee,
        "MPPX_CHAIN_ID": str(asset.chain_id),
        "MPPX_DECIMALS": str(asset.decimals),
        "MPPX_TOKEN_NAME": asset.name or "",
        "MPPX_TOKEN_VERSION": asset.version or "",
        "MPPX_ROUTE_BINDING": route_binding,
        "MPPX_AMOUNT": "0.01",
    }
    process = await asyncio.create_subprocess_exec(
        NODE,
        str(FIXTURE / "server.mjs"),
        cwd=FIXTURE,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        assert process.stdout is not None and process.stderr is not None
        try:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=30)
        except TimeoutError:
            line = b""
        if not line:
            process.kill()
            stderr = await process.stderr.read()
            raise RuntimeError(f"mppx server did not start: {stderr.decode()}")
        yield json.loads(line)["url"]
    finally:
        if process.returncode is None:
            process.terminate()
        await process.wait()


@dataclass
class Tap(httpx.AsyncBaseTransport):
    """Record each request sent; optionally rewrite it or the 402 it gets.

    ``x402_only`` drops ``WWW-Authenticate`` from 402s and keeps the x402
    offer, as a server that speaks only x402 sends it.
    """

    x402_only: bool = False
    rewrite: Callable[[httpx.Request], None] | None = None
    requests: list[httpx.Request] = field(default_factory=list)
    inner: httpx.AsyncBaseTransport = field(default_factory=httpx.AsyncHTTPTransport)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.rewrite is not None:
            self.rewrite(request)
        self.requests.append(request)
        response = await self.inner.handle_async_request(request)
        if self.x402_only and response.status_code == 402:
            content = await response.aread()
            headers = httpx.Headers(response.headers)
            del headers["www-authenticate"]
            return httpx.Response(402, headers=headers, content=content)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()

    def signatures(self) -> list[str]:
        """The PAYMENT-SIGNATURE headers sent."""
        return [
            r.headers[PAYMENT_SIGNATURE_HEADER]
            for r in self.requests
            if PAYMENT_SIGNATURE_HEADER in r.headers
        ]


@contextlib.asynccontextmanager
async def pympp_client(
    tap: Tap, *, asset: EvmAsset = STUB_ASSET, max_amount: str | None = None, account: Any = payer
) -> AsyncIterator[tuple[httpx.AsyncClient, PaymentTransport]]:
    """An httpx client paying through pympp's evm client method and a tap.

    It pays once per request: a rejected payment comes back as the 402.
    """
    method = evm.charge(currency=asset, account=account, max_amount=max_amount)
    transport = PaymentTransport([method], inner=tap, max_payment_retries=1)
    async with httpx.AsyncClient(transport=transport, timeout=30) as client:
        yield client, transport


@pytest.fixture
def stub() -> StubFacilitator:
    return StubFacilitator()


@pytest.fixture
def stub_url(stub: StubFacilitator) -> Iterator[str]:
    with serve_in_thread(stub.app()) as url:
        yield url


@pytest.mark.parametrize("route_binding", ["required", "resource"])
async def test_x402_payment_accepted_by_mppx(
    stub: StubFacilitator, stub_url: str, route_binding: str
) -> None:
    async with mppx_server(facilitator=stub_url, route_binding=route_binding) as base:
        tap = Tap(x402_only=True)
        async with pympp_client(tap) as (client, _):
            response = await client.get(f"{base}/paid")

    assert response.status_code == 200, response.text
    assert response.text == "paid /paid"
    assert len(tap.requests) == 2
    assert "authorization" not in tap.requests[1].headers
    [signature] = tap.signatures()

    # mppx offers its route binding in both modes; pympp signs the
    # route-bound nonce, salted, as mppx's own client does.
    payment = decode_payment_signature(signature)
    extensions = payment.get("extensions")
    assert extensions is not None and "mppx" in extensions
    assert extensions["mppx"]["info"]["method"] == "GET"
    resource = payment.get("resource")
    assert resource is not None
    assert resource == {"url": f"{base}/paid"}
    authorization = payment["payload"]["authorization"]
    assert authorization["nonce"] == route_nonce(
        accepted=payment["accepted"], resource=resource, extensions=extensions
    )
    assert authorization["from"] == payer.address
    assert authorization["to"] == recipient.address
    assert authorization["value"] == "10000"

    settled = payment_response(response)
    assert settled is not None
    assert settled["success"] is True
    assert settled["network"] == f"eip155:{CHAIN_ID}"
    assert settled.get("payer") == payer.address
    assert settled["transaction"].startswith("0x")
    assert len(stub.settle_requests) == 1
    assert stub.settle_requests[0]["paymentPayload"]["payload"] == payment["payload"]


async def test_dual_offer_pays_native_mpp_challenge(stub: StubFacilitator, stub_url: str) -> None:
    async with mppx_server(facilitator=stub_url) as base:
        tap = Tap()
        async with pympp_client(tap) as (client, _):
            response = await client.get(f"{base}/paid")

    assert response.status_code == 200, response.text
    assert response.text == "paid /paid"
    unpaid, paid = tap.requests
    assert "authorization" not in unpaid.headers
    assert paid.headers["authorization"].startswith("Payment ")
    assert tap.signatures() == []
    assert "Payment-Receipt" in response.headers
    assert payment_response(response) is None
    # mppx settles native evm/charge credentials through the same facilitator.
    assert len(stub.settle_requests) == 1
    assert stub.settle_requests[0]["paymentPayload"]["payload"]["authorization"]["from"] == (
        payer.address
    )


@pytest.mark.parametrize("route_binding", ["required", "resource"])
async def test_replayed_payment_signature_rejected(
    stub: StubFacilitator, stub_url: str, route_binding: str
) -> None:
    async with mppx_server(facilitator=stub_url, route_binding=route_binding) as base:
        tap = Tap(x402_only=True)
        async with pympp_client(tap) as (client, _):
            response = await client.get(f"{base}/paid")
        assert response.status_code == 200, response.text
        [signature] = tap.signatures()

        async with httpx.AsyncClient(timeout=30) as raw:
            same_route = await raw.get(
                f"{base}/paid", headers={PAYMENT_SIGNATURE_HEADER: signature}
            )
            other_route = await raw.get(
                f"{base}/other", headers={PAYMENT_SIGNATURE_HEADER: signature}
            )

    assert same_route.status_code == 402, same_route.text
    assert other_route.status_code == 402, other_route.text
    assert payment_response(same_route) is None
    assert payment_response(other_route) is None
    assert len(stub.settle_requests) == 1


def _tamper_value(payment: dict[str, Any]) -> None:
    payment["payload"]["authorization"]["value"] = "20000"


def _tamper_signature(payment: dict[str, Any]) -> None:
    # A well-formed signature over the same authorization, by another key.
    accepted = payment["accepted"]
    payment["payload"]["signature"] = sign_authorization(
        hd_account(4),
        domain=authorization_domain(
            name=accepted["extra"]["name"],
            version=accepted["extra"]["version"],
            chain_id=int(accepted["network"].split(":")[1]),
            currency=accepted["asset"],
        ),
        payload=payment["payload"]["authorization"],
    )


@pytest.mark.parametrize("tamper", [_tamper_value, _tamper_signature], ids=["value", "signature"])
async def test_tampered_payment_signature_rejected(
    stub: StubFacilitator, stub_url: str, tamper: Callable[[dict[str, Any]], None]
) -> None:
    def rewrite(request: httpx.Request) -> None:
        if PAYMENT_SIGNATURE_HEADER in request.headers:
            payment: Any = decode_payment_signature(request.headers[PAYMENT_SIGNATURE_HEADER])
            tamper(payment)
            request.headers[PAYMENT_SIGNATURE_HEADER] = encode_payment_signature(payment)

    async with mppx_server(facilitator=stub_url) as base:
        tap = Tap(x402_only=True, rewrite=rewrite)
        async with pympp_client(tap) as (client, _):
            response = await client.get(f"{base}/paid")

    assert response.status_code == 402, response.text
    assert len(tap.signatures()) == 1
    assert payment_response(response) is None
    assert stub.settle_requests == []


@pytest.mark.parametrize("x402_only", [True, False], ids=["x402", "dual"])
async def test_amount_above_max_amount_sends_no_payment(
    stub: StubFacilitator, stub_url: str, x402_only: bool
) -> None:
    failures: list[dict[str, Any]] = []
    async with mppx_server(facilitator=stub_url) as base:
        tap = Tap(x402_only=x402_only)
        async with pympp_client(tap, max_amount="0.005") as (client, transport):
            transport.on_payment_failed(failures.append)
            response = await client.get(f"{base}/paid")

    assert response.status_code == 402
    assert len(tap.requests) == 1
    assert tap.signatures() == []
    [failure] = failures
    assert failure["credential"] is None
    assert "No compatible payment method" in str(failure["error"])
    assert stub.verify_requests == []
    assert stub.settle_requests == []


class Chain:
    """An EIP-3009 TestUSDC deployed on Anvil, as in ``test_x402_localnet.py``."""

    def __init__(self, rpc_url: str, deployer: Any) -> None:
        artifact = json.loads(ARTIFACT.read_text())
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.deployer = deployer
        contract = self.w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        self.token = self._send(contract.constructor())["contractAddress"]
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.token), abi=artifact["abi"]
        )
        self._send(self.contract.functions.mint(deployer.address, 1_000 * 10**6))
        self.asset = EvmAsset(
            address=self.token, decimals=6, chain_id=CHAIN_ID, name="USDC", version="2"
        )

    def _send(self, call: Any) -> Any:
        tx = call.build_transaction(
            {
                "from": self.deployer.address,
                "nonce": self.w3.eth.get_transaction_count(self.deployer.address),
                "chainId": CHAIN_ID,
                "gas": 3_000_000,
            }
        )
        signed = self.deployer.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt["status"] == 1
        return receipt

    def balance(self, address: str) -> int:
        return self.contract.functions.balanceOf(address).call()

    def authorization_used(self, owner: str, nonce: str) -> bool:
        return self.contract.functions.authorizationState(owner, bytes.fromhex(nonce[2:])).call()

    def receipt_status(self, tx_hash: str) -> int:
        return self.w3.eth.get_transaction_receipt(tx_hash)["status"]  # type: ignore[arg-type]


class CoinbaseFacilitator:
    """Coinbase's x402 facilitator settling on Anvil, behind HTTP routes."""

    def __init__(self, rpc_url: str, account: Any) -> None:
        self.facilitator = x402FacilitatorSync()
        register_exact_evm_facilitator(
            self.facilitator,
            FacilitatorWeb3Signer(private_key=account.key.hex(), rpc_url=rpc_url),
            networks=f"eip155:{CHAIN_ID}",
        )
        self.settle_requests = 0

    def app(self) -> Starlette:
        def parse(body: dict[str, Any]) -> tuple[PaymentPayload, PaymentRequirements]:
            return (
                PaymentPayload.model_validate(body["paymentPayload"]),
                PaymentRequirements.model_validate(body["paymentRequirements"]),
            )

        async def verify(request: Request) -> JSONResponse:
            payment, requirements = parse(await request.json())
            result = await asyncio.to_thread(self.facilitator.verify, payment, requirements)
            return JSONResponse(result.model_dump(by_alias=True, exclude_none=True))

        async def settle(request: Request) -> JSONResponse:
            self.settle_requests += 1
            payment, requirements = parse(await request.json())
            result = await asyncio.to_thread(self.facilitator.settle, payment, requirements)
            return JSONResponse(result.model_dump(by_alias=True, exclude_none=True))

        return Starlette(
            routes=[
                Route("/verify", verify, methods=["POST"]),
                Route("/settle", settle, methods=["POST"]),
            ]
        )


@pytest.mark.x402_localnet
@pytest.mark.skipif(not RPC_URL, reason="X402_ANVIL_RPC_URL not set (no Anvil node)")
async def test_x402_payment_settles_on_chain_through_mppx() -> None:
    assert RPC_URL is not None
    # Accounts no other localnet test sends from, so their nonces don't race.
    chain_payer, chain_payee, chain_facilitator = hd_account(6), hd_account(7), hd_account(8)
    chain = await asyncio.to_thread(Chain, RPC_URL, chain_payer)
    facilitator = CoinbaseFacilitator(RPC_URL, chain_facilitator)
    with serve_in_thread(facilitator.app()) as facilitator_url:
        async with mppx_server(
            facilitator=facilitator_url, asset=chain.asset, payee=chain_payee.address
        ) as base:
            payer_before = chain.balance(chain_payer.address)
            payee_before = chain.balance(chain_payee.address)
            tap = Tap(x402_only=True)
            async with pympp_client(tap, asset=chain.asset, account=chain_payer) as (client, _):
                response = await client.get(f"{base}/paid")

            assert response.status_code == 200, response.text
            assert response.text == "paid /paid"
            settled = payment_response(response)
            assert settled is not None
            assert settled["success"] is True
            assert settled["network"] == f"eip155:{CHAIN_ID}"
            assert settled.get("payer") == chain_payer.address
            assert chain.receipt_status(settled["transaction"]) == 1
            assert chain.balance(chain_payer.address) == payer_before - 10_000
            assert chain.balance(chain_payee.address) == payee_before + 10_000
            [signature] = tap.signatures()
            nonce = decode_payment_signature(signature)["payload"]["authorization"]["nonce"]
            assert chain.authorization_used(chain_payer.address, nonce)

            # The authorization is spent on chain: replaying it pays nothing.
            async with httpx.AsyncClient(timeout=30) as raw:
                replay = await raw.get(
                    f"{base}/paid", headers={PAYMENT_SIGNATURE_HEADER: signature}
                )
            assert replay.status_code == 402, replay.text
            assert chain.balance(chain_payee.address) == payee_before + 10_000
            assert facilitator.settle_requests == 1
