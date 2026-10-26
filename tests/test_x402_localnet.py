"""x402 settlement on an Anvil localnet, end to end over real HTTP.

Port of mppx's ``src/x402/Exact.localnet.test.ts`` and its Coinbase client
test: an EIP-3009 token is deployed to Anvil, Coinbase's official x402
facilitator settles on-chain behind a live HTTP server, and both Coinbase's
official x402 client and pympp's own client pay a live pympp server.

Requires X402_ANVIL_RPC_URL. Run with:
    anvil --port 18546 --chain-id 31337 &
    X402_ANVIL_RPC_URL=http://127.0.0.1:18546 pytest -m x402_localnet -v

The token is ``tests/fixtures/x402/TestUSDC.sol`` (copied from mppx's
``test/contracts/TestUSDC.sol``); ``TestUSDC.json`` holds its ABI and bytecode,
built with ``forge build --use 0.8.30 --optimize``.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from web3 import Web3
from x402 import x402Client, x402FacilitatorSync
from x402.http import x402HTTPClient
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm import FacilitatorWeb3Signer
from x402.mechanisms.evm.exact import register_exact_evm_client, register_exact_evm_facilitator
from x402.schemas import PaymentPayload, PaymentRequired, PaymentRequirements

from mpp import Challenge, Receipt
from mpp.client import Mpp as MppClient
from mpp.methods.evm import EvmAsset, challenge_hash, evm
from mpp.server import Mpp, pay
from mpp.store import MemoryStore
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_required,
    decode_payment_response,
)
from tests.x402_harness import hd_account, serve, sign_native

RPC_URL = os.environ.get("X402_ANVIL_RPC_URL")
CHAIN_ID = 31337
ARTIFACT = Path(__file__).parent / "fixtures" / "x402" / "TestUSDC.json"
SECRET_KEY = "x402-localnet-secret-key-32-bytes"

pytestmark = [
    pytest.mark.x402_localnet,
    pytest.mark.skipif(not RPC_URL, reason="X402_ANVIL_RPC_URL not set (no Anvil node)"),
]

payer = hd_account(0)
recipient = hd_account(1)
facilitator_account = hd_account(2)
poor_payer = hd_account(3)


class Chain:
    """The deployed token and helpers to read its state."""

    def __init__(self, rpc_url: str) -> None:
        artifact = json.loads(ARTIFACT.read_text())
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        contract = self.w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        self.token = self._deploy(contract)
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.token), abi=artifact["abi"]
        )
        self._transact(self.contract.functions.mint(payer.address, 1_000 * 10**6))
        self.asset = EvmAsset(
            address=self.token, decimals=6, chain_id=CHAIN_ID, name="USDC", version="2"
        )

    def _send(self, tx: dict[str, Any]) -> Any:
        tx = {
            **tx,
            "from": payer.address,
            "nonce": self.w3.eth.get_transaction_count(payer.address),
            "chainId": CHAIN_ID,
            "gas": 3_000_000,
        }
        signed = payer.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt["status"] == 1
        return receipt

    def _deploy(self, contract: Any) -> str:
        return self._send(contract.constructor().build_transaction({"from": payer.address}))[
            "contractAddress"
        ]

    def _transact(self, call: Any) -> None:
        self._send(call.build_transaction({"from": payer.address}))

    def balance(self, address: str) -> int:
        return self.contract.functions.balanceOf(address).call()

    def authorization_used(self, owner: str, nonce: str) -> bool:
        return self.contract.functions.authorizationState(owner, bytes.fromhex(nonce[2:])).call()

    def receipt_status(self, tx_hash: str) -> int:
        return self.w3.eth.get_transaction_receipt(tx_hash)["status"]  # type: ignore[arg-type]


class CoinbaseFacilitator:
    """Coinbase's x402 facilitator, settling on Anvil, behind HTTP routes."""

    def __init__(self, rpc_url: str) -> None:
        self.facilitator = x402FacilitatorSync()
        register_exact_evm_facilitator(
            self.facilitator,
            FacilitatorWeb3Signer(private_key=facilitator_account.key.hex(), rpc_url=rpc_url),
            networks=f"eip155:{CHAIN_ID}",
        )
        self.verify_requests = 0
        self.settle_requests = 0

    def app(self) -> Starlette:
        def parse(body: dict[str, Any]) -> tuple[PaymentPayload, PaymentRequirements]:
            return (
                PaymentPayload.model_validate(body["paymentPayload"]),
                PaymentRequirements.model_validate(body["paymentRequirements"]),
            )

        # Sync handlers run in Starlette's thread pool, so web3's blocking
        # calls don't stall the event loop the paid server and clients share.
        async def verify(request: Request) -> JSONResponse:
            self.verify_requests += 1
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


def paid_app(server: Mpp, amount: str) -> Starlette:
    @pay(server.charge(amount=amount, description="localnet x402"))
    async def paid(request: Request, credential: Any, receipt: Receipt) -> PlainTextResponse:
        return PlainTextResponse("paid", headers={"Payment-Receipt": receipt.to_payment_receipt()})

    return Starlette(routes=[Route("/paid", paid)])


@pytest.fixture(scope="module")
def chain() -> Chain:
    assert RPC_URL is not None
    return Chain(RPC_URL)


def coinbase_x402_client(account: Any, chain: Chain) -> x402Client:
    """Coinbase's x402 client, allowed to pay the localnet token."""
    client = x402Client()
    register_exact_evm_client(client, account)
    client.set_spend_controls(
        {"allowed_assets": [{"network": f"eip155:{CHAIN_ID}", "asset": chain.token}]}
    )
    return client


def coinbase_client(chain: Chain, account: Any = payer) -> x402HttpxClient:
    return x402HttpxClient(coinbase_x402_client(account, chain), timeout=30)


async def start(chain: Chain, amount: str = "0.01", store: MemoryStore | None = None):
    assert RPC_URL is not None
    facilitator = CoinbaseFacilitator(RPC_URL)
    facilitator_server = serve(facilitator.app())
    facilitator_url = await facilitator_server.__aenter__()
    server = Mpp(
        methods=evm(
            currency=chain.asset,
            recipient=recipient.address,
            facilitator=facilitator_url,
            route_binding="resource",
            store=store,
        ),
        realm="localnet.test",
        secret_key=SECRET_KEY,
    )
    paid_server = serve(paid_app(server, amount))
    url = await paid_server.__aenter__()

    async def stop() -> None:
        await paid_server.__aexit__(None, None, None)
        await facilitator_server.__aexit__(None, None, None)

    return f"{url}/paid", facilitator, stop


async def test_coinbase_client_settles_x402_payment_on_chain(chain: Chain) -> None:
    url, facilitator, stop = await start(chain)
    try:
        async with httpx.AsyncClient() as http:
            unpaid = await http.get(url)
        assert unpaid.status_code == 402
        required = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])
        assert required["accepts"][0] == {
            "scheme": "exact",
            "network": f"eip155:{CHAIN_ID}",
            "amount": "10000",
            "asset": chain.token,
            "payTo": recipient.address,
            "maxTimeoutSeconds": 300,
            "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        }

        payer_before = chain.balance(payer.address)
        recipient_before = chain.balance(recipient.address)
        async with coinbase_client(chain) as client:
            response = await client.get(url)

        assert response.status_code == 200, response.text
        assert response.text == "paid"
        settled = decode_payment_response(response.headers[PAYMENT_RESPONSE_HEADER])
        assert settled["success"] is True
        assert settled["network"] == f"eip155:{CHAIN_ID}"
        assert settled.get("payer") == payer.address
        assert chain.receipt_status(settled["transaction"]) == 1
        assert chain.balance(payer.address) == payer_before - 10_000
        assert chain.balance(recipient.address) == recipient_before + 10_000
        assert facilitator.settle_requests == 1
    finally:
        await stop()


async def test_pympp_client_settles_native_evm_charge_on_chain(chain: Chain) -> None:
    url, facilitator, stop = await start(chain)
    try:
        recipient_before = chain.balance(recipient.address)
        method = evm(currency=chain.asset, account=payer, max_amount="0.05")
        async with MppClient(methods=[method]) as client:
            response = await client.fetch(url)

        assert response.status_code == 200, response.text
        assert PAYMENT_RESPONSE_HEADER not in response.headers
        receipt = Receipt.from_payment_receipt(response.headers["Payment-Receipt"])
        assert receipt.method == "evm"
        assert chain.receipt_status(receipt.reference) == 1
        assert chain.balance(recipient.address) == recipient_before + 10_000
        assert facilitator.settle_requests == 1
    finally:
        await stop()


async def test_native_evm_charge_uses_the_challenge_hash_as_nonce(chain: Chain) -> None:
    url, _, stop = await start(chain)
    try:
        async with httpx.AsyncClient() as http:
            unpaid = await http.get(url)
        challenge = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
        credential = await sign_native(payer, challenge, chain.asset)
        nonce = challenge_hash(challenge.id, challenge.realm)
        assert credential.payload["nonce"] == nonce
        assert not chain.authorization_used(payer.address, nonce)

        async with httpx.AsyncClient() as http:
            paid = await http.get(url, headers={"Authorization": credential.to_authorization()})
            assert paid.status_code == 200, paid.text
            assert chain.authorization_used(payer.address, nonce)

            replayed = await http.get(url, headers={"Authorization": credential.to_authorization()})
        assert replayed.status_code == 403
    finally:
        await stop()


async def signed_payment(url: str, chain: Chain, account: Any = payer) -> dict[str, str]:
    """Pay the route's x402 challenge with Coinbase's client and return the headers."""
    async with httpx.AsyncClient() as http:
        unpaid = await http.get(url)
    required = decode_payment_required(unpaid.headers[PAYMENT_REQUIRED_HEADER])
    client = coinbase_x402_client(account, chain)
    payload = await client.create_payment_payload(PaymentRequired.model_validate(required))
    return x402HTTPClient(client).encode_payment_signature_header(payload)


async def test_replayed_x402_payment_is_rejected_without_a_second_transfer(chain: Chain) -> None:
    url, facilitator, stop = await start(chain)
    try:
        headers = await signed_payment(url, chain)
        assert PAYMENT_SIGNATURE_HEADER in headers
        recipient_before = chain.balance(recipient.address)
        async with httpx.AsyncClient(timeout=30) as http:
            first = await http.get(url, headers=headers)
            assert first.status_code == 200, first.text
            second = await http.get(url, headers=headers)

        # A replay gets a 403 and no new challenge, so clients aren't invited to pay again.
        assert second.status_code == 403
        assert PAYMENT_REQUIRED_HEADER not in second.headers
        assert chain.balance(recipient.address) == recipient_before + 10_000
        assert facilitator.settle_requests == 1
    finally:
        await stop()


async def test_concurrent_duplicate_x402_payments_settle_once(chain: Chain) -> None:
    url, facilitator, stop = await start(chain, store=MemoryStore())
    try:
        headers = await signed_payment(url, chain)
        recipient_before = chain.balance(recipient.address)
        async with httpx.AsyncClient(timeout=30) as http:
            responses = await asyncio.gather(*(http.get(url, headers=headers) for _ in range(4)))

        statuses = sorted(response.status_code for response in responses)
        assert statuses.count(200) == 1, [r.text for r in responses]
        assert all(status in (200, 402, 403) for status in statuses)
        assert chain.balance(recipient.address) == recipient_before + 10_000
        assert facilitator.settle_requests == 1
    finally:
        await stop()


async def test_sub_cent_x402_payment_settles(chain: Chain) -> None:
    url, _, stop = await start(chain, amount="0.00001")
    try:
        recipient_before = chain.balance(recipient.address)
        async with coinbase_client(chain) as client:
            response = await client.get(url)
        assert response.status_code == 200, response.text
        assert chain.balance(recipient.address) == recipient_before + 10
    finally:
        await stop()


async def test_unfunded_payer_is_rejected_before_settlement(chain: Chain) -> None:
    url, facilitator, stop = await start(chain)
    try:
        async with coinbase_client(chain, poor_payer) as http:
            response = await http.get(url)
        assert response.status_code == 402
        assert facilitator.verify_requests >= 1
        assert facilitator.settle_requests == 0
        assert chain.balance(poor_payer.address) == 0
    finally:
        await stop()
