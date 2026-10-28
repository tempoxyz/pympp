"""Live HTTP harness for x402 tests: real servers on localhost ports.

Mirrors mppx's x402 e2e and localnet tests (``src/x402/Exact.e2e.test.ts``,
``src/x402/Exact.localnet.test.ts``): the paid server, the facilitator and the
clients talk over real HTTP connections.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from eth_account import Account
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential
from mpp.methods.evm import EvmAsset
from mpp.methods.evm import client as evm_client
from mpp.methods.evm._eip3009 import authorization_domain, recover_authorizer, sign_authorization
from mpp.runtime import CredentialParams
from mpp.x402 import encode_payment_signature, route_nonce

MNEMONIC = "test test test test test test test test test test test junk"
Account.enable_unaudited_hdwallet_features()


def hd_account(index: int) -> Any:
    """Return the Anvil default account at an index."""
    return Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")


@contextlib.asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    """Serve an ASGI app on a free localhost port and yield its base URL."""
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


@contextlib.contextmanager
def serve_in_thread(app: Any) -> Iterator[str]:
    """Serve an ASGI app from its own thread and event loop; yield its base URL.

    For servers that blocking code on the test's event loop calls, such as an
    x402 facilitator that Coinbase's resource server queries synchronously for
    ``/supported`` while it starts.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@dataclass
class StubFacilitator:
    """An x402 facilitator that checks EIP-3009 signatures without a chain.

    It verifies the payload against the requirements like a real facilitator
    (recipient, amount, validity window, signature, unused nonce) and settles
    by marking the nonce used and returning a deterministic transaction hash.
    """

    settle_result: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None
    verify_result: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None
    networks: tuple[str, ...] = ("eip155:84532", "eip155:8453", "eip155:31337")
    verify_requests: list[dict[str, Any]] = field(default_factory=list)
    settle_requests: list[dict[str, Any]] = field(default_factory=list)
    used: set[tuple[str, str]] = field(default_factory=set)

    def check(self, body: dict[str, Any]) -> dict[str, Any]:
        if body.get("x402Version") != 2:
            return {"isValid": False, "invalidReason": "unsupported_version"}
        payment = body["paymentPayload"]
        requirements = body["paymentRequirements"]
        if payment.get("accepted") != requirements:
            return {"isValid": False, "invalidReason": "requirements_mismatch"}
        authorization = payment["payload"]["authorization"]
        if authorization["to"].lower() != requirements["payTo"].lower():
            return {"isValid": False, "invalidReason": "recipient_mismatch"}
        if authorization["value"] != requirements["amount"]:
            return {"isValid": False, "invalidReason": "amount_mismatch"}
        now = int(time.time())
        if int(authorization["validAfter"]) > now or int(authorization["validBefore"]) <= now:
            return {"isValid": False, "invalidReason": "authorization_window"}
        domain = {
            "name": requirements["extra"]["name"],
            "version": requirements["extra"]["version"],
            "chainId": int(requirements["network"].split(":")[1]),
            "verifyingContract": to_checksum_address(requirements["asset"]),
        }
        signer = recover_authorizer(
            domain=domain,
            payload=authorization,
            signature=payment["payload"]["signature"],
        )
        if signer.lower() != authorization["from"].lower():
            return {"isValid": False, "invalidReason": "invalid_signature"}
        if (authorization["from"].lower(), authorization["nonce"].lower()) in self.used:
            return {
                "isValid": False,
                "invalidReason": "nonce_used",
                "invalidMessage": "authorization nonce already used",
            }
        return {"isValid": True, "payer": to_checksum_address(authorization["from"])}

    def app(self) -> Starlette:
        async def verify(request: Request) -> JSONResponse:
            body = await request.json()
            self.verify_requests.append(body)
            if self.verify_result is not None:
                override = self.verify_result(body)
                if override is not None:
                    return JSONResponse(override)
            return JSONResponse(self.check(body))

        async def supported(request: Request) -> JSONResponse:
            # Coinbase's resource server reads /supported when it starts.
            kinds = [
                {"x402Version": 2, "scheme": "exact", "network": network}
                for network in self.networks
            ]
            return JSONResponse({"kinds": kinds, "extensions": [], "signers": {}})

        async def settle(request: Request) -> JSONResponse:
            body = await request.json()
            self.settle_requests.append(body)
            network = body["paymentRequirements"]["network"]
            if self.settle_result is not None:
                override = self.settle_result(body)
                if override is not None:
                    return JSONResponse(override)
            verified = self.check(body)
            if not verified["isValid"]:
                return JSONResponse(
                    {
                        "success": False,
                        "errorReason": verified["invalidReason"],
                        "network": network,
                        "transaction": "",
                    }
                )
            authorization = body["paymentPayload"]["payload"]["authorization"]
            self.used.add((authorization["from"].lower(), authorization["nonce"].lower()))
            transaction = "0x" + keccak(text=authorization["nonce"]).hex()
            return JSONResponse(
                {
                    "success": True,
                    "transaction": transaction,
                    "network": network,
                    "payer": verified["payer"],
                    "amount": authorization["value"],
                }
            )

        return Starlette(
            routes=[
                Route("/verify", verify, methods=["POST"]),
                Route("/settle", settle, methods=["POST"]),
                Route("/supported", supported, methods=["GET"]),
            ]
        )


async def sign_native(account: Any, challenge: Challenge, currency: EvmAsset) -> Credential:
    """Sign a native ``evm/charge`` credential with a client ``evm`` method."""
    method = evm_client.charge(currency=currency, account=account)
    serialized = await method.create_credential(CredentialParams(challenge=challenge))
    return Credential.from_authorization(serialized)


async def wait_for(predicate: Callable[[], Awaitable[bool]], timeout: float = 10.0) -> None:
    """Poll an async predicate until it holds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError("condition not met")


def sign_x402_payment(
    account: Any,
    accepted: dict[str, Any],
    resource_url: str | None,
    *,
    nonce: str | None = None,
    valid_after: int | None = None,
    valid_before: int | None = None,
    to: str | None = None,
    value: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> str:
    """Sign an x402 v2 exact EIP-3009 payment like a standard x402 client.

    With ``extensions`` carrying ``mppx``, signs like mppx's client instead:
    adds a random salt to ``extensions.mppx.info.nonce`` and uses the
    route-bound nonce unless ``nonce`` is given.
    """
    now = int(time.time())
    if extensions is not None and "mppx" in extensions:
        mppx = extensions["mppx"]
        extensions = {
            **extensions,
            "mppx": {**mppx, "info": {**mppx["info"], "nonce": os.urandom(32).hex()}},
        }
        if nonce is None and resource_url is not None:
            nonce = route_nonce(
                accepted=accepted, resource={"url": resource_url}, extensions=extensions
            )
    authorization = {
        "from": account.address,
        "to": to or accepted["payTo"],
        "value": value or accepted["amount"],
        "validAfter": str(now - 600 if valid_after is None else valid_after),
        "validBefore": str(
            now + accepted["maxTimeoutSeconds"] if valid_before is None else valid_before
        ),
        "nonce": nonce or "0x" + os.urandom(32).hex(),
    }
    signature = sign_authorization(
        account,
        domain=authorization_domain(
            name=accepted["extra"]["name"],
            version=accepted["extra"]["version"],
            chain_id=int(accepted["network"].split(":")[1]),
            currency=accepted["asset"],
        ),
        payload=authorization,
    )
    payment: dict[str, Any] = {
        "x402Version": 2,
        "accepted": accepted,
        "payload": {"authorization": authorization, "signature": signature},
    }
    if resource_url is not None:
        payment["resource"] = {"url": resource_url}
    if extensions is not None:
        payment["extensions"] = extensions
    return encode_payment_signature(payment)  # type: ignore[arg-type]
