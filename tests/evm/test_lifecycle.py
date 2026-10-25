"""Ports mppx ``evm/server/Charge.lifecycle.test.ts`` and ``evm/client/DeferredSigner.test.ts``."""

from typing import Any, Literal

import httpx
import pytest
from eth_account import Account

from mpp import Challenge, Credential
from mpp.client import Mpp as ClientMppx
from mpp.evm import assets
from mpp.evm import client as evm_client
from mpp.evm import server as evm_server
from mpp.method import PaymentSuccessHookContext
from mpp.server import Mpp, Request
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_signature,
)

from ._helpers import PRIVATE_KEY, SECRET_KEY, TRANSACTION, Facilitator, to_httpx

RECIPIENT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
REALM = "example.test"
account = Account.from_key(PRIVATE_KEY)

type Protocol = Literal["mpp", "x402"]


def x402_only(response: Any) -> httpx.Response:
    return httpx.Response(
        402,
        headers={PAYMENT_REQUIRED_HEADER: response.headers[PAYMENT_REQUIRED_HEADER]},
        request=httpx.Request("GET", "https://example.test/paid"),
    )


class Fixture:
    def __init__(self, protocol: Protocol) -> None:
        self.protocol = protocol
        self.payers: list[str | None] = []
        self.facilitator = Facilitator(invalid_reason="Authorization is no longer spendable")

        def on_success(context: PaymentSuccessHookContext) -> None:
            self.payers.append(context.payer)

        self.method = evm_server.charge(
            currency=assets.BASE_USDC,
            on_payment_success=on_success,
            recipient=RECIPIENT,
            x402=evm_server.X402Options(facilitator=self.facilitator),
        )
        self.server = Mpp(methods=[self.method], realm=REALM, secret_key=SECRET_KEY)
        self.server.on_payment_success(lambda event: self.payers.append(event.payer))
        self.request = Request("GET", "https://example.test/paid")
        self.route_options: dict[str, Any] = {
            "realm": REALM,
            "request": {"amount": "0.25"},
            "scope": "job",
        }

    async def prepare(self) -> None:
        offered = await self.server.charge(amount="0.25", scope="job")(self.request)
        assert offered.status == 402
        self.offered = offered.challenge  # type: ignore[attr-defined]
        self.challenge = await self.server.challenge.evm.charge(
            amount="0.25",
            scope="job",
            expires=Challenge.from_headers(self.offered.headers).expires,
        )
        response = to_httpx(self.offered) if self.protocol == "mpp" else x402_only(self.offered)
        client = ClientMppx(
            methods=[
                evm_client.charge(account=account, currencies=[assets.BASE_USDC], networks=[8453])
            ]
        )
        self.prepared = await client.prepare_payment(response)

    async def credential(self) -> Credential[Any]:
        serialized = await self.prepared.create_credential()
        if self.protocol == "mpp":
            return Credential.deserialize(serialized)
        paid = Request(
            "GET", "https://example.test/paid", headers={PAYMENT_SIGNATURE_HEADER: serialized}
        )
        transport = self.method.transport
        assert transport is not None
        pending = transport.get_credential(paid)
        assert pending is not None
        return await transport.bind_credential(
            challenge=self.challenge, credential=pending, input=paid
        )


@pytest.fixture(params=["mpp", "x402"])
async def context(request: pytest.FixtureRequest) -> Fixture:
    fixture = Fixture(request.param)
    await fixture.prepare()
    return fixture


async def test_validates_without_settlement_and_broadcasts_once(context: Fixture) -> None:
    assert context.facilitator.reached == []
    credential = await context.credential()
    first = await context.server.validate_credential(credential, **context.route_options)
    second = await context.server.validate_credential(credential, **context.route_options)
    assert first.source == f"did:pkh:eip155:8453:{account.address}"
    assert second.request["amount"] == "250000"
    assert context.facilitator.reached == ["verify", "verify"]

    receipt = await context.server.broadcast_credential(credential, **context.route_options)
    assert receipt.reference == TRANSACTION
    assert context.facilitator.reached == ["verify", "verify", "verify", "settle"]
    payload, _ = context.facilitator.settlements[0]
    authorization = payload.payload.authorization
    assert (authorization.from_, authorization.to, authorization.value) == (
        account.address,
        RECIPIENT,
        "250000",
    )


async def test_rechecks_facilitator_approval_at_broadcast(context: Fixture) -> None:
    credential = await context.credential()
    await context.server.validate_credential(credential, **context.route_options)
    context.facilitator.valid = False
    with pytest.raises(Exception, match="Authorization is no longer spendable"):
        await context.server.broadcast_credential(credential, **context.route_options)
    assert context.facilitator.reached == ["verify", "verify"]
    assert context.facilitator.settlements == []


async def test_exposes_the_recovered_payer_on_success(context: Fixture) -> None:
    header = "Authorization" if context.protocol == "mpp" else PAYMENT_SIGNATURE_HEADER
    paid = await context.server.charge(amount="0.25", scope="job")(
        Request(
            "GET",
            "https://example.test/paid",
            headers={header: await context.prepared.create_credential()},
        )
    )
    assert paid.status == 200
    # A native credential's nonce is its challenge hash: pay a fresh challenge, not a replay.
    await context.prepare()
    await context.server.broadcast_credential(await context.credential(), **context.route_options)
    assert context.payers == [account.address] * 4


# -- deferred signer ---------------------------------------------------------------------------


async def deferred(protocol: Protocol, configured: Any = None) -> tuple[Any, Facilitator]:
    facilitator = Facilitator()
    server = Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=facilitator),
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )
    offered = await server.charge(amount="0.25")(Request("GET", "https://example.test/paid"))
    assert offered.status == 402
    challenge = offered.challenge  # type: ignore[attr-defined]
    response = to_httpx(challenge) if protocol == "mpp" else x402_only(challenge)
    client = ClientMppx(
        methods=[
            evm_client.charge(account=configured, currencies=[assets.BASE_USDC], networks=[8453])
        ]
    )
    return await client.prepare_payment(response), facilitator


def payer(protocol: Protocol, serialized: str) -> str:
    if protocol == "x402":
        return decode_payment_signature(serialized).payload.authorization.from_  # type: ignore[union-attr]
    return Credential.deserialize(serialized).payload["from"]


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
async def test_prepares_without_account_and_signs_with_context(protocol: Protocol) -> None:
    payment, facilitator = await deferred(protocol)
    assert payer(protocol, await payment.create_credential({"account": account})) == account.address
    assert facilitator.reached == []


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
async def test_reports_missing_signer_when_creating(protocol: Protocol) -> None:
    payment, facilitator = await deferred(protocol)
    with pytest.raises(ValueError, match=r"requires a typed-data signer\."):
        await payment.create_credential()
    assert facilitator.reached == []


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
async def test_prefers_context_over_configured_account(protocol: Protocol) -> None:
    configured = Account.from_key("0x" + "02" * 32)
    fallback, _ = await deferred(protocol, configured)
    assert payer(protocol, await fallback.create_credential()) == configured.address
    explicit, _ = await deferred(protocol, configured)
    assert (
        payer(protocol, await explicit.create_credential({"account": account})) == account.address
    )
