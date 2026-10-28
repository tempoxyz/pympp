"""Unit tests for the x402 client: offers, policy, signing and the HTTP transport.

Mirrors mppx's client tests (``src/x402/client/Exact.test.ts``,
``src/client/Transport.test.ts`` and ``src/internal/AcceptPayment.test.ts``'s
protocol ranking). Live-server interop tests are in ``test_x402_client_e2e.py``,
``test_x402_client_mppx.py`` and ``test_x402_client_localnet.py``.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest
from eth_account import Account

from mpp import Challenge, Credential
from mpp.client import Mpp, PaymentTransport
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.events import CREDENTIAL_CREATED
from mpp.methods.evm import BASE_SEPOLIA_USDC, BASE_USDC, EvmAsset
from mpp.methods.evm import client as evm_client
from mpp.methods.evm._eip3009 import authorization_domain, recover_authorizer
from mpp.runtime import ClientMethod, CredentialParams, PaymentRuntime
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    InvalidHeaderError,
    X402Challenge,
    X402FormatError,
    decode_payment_signature,
    encode_payment_response,
    is_x402_challenge,
    payment_response,
    route_extensions,
    route_nonce,
    x402_challenges,
)
from mpp.x402._client import payment_requirements, x402_credential

PAYER = Account.from_key("0x" + "11" * 32)
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
URL = "https://api.example.com/paid"
SEPOLIA = "eip155:84532"


def requirements(**overrides: Any) -> dict[str, Any]:
    accepted: dict[str, Any] = {
        "scheme": "exact",
        "network": SEPOLIA,
        "amount": "100",
        "asset": BASE_SEPOLIA_USDC.address,
        "payTo": RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    accepted.update(overrides)
    return {key: value for key, value in accepted.items() if value is not None}


def encode(value: Any) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


def payment_required(*accepts: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "accepts": list(accepts) or [requirements()],
        "resource": {"url": URL, "description": "Premium data"},
        **fields,
    }


def header(*accepts: dict[str, Any], **fields: Any) -> str:
    return encode(payment_required(*accepts, **fields))


def offer(*accepts: dict[str, Any], **fields: Any) -> Challenge:
    return x402_challenges(header(*accepts, **fields))[0]


def method(**options: Any) -> ClientMethod:
    return evm_client.charge(currency=BASE_SEPOLIA_USDC, account=PAYER, **options)


async def sign(challenge: Challenge, client: ClientMethod | None = None) -> dict[str, Any]:
    signature = await (client or method()).create_credential(CredentialParams(challenge=challenge))
    return dict(decode_payment_signature(signature))


def native_challenge(asset: EvmAsset = BASE_SEPOLIA_USDC) -> Challenge:
    return Challenge.create(
        secret_key="unit-secret-key",
        realm="api.example.com",
        method="evm",
        intent="charge",
        request={
            "amount": "100",
            "currency": asset.address,
            "recipient": RECIPIENT,
            "methodDetails": {
                "chainId": asset.chain_id,
                "credentialTypes": ["authorization"],
                "decimals": 6,
            },
        },
    )


# -- PAYMENT-REQUIRED offers -------------------------------------------------


class TestOffers:
    def test_each_accepted_entry_becomes_a_branded_challenge(self) -> None:
        base = requirements(network="eip155:8453", asset=BASE_USDC.address)
        challenges = x402_challenges(header(requirements(), base))
        assert [c.id for c in challenges] == ["x402:0", "x402:1"]
        assert all(isinstance(c, X402Challenge) and is_x402_challenge(c) for c in challenges)
        assert {(c.method, c.intent) for c in challenges} == {("evm", "charge")}
        assert challenges[0].realm == "api.example.com"
        assert challenges[0].request["resource"] == {"url": URL, "description": "Premium data"}
        assert challenges[1].request["network"] == "eip155:8453"
        assert challenges[0].to_echo().request

    def test_unsupported_entries_are_skipped_keeping_indexes(self) -> None:
        challenges = x402_challenges(
            header(
                requirements(scheme="upto"),
                requirements(network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
                requirements(amount="1.5"),
                requirements(maxTimeoutSeconds=0),
                requirements(),
            )
        )
        assert [c.id for c in challenges] == ["x402:4"]

    def test_unknown_fields_are_dropped_like_mppx(self) -> None:
        challenge = offer(
            requirements(somethingNew=True),
            resource={"url": URL, "unknown": 1, "mimeType": "application/json"},
        )
        assert "somethingNew" not in challenge.request
        assert challenge.request["resource"] == {"url": URL, "mimeType": "application/json"}

    def test_extensions_are_kept_and_invalid_ones_dropped(self) -> None:
        extensions = route_extensions(http_method="GET")
        assert offer(extensions=extensions).request["extensions"] == extensions
        assert "extensions" not in offer(extensions={"mppx": {"info": "nope"}}).request

    def test_realm_keeps_a_non_default_port(self) -> None:
        challenge = offer(resource={"url": "http://user@LOCALHOST:8402/paid"})
        assert challenge.realm == "localhost:8402"

    @pytest.mark.parametrize(
        "value",
        [
            "not base64!",
            encode([1, 2]),
            encode({**payment_required(), "x402Version": 1}),
            encode({**payment_required(), "accepts": {}}),
            encode({"x402Version": 2, "accepts": [requirements()]}),
            encode({**payment_required(), "resource": {"url": "/relative"}}),
            encode({**payment_required(), "resource": {"url": "http://[bad"}}),
        ],
    )
    def test_malformed_headers_raise(self, value: str) -> None:
        with pytest.raises(X402FormatError):
            x402_challenges(value)

    def test_native_challenges_are_not_x402(self) -> None:
        assert not is_x402_challenge(native_challenge())
        lookalike = X402Challenge(id="x402:0", method="evm", intent="charge", request={})
        assert not is_x402_challenge(lookalike)

    def test_payment_requirements_strip_resource_and_extensions(self) -> None:
        challenge = offer(extensions=route_extensions(http_method="GET"))
        assert payment_requirements(challenge) == requirements()


# -- policy ------------------------------------------------------------------


class TestPolicy:
    def test_accepts_its_own_chain_and_currency(self) -> None:
        assert method().can_handle_challenge(offer())  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"network": "eip155:8453"}, "chain ID is not allowed"),
            ({"asset": BASE_USDC.address}, "currency is not allowed"),
            ({"asset": "usdc"}, "currency is not allowed"),
            ({"payTo": "alice"}, "payTo must be an address"),
            (
                {"extra": {"name": "USDC", "version": "2", "assetTransferMethod": "permit2"}},
                "permit2",
            ),
            ({"extra": {"name": "USDC"}}, "token name and version"),
            ({"extra": None}, "token name and version"),
        ],
    )
    async def test_rejects_offers_outside_policy(
        self, overrides: dict[str, Any], message: str
    ) -> None:
        challenge = offer(requirements(**overrides))
        assert not method().can_handle_challenge(challenge)  # type: ignore[misc]
        with pytest.raises(ValueError, match=message):
            await sign(challenge)

    async def test_max_amount_is_inclusive(self) -> None:
        client = method(max_amount="0.0001")
        assert client.can_handle_challenge(offer(requirements(amount="100")))  # type: ignore[misc]
        over = offer(requirements(amount="101"))
        assert not client.can_handle_challenge(over)  # type: ignore[misc]
        with pytest.raises(ValueError, match="exceeds max_amount"):
            await sign(over, client)

    async def test_zero_amount_offers_are_not_signed(self) -> None:
        zero = offer(requirements(amount="0"))
        assert not method().can_handle_challenge(zero)  # type: ignore[misc]
        with pytest.raises(ValueError, match="zero-amount"):
            await sign(zero)

    async def test_amounts_beyond_uint256_are_skipped(self) -> None:
        too_big = offer(requirements(amount=str(2**256)))
        assert not method().can_handle_challenge(too_big)  # type: ignore[misc]
        with pytest.raises(ValueError, match="uint256"):
            await sign(too_big)
        runtime = PaymentRuntime([method()])
        fine = offer(requirements(amount="100"))
        assert runtime.match_challenge([too_big, fine])[0] is fine

    async def test_requires_resource_information(self) -> None:
        challenge = offer()
        bare = X402Challenge(
            id=challenge.id,
            method=challenge.method,
            intent=challenge.intent,
            request={k: v for k, v in challenge.request.items() if k != "resource"},
        )
        assert not method().can_handle_challenge(bare)  # type: ignore[misc]
        with pytest.raises(ValueError, match="resource information"):
            await sign(bare)

    async def test_malformed_requirements_are_rejected(self) -> None:
        challenge = offer()
        broken = X402Challenge(
            id=challenge.id,
            method="evm",
            intent="charge",
            request={**challenge.request, "amount": "-1"},
        )
        assert not method().can_handle_challenge(broken)  # type: ignore[misc]
        with pytest.raises(ValueError, match="malformed"):
            await sign(broken)


# -- signing -----------------------------------------------------------------


class TestSigning:
    async def test_signs_an_eip3009_authorization_for_the_offer(self) -> None:
        before = int(time.time())
        payment = await sign(offer())
        authorization = payment["payload"]["authorization"]
        assert payment["x402Version"] == 2
        assert payment["accepted"] == requirements()
        assert payment["resource"] == {"url": URL, "description": "Premium data"}
        assert "extensions" not in payment
        assert authorization["from"] == PAYER.address
        assert authorization["to"] == RECIPIENT
        assert authorization["value"] == "100"
        assert before - 600 <= int(authorization["validAfter"]) <= int(time.time()) - 600
        assert before + 60 <= int(authorization["validBefore"]) <= int(time.time()) + 60
        signer = recover_authorizer(
            domain=authorization_domain(
                name="USDC", version="2", chain_id=84532, currency=BASE_SEPOLIA_USDC.address
            ),
            payload=authorization,
            signature=payment["payload"]["signature"],
        )
        assert signer == PAYER.address

    async def test_uses_the_token_domain_the_server_advertises(self) -> None:
        challenge = offer(requirements(extra={"name": "USD Coin", "version": "7"}))
        payment = await sign(challenge)
        signer = recover_authorizer(
            domain=authorization_domain(
                name="USD Coin", version="7", chain_id=84532, currency=BASE_SEPOLIA_USDC.address
            ),
            payload=payment["payload"]["authorization"],
            signature=payment["payload"]["signature"],
        )
        assert signer == PAYER.address

    async def test_random_nonces_differ_between_payments(self) -> None:
        nonces = {(await sign(offer()))["payload"]["authorization"]["nonce"] for _ in range(3)}
        assert len(nonces) == 3
        assert all(len(nonce) == 66 for nonce in nonces)

    async def test_route_binding_salts_extensions_and_binds_the_nonce(self) -> None:
        extensions = route_extensions(http_method="POST", digest="sha-256=:abc:")
        payment = await sign(offer(extensions=extensions))
        echoed = payment["extensions"]
        salt = echoed["mppx"]["info"].pop("nonce")
        assert len(salt) == 64 and int(salt, 16) >= 0
        assert echoed == extensions
        echoed["mppx"]["info"]["nonce"] = salt
        assert payment["payload"]["authorization"]["nonce"] == route_nonce(
            accepted=payment["accepted"], resource=payment["resource"], extensions=echoed
        )

    async def test_other_extensions_are_echoed_unchanged(self) -> None:
        extensions = {"bazaar": {"info": {"a": 1}, "schema": {}}}
        payment = await sign(offer(extensions=extensions))
        assert payment["extensions"] == extensions


# -- runtime -----------------------------------------------------------------


def fake_tempo_method(calls: list[Challenge]) -> ClientMethod:
    from mpp.methods.tempo.schemas import charge as tempo_definition  # noqa: PLC0415

    async def create_credential(params: CredentialParams) -> str:
        calls.append(params.challenge)
        return Credential(
            challenge=params.challenge.to_echo(), payload={"type": "hash", "hash": "0x" + "1" * 64}
        ).to_authorization()

    return ClientMethod(method=tempo_definition, create_credential=create_credential)


class TestRuntime:
    def test_native_challenges_win_over_x402_offers(self) -> None:
        runtime = PaymentRuntime([method()])
        x402 = offer()
        native = native_challenge()
        assert runtime.match_challenge([x402, native])[0] is native

    def test_x402_is_used_when_no_native_challenge_suits(self) -> None:
        runtime = PaymentRuntime([method()])
        x402 = offer()
        assert runtime.match_challenge([native_challenge(BASE_USDC), x402])[0] is x402

    async def test_x402_credentials_carry_the_payment_payload(self) -> None:
        runtime = PaymentRuntime([method()])
        created: list[Credential] = []
        runtime.events.on(CREDENTIAL_CREATED, lambda payload: created.append(payload["credential"]))
        challenge = offer()
        credential = await runtime.create_credential(challenge, runtime.methods[0])
        assert credential.payload["accepted"] == requirements()
        assert credential.challenge.id == "x402:0"
        assert created == [credential]

    def test_x402_credential_rejects_malformed_signatures(self) -> None:
        with pytest.raises(InvalidHeaderError):
            x402_credential(offer(), "bm90IGpzb24=")


# -- HTTP transport ----------------------------------------------------------


class Server:
    """A scripted HTTP server: answers each request with the next response."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def paid(transaction: str = "0x" + "ab" * 32) -> httpx.Response:
    receipt = encode_payment_response(
        {"success": True, "transaction": transaction, "network": SEPOLIA, "payer": PAYER.address}
    )
    return httpx.Response(200, headers={PAYMENT_RESPONSE_HEADER: receipt}, text="paid")


def required(value: str | None = None, **headers: str) -> httpx.Response:
    return httpx.Response(
        402, headers={PAYMENT_REQUIRED_HEADER: value or header(), **headers}, text="pay"
    )


def mpp(server: Server, *, methods: list[ClientMethod] | None = None, **options: Any) -> Mpp:
    """A client engine whose transport talks to a scripted server."""
    client = Mpp(methods=methods or [method()], **options)
    client.payment_transport._inner = httpx.MockTransport(server)  # pyright: ignore[reportPrivateUsage]
    return client


class TestTransport:
    async def test_pays_an_x402_offer_with_payment_signature(self) -> None:
        server = Server(required(), paid())
        async with mpp(server) as client:
            response = await client.fetch(URL, headers={"Authorization": "Bearer app-key"})
        assert response.status_code == 200
        retry = server.requests[1]
        payment = decode_payment_signature(retry.headers[PAYMENT_SIGNATURE_HEADER])
        assert payment["accepted"] == requirements()
        assert retry.headers["Authorization"] == "Bearer app-key"
        assert retry.headers["Accept-Payment"] == "evm/charge"
        receipt = payment_response(response)
        assert receipt is not None and receipt["transaction"] == "0x" + "ab" * 32

    async def test_prefers_the_native_challenge_on_dual_offers(self) -> None:
        native = native_challenge()
        server = Server(
            required(**{"WWW-Authenticate": native.to_www_authenticate(native.realm)}), paid()
        )
        async with mpp(server) as client:
            response = await client.fetch(URL)
        assert response.status_code == 200
        retry = server.requests[1]
        assert retry.headers["Authorization"].startswith("Payment ")
        assert PAYMENT_SIGNATURE_HEADER not in retry.headers
        assert Credential.from_authorization(retry.headers["Authorization"]).challenge.id == (
            native.id
        )

    async def test_unpayable_native_challenge_falls_back_to_x402(self) -> None:
        tempo = Challenge.create(
            secret_key="unit-secret-key",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1", "currency": "0x" + "20" * 20, "recipient": RECIPIENT},
        )
        server = Server(
            required(**{"WWW-Authenticate": tempo.to_www_authenticate(tempo.realm)}), paid()
        )
        async with mpp(server) as client:
            response = await client.fetch(URL)
        assert response.status_code == 200
        assert PAYMENT_SIGNATURE_HEADER in server.requests[1].headers
        assert "Authorization" not in server.requests[1].headers

    async def test_payable_native_tempo_challenge_wins_over_x402(self) -> None:
        tempo = Challenge.create(
            secret_key="unit-secret-key",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1", "currency": "0x" + "20" * 20, "recipient": RECIPIENT},
        )
        calls: list[Challenge] = []
        server = Server(
            required(**{"WWW-Authenticate": tempo.to_www_authenticate(tempo.realm)}), paid()
        )
        async with mpp(server, methods=[method(), fake_tempo_method(calls)]) as client:
            await client.fetch(URL)
        assert [c.id for c in calls] == [tempo.id]
        assert PAYMENT_SIGNATURE_HEADER not in server.requests[1].headers

    async def test_malformed_payment_required_does_not_block_native(self) -> None:
        native = native_challenge()
        server = Server(
            required("%%%", **{"WWW-Authenticate": native.to_www_authenticate(native.realm)}),
            paid(),
        )
        async with mpp(server) as client:
            response = await client.fetch(URL)
        assert response.status_code == 200
        assert server.requests[1].headers["Authorization"].startswith("Payment ")

    async def test_malformed_payment_required_alone_is_reported(self) -> None:
        server = Server(required("%%%"))
        failures: list[dict[str, Any]] = []
        async with mpp(server) as client:
            client.on_payment_failed(failures.append)
            response = await client.fetch(URL)
        assert response.status_code == 402
        assert len(server.requests) == 1
        assert isinstance(failures[0]["error"], X402FormatError)

    async def test_offers_outside_policy_are_not_paid(self) -> None:
        server = Server(required(header(requirements(amount="1000001"))))
        failures: list[dict[str, Any]] = []
        async with mpp(server, methods=[method(max_amount="1")]) as client:
            client.on_payment_failed(failures.append)
            response = await client.fetch(URL)
        assert response.status_code == 402
        assert len(server.requests) == 1
        assert [c.id for c in failures[0]["challenges"]] == ["x402:0"]

    async def test_payment_required_outside_402_is_ignored(self) -> None:
        server = Server(httpx.Response(200, headers={PAYMENT_REQUIRED_HEADER: header()}))
        async with mpp(server) as client:
            response = await client.fetch(URL)
        assert response.status_code == 200
        assert len(server.requests) == 1

    async def test_allowed_origins_apply_to_x402(self) -> None:
        server = Server(required())
        async with mpp(server, allowed_origins=["https://other.example.com"]) as client:
            with pytest.raises(PaymentError, match="origin is not allowed"):
                await client.fetch(URL)
        assert len(server.requests) == 1

    async def test_caller_supplied_payment_signature_is_sent_as_is(self) -> None:
        server = Server(required())
        async with mpp(server) as client:
            response = await client.fetch(URL, headers={PAYMENT_SIGNATURE_HEADER: "abc"})
        assert response.status_code == 402
        assert len(server.requests) == 1
        assert server.requests[0].headers[PAYMENT_SIGNATURE_HEADER] == "abc"

    async def test_stale_x402_headers_are_replaced(self) -> None:
        native = native_challenge()
        server = Server(
            required(**{"WWW-Authenticate": native.to_www_authenticate(native.realm)}), paid()
        )
        transport = PaymentTransport([method()], inner=httpx.MockTransport(server))
        request = httpx.Request("GET", URL, headers={PAYMENT_RESPONSE_HEADER: "stale"})
        await transport.handle_async_request(request)
        assert PAYMENT_RESPONSE_HEADER not in server.requests[1].headers

    async def test_rejected_payments_are_retried_a_bounded_number_of_times(self) -> None:
        server = Server(required())
        async with mpp(server, max_payment_retries=3) as client:
            response = await client.fetch(URL)
        assert response.status_code == 402
        signatures = [r.headers.get(PAYMENT_SIGNATURE_HEADER) for r in server.requests]
        assert signatures[0] is None
        assert len(set(signatures[1:])) == 3

    async def test_server_error_after_paying_is_an_unknown_outcome(self) -> None:
        server = Server(required(), httpx.Response(500, text="boom"))
        failures: list[dict[str, Any]] = []
        async with mpp(server) as client:
            client.on_payment_failed(failures.append)
            response = await client.fetch(URL)
        assert response.status_code == 500
        assert len(server.requests) == 2
        error = failures[0]["error"]
        assert isinstance(error, PaymentOutcomeUnknownError)
        assert error.credential is not None
        assert error.credential.payload["accepted"] == requirements()

    def test_payment_response_is_none_without_the_header(self) -> None:
        assert payment_response(httpx.Response(200)) is None
