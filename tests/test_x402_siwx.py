"""x402 ``sign-in-with-x`` (SIWX): server option, client transport and wire format.

Mirrors mppx's ``src/x402/Siwx.test.ts``; the vectors at the bottom were produced by
mppx's ``Siwx.toMessage`` and a viem account, so pympp's messages and signatures match.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from eth_account import Account

from mpp import Receipt
from mpp.client import PaymentTransport
from mpp.errors import PaymentError
from mpp.events import PAYMENT_FAILED
from mpp.identity import Prover, with_headers
from mpp.methods.evm import BASE_SEPOLIA_USDC, BASE_USDC, evm
from mpp.methods.evm import client as evm_client
from mpp.server import Mpp, PaymentRequired, PaymentVerified
from mpp.server.http import Request, Response
from mpp.store import MemoryStore
from mpp.x402 import PAYMENT_REQUIRED_HEADER, decode_payment_required, siwx

ACCOUNT = Account.from_key("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
OTHER = Account.from_key("0x" + "77" * 32)
RECIPIENT = Account.from_key("0x" + "42" * 32).address
SECRET_KEY = "test-secret-key-test-secret-key-32"
ORIGIN = "https://api.example.com"
URL = f"{ORIGIN}/credits?task=1"


def iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now() -> datetime:
    return datetime.now(UTC)


def settle_ok(_authorization: Any) -> str:
    return "0x" + "1" * 64


class Route:
    """An evm charge route with SIWX, answering like an HTTP framework would."""

    def __init__(self, granted: list[str] | None = None, *, siwx_enabled: bool = True) -> None:
        self.settled: list[str] = []
        self.failures: list[dict[str, Any]] = []
        granted_addresses = [ACCOUNT.address] if granted is None else granted

        def settle(_authorization: Any) -> str:
            self.settled.append("settle")
            return "0x" + "1" * 64

        options = siwx.SiwxOptions(
            origin=ORIGIN,
            store=MemoryStore(),
            grant=lambda address, _chain_id, _request: address in granted_addresses,
        )
        self.server = Mpp(
            methods=evm(
                currency=BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                settle=settle,
                siwx=options if siwx_enabled else None,
            ),
            secret_key=SECRET_KEY,
            realm="api.example.com",
        )
        self.server._events.on(PAYMENT_FAILED, self.failures.append)
        self.handler = self.server.charge(amount="0.25")

    async def __call__(self, request: Request) -> Response:
        result = await self.handler(request)
        if isinstance(result, PaymentRequired):
            return result.challenge
        assert isinstance(result, PaymentVerified)
        return result.with_receipt(Response.json({"ok": True}))


def read_challenge(response: Response) -> dict[str, Any]:
    header = response.headers.get(PAYMENT_REQUIRED_HEADER)
    assert header is not None
    return dict(decode_payment_required(header))


def unsigned_of(
    extension: siwx.Extension, signer: Any = ACCOUNT, **overrides: Any
) -> dict[str, Any]:
    return {
        **extension["info"],
        "address": signer.address,
        "chainId": extension["supportedChains"][0]["chainId"],
        "type": "eip191",
        **overrides,
    }


def sign(extension: siwx.Extension, signer: Any = ACCOUNT, **overrides: Any) -> str:
    unsigned = unsigned_of(extension, signer, **overrides)
    return siwx.encode({**unsigned, "signature": siwx._sign(signer, siwx.to_message(unsigned))})


async def challenge(route: Route) -> siwx.Extension:
    response = await route(Request("GET", URL))
    assert response.status == 402
    extension = siwx.from_payment_required(read_challenge(response))
    assert extension is not None
    return extension


def with_proof(proof: str) -> Request:
    return Request("GET", URL, headers={siwx.HEADER: proof})


def receipt_of(response: Response) -> Receipt:
    header = response.headers.get("Payment-Receipt")
    assert header is not None
    return Receipt.from_payment_receipt(header)


class TestServer:
    async def test_the_402_offers_the_extension_for_the_server_origin_and_chain(self) -> None:
        extension = await challenge(Route())
        info = extension["info"]
        issued_at = datetime.fromisoformat(info["issuedAt"])
        expires = datetime.fromisoformat(info.get("expirationTime", ""))
        assert (expires - issued_at).total_seconds() == siwx.TTL_SECONDS
        assert info["domain"] == "api.example.com"
        assert info["uri"] == URL
        assert info["version"] == "1"
        assert len(info["nonce"]) == 32
        assert extension["supportedChains"] == [{"chainId": "eip155:84532", "type": "eip191"}]
        assert extension["schema"] == siwx.PAYLOAD_JSON_SCHEMA

    async def test_a_granted_wallet_gets_the_resource_without_paying(self) -> None:
        route = Route()
        response = await route(with_proof(sign(await challenge(route))))
        assert response.status == 200
        assert route.settled == []
        assert receipt_of(response).reference == f"did:pkh:eip155:84532:{ACCOUNT.address}"

    async def test_a_wallet_grant_refuses_gets_the_402_so_it_can_pay(self) -> None:
        route = Route(granted=[])
        response = await route(with_proof(sign(await challenge(route))))
        assert response.status == 402
        assert "siwx" not in read_challenge(response).get("error", "")

    async def test_an_async_grant_is_awaited_with_the_request(self) -> None:
        seen: list[tuple[str, int, str]] = []

        async def grant(address: str, chain_id: int, request: Request) -> bool:
            seen.append((address, chain_id, request.url))
            return True

        route = Route()
        route.server = Mpp(
            methods=evm(
                currency=BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                settle=settle_ok,
                siwx=siwx.SiwxOptions(origin=ORIGIN, store=MemoryStore(), grant=grant),
            ),
            secret_key=SECRET_KEY,
        )
        route.handler = route.server.charge(amount="0.25")
        response = await route(with_proof(sign(await challenge(route))))
        assert response.status == 200
        assert seen == [(ACCOUNT.address, 84532, URL)]

    async def test_a_proof_is_accepted_once(self) -> None:
        route = Route()
        proof = sign(await challenge(route))
        assert (await route(with_proof(proof))).status == 200
        replay = await route(with_proof(proof))
        assert replay.status == 402
        assert "invalid_siwx_nonce" in read_challenge(replay)["error"]

    @pytest.mark.parametrize(
        ("overrides", "code"),
        [
            ({"domain": "evil.example"}, "invalid_siwx_domain_mismatch"),
            ({"uri": "https://evil.example/credits"}, "invalid_siwx_uri_mismatch"),
            ({"chainId": "eip155:1"}, "invalid_siwx_unsupported_chain"),
            ({"expirationTime": lambda: iso(now() - timedelta(seconds=1))}, "invalid_siwx_expired"),
            (
                {"issuedAt": lambda: iso(now() - timedelta(seconds=siwx.TTL_SECONDS + 1))},
                "invalid_siwx_issued_at_too_old",
            ),
            (
                {"issuedAt": lambda: iso(now() + timedelta(minutes=10))},
                "invalid_siwx_issued_at_in_future",
            ),
            (
                {"notBefore": lambda: iso(now() + timedelta(seconds=60))},
                "invalid_siwx_not_yet_valid",
            ),
        ],
        ids=[
            "another domain",
            "another origin in uri",
            "another chain",
            "an expired message",
            "an old message",
            "a future message",
            "a not-yet-valid message",
        ],
    )
    async def test_rejects(self, overrides: dict[str, Any], code: str) -> None:
        route = Route()
        # Times are computed when the test runs, not when it is collected.
        resolved = {key: value() if callable(value) else value for key, value in overrides.items()}
        response = await route(with_proof(sign(await challenge(route), **resolved)))
        assert response.status == 402
        assert code in read_challenge(response)["error"]
        assert route.settled == []
        assert route.failures
        assert route.failures[0]["credential"] is None

    @pytest.mark.parametrize(
        ("overrides", "code"),
        [
            (
                {"chainId": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"},
                "invalid_siwx_unsupported_chain",
            ),
            ({"nonce": "abc"}, "invalid_siwx_nonce"),
        ],
        ids=["a non-EVM chain", "a short nonce"],
    )
    async def test_rejects_before_checking_the_signature(
        self, overrides: dict[str, Any], code: str
    ) -> None:
        route = Route()
        payload = {**unsigned_of(await challenge(route)), "signature": "0x00", **overrides}
        response = await route(with_proof(siwx.encode(payload)))
        assert code in read_challenge(response)["error"]

    async def test_rejects_a_signature_from_another_wallet(self) -> None:
        route = Route()
        unsigned = unsigned_of(await challenge(route))
        signature = siwx._sign(OTHER, siwx.to_message(unsigned))
        response = await route(with_proof(siwx.encode({**unsigned, "signature": signature})))
        assert "invalid_siwx_signature" in read_challenge(response)["error"]

    async def test_a_rejected_proof_does_not_use_up_its_nonce(self) -> None:
        route = Route()
        extension = await challenge(route)
        unsigned = unsigned_of(extension)
        forged = siwx._sign(OTHER, siwx.to_message(unsigned))
        await route(with_proof(siwx.encode({**unsigned, "signature": forged})))
        assert (await route(with_proof(sign(extension)))).status == 200

    async def test_rejects_a_malformed_header(self) -> None:
        response = await Route()(with_proof("not-base64-json"))
        assert "invalid_siwx_payload" in read_challenge(response)["error"]

    async def test_a_route_without_siwx_offers_no_extension(self) -> None:
        route = Route(siwx_enabled=False)
        response = await route(Request("GET", URL))
        assert siwx.EXTENSION_KEY not in read_challenge(response).get("extensions", {})
        # A proof on such a route is ignored, not rejected.
        response = await route(with_proof("not-base64-json"))
        assert response.status == 402
        assert "siwx" not in read_challenge(response).get("error", "")

    async def test_composed_routes_keep_every_offer_and_list_every_chain(self) -> None:
        options = siwx.SiwxOptions(origin=ORIGIN, store=MemoryStore(), grant=lambda *_: True)
        server = Mpp(
            methods=[
                evm(
                    currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=options
                ),
                evm(currency=BASE_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=options),
            ],
            secret_key=SECRET_KEY,
        )
        handler = server.charge(amount="0.25")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        required = read_challenge(result.challenge)
        assert "Cannot merge" not in required.get("error", "")
        assert [offer["network"] for offer in required["accepts"]] == [
            "eip155:84532",
            "eip155:8453",
        ]
        extension = siwx.from_payment_required(required)
        assert extension is not None
        assert extension["supportedChains"] == [
            {"chainId": "eip155:84532", "type": "eip191"},
            {"chainId": "eip155:8453", "type": "eip191"},
        ]
        # A proof for the second offer's chain is granted by that offer.
        granted = await handler(with_proof(sign(extension, chainId="eip155:8453")))
        assert isinstance(granted, PaymentVerified)
        assert granted.receipt.reference == f"did:pkh:eip155:8453:{ACCOUNT.address}"

    def test_options_need_an_absolute_origin(self) -> None:
        with pytest.raises(ValueError, match="origin"):
            siwx.SiwxOptions(origin="api.example.com", store=MemoryStore(), grant=lambda *_: True)


def fresh_payload(**overrides: Any) -> siwx.Payload:
    extension = siwx.create_extension(chain_id=8453, origin=ORIGIN, url=URL)
    return siwx.decode(sign(extension, **overrides))


class TestVerify:
    async def test_claims_the_nonce_under_the_mppx_key(self) -> None:
        store = MemoryStore()
        payload = fresh_payload()
        proof = await siwx.verify(chain_id=8453, origin=ORIGIN, store=store, payload=payload)
        assert proof == siwx.VerifiedProof(address=ACCOUNT.address, chain_id=8453)
        assert await store.get(f"mppx:x402:siwx:{payload['nonce']}") is not None

    async def test_uses_the_verifier_for_smart_wallets(self) -> None:
        calls: list[tuple[str, str, str]] = []

        async def verifier(address: str, message: str, signature: str) -> bool:
            calls.append((address, message, signature))
            return True

        payload = fresh_payload()
        payload["signature"] = "0xdeadbeef"
        proof = await siwx.verify(
            chain_id=8453, origin=ORIGIN, store=MemoryStore(), payload=payload, verifier=verifier
        )
        assert proof.address == ACCOUNT.address
        assert calls == [(ACCOUNT.address, siwx.to_message(payload), "0xdeadbeef")]

    async def test_a_verifier_error_has_its_code(self) -> None:
        def verifier(address: str, message: str, signature: str) -> bool:
            raise RuntimeError("rpc down")

        with pytest.raises(siwx.InvalidProofError) as error:
            await siwx.verify(
                chain_id=8453,
                origin=ORIGIN,
                store=MemoryStore(),
                payload=fresh_payload(),
                verifier=verifier,
            )
        assert error.value.code == "invalid_siwx_verifier_error"

    async def test_rejects_an_unparseable_issued_at(self) -> None:
        payload = fresh_payload()
        payload["issuedAt"] = "yesterday"
        with pytest.raises(siwx.InvalidProofError) as error:
            await siwx.verify(chain_id=8453, origin=ORIGIN, store=MemoryStore(), payload=payload)
        assert error.value.code == "invalid_siwx_issued_at"


class TestWireFormat:
    def test_encode_and_decode_round_trip(self) -> None:
        payload = fresh_payload()
        assert siwx.decode(siwx.encode(payload)) == payload

    def test_decode_rejects_a_payload_missing_fields(self) -> None:
        value = base64.b64encode(json.dumps({"domain": "x"}).encode()).decode()
        with pytest.raises(siwx.InvalidProofError) as error:
            siwx.decode(value)
        assert error.value.code == "invalid_siwx_payload"

    def test_from_payment_required_keeps_supported_chains(self) -> None:
        extension = siwx.create_extension(chain_id=8453, origin=ORIGIN, url=URL)
        assert siwx.from_payment_required({"extensions": {siwx.EXTENSION_KEY: extension}}) == (
            extension
        )
        assert siwx.from_payment_required({"extensions": {}}) is None

    def test_create_extension_uses_a_fresh_random_nonce(self) -> None:
        first = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)["info"]["nonce"]
        second = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)["info"]["nonce"]
        assert first != second
        assert len(first) == 32
        int(first, 16)


# Produced by mppx's Siwx.toMessage and viem's signMessage with the Hardhat #0 key.
INTEROP_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
INTEROP_VECTORS: dict[str, Any] = {
    "base": {
        "payload": {
            "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "chainId": "eip155:8453",
            "domain": "api.example.com",
            "issuedAt": "2026-01-02T03:04:05.678Z",
            "nonce": "0123456789abcdef0123456789abcdef",
            "type": "eip191",
            "uri": "https://api.example.com/weather?city=paris",
            "version": "1",
        },
        "message": "api.example.com wants you to sign in with your Ethereum account:\n"
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n"
        "\n"
        "\n"
        "URI: https://api.example.com/weather?city=paris\n"
        "Version: 1\n"
        "Chain ID: 8453\n"
        "Nonce: 0123456789abcdef0123456789abcdef\n"
        "Issued At: 2026-01-02T03:04:05.678Z",
        "signature": (
            "0x58a6cf6185a6d6628481da38f8ec6f0748f41e1eff679691fa107ec07bf40e7d"
            "2a3d5ee92797673fc73a9403565b9d86f91e0b1b17c84908713e58acce2357531b"
        ),
    },
    "full": {
        "payload": {
            "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "chainId": "eip155:8453",
            "domain": "api.example.com",
            "issuedAt": "2026-01-02T03:04:05.678Z",
            "nonce": "0123456789abcdef0123456789abcdef",
            "type": "eip191",
            "uri": "https://api.example.com/weather?city=paris",
            "version": "1",
            "statement": "Sign in to Example",
            "expirationTime": "2026-01-02T03:09:05Z",
            "notBefore": "2026-01-02T03:04:05.000+00:00",
            "requestId": "req-1",
            "resources": ["https://api.example.com/a", "ipfs://bafy"],
        },
        "message": "api.example.com wants you to sign in with your Ethereum account:\n"
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n"
        "\n"
        "Sign in to Example\n"
        "\n"
        "URI: https://api.example.com/weather?city=paris\n"
        "Version: 1\n"
        "Chain ID: 8453\n"
        "Nonce: 0123456789abcdef0123456789abcdef\n"
        "Issued At: 2026-01-02T03:04:05.678Z\n"
        "Expiration Time: 2026-01-02T03:09:05Z\n"
        "Not Before: 2026-01-02T03:04:05.000+00:00\n"
        "Request ID: req-1\n"
        "Resources:\n"
        "- https://api.example.com/a\n"
        "- ipfs://bafy",
        "signature": (
            "0x4074615658de779ab2ca52da36894b1b91a936553daa563023869cf2499d35fe"
            "4942aa84929b35270e4731347ac7398ca4fd25f104a0a6a6c143c7bf9d325f051b"
        ),
    },
}


class TestMppxInterop:
    @pytest.mark.parametrize("name", sorted(INTEROP_VECTORS))
    def test_message_matches_mppx(self, name: str) -> None:
        vector = INTEROP_VECTORS[name]
        assert siwx.to_message(vector["payload"]) == vector["message"]

    @pytest.mark.parametrize("name", sorted(INTEROP_VECTORS))
    def test_signature_matches_mppx(self, name: str) -> None:
        vector = INTEROP_VECTORS[name]
        signed = siwx._sign(Account.from_key(INTEROP_KEY), vector["message"])
        assert signed == vector["signature"]

    @pytest.mark.parametrize("name", sorted(INTEROP_VECTORS))
    def test_mppx_signature_recovers(self, name: str) -> None:
        vector = INTEROP_VECTORS[name]
        address = siwx._recover(vector["message"], vector["signature"])
        assert address == Account.from_key(INTEROP_KEY).address


class ServerTransport(httpx.AsyncBaseTransport):
    """Sends httpx requests to a route, as if served at ``url``, recording each one."""

    def __init__(self, route: Route) -> None:
        self.route = route
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        self.requests.append(request)
        self.bodies.append(body)
        response = await self.route(
            Request(
                request.method, URL, headers=list(request.headers.multi_items()), body=body or None
            )
        )
        return httpx.Response(
            response.status, headers=list(response.headers.multi_items()), content=response.body
        )


def client_for(inner: httpx.AsyncBaseTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=siwx.SiwxTransport(account=ACCOUNT, inner=inner))


class TestSiwxTransport:
    async def test_signs_in_once_and_skips_payment_for_a_granted_wallet(self) -> None:
        route = Route()
        server = ServerTransport(route)
        async with client_for(server) as client:
            response = await client.get(URL)
        assert response.status_code == 200
        assert len(server.requests) == 2
        assert siwx.HEADER in server.requests[1].headers
        assert route.settled == []

    async def test_falls_through_to_payment_when_the_wallet_is_not_granted(self) -> None:
        route = Route(granted=[])
        transport = PaymentTransport(
            [evm_client.charge(currency=BASE_SEPOLIA_USDC, account=ACCOUNT)],
            inner=siwx.SiwxTransport(account=ACCOUNT, inner=ServerTransport(route)),
        )
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get(URL)
        assert response.status_code == 200
        assert route.settled == ["settle"]

    async def test_resends_a_request_body_with_the_proof(self) -> None:
        server = ServerTransport(Route())
        async with client_for(server) as client:
            response = await client.post(URL, content=b'{"task":1}')
        assert response.status_code == 200
        assert server.bodies == [b'{"task":1}', b'{"task":1}']

    async def test_does_not_sign_a_challenge_naming_another_site(self) -> None:
        # The 402 comes from the real server, but the client asked another host.
        server = ServerTransport(Route())
        async with client_for(server) as client:
            response = await client.get("https://other.example.com/credits?task=1")
        assert response.status_code == 402
        assert len(server.requests) == 1

    async def test_does_not_sign_without_a_siwx_offer(self) -> None:
        server = ServerTransport(Route(siwx_enabled=False))
        async with client_for(server) as client:
            response = await client.get(URL)
        assert response.status_code == 402
        assert len(server.requests) == 1


class TestEdgeCases:
    """Inputs the happy paths don't reach: malformed fields, headers and challenges."""

    def base(self, **overrides: Any) -> dict[str, Any]:
        return {**INTEROP_VECTORS["base"]["payload"], **overrides}

    @pytest.mark.parametrize(
        "overrides",
        [
            {"address": "0x1234"},
            {"domain": "not a domain"},
            {"nonce": "short"},
            {"uri": "not a uri"},
            {"uri": "https://exa mple.com"},
            {"uri": "https://example.com/%zz"},
            {"uri": "https://example.com/%a"},
            {"uri": "//example.com/x"},
            {"statement": "two\nlines"},
            {"issuedAt": "yesterday"},
            {"expirationTime": "later"},
            {"resources": ["not a uri"]},
        ],
    )
    def test_to_message_rejects_invalid_fields(self, overrides: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            siwx.to_message(self.base(**overrides))

    def test_to_message_signs_timestamps_as_sent(self) -> None:
        message = siwx.to_message(self.base(issuedAt="2026-01-02T04:04:05+01:00"))
        assert "\nIssued At: 2026-01-02T04:04:05+01:00\n" in message + "\n"
        with pytest.raises(ValueError):
            siwx.to_message(self.base(issuedAt="2026-01-02"))

    def test_to_message_rejects_a_non_eip155_chain(self) -> None:
        with pytest.raises(siwx.InvalidProofError) as error:
            siwx.to_message(self.base(chainId="eip155:abc"))
        assert error.value.code == "invalid_siwx_chain_id"

    @pytest.mark.parametrize(
        "domain", ["127.0.0.1:8080", "localhost:3000", "xn--bcher-kva.example"]
    )
    def test_to_message_accepts_ip_localhost_and_idn_domains(self, domain: str) -> None:
        assert siwx.to_message(self.base(domain=domain)).startswith(domain)

    def test_offsetless_times_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            siwx.to_message(self.base(issuedAt="2026-01-02T03:04:05"))

    @pytest.mark.parametrize(
        "value",
        [
            {"domain": 1},
            {**INTEROP_VECTORS["base"]["payload"], "signature": "0x", "statement": 1},
            {**INTEROP_VECTORS["base"]["payload"], "signature": "0x", "resources": "x"},
            {**INTEROP_VECTORS["base"]["payload"], "signature": "0x", "resources": [1]},
            {**INTEROP_VECTORS["base"]["payload"]},
            [],
        ],
    )
    def test_decode_rejects_bad_shapes(self, value: Any) -> None:
        with pytest.raises(siwx.InvalidProofError):
            siwx.decode(base64.b64encode(json.dumps(value).encode()).decode())

    def test_decode_accepts_base64url_and_keeps_resources(self) -> None:
        payload = {**self.base(resources=["https://a.example/"]), "signature": "0x00"}
        value = siwx.encode(payload).replace("+", "-").replace("/", "_").rstrip("=")
        assert siwx.decode(value) == payload

    @pytest.mark.parametrize(
        "extension",
        [
            "x",
            {"info": {}, "schema": {}, "supportedChains": []},
            {"info": INTEROP_VECTORS["base"]["payload"], "schema": {}, "supportedChains": ["x"]},
            {
                "info": INTEROP_VECTORS["base"]["payload"],
                "schema": {},
                "supportedChains": [{"chainId": 1, "type": "eip191"}],
            },
        ],
    )
    def test_from_payment_required_ignores_malformed_extensions(self, extension: Any) -> None:
        assert siwx.from_payment_required({"extensions": {siwx.EXTENSION_KEY: extension}}) is None
        assert siwx.from_payment_required({"extensions": "x"}) is None

    def test_create_extension_needs_an_http_origin(self) -> None:
        with pytest.raises(ValueError):
            siwx.create_extension(chain_id=1, origin="ftp:x", url=URL)
        extension = siwx.create_extension(
            chain_id=1, origin="http://[::1]:8080", url="http://[::1]:8080"
        )
        assert extension["info"]["domain"] == "[::1]:8080"
        assert extension["info"]["uri"] == "http://[::1]:8080/"

    @pytest.mark.parametrize(
        ("overrides", "code"),
        [
            ({"expirationTime": "later"}, "invalid_siwx_expiration_time"),
            ({"notBefore": "soon"}, "invalid_siwx_not_before"),
            ({"chainId": "eip155:x"}, "invalid_siwx_chain_id"),
            ({"address": "0x1234"}, "invalid_siwx_payload"),
            ({"signature": "zz"}, "invalid_siwx_signature"),
            ({"signature": "0x" + "00" * 65}, "invalid_siwx_signature"),
            ({"uri": "https://api.example.com/%zz"}, "invalid_siwx_payload"),
        ],
    )
    async def test_verify_rejects(self, overrides: dict[str, Any], code: str) -> None:
        payload = fresh_payload()
        payload.update(overrides)  # type: ignore[typeddict-item]
        with pytest.raises(siwx.InvalidProofError) as error:
            await siwx.verify(chain_id=8453, origin=ORIGIN, store=MemoryStore(), payload=payload)
        assert error.value.code == code

    async def test_verify_needs_an_http_origin(self) -> None:
        with pytest.raises(ValueError):
            await siwx.verify(
                chain_id=8453, origin="nope", store=MemoryStore(), payload=fresh_payload()
            )

    async def test_a_verifier_returning_false_rejects(self) -> None:
        with pytest.raises(siwx.InvalidProofError) as error:
            await siwx.verify(
                chain_id=8453,
                origin=ORIGIN,
                store=MemoryStore(),
                payload=fresh_payload(),
                verifier=lambda *_: False,
            )
        assert error.value.code == "invalid_siwx_signature"

    async def test_a_store_without_expiry_still_claims_once(self) -> None:
        class PlainStore:
            def __init__(self) -> None:
                self.data: dict[str, Any] = {}

            async def get(self, key: str) -> Any:
                return self.data.get(key)

            async def put(self, key: str, value: Any) -> None:
                self.data[key] = value

            async def delete(self, key: str) -> None:
                self.data.pop(key, None)

            async def put_if_absent(self, key: str, value: Any) -> bool:
                if key in self.data:
                    return False
                self.data[key] = value
                return True

        store = PlainStore()
        payload = fresh_payload()
        await siwx.verify(chain_id=8453, origin=ORIGIN, store=store, payload=payload)
        with pytest.raises(siwx.InvalidProofError):
            await siwx.verify(chain_id=8453, origin=ORIGIN, store=store, payload=payload)

    @pytest.mark.parametrize(
        "kwargs",
        [{"grant": "x"}, {"verifier": "x"}],
    )
    def test_options_need_callables(self, kwargs: dict[str, Any]) -> None:
        options: dict[str, Any] = {"origin": ORIGIN, "store": MemoryStore(), "grant": bool}
        with pytest.raises(ValueError):
            siwx.SiwxOptions(**{**options, **kwargs})


def required_with(extension: Any) -> httpx.Response:
    accepted = {
        "scheme": "exact",
        "network": "eip155:84532",
        "amount": "100",
        "asset": BASE_SEPOLIA_USDC.address,
        "payTo": RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    body = {
        "x402Version": 2,
        "accepts": [accepted],
        "resource": {"url": URL},
        "extensions": {siwx.EXTENSION_KEY: extension},
    }
    header = base64.b64encode(json.dumps(body).encode()).decode()
    return httpx.Response(402, headers={PAYMENT_REQUIRED_HEADER: header})


class TestSiwxTransportEdgeCases:
    async def send(self, response: httpx.Response, account: Any = ACCOUNT) -> int:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return response

        transport = siwx.SiwxTransport(account=account, inner=httpx.MockTransport(handler))
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get(URL)
        return len(calls)

    async def test_ignores_a_402_without_payment_required(self) -> None:
        assert await self.send(httpx.Response(402)) == 1

    async def test_ignores_an_unreadable_payment_required(self) -> None:
        assert await self.send(httpx.Response(402, headers={PAYMENT_REQUIRED_HEADER: "!"})) == 1

    async def test_ignores_an_offer_without_an_evm_chain(self) -> None:
        extension = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)
        extension["supportedChains"] = [{"chainId": "solana:x", "type": "ed25519"}]
        assert await self.send(required_with(extension)) == 1

    async def test_ignores_a_challenge_it_cannot_format(self) -> None:
        extension = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)
        extension["info"]["nonce"] = "short"
        assert await self.send(required_with(extension)) == 1

    async def test_ignores_an_account_that_cannot_sign(self) -> None:
        extension = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)
        assert await self.send(required_with(extension), account=object()) == 1

    async def test_sends_the_signature_scheme(self) -> None:
        extension = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)
        extension["supportedChains"][0]["signatureScheme"] = "eip191"
        assert await self.send(required_with(extension)) == 2

    async def test_signs_a_well_formed_offer(self) -> None:
        extension = siwx.create_extension(chain_id=1, origin=ORIGIN, url=URL)
        assert await self.send(required_with(extension)) == 2

    async def test_uses_a_default_inner_transport(self) -> None:
        transport = siwx.SiwxTransport(account=ACCOUNT)
        await transport.aclose()


class TestReviewFixes:
    """Cases from review: body-reading grants, IPv6 origins, nested JSON, streams."""

    @pytest.mark.parametrize("reads_body", [False, True])
    def test_a_body_reading_grant_makes_the_route_load_the_body(self, reads_body: bool) -> None:
        options = siwx.SiwxOptions(
            origin=ORIGIN, store=MemoryStore(), grant=lambda *_: True, body=reads_body
        )
        server = Mpp(
            methods=evm(
                currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=options
            ),
            secret_key=SECRET_KEY,
            realm="api.example.com",
        )
        assert server.charge(amount="0.25").needs_request_body is reads_body

    @pytest.mark.parametrize("origin", ["http://[::1]:8080", "https://[2001:db8::1]"])
    async def test_an_ipv6_origin_signs_in(self, origin: str) -> None:
        store = MemoryStore()
        extension = siwx.create_extension(chain_id=84532, origin=origin, url=f"{origin}/x")
        unsigned = unsigned_of(extension)
        payload = siwx.decode(
            siwx.encode({**unsigned, "signature": siwx._sign(ACCOUNT, siwx.to_message(unsigned))})
        )
        verified = await siwx.verify(chain_id=84532, origin=origin, store=store, payload=payload)
        assert verified.address == ACCOUNT.address

    @pytest.mark.parametrize("domain", ["[::1", "[zz::1]:80", "[]"])
    def test_rejects_a_malformed_ipv6_domain(self, domain: str) -> None:
        with pytest.raises(ValueError):
            siwx.to_message({**fresh_payload(), "domain": domain})

    def test_decode_rejects_deeply_nested_json(self) -> None:
        nested = "[" * 5000 + "]" * 5000
        value = base64.b64encode(f'{{"x":{nested}}}'.encode()).decode()
        with pytest.raises(siwx.InvalidProofError) as error:
            siwx.decode(value)
        assert error.value.code == "invalid_siwx_payload"

    async def test_passes_a_streaming_body_through_without_signing(self) -> None:
        server = ServerTransport(Route())

        async def chunks() -> AsyncIterator[bytes]:
            yield b'{"task":'
            yield b"1}"

        async with client_for(server) as client:
            response = await client.post(URL, content=chunks())
        assert response.status_code == 402
        assert len(server.requests) == 1
        assert server.bodies == [b'{"task":1}']

    async def test_a_later_same_chain_offer_can_grant(self) -> None:
        store = MemoryStore()
        refuse = siwx.SiwxOptions(origin=ORIGIN, store=store, grant=lambda *_: False)
        allow = siwx.SiwxOptions(origin=ORIGIN, store=store, grant=lambda *_: True)
        server = Mpp(
            methods=[
                evm(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=refuse),
                evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=Account.create().address,
                    settle=settle_ok,
                    siwx=allow,
                ),
            ],
            secret_key=SECRET_KEY,
        )
        handler = server.charge(amount="0.25")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        extension = siwx.from_payment_required(read_challenge(result.challenge))
        assert extension is not None
        granted = await handler(with_proof(sign(extension)))
        assert isinstance(granted, PaymentVerified)

    async def test_each_offer_checks_the_proof_with_its_own_verifier(self) -> None:
        store = MemoryStore()
        refuse = siwx.SiwxOptions(origin=ORIGIN, store=store, grant=lambda *_: False)
        allow = siwx.SiwxOptions(
            origin=ORIGIN, store=store, grant=lambda *_: True, verifier=lambda *_: False
        )
        server = Mpp(
            methods=[
                evm(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=refuse),
                evm(
                    currency=BASE_SEPOLIA_USDC,
                    recipient=Account.create().address,
                    settle=settle_ok,
                    siwx=allow,
                ),
            ],
            secret_key=SECRET_KEY,
        )
        handler = server.charge(amount="0.25")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        extension = siwx.from_payment_required(read_challenge(result.challenge))
        assert extension is not None
        refused = await handler(with_proof(sign(extension)))
        assert isinstance(refused, PaymentRequired)

    async def test_a_replayed_proof_never_reaches_grant(self) -> None:
        grants: list[str] = []

        def grant(address: str, *_: object) -> bool:
            grants.append(address)
            return True

        options = siwx.SiwxOptions(origin=ORIGIN, store=MemoryStore(), grant=grant)
        server = Mpp(
            methods=evm(
                currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=options
            ),
            secret_key=SECRET_KEY,
        )
        handler = server.charge(amount="0.25")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        extension = siwx.from_payment_required(read_challenge(result.challenge))
        assert extension is not None
        proof = sign(extension)
        assert isinstance(await handler(with_proof(proof)), PaymentVerified)
        replay = await handler(with_proof(proof))
        assert isinstance(replay, PaymentRequired)
        assert "invalid_siwx_nonce" in read_challenge(replay.challenge)["error"]
        assert grants == [ACCOUNT.address]

    async def test_an_oversized_nonce_is_rejected_before_it_is_stored(self) -> None:
        store = MemoryStore()
        extension = siwx.create_extension(chain_id=84532, origin=ORIGIN, url=URL)
        extension["info"]["nonce"] = "a" * 129
        payload = siwx.decode(sign(extension))
        with pytest.raises(siwx.InvalidProofError) as error:
            await siwx.verify(chain_id=84532, origin=ORIGIN, store=store, payload=payload)
        assert error.value.code == "invalid_siwx_nonce"
        assert await store.get("mppx:x402:siwx:" + "a" * 129) is None

    async def test_a_proof_every_offer_declined_is_spent(self) -> None:
        approved: list[str] = []
        options = siwx.SiwxOptions(
            origin=ORIGIN, store=MemoryStore(), grant=lambda address, *_: address in approved
        )
        server = Mpp(
            methods=evm(
                currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=settle_ok, siwx=options
            ),
            secret_key=SECRET_KEY,
        )
        handler = server.charge(amount="0.25")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        extension = siwx.from_payment_required(read_challenge(result.challenge))
        assert extension is not None
        proof = sign(extension)
        assert isinstance(await handler(with_proof(proof)), PaymentRequired)
        approved.append(ACCOUNT.address)
        replay = await handler(with_proof(proof))
        assert isinstance(replay, PaymentRequired)
        assert "invalid_siwx_nonce" in read_challenge(replay.challenge)["error"]

    async def test_an_oversized_chain_id_is_a_proof_error(self) -> None:
        route = Route()
        payload = {
            **unsigned_of(await challenge(route)),
            "signature": "0x00",
            "chainId": "eip155:" + "9" * 4301,
        }
        response = await route(with_proof(siwx.encode(payload)))
        assert "invalid_siwx_chain_id" in read_challenge(response)["error"]

    async def test_never_signs_after_a_cross_origin_redirect(self) -> None:
        server = ServerTransport(Route())

        class Redirecting(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.host == "start.example":
                    return httpx.Response(302, headers={"location": URL})
                return await server.handle_async_request(request)

        async with httpx.AsyncClient(
            transport=siwx.SiwxTransport(account=ACCOUNT, inner=Redirecting()),
            follow_redirects=True,
        ) as client:
            response = await client.get("https://start.example/go")
        assert response.status_code == 402
        assert [siwx.HEADER in request.headers for request in server.requests] == [False]

    async def test_never_signs_after_a_cross_origin_redirect_under_identity(self) -> None:
        # Identity provers hand SiwxTransport a copy of each request, so the first origin
        # comes from the one PaymentTransport recorded.
        server = ServerTransport(Route())

        class Redirecting(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.host == "start.example":
                    return httpx.Response(302, headers={"location": URL})
                return await server.handle_async_request(request)

        async def prove(request: httpx.Request, _context: object) -> httpx.Request:
            return with_headers(request, {"X-Id": "alice"})

        transport = PaymentTransport(
            [evm_client.charge(currency=BASE_SEPOLIA_USDC, account=ACCOUNT)],
            identity=[Prover(scope="*", prove=prove, headers=("X-Id",))],
            inner=siwx.SiwxTransport(account=ACCOUNT, inner=Redirecting()),
        )
        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            # PaymentTransport then refuses to pay across the redirect too.
            with pytest.raises(PaymentError):
                await client.get("https://start.example/go")
        assert not any(siwx.HEADER in request.headers for request in server.requests)
