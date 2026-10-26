"""Tests for request attestation (TAP and Web Bot Auth)."""

import asyncio
import base64
import gc
import time
import weakref
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mpp import Challenge
from mpp.attestation import (
    Absent,
    Guard,
    Invalid,
    KeyLookup,
    SigningContext,
    Unverified,
    Verified,
    compose_signers,
    tap,
    web_bot_auth,
)
from mpp.attestation._signature import _parse, _signature_base
from mpp.client import Mpp as Client
from mpp.client import PaymentTransport
from mpp.extensions.mcp.verify import _TOOL_CALL_URL
from mpp.server import Mpp, PaymentRequired, Request, compose
from mpp.store import MemoryStore
from tests import server_method

URL = "https://api.example.com/v1/items?id=1"
DIRECTORY = "https://bot.example.com"


def _server_request(signed: httpx.Request) -> Request:
    return Request(signed.method, str(signed.url), headers=signed.headers)


async def _signed(signer: Any, url: str = URL, **kwargs: Any) -> Request:
    return _server_request(await signer.sign(httpx.Request("GET", url), **kwargs))


def _copy(request: Request) -> Request:
    return Request(request.method, request.url, headers=request.headers)


def _resolver(key: Any, lookups: list[KeyLookup] | None = None) -> Any:
    def resolve(lookup: KeyLookup) -> Any:
        if lookups is not None:
            lookups.append(lookup)
        return key.public_key()

    return resolve


class TestTap:
    @pytest.mark.parametrize(
        "key",
        [
            Ed25519PrivateKey.generate(),
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ],
        ids=["ed25519", "rsa-pss-sha512"],
    )
    async def test_round_trip_consumes_nonce(self, key: Any) -> None:
        lookups: list[KeyLookup] = []
        verifier = tap.verifier(key_resolver=_resolver(key, lookups), nonce_store=MemoryStore())
        request = await _signed(tap.signer(intent="payment", key=key, key_id="agent-1"))

        result = await verifier.verify(request)

        assert isinstance(result, Verified)
        assert result.value.intent == "payment"
        assert result.value.key_id == "agent-1"
        assert lookups[0].key_id == "agent-1"
        assert await verifier.verify(_copy(request)) == Invalid(
            "The signature nonce has already been used."
        )

    async def test_signature_base_matches_profile(self) -> None:
        key = Ed25519PrivateKey.generate()
        signed = await tap.signer(intent="browse", key=key, key_id="k").sign(
            httpx.Request("GET", "https://API.example.com:443/a%20b?q=1"),
            SigningContext(created=1, nonce="n"),
        )

        assert signed.headers["Signature-Input"] == (
            'tap=("@authority" "@path");created=1;expires=481;keyid="k";'
            'alg="ed25519";nonce="n";tag="agent-browser-auth"'
        )
        parsed = _parse(signed.headers, ("agent-browser-auth",))
        assert isinstance(parsed, tuple)
        assert _signature_base(signed.url, signed.headers, parsed[0]) == (
            '"@authority": api.example.com\n'
            '"@path": /a%20b\n'
            '"@signature-params": ("@authority" "@path");created=1;expires=481;keyid="k";'
            'alg="ed25519";nonce="n";tag="agent-browser-auth"'
        )

    async def test_rejects_tampered_and_expired_signatures(self) -> None:
        key = Ed25519PrivateKey.generate()
        verifier = tap.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())
        signer = tap.signer(intent="browse", key=key, key_id="k")
        signed = await signer.sign(httpx.Request("GET", URL))
        moved = Request("GET", "https://api.example.com/v1/other", headers=signed.headers)
        stale = await _signed(
            signer, context=SigningContext(created=int(time.time()) - 600, nonce="n")
        )

        assert await verifier.verify(moved) == Invalid("The HTTP message signature is invalid.")
        assert await verifier.verify(stale) == Invalid(
            "The signature is expired or has an invalid lifetime."
        )
        assert await verifier.verify(Request("GET", URL)) == Absent()

    async def test_accepts_created_slightly_ahead_of_server_clock(self) -> None:
        key = Ed25519PrivateKey.generate()
        verifier = tap.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())
        signer = tap.signer(intent="browse", key=key, key_id="k")
        ahead = await _signed(
            signer, context=SigningContext(created=int(time.time()) + 2, nonce="a")
        )
        far = await _signed(
            signer, context=SigningContext(created=int(time.time()) + 60, nonce="b")
        )

        assert isinstance(await verifier.verify(ahead), Verified)
        assert await verifier.verify(far) == Invalid(
            "The signature is expired or has an invalid lifetime."
        )

    def test_verifiers_require_expiring_nonce_store(self) -> None:
        class PermanentStore:
            async def get(self, key: str) -> Any: ...
            async def put(self, key: str, value: Any) -> None: ...
            async def delete(self, key: str) -> None: ...
            async def put_if_absent(self, key: str, value: Any) -> bool:
                return True

        store: Any = PermanentStore()
        resolver = _resolver(Ed25519PrivateKey.generate())
        with pytest.raises(TypeError, match="put_if_absent_until"):
            tap.verifier(key_resolver=resolver, nonce_store=store)
        with pytest.raises(TypeError, match="put_if_absent_until"):
            web_bot_auth.verifier(key_resolver=resolver, nonce_store=store)

    async def test_key_resolution_failures_are_unverified(self) -> None:
        key = Ed25519PrivateKey.generate()
        request = await _signed(tap.signer(intent="browse", key=key, key_id="k"))

        def fail(lookup: KeyLookup) -> Any:
            raise RuntimeError("down")

        async def missing(lookup: KeyLookup) -> Any:
            return None

        for resolver, reason in [
            (fail, "The public key could not be resolved."),
            (missing, "No public key is available for the signature key ID."),
        ]:
            verifier = tap.verifier(key_resolver=resolver, nonce_store=MemoryStore())
            assert await verifier.verify(request) == Unverified(reason)

    async def test_claims_nonce_in_redis_store(self) -> None:
        redis = pytest.importorskip("redis")
        from mpp.stores import RedisStore

        class Client:
            def __init__(self) -> None:
                self.encoder = redis.connection.Encoder("utf-8", "strict", False)
                self.data: dict[str, bytes] = {}

            async def set(self, name: str, value: Any, nx: bool = False, pxat: int = 0) -> Any:
                encoded = self.encoder.encode(value)  # Rejects bool, as redis-py does.
                if nx and name in self.data:
                    return None
                self.data[name] = encoded
                return True

        key = Ed25519PrivateKey.generate()
        verifier = tap.verifier(key_resolver=_resolver(key), nonce_store=RedisStore(Client()))
        request = await _signed(tap.signer(intent="payment", key=key, key_id="k"))

        assert isinstance(await verifier.verify(request), Verified)
        assert await verifier.verify(_copy(request)) == Invalid(
            "The signature nonce has already been used."
        )

    def test_rejects_lifetime_beyond_eight_minutes(self) -> None:
        with pytest.raises(ValueError, match="from 1 to 480"):
            tap.signer(
                intent="browse", key=Ed25519PrivateKey.generate(), key_id="k", expires_in=481
            )


class TestWebBotAuth:
    async def test_round_trip_passes_directory_to_resolver(self) -> None:
        key = Ed25519PrivateKey.generate()
        key_id = web_bot_auth.jwk_thumbprint(key.public_key())
        lookups: list[KeyLookup] = []
        verifier = web_bot_auth.verifier(
            key_resolver=_resolver(key, lookups), nonce_store=MemoryStore()
        )
        signer = web_bot_auth.signer(key=key, key_id=key_id, signature_agent=DIRECTORY + "/")

        signed = await signer.sign(httpx.Request("GET", URL))
        result = await verifier.verify(_server_request(signed))

        assert signed.headers["Signature-Agent"] == f'webbot="{DIRECTORY}"'
        assert isinstance(result, Verified)
        assert result.value.signature_agent == DIRECTORY
        assert lookups[0].signature_agent == DIRECTORY

    async def test_rejects_key_that_does_not_match_thumbprint(self) -> None:
        key = Ed25519PrivateKey.generate()
        other = Ed25519PrivateKey.generate()
        signer = web_bot_auth.signer(
            key=key,
            key_id=web_bot_auth.jwk_thumbprint(other.public_key()),
            signature_agent=DIRECTORY,
        )
        verifier = web_bot_auth.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())

        assert await verifier.verify(await _signed(signer)) == Invalid(
            "The Web Bot Auth key does not match its RFC 7638 keyid."
        )

    async def test_rejects_unsupported_discovery_type(self) -> None:
        key = Ed25519PrivateKey.generate()
        signer = web_bot_auth.signer(
            key=key, key_id=web_bot_auth.jwk_thumbprint(key.public_key()), signature_agent=DIRECTORY
        )
        signed = await signer.sign(httpx.Request("GET", URL))
        headers = httpx.Headers(signed.headers)
        headers["Signature-Agent"] = f'webbot="{DIRECTORY}";type=inline'
        verifier = web_bot_auth.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())

        result = await verifier.verify(Request("GET", URL, headers=headers))

        assert result == Invalid(
            "The Signature-Agent discovery type is not supported by this directory profile."
        )

    def test_rsa_thumbprint_matches_rfc_7638(self) -> None:
        # RFC 7638 section 3.1 example key.
        n = int.from_bytes(
            base64.urlsafe_b64decode(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6"
                "tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-"
                "65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qN"
                "Lyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awa"
                "pJzKnqDKgw=="
            ),
            "big",
        )
        key = rsa.RSAPublicNumbers(65537, n).public_key()

        assert web_bot_auth.jwk_thumbprint(key) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"key_id": "short"},
            {"signature_agent": "http://bot.example.com"},
            {"signature_agent": "https://bot.example.com/path"},
            {"expires_in": 0},
        ],
    )
    def test_signer_rejects_invalid_config(self, kwargs: dict[str, Any]) -> None:
        key = Ed25519PrivateKey.generate()
        config: dict[str, Any] = {
            "key": key,
            "key_id": web_bot_auth.jwk_thumbprint(key.public_key()),
            "signature_agent": DIRECTORY,
            **kwargs,
        }
        with pytest.raises(ValueError):
            web_bot_auth.signer(**config)


async def test_composed_signers_share_one_context() -> None:
    tap_key = Ed25519PrivateKey.generate()
    bot_key = Ed25519PrivateKey.generate()
    signer = compose_signers(
        tap.signer(intent="payment", key=tap_key, key_id="agent"),
        web_bot_auth.signer(
            key=bot_key,
            key_id=web_bot_auth.jwk_thumbprint(bot_key.public_key()),
            signature_agent=DIRECTORY,
        ),
    )
    request = await _signed(signer)
    store = MemoryStore()

    tap_result = await tap.verifier(key_resolver=_resolver(tap_key), nonce_store=store).verify(
        request
    )
    bot_result = await web_bot_auth.verifier(
        key_resolver=_resolver(bot_key), nonce_store=store
    ).verify(request)

    assert isinstance(tap_result, Verified) and isinstance(bot_result, Verified)
    assert tap_result.value.nonce == bot_result.value.nonce


class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)


async def test_client_signs_initial_request_and_paid_retry() -> None:
    from tests.test_client import MockMethod

    key = Ed25519PrivateKey.generate()
    www_auth = Challenge(
        id="test-id", method="tempo", intent="charge", request={"amount": "1"}
    ).to_www_authenticate("api.example.com")
    inner = _Recorder(
        httpx.Response(402, headers={"www-authenticate": www_auth}), httpx.Response(200)
    )
    transport = PaymentTransport(
        methods=[MockMethod().client],
        inner=inner,
        attestation={"tap": tap.signer(intent="payment", key=key, key_id="k")},
    )
    verifier = tap.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())

    response = await transport.handle_async_request(httpx.Request("GET", URL))

    assert response.status_code == 200
    first, retry = inner.requests
    assert retry.headers["Authorization"].startswith("Payment ")
    for sent in (first, retry):
        assert isinstance(await verifier.verify(_server_request(sent)), Verified)
    with pytest.raises(TypeError, match="at least one signer"):
        Client(methods=[MockMethod().client], attestation={})


async def _unreachable(context: Any) -> Any:
    raise AssertionError("no credential is presented")


class TestServer:
    def _server(self, key: Any) -> Mpp:
        verifier = tap.verifier(key_resolver=_resolver(key), nonce_store=MemoryStore())
        return Mpp(
            methods=server_method(request={"amount": "1000"}, verify=_unreachable),
            realm="api.example.com",
            secret_key="test-secret",
            attestation={"tap": verifier},
        )

    async def test_requires_attestation_before_challenge(self) -> None:
        key = Ed25519PrivateKey.generate()
        mpp = self._server(key)
        handler = mpp.charge()

        missing = await handler(Request("GET", URL))
        signed = await _signed(tap.signer(intent="payment", key=key, key_id="k"))
        tampered = Request("POST", "https://api.example.com/other", headers=signed.headers)

        assert isinstance(missing, PaymentRequired)
        assert missing.status == 403
        assert missing.challenge.body == b'Request attestation "tap" is required.'
        result = await handler(tampered)
        assert result.status == 401
        assert isinstance(result, PaymentRequired)
        assert result.challenge.body == (
            b'Request attestation "tap" is invalid: The HTTP message signature is invalid.'
        )
        assert (await handler(signed)).status == 402
        assert (await handler(signed)).status == 402  # Verified once per request object.

    @pytest.mark.parametrize("url", ["/v1/items", "HTTPS://api.example.com/v1/items"])
    async def test_guards_non_mcp_requests_without_http_scheme(self, url: str) -> None:
        result = await self._server(Ed25519PrivateKey.generate()).charge()(Request("GET", url))

        assert result.status == 403

    async def test_composed_handlers_require_every_servers_attestation(self) -> None:
        plain = Mpp(
            methods=server_method(request={"amount": "1000"}, verify=_unreachable),
            realm="api.example.com",
            secret_key="test-secret",
        )
        handler = compose(plain.charge(), self._server(Ed25519PrivateKey.generate()).charge())

        assert (await handler(Request("GET", URL))).status == 403

    async def test_composed_servers_sharing_a_nonce_store_claim_once(self) -> None:
        key = Ed25519PrivateKey.generate()
        store = MemoryStore()
        servers = [
            Mpp(
                methods=server_method(request={"amount": "1000"}, verify=_unreachable),
                realm="api.example.com",
                secret_key="test-secret",
                attestation={"tap": tap.verifier(key_resolver=_resolver(key), nonce_store=store)},
            )
            for _ in range(2)
        ]
        handler = compose(servers[0].charge(), servers[1].charge())
        signed = await _signed(tap.signer(intent="payment", key=key, key_id="k"))

        assert (await handler(signed)).status == 402
        assert (await handler(_copy(signed))).status == 401

    async def test_composed_servers_with_stores_over_one_backend_claim_once(self) -> None:
        key = Ed25519PrivateKey.generate()
        backend = MemoryStore()

        class Wrapper:
            async def get(self, key: str) -> Any:
                return await backend.get(key)

            async def put(self, key: str, value: Any) -> None:
                await backend.put(key, value)

            async def delete(self, key: str) -> None:
                await backend.delete(key)

            async def put_if_absent(self, key: str, value: Any) -> bool:
                return await backend.put_if_absent(key, value)

            async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
                return await backend.put_if_absent_until(key, value, expires_at)

        servers = [
            Mpp(
                methods=server_method(request={"amount": "1000"}, verify=_unreachable),
                realm="api.example.com",
                secret_key="test-secret",
                attestation={
                    "tap": tap.verifier(key_resolver=_resolver(key), nonce_store=Wrapper())
                },
            )
            for _ in range(2)
        ]
        handler = compose(servers[0].charge(), servers[1].charge())
        signed = await _signed(tap.signer(intent="payment", key=key, key_id="k"))

        assert (await handler(signed)).status == 402
        assert (await handler(_copy(signed))).status == 401

    async def test_guard_releases_request_when_verifier_raises(self) -> None:
        class Failing:
            async def verify(self, request: Request) -> Any:
                raise RuntimeError("boom")

        guard = Guard({"failing": Failing()})
        request = Request("GET", URL)
        alive = weakref.ref(request)
        with pytest.raises(RuntimeError, match="boom"):
            await guard(request)
        del request
        await asyncio.sleep(0)  # Let the loop drop its references to the finished task.
        gc.collect()

        assert alive() is None

    async def test_skips_mcp_requests_and_rejects_empty_config(self) -> None:
        mpp = self._server(Ed25519PrivateKey.generate())

        assert (await mpp.charge()(Request("POST", _TOOL_CALL_URL))).status == 402
        with pytest.raises(TypeError, match="at least one verifier"):
            Mpp(
                methods=server_method(verify=_unreachable), secret_key="test-secret", attestation={}
            )
