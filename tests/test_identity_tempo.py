"""Tempo ID: offline access tokens, DPoP proofs, ID tokens, the payment check and the prover."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mpp import Challenge, Credential, Receipt
from mpp.extensions.identity import tempo
from mpp.extensions.identity.tempo import _jwt as jwt
from mpp.extensions.identity.tempo.client import DpopKey, prover
from mpp.extensions.identity.tempo.server import TempoId, create
from mpp.identity import PaymentCheckInput, ProveContext, Rejected, Route, Valid
from mpp.server import Request
from mpp.store import MemoryStore
from tests import http_request

ISSUER = "https://id.tempo.xyz"
API = "https://api.example/paid"
ALICE = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
ALICE_CHECKSUM = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"
BOB_CHECKSUM = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"


class Issuer:
    """A fake Tempo ID: an RS256 key set it serves, and the tokens it signs."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.fetches = 0
        self.status = 200

    def jwks(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        size = (numbers.n.bit_length() + 7) // 8
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "e": jwt.b64url_encode(numbers.e.to_bytes(3, "big")),
                    "n": jwt.b64url_encode(numbers.n.to_bytes(size, "big")),
                }
            ]
        }

    def http(self) -> httpx.AsyncClient:
        def handle(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == f"{ISSUER}/oauth2/jwks"
            self.fetches += 1
            return httpx.Response(self.status, json=self.jwks())

        return httpx.AsyncClient(transport=httpx.MockTransport(handle))

    def sign(self, claims: dict[str, Any], **header: Any) -> str:
        head = {"alg": "RS256", "kid": self.kid, "typ": "at+jwt", **header}
        signing_input = f"{jwt.encode(head)}.{jwt.encode(claims)}"
        signature = self.key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{jwt.b64url_encode(signature)}"

    def access_token(self, dpop: DpopKey | None = None, **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "user-1",
            "aud": ISSUER,
            "client_id": "app_1",
            "exp": int(time.time()) + 600,
            "access_keys": [{"account": ALICE, "chain_id": 4217}, {"account": BOB, "chain_id": 1}],
            "tempo_accounts": [ALICE.upper().replace("0X", "0x")],
            "compliance": {ALICE: "clear"},
        }
        if dpop is not None:
            claims["cnf"] = {"jkt": dpop.thumbprint}
        claims.update(overrides)
        return self.sign({k: v for k, v in claims.items() if v is not None})

    def id_token(self, **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "user-1",
            "aud": "app_1",
            "exp": int(time.time()) + 600,
            "email": "Alice@Example.com",
            "email_verified": True,
        }
        claims.update(overrides)
        return self.sign({k: v for k, v in claims.items() if v is not None}, typ="JWT")


@pytest.fixture
def issuer() -> Issuer:
    return Issuer()


def tempo_id(issuer: Issuer, **options: Any) -> TempoId:
    return create(client_id="app_1", http=issuer.http(), **options)


def bearer(token: str, **headers: str) -> Request:
    return http_request(f"Bearer {token}", url=API, headers=headers)


def dpop_request(
    token: str, key: DpopKey, *, method: str = "GET", url: str = API, **kw: Any
) -> Request:
    proof = kw.pop("proof", None) or key.proof(token, method, url)
    return http_request(f"DPoP {token}", method=method, url=url, headers={"DPoP": proof})


def reason(outcome: Any) -> tuple[str, str]:
    assert isinstance(outcome, Rejected), outcome
    return (outcome.status, outcome.reason)


# --- Access tokens ------------------------------------------------------------------------------

TOKEN_CASES: list[tuple[str, Callable[[Issuer], Request], tuple[str, str]]] = [
    ("no token", lambda i: http_request(url=API), ("missing", "Sign in with Tempo ID.")),
    ("basic", lambda i: http_request("Basic abc", url=API), ("missing", "Sign in with Tempo ID.")),
    (
        "not a jws",
        lambda i: bearer("abc"),
        ("invalid", "The token is not a Tempo ID access token."),
    ),
    (
        "wrong typ",
        lambda i: bearer(i.sign({"iss": ISSUER}, typ="JWT")),
        ("invalid", "The token is not a Tempo ID access token."),
    ),
    (
        "wrong alg",
        lambda i: bearer(i.sign({"iss": ISSUER}, alg="HS256")),
        ("invalid", "The access token signature is invalid."),
    ),
    (
        "unknown kid",
        lambda i: bearer(i.sign({"iss": ISSUER}, kid="other")),
        ("invalid", "The access token signature is invalid."),
    ),
    (
        "tampered",
        lambda i: bearer(i.access_token()[:-4] + "AAAA"),
        ("invalid", "The access token signature is invalid."),
    ),
    (
        "other issuer",
        lambda i: bearer(i.access_token(iss="https://evil.example")),
        ("invalid", "The access token is not from Tempo ID."),
    ),
    (
        "no subject",
        lambda i: bearer(i.access_token(sub=None)),
        ("invalid", "The access token is not from Tempo ID."),
    ),
    (
        "other audience",
        lambda i: bearer(i.access_token(aud="https://other.example")),
        ("invalid", "The access token is for another API."),
    ),
    (
        "extra audience",
        lambda i: bearer(i.access_token(aud=[ISSUER, "https://other.example"])),
        ("invalid", "The access token is for another API."),
    ),
    (
        "expired",
        lambda i: bearer(i.access_token(exp=int(time.time()) - 61)),
        ("invalid", "The access token has expired."),
    ),
    (
        "no expiry",
        lambda i: bearer(i.access_token(exp=None)),
        ("invalid", "The access token has expired."),
    ),
    (
        "other app",
        lambda i: bearer(i.access_token(client_id="app_2")),
        ("forbidden", "This app may not call this API."),
    ),
    (
        "bearer for a bound token",
        lambda i: bearer(i.access_token(DpopKey.generate())),
        ("invalid", "The access token scheme does not match its binding."),
    ),
    (
        "dpop for an unbound token",
        lambda i: http_request(f"DPoP {i.access_token()}", url=API),
        ("invalid", "The access token scheme does not match its binding."),
    ),
]


@pytest.mark.parametrize(
    ("case", "build", "expected"), TOKEN_CASES, ids=[c[0] for c in TOKEN_CASES]
)
async def test_access_token_rejections(
    issuer: Issuer, case: str, build: Callable[[Issuer], Request], expected: tuple[str, str]
) -> None:
    outcome = await tempo_id(issuer).verifier.verify(build(issuer))
    assert reason(outcome) == expected
    assert isinstance(outcome, Rejected)
    if expected[0] in ("missing", "invalid"):
        assert outcome.headers == (("WWW-Authenticate", 'DPoP algs="ES256", Bearer'),)


@pytest.mark.parametrize(
    "overrides",
    [
        lambda: {},
        lambda: {"aud": [ISSUER, f"{ISSUER}/oauth2/userinfo"]},
        lambda: {"exp": int(time.time()) - 30},  # within clock tolerance
    ],
    ids=["plain", "several audiences", "just expired"],
)
async def test_a_valid_bearer_token_names_the_caller(
    issuer: Issuer, overrides: Callable[[], dict[str, Any]]
) -> None:
    # Built when the test runs: a time taken at collection would be stale by then.
    token = issuer.access_token(**overrides())
    outcome = await tempo_id(issuer).verifier.verify(bearer(token))
    assert isinstance(outcome, Valid)
    caller = outcome.value
    assert (caller.user_id, caller.client_id, caller.accounts) == (
        "user-1",
        "app_1",
        (ALICE_CHECKSUM,),
    )
    assert dict(caller.compliance) == {ALICE_CHECKSUM: "clear"}
    assert (caller.email, caller.email_verified) == (None, None)


async def test_accounts_come_from_the_configured_chain(issuer: Issuer) -> None:
    outcome = await tempo_id(issuer, chain_id=1).verifier.verify(
        bearer(issuer.access_token(tempo_accounts=[]))
    )
    assert isinstance(outcome, Valid) and outcome.value.accounts == (BOB_CHECKSUM,)


async def test_several_apps_and_a_custom_audience(issuer: Issuer) -> None:
    verifier = create(
        client_id=["app_1", "app_2"], audience="https://api.example", http=issuer.http()
    ).verifier
    token = issuer.access_token(client_id="app_2", aud="https://api.example")
    assert isinstance(await verifier.verify(bearer(token)), Valid)


async def test_unavailable_keys_are_a_503(issuer: Issuer) -> None:
    issuer.status = 500
    outcome = await tempo_id(issuer).verifier.verify(bearer(issuer.access_token()))
    assert reason(outcome) == ("unavailable", "Tempo ID's signing keys are unavailable.")
    assert isinstance(outcome, Rejected) and outcome.code == 503


# --- DPoP ---------------------------------------------------------------------------------------


async def test_a_dpop_bound_token_with_its_proof_is_valid_once(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    verifier = tempo_id(issuer, store=MemoryStore()).verifier
    request = dpop_request(token, key)
    assert isinstance(await verifier.verify(request), Valid)
    replay = http_request(f"DPoP {token}", url=API, headers={"DPoP": request.headers["DPoP"]})
    assert reason(await verifier.verify(replay)) == ("invalid", "The DPoP proof was already used.")


async def test_without_a_store_a_proof_can_be_replayed(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    verifier = tempo_id(issuer).verifier
    proof = key.proof(token, "GET", API)
    for _ in range(2):
        assert isinstance(await verifier.verify(dpop_request(token, key, proof=proof)), Valid)


def _proof(key: DpopKey, token: str, **claims: Any) -> str:
    header = jwt.encode({"alg": "ES256", "jwk": key.jwk, "typ": "dpop+jwt"})
    body = {
        "ath": jwt.sha256(token),
        "htm": "GET",
        "htu": API,
        "iat": int(time.time()),
        "jti": "j1",
    }
    body.update(claims)
    signing_input = f"{header}.{jwt.encode({k: v for k, v in body.items() if v is not None})}"
    return f"{signing_input}.{jwt.sign_es256(key.private_key, signing_input.encode())}"


PROOF_CASES: list[tuple[str, Callable[[DpopKey, str], str], str]] = [
    ("malformed", lambda k, t: "not-a-proof", "The DPoP proof is malformed."),
    (
        "other key",
        lambda k, t: _proof(DpopKey.generate(), t),
        "The DPoP proof key does not bind the token.",
    ),
    (
        "bad signature",
        lambda k, t: _proof(k, t)[:-4] + "AAAA",
        "The DPoP proof signature is invalid.",
    ),
    (
        "other method",
        lambda k, t: _proof(k, t, htm="POST"),
        "The DPoP proof is for another request.",
    ),
    (
        "other url",
        lambda k, t: _proof(k, t, htu="https://api.example/other"),
        "The DPoP proof is for another request.",
    ),
    (
        "other token",
        lambda k, t: _proof(k, t, ath=jwt.sha256("x")),
        "The DPoP proof is for another token.",
    ),
    ("old", lambda k, t: _proof(k, t, iat=int(time.time()) - 361), "The DPoP proof has expired."),
    ("future", lambda k, t: _proof(k, t, iat=int(time.time()) + 61), "The DPoP proof has expired."),
    ("no iat", lambda k, t: _proof(k, t, iat=None), "The DPoP proof has expired."),
    ("no jti", lambda k, t: _proof(k, t, jti=None), "The DPoP proof has no ID."),
]


@pytest.mark.parametrize(
    ("case", "build", "expected"), PROOF_CASES, ids=[c[0] for c in PROOF_CASES]
)
async def test_dpop_proof_rejections(
    issuer: Issuer, case: str, build: Callable[[DpopKey, str], str], expected: str
) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    request = dpop_request(token, key, proof=build(key, token))
    assert reason(await tempo_id(issuer).verifier.verify(request)) == ("invalid", expected)


async def test_a_proof_ignores_the_query_string(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    proof = key.proof(token, "POST", API)
    request = dpop_request(token, key, method="POST", url=f"{API}?page=2", proof=proof)
    assert isinstance(await tempo_id(issuer).verifier.verify(request), Valid)


# --- ID tokens ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, ("alice@example.com", True)),
        ({"email_verified": None}, ("alice@example.com", False)),
        ({"exp": int(time.time()) - 120}, (None, None)),
        ({"email": None}, (None, None)),
    ],
)
async def test_the_id_token_adds_the_email(
    issuer: Issuer, overrides: dict[str, Any], expected: tuple[Any, Any]
) -> None:
    request = bearer(issuer.access_token(), **{"Tempo-Id-Token": issuer.id_token(**overrides)})
    outcome = await tempo_id(issuer).verifier.verify(request)
    assert isinstance(outcome, Valid)
    assert (outcome.value.email, outcome.value.email_verified) == expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (lambda i: "garbage", "The ID token is malformed."),
        (lambda i: i.id_token()[:-4] + "AAAA", "The ID token signature is invalid."),
        (lambda i: i.id_token(sub="user-2"), "The ID token is for another user or app."),
        (lambda i: i.id_token(aud="app_2"), "The ID token is for another user or app."),
        (
            lambda i: i.id_token(iss="https://evil.example"),
            "The ID token is for another user or app.",
        ),
    ],
)
async def test_a_bad_id_token_rejects(
    issuer: Issuer, token: Callable[[Issuer], str], expected: str
) -> None:
    request = bearer(issuer.access_token(), **{"Tempo-Id-Token": token(issuer)})
    assert reason(await tempo_id(issuer).verifier.verify(request)) == ("invalid", expected)


async def test_allow_decides_by_the_verified_user(issuer: Issuer) -> None:
    seen: list[Any] = []

    async def allow(user: tempo.Caller) -> bool:
        seen.append(user)
        return user.email_verified is True and (user.email or "").endswith("@example.com")

    verifier = tempo_id(issuer, allow=allow).verifier
    allowed = bearer(issuer.access_token(), **{"Tempo-Id-Token": issuer.id_token()})
    assert isinstance(await verifier.verify(allowed), Valid)
    refused = bearer(issuer.access_token())
    assert reason(await verifier.verify(refused)) == (
        "forbidden",
        "This user may not call this API.",
    )
    assert [user.email for user in seen] == ["alice@example.com", None]


# --- Payment check ------------------------------------------------------------------------------


def payment(
    request: Request, *, method: str = "tempo.charge", source: str | None
) -> PaymentCheckInput:
    """A paid retry's check input; ``method`` is ``<method>.<intent>``."""
    name, _, intent = method.partition(".")
    challenge = Challenge(id="c1", realm="api.example", method=name, intent=intent, request={})
    credential = Credential(challenge=challenge.to_echo(), payload={}, source=source)
    return PaymentCheckInput(request=request, challenge=challenge, credential=credential)


@pytest.mark.parametrize(
    ("method", "source", "compliance", "expected"),
    [
        ("tempo.charge", f"did:pkh:eip155:4217:{ALICE}", {ALICE: "clear"}, None),
        ("tempo.charge", f"did:pkh:eip155:4217:{ALICE_CHECKSUM}", {}, None),
        (
            "stripe.charge",
            f"did:pkh:eip155:4217:{ALICE}",
            {},
            ("forbidden", "Pay with a tempo charge."),
        ),
        (
            "tempo.session",
            f"did:pkh:eip155:4217:{ALICE}",
            {ALICE: "clear"},
            ("forbidden", "Pay with a tempo charge."),
        ),
        (
            "tempo.charge",
            None,
            {},
            ("invalid", "The payment must name its source account on chain 4217."),
        ),
        (
            "tempo.charge",
            f"did:pkh:eip155:1:{ALICE}",
            {},
            ("invalid", "The payment must name its source account on chain 4217."),
        ),
        (
            "tempo.charge",
            f"did:pkh:eip155:4217:{BOB}",
            {},
            ("forbidden", "The paying account is not one this user granted to the app."),
        ),
        (
            "tempo.charge",
            f"did:pkh:eip155:4217:{ALICE}",
            {ALICE: "blocked"},
            ("forbidden", "The paying account is not cleared to pay."),
        ),
    ],
)
async def test_the_payment_check_requires_one_of_the_users_accounts(
    issuer: Issuer, method: str, source: str | None, compliance: dict[str, str], expected: Any
) -> None:
    check = tempo_id(issuer).payment_check
    request = bearer(issuer.access_token(compliance=compliance))
    outcome = await check.verify(payment(request, method=method, source=source))
    if expected is None:
        assert isinstance(outcome, Valid) and isinstance(outcome.value, tempo.Payer)
        assert outcome.value.account == ALICE_CHECKSUM
        assert outcome.value.user_id == "user-1"
    else:
        assert reason(outcome) == expected


async def test_the_payment_check_advertises_tempo_id(issuer: Issuer) -> None:
    check = tempo_id(issuer).payment_check
    assert [(r.type, r.issuer) for r in check.requires] == [("tempo-id", ISSUER)]


async def test_one_verification_per_request_spends_the_proof_once(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    tempo_ids = tempo_id(issuer, store=MemoryStore())
    request = dpop_request(token, key)
    assert isinstance(await tempo_ids.verifier.verify(request), Valid)
    outcome = await tempo_ids.payment_check.verify(
        payment(request, source=f"did:pkh:eip155:4217:{ALICE}")
    )
    assert isinstance(outcome, Valid)


async def test_allow_sees_the_payer_on_the_paid_retry(issuer: Issuer) -> None:
    seen: list[Any] = []
    check = tempo_id(issuer, allow=lambda user: seen.append(user) or True).payment_check
    await check.verify(
        payment(bearer(issuer.access_token()), source=f"did:pkh:eip155:4217:{ALICE}")
    )
    assert [type(user).__name__ for user in seen] == ["Payer"]


def test_create_needs_an_app() -> None:
    with pytest.raises(ValueError, match="at least one app"):
        create(client_id=[])


# --- Key set ------------------------------------------------------------------------------------


async def test_keys_are_cached_and_unknown_ids_refetch_at_most_every_30_seconds(
    issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    keys = jwt.KeySet(ISSUER, issuer.http())
    assert await keys.get("key-1") is not None
    assert await keys.get("key-1") is not None
    assert issuer.fetches == 1
    assert await keys.get("unknown") is None
    assert issuer.fetches == 1, "within 30 seconds the last set serves"
    now[0] += 31
    assert await keys.get("unknown") is None
    assert issuer.fetches == 2
    now[0] += 301
    issuer.status = 500
    assert await keys.get("key-1") is not None, "a failed refetch keeps the last set"


async def test_a_key_set_that_never_loaded_raises(issuer: Issuer) -> None:
    issuer.status = 500
    with pytest.raises(RuntimeError, match="500"):
        await jwt.KeySet(ISSUER, issuer.http()).get("key-1")


# --- Prover -------------------------------------------------------------------------------------


@pytest.mark.parametrize("bound", [False, True])
async def test_the_prover_sends_a_token_the_server_accepts(issuer: Issuer, bound: bool) -> None:
    key = DpopKey.generate() if bound else None
    token = issuer.access_token(key)

    async def access_token() -> str:
        return token

    tempo_prover = prover(
        access_token=access_token, scope=["https://api.example"], dpop=key, id_token=issuer.id_token
    )
    assert tempo_prover.headers == ("dpop", "tempo-id-token")
    proved = await tempo_prover.prove(httpx.Request("POST", API), ProveContext.new())
    assert proved.headers["Authorization"] == f"{'DPoP' if bound else 'Bearer'} {token}"
    assert ("dpop" in proved.headers) is bound
    request = Request("POST", API, headers=list(proved.headers.multi_items()))
    outcome = await tempo_id(issuer, store=MemoryStore()).verifier.verify(request)
    assert isinstance(outcome, Valid) and outcome.value.email == "alice@example.com"


def test_dpop_keys_must_be_p256() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    with pytest.raises(ValueError, match="P-256"):
        DpopKey(ec.generate_private_key(ec.SECP384R1()))


# --- Full flow ----------------------------------------------------------------------------------


async def test_a_tempo_id_user_pays_with_their_own_account(issuer: Issuer) -> None:
    from mpp.client import Mpp
    from mpp.server import Mpp as Server
    from mpp.server import VerifyContext
    from tests import server_method
    from tests.test_identity_client import ServerTransport, paying_method

    async def settle(context: VerifyContext) -> Receipt:
        # Like a tempo charge, report the account that paid.
        paid_by = (context.credential.source or "").rsplit(":", 1)[-1]
        return dataclasses.replace(Receipt.success("tx"), payer=paid_by)

    tempo_ids = tempo_id(issuer, store=MemoryStore())
    server = Server(
        methods=server_method(request={"amount": "1"}, verify=settle),
        realm="api.example",
        secret_key="secret",
        requires_auth=True,
    )
    handler = server.charge(identity=Route(payment=tempo_ids.payment_check))
    key = DpopKey.generate()
    token = issuer.access_token(key)
    tempo_prover = prover(access_token=lambda: token, scope=["https://api.example"], dpop=key)

    for source, status in [
        (f"did:pkh:eip155:4217:{ALICE}", 200),
        (f"did:pkh:eip155:4217:{BOB}", 403),
    ]:
        transport = ServerTransport(handler)
        client = Mpp(methods=[paying_method(source)], identity=[tempo_prover])
        client.payment_transport._inner = transport
        async with client:
            response = await client.fetch(API)
        assert response.status_code == status
        unpaid, paid = transport.requests
        assert paid.headers["DPoP"] != unpaid.headers["DPoP"], "a new proof per request"


# --- Cross-SDK vectors --------------------------------------------------------------------------
# tests/fixtures/identity/tempo_id_vectors.json holds requests proved by mppx's prover and mppx's
# server verdict on each; tests/fixtures/identity/generate_tempo_id_vectors.mjs regenerates it.

VECTORS: dict[str, Any] = __import__("json").loads(
    (
        __import__("pathlib").Path(__file__).parent
        / "fixtures"
        / "identity"
        / "tempo_id_vectors.json"
    ).read_text()
)


def _wire(value: tempo.Caller) -> dict[str, Any]:
    """A Caller or Payer in mppx's shape."""
    wire: dict[str, Any] = {
        "accounts": list(value.accounts),
        "clientId": value.client_id,
        "compliance": dict(value.compliance),
        "userId": value.user_id,
    }
    if value.email is not None:
        wire |= {"email": value.email, "emailVerified": value.email_verified}
    if isinstance(value, tempo.Payer) and value.account is not None:
        wire["account"] = value.account
    return wire


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
async def test_mppx_proofs_get_the_same_verdict(
    vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(time, "time", lambda: VECTORS["generated"] + 1.0)
    jwks = VECTORS["jwks"]
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=jwks))
    )
    tempo_ids = create(client_id="app_1", http=http, store=MemoryStore())
    wire = vector["request"]
    request = Request(wire["method"], wire["url"], headers=list(wire["headers"].items()))
    caller = await tempo_ids.verifier.verify(request)
    payer = await tempo_ids.payment_check.verify(payment(request, source=VECTORS["source"]))
    assert isinstance(caller, Valid) and isinstance(payer, Valid)
    assert _wire(caller.value) == vector["caller"]["value"]
    assert _wire(payer.value) == vector["payer"]["value"]


# --- JWS helpers ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "a.b",
        "a.b.c.d",
        "!!!.e30.sig",
        "e30.!!!.sig",
        "W10.e30.c2ln",
        "e30.W10.c2ln",
        "x" * 16_385,
    ],
)
def test_malformed_jws_decodes_to_none(token: str) -> None:
    assert jwt.decode(token) is None


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "RSA", "crv": "P-256", "x": "AA", "y": "AA"},
        {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"},
        {"kty": "EC", "crv": "P-256", "x": "AA"},
        {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
        {**DpopKey.generate().jwk, "d": "private"},
    ],
)
def test_only_public_p256_jwks_are_dpop_keys(jwk: dict[str, Any]) -> None:
    assert jwt.es256_public_key(jwk) is None


def test_an_es256_signature_must_be_64_bytes() -> None:
    key = DpopKey.generate()
    decoded = jwt.decode(key.proof("token", "GET", API))
    assert decoded is not None
    public = jwt.es256_public_key(key.jwk)
    assert public is not None and jwt.verify_es256(public, decoded)
    short = jwt.Decoded(decoded.header, decoded.claims, decoded.signing_input, b"\x00" * 63)
    assert not jwt.verify_es256(public, short)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.example/paid?x=1#f", "https://api.example/paid"),
        ("https://api.example:443/paid", "https://api.example/paid"),
        ("http://localhost:8000", "http://localhost:8000/"),
        ("https://[::1]:8443/a", "https://[::1]:8443/a"),
    ],
)
def test_htu_drops_the_query_fragment_and_default_port(url: str, expected: str) -> None:
    assert jwt.htu(url) == expected


async def test_the_key_set_skips_entries_that_are_not_rsa_keys(issuer: Issuer) -> None:
    good = issuer.jwks()["keys"][0]
    body = {"keys": [good, "nope", {"kty": "EC", "kid": "ec"}, {**good, "kid": "bad", "n": "!!"}]}
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    )
    keys = jwt.KeySet(ISSUER, http)
    assert await keys.get("key-1") is not None
    assert await keys.get("ec") is None and await keys.get("bad") is None


async def test_a_key_set_body_without_keys_is_empty(issuer: Issuer) -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[1])))
    assert await jwt.KeySet(ISSUER, http).get("key-1") is None


def test_the_tempo_module_loads_its_submodules_lazily() -> None:
    assert tempo.server.create is create
    with pytest.raises(AttributeError, match="no attribute"):
        tempo.nothing  # noqa: B018  # pyright: ignore[reportAttributeAccessIssue]


# --- Review fixes -------------------------------------------------------------------------------


def test_deeply_nested_jws_json_decodes_to_none() -> None:
    nested = jwt.b64url_encode(("[" * 5000 + "]" * 5000).encode())
    assert jwt.decode(f"{nested}.e30.c2ln") is None
    assert jwt.decode(f"e30.{nested}.c2ln") is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.example/hello%20world?q=1", "https://api.example/hello%20world"),
        ("https://api.example/files/a%2Fb", "https://api.example/files/a%2Fb"),
        ("https://api.example/files/a/b", "https://api.example/files/a/b"),
    ],
)
def test_htu_keeps_percent_encoding(url: str, expected: str) -> None:
    assert jwt.htu(url) == expected


async def test_a_proof_for_an_encoded_path_verifies(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    url = "https://api.example/files/a%2Fb"
    request = dpop_request(token, key, url=url)
    assert isinstance(await tempo_id(issuer).verifier.verify(request), Valid)
    other = dpop_request(
        token, key, url="https://api.example/files/a/b", proof=key.proof(token, "GET", url)
    )
    assert reason(await tempo_id(issuer).verifier.verify(other)) == (
        "invalid",
        "The DPoP proof is for another request.",
    )


def test_the_key_set_loads_on_trio(issuer: Issuer) -> None:
    import trio

    async def main() -> tuple[object, object]:
        keys = jwt.KeySet(ISSUER, issuer.http())
        async with trio.open_nursery() as nursery:
            results: list[object] = []

            async def get() -> None:
                results.append(await keys.get("key-1"))

            for _ in range(5):
                nursery.start_soon(get)
        return results[0], results[-1]

    first, last = trio.run(main)
    assert first is not None and last is not None
    assert issuer.fetches == 1, "concurrent callers share one fetch"


def test_htu_uses_the_encoded_host() -> None:
    assert jwt.htu("https://b\u00fccher.example/a") == "https://xn--bcher-kva.example/a"


class StringStore(MemoryStore):
    """A store that, like Redis and Postgres, only takes string values."""

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        if not isinstance(value, str):
            raise TypeError(f"expected str, got {type(value).__name__}")
        return await super().put_if_absent_until(key, value, expires_at)


async def test_dpop_replay_claims_work_with_string_stores(issuer: Issuer) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    verifier = tempo_id(issuer, store=StringStore()).verifier
    request = dpop_request(token, key)
    assert isinstance(await verifier.verify(request), Valid)
    replay = dpop_request(token, key, proof=request.headers["DPoP"])
    assert reason(await verifier.verify(replay)) == ("invalid", "The DPoP proof was already used.")


async def test_a_used_proof_stays_claimed_for_as_long_as_it_is_accepted(
    issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = DpopKey.generate()
    token = issuer.access_token(key)
    verifier = tempo_id(issuer, store=MemoryStore()).verifier
    request = dpop_request(token, key)
    iat = int(time.time())
    monkeypatch.setattr(time, "time", lambda: iat + 10.0)
    assert isinstance(await verifier.verify(request), Valid)
    # Just before the second in which the proof's age stops being accepted.
    last = iat + tempo.PROOF_MAX_AGE + tempo.CLOCK_TOLERANCE + 0.9
    monkeypatch.setattr(time, "time", lambda: last)
    replay = dpop_request(token, key, proof=request.headers["DPoP"])
    assert reason(await verifier.verify(replay)) == ("invalid", "The DPoP proof was already used.")


def test_tempo_ids_payment_check_reads_authorization_and_names_the_payer(issuer: Issuer) -> None:
    check = tempo_id(issuer).payment_check
    assert check.authorization
    assert check.payer is not None
    payer = tempo.Payer(user_id="u", client_id="c", account=ALICE_CHECKSUM)
    assert check.payer(payer) == ALICE_CHECKSUM
