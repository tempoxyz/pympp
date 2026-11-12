"""Route identity on the server: verifiers before any 402, payment checks before settlement."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential, Receipt
from mpp.identity import (
    IDENTITY_REQUIRED_HEADER,
    PaymentCheck,
    PaymentCheckInput,
    Rejected,
    Rejection,
    Requirement,
    Results,
    Route,
    Valid,
    Verification,
    Verifier,
    any_of,
    forbidden,
    from_fn,
)
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request, Response, VerifyContext
from tests import challenges, http_request, server_method

REALM = "test.example.com"
SECRET = "test-secret"


class Recorder:
    """Counts calls and settlements across a test."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.settled = 0
        self.failures: list[Any] = []

    def method(self, name: str = "tempo") -> Any:
        async def verify(context: VerifyContext) -> Receipt:
            self.settled += 1
            return Receipt.success(f"{name}-tx")

        return server_method(name=name, request={"amount": "1"}, verify=verify)


def api_key(recorder: Recorder, name: str = "key") -> Verifier[str]:
    """Valid with the X-Api-Key value; missing without one; forbidden for "blocked"."""

    async def lookup(request: Request) -> str | None:
        recorder.calls.append(name)
        key = request.headers.get("X-Api-Key")
        if key == "blocked":
            from mpp.identity import RejectionError

            raise RejectionError("blocked key", status="forbidden")
        return key

    return from_fn(lookup, challenge={"WWW-Authenticate": 'ApiKey realm="test"'})


KYC_OK: Verification[Any] = Valid("kyc-ok")


def kyc(recorder: Recorder, outcome: Verification[Any] = KYC_OK) -> PaymentCheck[Any]:
    async def verify(input: PaymentCheckInput) -> Verification[Any]:
        recorder.calls.append(f"check:{input.challenge.id[:6]}:{input.credential.source}")
        return outcome

    return PaymentCheck(requires=(Requirement("kyc", "https://kyc.example"),), verify=verify)


def server(recorder: Recorder, *methods: Any, requires_auth: bool = False) -> Mpp:
    mpp = Mpp(
        methods=list(methods) or recorder.method(),
        realm=REALM,
        secret_key=SECRET,
        requires_auth=requires_auth,
    )
    mpp.on_payment_failed(recorder.failures.append)
    return mpp


def paid(
    challenge: Challenge, headers: dict[str, str] | None = None, source: str | None = None
) -> Request:
    credential = Credential(challenge=challenge.to_echo(), payload={}, source=source)
    return http_request(credential.to_authorization(), headers=headers)


def rejection(result: Any) -> tuple[int, Rejection | None, str, str | None]:
    assert isinstance(result, PaymentRequired)
    response = result.challenge
    return (
        response.status,
        result.rejection,
        (response.body or b"").decode(),
        response.headers.get("cache-control"),
    )


# --- Request verifiers ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "status", "reason"),
    [
        ({}, 401, "Identity verification is required."),
        ({"X-Api-Key": "blocked"}, 403, "blocked key"),
    ],
)
async def test_a_rejected_identity_gets_its_fixed_status_and_no_challenge(
    headers: dict[str, str], status: int, reason: str
) -> None:
    recorder = Recorder()
    handler = server(recorder).charge(identity=[api_key(recorder)])
    result = await handler(http_request(headers=headers))
    code, rejected, body, cache = rejection(result)
    assert (code, body, cache) == (status, reason, "no-store")
    assert rejected == Rejection(
        stage="request", status="missing" if status == 401 else "forbidden", reason=reason
    )
    assert result.challenge.headers.get("www-authenticate") == 'ApiKey realm="test"'
    assert recorder.settled == 0


async def test_a_verified_identity_gets_the_402_then_its_value_on_the_paid_retry() -> None:
    recorder = Recorder()
    verifier = api_key(recorder)
    handler = server(recorder).charge(identity=[verifier])
    [issued] = challenges(await handler(http_request(headers={"X-Api-Key": "alice"})))
    result = await handler(paid(issued, {"X-Api-Key": "alice"}))
    assert isinstance(result, PaymentVerified)
    assert result.identity.get(verifier) == "alice"
    assert recorder.settled == 1


async def test_a_paid_retry_without_the_identity_is_rejected_before_settlement() -> None:
    recorder = Recorder()
    handler = server(recorder).charge(identity=[api_key(recorder)])
    [issued] = challenges(await handler(http_request(headers={"X-Api-Key": "alice"})))
    code, rejected, _, _ = rejection(await handler(paid(issued)))
    assert code == 401 and rejected is not None and rejected.stage == "request"
    assert recorder.settled == 0


async def test_routes_without_identity_are_unchanged() -> None:
    recorder = Recorder()
    handler = server(recorder).charge()
    result = await handler(http_request())
    assert isinstance(result, PaymentRequired) and result.rejection is None
    assert IDENTITY_REQUIRED_HEADER not in result.challenge.headers
    verified = await handler(paid(challenges(result)[0]))
    assert isinstance(verified, PaymentVerified) and verified.identity == Results()


# --- Payment checks -------------------------------------------------------------------------------


async def test_every_402_lists_what_the_payment_check_requires() -> None:
    recorder = Recorder()
    handler = server(recorder).charge(identity=Route(payment=kyc(recorder)))
    result = await handler(http_request())
    assert isinstance(result, PaymentRequired)
    assert result.challenge.headers[IDENTITY_REQUIRED_HEADER] == 'kyc;issuer="https://kyc.example"'
    assert recorder.calls == []


async def test_a_passing_payment_check_settles_and_exposes_its_value() -> None:
    recorder = Recorder()
    check = kyc(recorder)
    handler = server(recorder).charge(identity=Route(payment=check))
    [issued] = challenges(await handler(http_request()))
    result = await handler(paid(issued, source="did:pkh:eip155:1:0xabc"))
    assert isinstance(result, PaymentVerified)
    assert result.identity.get(check) == "kyc-ok"
    assert recorder.calls == [f"check:{issued.id[:6]}:did:pkh:eip155:1:0xabc"]
    assert recorder.settled == 1


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (forbidden("Not cleared."), 403),
        (Rejected("missing"), 401),
        (Rejected("unavailable"), 503),
    ],
)
async def test_a_failing_payment_check_rejects_without_a_fresh_402(
    outcome: Rejected, status: int
) -> None:
    recorder = Recorder()
    handler = server(recorder).charge(identity=Route(payment=kyc(recorder, outcome)))
    [issued] = challenges(await handler(http_request()))
    result = await handler(paid(issued))
    code, rejected, body, cache = rejection(result)
    assert (code, cache) == (status, "no-store")
    assert rejected == Rejection(stage="payment", status=outcome.status, reason=outcome.reason)
    assert body == outcome.reason
    assert "www-authenticate" not in result.challenge.headers
    assert recorder.settled == 0
    assert [failure["challenge"].id for failure in recorder.failures] == [issued.id]


async def test_request_verifiers_and_payment_check_together() -> None:
    recorder = Recorder()
    verifier, check = api_key(recorder), kyc(recorder)
    handler = server(recorder).charge(identity=Route(request=(verifier,), payment=check))
    code, _, _, _ = rejection(await handler(http_request()))
    assert code == 401
    [issued] = challenges(await handler(http_request(headers={"X-Api-Key": "bob"})))
    result = await handler(paid(issued, {"X-Api-Key": "bob"}))
    assert isinstance(result, PaymentVerified)
    assert (result.identity.get(verifier), result.identity.get(check)) == ("bob", "kyc-ok")


# --- Composition ----------------------------------------------------------------------------------


async def test_composed_offers_share_one_run_of_each_verifier() -> None:
    recorder = Recorder()
    shared = api_key(recorder)
    mpp = server(recorder, recorder.method("a"), recorder.method("b"))
    handler = mpp.compose(
        ("a/charge", {"identity": [shared]}), ("b/charge", {"identity": [shared]})
    )
    assert len(challenges(await handler(http_request(headers={"X-Api-Key": "k"})))) == 2
    assert recorder.calls == ["key"]


async def test_an_offer_whose_identity_rejects_is_not_offered() -> None:
    recorder = Recorder()
    mpp = server(recorder, recorder.method("a"), recorder.method("b"))
    handler = mpp.compose(("a/charge", {"identity": [api_key(recorder)]}), ("b/charge", {}))
    assert [c.method for c in challenges(await handler(http_request()))] == ["b"]
    with_key = challenges(await handler(http_request(headers={"X-Api-Key": "k"})))
    assert [c.method for c in with_key] == ["a", "b"]


async def test_when_every_offer_rejects_the_first_rejection_is_returned() -> None:
    recorder = Recorder()
    mpp = server(recorder, recorder.method("a"), recorder.method("b"))
    blocked = from_fn(_blocked)
    handler = mpp.compose(
        ("a/charge", {"identity": [api_key(recorder)]}), ("b/charge", {"identity": [blocked]})
    )
    code, rejected, _, _ = rejection(await handler(http_request()))
    assert code == 401 and rejected is not None and rejected.status == "missing"


async def _blocked(request: Request) -> str:
    from mpp.identity import RejectionError

    raise RejectionError("nope", status="forbidden")


async def test_identity_required_merges_the_advertised_offers() -> None:
    recorder = Recorder()
    check = kyc(recorder)
    mpp = server(recorder, recorder.method("a"), recorder.method("b"))
    handler = mpp.compose(
        ("a/charge", {"identity": Route(payment=check)}),
        ("b/charge", {"identity": Route(payment=check), "amount": "2"}),
    )
    result = await handler(http_request())
    assert isinstance(result, PaymentRequired)
    assert result.challenge.headers.get_list(IDENTITY_REQUIRED_HEADER) == [
        'kyc;issuer="https://kyc.example"'
    ]


def test_composed_offers_must_share_one_payment_check() -> None:
    recorder = Recorder()
    mpp = server(recorder, recorder.method("a"), recorder.method("b"))
    with pytest.raises(TypeError, match="same identity payment check"):
        mpp.compose(
            ("a/charge", {"identity": Route(payment=kyc(recorder))}),
            ("b/charge", {"identity": Route(payment=kyc(recorder))}),
        )


def test_offers_with_the_same_terms_must_agree_on_the_payment_check() -> None:
    recorder = Recorder()
    mpp = server(recorder)
    with pytest.raises(TypeError, match="same payment terms"):
        mpp.compose(
            ("tempo/charge", {"identity": Route(payment=kyc(recorder))}),
            ("tempo/charge", {}),
        )


# --- Configuration --------------------------------------------------------------------------------


def test_a_verifier_reading_authorization_needs_requires_auth() -> None:
    recorder = Recorder()
    reads = Verifier(verify=api_key(recorder).verify, authorization=True)
    with pytest.raises(TypeError, match="requires_auth=True"):
        server(recorder).charge(identity=[reads])
    server(recorder, requires_auth=True).charge(identity=[reads])


def test_a_payment_check_refuses_methods_with_a_preflight_hook() -> None:
    recorder = Recorder()

    async def preflight(context: Any) -> None:
        return None

    method = server_method(
        request={"amount": "1"}, verify=recorder.method().verify, preflight=preflight
    )
    with pytest.raises(TypeError, match="preflight hook"):
        server(recorder, method).charge(identity=Route(payment=kyc(recorder)))


def test_route_identity_must_be_a_list_or_route() -> None:
    recorder = Recorder()
    with pytest.raises(TypeError, match="wrap a single verifier"):
        server(recorder).charge(identity=api_key(recorder))


async def test_route_identity_requires_http() -> None:
    recorder = Recorder()
    handler = server(recorder).charge(identity=[api_key(recorder)])
    with pytest.raises(TypeError, match="HTTP transport"):
        await handler(Request("POST", "mcp:tools/call/paid"))


async def test_requires_auth_keeps_authorization_for_the_verifier() -> None:
    recorder = Recorder()

    async def bearer(request: Request) -> Verification[str]:
        value = request.headers.get("Authorization", "")
        return Valid(value[7:]) if value.startswith("Bearer ") else Rejected("missing")

    verifier = Verifier(verify=bearer, authorization=True)
    handler = server(recorder, requires_auth=True).charge(identity=[verifier])
    [issued] = challenges(await handler(http_request("Bearer token-1")))
    credential = Credential(challenge=issued.to_echo(), payload={})
    result = await handler(
        http_request("Bearer token-1", payment_authorization=credential.to_authorization())
    )
    assert isinstance(result, PaymentVerified) and result.identity.get(verifier) == "token-1"


# --- Framework integration ------------------------------------------------------------------------


async def test_asgi_middleware_sends_rejections_and_exposes_identity() -> None:
    from mpp.server.asgi import PaymentMiddleware

    recorder = Recorder()
    verifier = api_key(recorder)
    seen: list[Any] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["state"]["mpp_identity"].get(verifier))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    handler = server(recorder).charge(identity=[verifier])
    middleware = PaymentMiddleware(app, handler)
    transport = httpx.ASGITransport(app=middleware)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://test.example.com"
    ) as client:
        assert (await client.get("/resource")).status_code == 401
        unpaid = await client.get("/resource", headers={"X-Api-Key": "carol"})
        issued = Challenge.from_www_authenticate(unpaid.headers["www-authenticate"])
        credential = Credential(challenge=issued.to_echo(), payload={})
        response = await client.get(
            "/resource",
            headers={"X-Api-Key": "carol", "Authorization": credential.to_authorization()},
        )
    assert response.status_code == 200
    assert seen == ["carol"]


async def test_pay_decorator_passes_identity_to_endpoints_that_ask() -> None:
    from mpp.server import pay
    from tests import MockRequest

    recorder = Recorder()
    check = kyc(recorder)
    handler = server(recorder).charge(identity=Route(payment=check))

    @pay(handler)
    async def endpoint(
        request: Any, credential: Credential, receipt: Receipt, identity: Results
    ) -> Response:
        return Response(200, body=str(identity.get(check)))

    unpaid = await endpoint(MockRequest(path="/resource"))
    issued = Challenge.from_www_authenticate(unpaid.headers["WWW-Authenticate"])
    response = await endpoint(
        MockRequest(
            authorization=Credential(challenge=issued.to_echo(), payload={}).to_authorization(),
            path="/resource",
        )
    )
    assert response.body == b"kyc-ok"


async def test_any_of_values_reach_the_route() -> None:
    recorder = Recorder()
    first, second = api_key(recorder, "first"), from_fn(_constant)
    either = any_of(first, second)
    handler = server(recorder).charge(identity=[either])
    [issued] = challenges(await handler(http_request()))
    result = await handler(paid(issued))
    assert isinstance(result, PaymentVerified)
    assert result.identity.get(second) == "constant"
    assert result.identity.get(first) is None


async def _constant(request: Request) -> str:
    return "constant"


# --- x402 -----------------------------------------------------------------------------------------


async def test_a_route_with_a_payment_check_neither_offers_nor_accepts_x402() -> None:
    from tests.test_x402_server import REALM as X402_REALM
    from tests.test_x402_server import evm_method, payment_required, signed, x402_request

    recorder = Recorder()
    mpp = Mpp(methods=evm_method(), realm=X402_REALM, secret_key="k")
    signature = await signed(mpp)
    plain = mpp.charge(amount="0.01")
    checked = mpp.charge(amount="0.01", identity=Route(payment=kyc(recorder)))
    assert payment_required(await plain(x402_request())) is not None
    assert payment_required(await checked(x402_request())) is None
    code, rejected, body, _ = rejection(await checked(x402_request(signature)))
    assert (code, body) == (
        401,
        "This route's identity payment check does not accept x402 credentials.",
    )
    assert rejected is not None and rejected.stage == "payment"
    assert recorder.calls == []
    assert isinstance(await plain(x402_request(signature)), PaymentVerified)


async def test_a_paid_retry_ignores_same_terms_offers_whose_identity_rejects() -> None:
    recorder = Recorder()
    mpp = server(recorder)
    first = api_key(recorder, "first")
    blocked = from_fn(_blocked)
    handler = mpp.compose(
        ("tempo/charge", {"identity": [blocked]}), ("tempo/charge", {"identity": [first]})
    )
    [issued] = challenges(await handler(http_request(headers={"X-Api-Key": "k"})))
    result = await handler(paid(issued, {"X-Api-Key": "k"}))
    assert isinstance(result, PaymentVerified)
    assert result.identity.get(first) == "k"
    assert recorder.settled == 1


@pytest.mark.parametrize(
    ("paid_by", "rejected_with"),
    [
        ("0xABC", None),
        ("0xabc", None),
        (None, "The payment method did not report which account paid."),
        ("0xdef", "The account that paid is not the one the identity check vetted."),
    ],
)
async def test_the_account_that_paid_must_be_the_one_the_check_vetted(
    paid_by: str | None, rejected_with: str | None
) -> None:
    from dataclasses import replace as replace_receipt

    recorder = Recorder()

    async def settle(context: VerifyContext) -> Receipt:
        recorder.settled += 1
        return replace_receipt(Receipt.success("tx"), payer=paid_by)

    async def vet(input: PaymentCheckInput) -> Verification[str]:
        return Valid("0xAbc")

    check = PaymentCheck(requires=(), verify=vet, payer=lambda account: account)
    handler = server(recorder, server_method(request={"amount": "1"}, verify=settle)).charge(
        identity=Route(payment=check)
    )
    [issued] = challenges(await handler(http_request()))
    result = await handler(paid(issued))
    if rejected_with is None:
        assert isinstance(result, PaymentVerified)
    else:
        code, rejected, body, _ = rejection(result)
        assert (code, body) == (403, rejected_with)
        assert rejected is not None and rejected.stage == "payment"


def test_a_payment_check_reading_authorization_needs_requires_auth() -> None:
    recorder = Recorder()

    async def vet(input: PaymentCheckInput) -> Verification[str]:
        return Valid("x")

    reads = Route(payment=PaymentCheck(requires=(), verify=vet, authorization=True))
    with pytest.raises(TypeError, match="requires_auth=True"):
        server(recorder).charge(identity=reads)
    server(recorder, requires_auth=True).charge(identity=reads)


@pytest.mark.parametrize(
    ("validated_payer", "rejected_with"),
    [
        ("0xabc", None),
        (None, "The payment method did not report which account paid."),
        ("0xdef", "The account that paid is not the one the identity check vetted."),
    ],
)
async def test_a_method_that_validates_is_held_to_the_vetted_payer_before_it_broadcasts(
    validated_payer: str | None, rejected_with: str | None
) -> None:
    from mpp.server import ValidateContext, Validation

    recorder = Recorder()

    async def validate(context: ValidateContext) -> Validation:
        return Validation(
            credential=context.credential,
            details={},
            intent="charge",
            request=context.challenge.request,
            payer=validated_payer,
        )

    async def broadcast(context: VerifyContext) -> Receipt:
        recorder.settled += 1
        return Receipt.success("tx")

    async def vet(input: PaymentCheckInput) -> Verification[str]:
        return Valid("0xAbc")

    check = PaymentCheck(requires=(), verify=vet, payer=lambda account: account)
    method = server_method(request={"amount": "1"}, validate=validate, broadcast=broadcast)
    handler = server(recorder, method).charge(identity=Route(payment=check))
    [issued] = challenges(await handler(http_request()))
    result = await handler(paid(issued))
    if rejected_with is None:
        assert isinstance(result, PaymentVerified)
        assert recorder.settled == 1
    else:
        code, rejected, body, _ = rejection(result)
        assert (code, body) == (403, rejected_with)
        assert rejected is not None and rejected.stage == "payment"
        assert recorder.settled == 0, "rejected before any funds move"


@pytest.mark.parametrize("reads_body", [True, False])
async def test_middleware_reads_the_body_for_a_verifier_that_asks(reads_body: bool) -> None:
    from mpp.server.asgi import PaymentMiddleware

    recorder = Recorder()
    bodies: list[bytes | None] = []

    async def digest(request: Request) -> str:
        bodies.append(request.body)
        return "signed"

    verifier = from_fn(digest, body=reads_body)
    either = any_of(verifier, from_fn(_constant))
    received: list[bytes] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        received.append((await receive()).get("body", b""))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    for identity in ([verifier], [either], Route(request=(either,))):
        assert server(recorder).charge(identity=identity).needs_request_body is reads_body
    handler = server(recorder).charge(identity=[verifier])
    transport = httpx.ASGITransport(app=PaymentMiddleware(app, handler))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://test.example.com"
    ) as client:
        response = await client.post("/resource", content=b"payload")
    assert response.status_code == 402
    assert bodies == [b"payload" if reads_body else None]


def test_a_payment_check_that_reads_the_body_makes_the_route_read_it() -> None:
    async def vet(input: PaymentCheckInput) -> Verification[str]:
        return Valid("x")

    reads = Route(payment=PaymentCheck(requires=(), verify=vet, body=True))
    assert server(Recorder()).charge(identity=reads).needs_request_body


def test_identity_requirements_follow_a_retained_challenge_with_an_older_request() -> None:
    from types import SimpleNamespace

    from mpp.server.compose import _Call, _issuers  # pyright: ignore[reportPrivateUsage]

    offer = SimpleNamespace(
        offer=SimpleNamespace(
            method=SimpleNamespace(name="tempo", intent="session"),
            server=SimpleNamespace(realm="api.example"),
        ),
        request={"amount": "2"},
    )
    call = _Call(prepared=[offer])  # pyright: ignore[reportArgumentType]
    retained = Challenge(
        id="c1", realm="api.example", method="tempo", intent="session", request={"amount": "1"}
    )
    assert _issuers(call, [retained]) == []
    assert _issuers(call, [retained], same_request=False) == [offer]
