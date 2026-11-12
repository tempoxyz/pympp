"""Identity provers on the client: proving, preparing, retrying, and the full paid flow."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import Mpp
from mpp.client._identity import IdentityClient, is_paid
from mpp.identity import (
    PaymentCheck,
    PaymentCheckInput,
    PrepareContext,
    ProveContext,
    Prover,
    Rejected,
    Requirement,
    RetryContext,
    Route,
    Valid,
    Verification,
    from_fn,
    with_headers,
)
from mpp.methods import Method
from mpp.runtime import ClientMethod, CredentialParams
from mpp.server import Mpp as Server
from mpp.server import PaymentRequired, Request, Response, VerifyContext
from tests import server_method

API = "https://api.example"


class Script:
    """A send function answering with scripted responses and recording what it sent."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.sent: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request)
        response = self.responses.pop(0)
        response.request = request
        return response


def header_prover(
    name: str,
    value: Callable[[ProveContext], str] = lambda context: context.nonce,
    *,
    scope: Sequence[str] | str = (API,),
    retry: Callable[[httpx.Response, RetryContext], Mapping[str, str] | None] | None = None,
    log: list[Any] | None = None,
) -> Prover:
    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        if log is not None:
            log.append((name, context))
        return with_headers(request, {name: value(context)})

    async def retry_hook(
        response: httpx.Response, context: RetryContext
    ) -> Mapping[str, str] | None:
        assert retry is not None
        return retry(response, context)

    return Prover(
        scope="*" if scope == "*" else tuple(scope),
        prove=prove,
        headers=(name,),
        retry=retry_hook if retry else None,
    )


def challenge(**overrides: Any) -> Challenge:
    return Challenge(
        id="challenge-1",
        realm="api.example",
        method="tempo",
        intent="charge",
        request={},
        **overrides,
    )


# --- Proving ------------------------------------------------------------------------------------


async def test_in_scope_provers_prove_a_copy_in_order() -> None:
    log: list[Any] = []
    client = IdentityClient(
        [
            header_prover("X-First", log=log),
            header_prover("X-Elsewhere", scope=("https://other.example",), log=log),
            header_prover("X-Second", lambda context: str(context.created), log=log),
        ]
    )
    send = Script(httpx.Response(200))
    original = httpx.Request("GET", f"{API}/x")
    response, carried = await client.send(send, original)
    assert response.status_code == 200 and carried == ()
    [sent] = send.sent
    assert [name for name, _ in log] == ["X-First", "X-Second"]
    assert log[0][1] is log[1][1], "provers on one attempt share one context"
    assert sent.headers["X-First"] == log[0][1].nonce
    assert "x-first" not in original.headers, "the caller's request is never changed"


async def test_requests_out_of_scope_are_sent_unchanged() -> None:
    client = IdentityClient([header_prover("X-Proof")])
    send = Script(httpx.Response(200))
    original = httpx.Request("GET", "https://other.example/x")
    await client.send(send, original)
    assert send.sent == [original]


async def test_a_paid_attempt_gets_the_challenge_in_its_context() -> None:
    log: list[Any] = []
    client = IdentityClient([header_prover("X-Proof", log=log)])
    await client.send(Script(httpx.Response(200)), httpx.Request("GET", API), challenge=challenge())
    assert log[0][1].challenge == challenge()


def test_client_identity_validates_provers() -> None:
    with pytest.raises(ValueError, match="at least one"):
        IdentityClient([])
    with pytest.raises(TypeError, match="Prover"):
        IdentityClient(["nope"])  # pyright: ignore[reportArgumentType]


async def test_prove_must_return_a_request() -> None:
    async def wrong(request: httpx.Request, context: ProveContext) -> Any:
        return None

    client = IdentityClient([Prover(scope="*", prove=wrong)])
    with pytest.raises(TypeError, match="httpx.Request"):
        await client.send(Script(httpx.Response(200)), httpx.Request("GET", API))


@pytest.mark.parametrize(
    ("headers", "paid"),
    [
        ({}, False),
        ({"Authorization": "Bearer token"}, False),
        ({"Authorization": "Payment eyJ"}, True),
        ({"Payment-Authorization": "Payment eyJ"}, True),
        ({"Authorization": "Bearer a, Payment eyJ"}, True),
        ({"Payment-Signature": "abc"}, True),
        ({"X-Payment": "abc"}, True),
    ],
)
def test_a_request_carrying_a_credential_is_paid(headers: dict[str, str], paid: bool) -> None:
    assert is_paid(httpx.Request("GET", API, headers=headers)) is paid


# --- Retrying -----------------------------------------------------------------------------------


def resend_with(headers: Mapping[str, str]) -> Callable[[httpx.Response, RetryContext], Any]:
    return lambda response, context: headers if response.status_code == 401 else None


@pytest.mark.parametrize(
    ("status", "paid", "resent"),
    [
        (401, False, True),
        (403, False, True),
        (503, False, True),
        (402, False, False),
        (200, False, False),
        (401, True, False),
    ],
)
async def test_only_an_unpaid_rejection_is_resent(status: int, paid: bool, resent: bool) -> None:
    calls: list[int] = []

    def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        calls.append(response.status_code)
        return {"X-Fresh": "1"}

    client = IdentityClient([header_prover("X-Proof", retry=retry)])
    send = Script(httpx.Response(status), httpx.Response(200))
    await client.send(send, httpx.Request("GET", API), challenge=challenge() if paid else None)
    assert len(send.sent) == (2 if resent else 1)
    assert bool(calls) is resent


async def test_a_resend_is_proved_again_with_the_retry_headers_once() -> None:
    log: list[Any] = []
    client = IdentityClient(
        [header_prover("X-Proof", retry=resend_with({"X-Fresh": "1"}), log=log)]
    )
    send = Script(httpx.Response(401), httpx.Response(401))
    response, carried = await client.send(send, httpx.Request("GET", API))
    assert response.status_code == 401
    assert len(send.sent) == 2, "resent at most once"
    assert send.sent[1].headers["X-Fresh"] == "1"
    assert log[0][1].nonce != log[1][1].nonce, "every attempt gets a new context"
    assert carried == (("X-Fresh", "1"),)


async def test_retry_sees_the_request_as_proved() -> None:
    seen: list[str] = []

    def retry(response: httpx.Response, context: RetryContext) -> None:
        seen.append(context.request.headers["X-Proof"])

    client = IdentityClient([header_prover("X-Proof", lambda _: "proof", retry=retry)])
    await client.send(Script(httpx.Response(401)), httpx.Request("GET", API))
    assert seen == ["proof"]


async def test_retry_headers_never_touch_payment_credentials() -> None:
    client = IdentityClient(
        [
            header_prover(
                "X-Proof",
                retry=resend_with({"Authorization": "x", "Payment-Signature": "x", "X-Fresh": "a"}),
            ),
            header_prover("X-Other", retry=resend_with({"x-fresh": "b"})),
        ]
    )
    send = Script(httpx.Response(401), httpx.Response(200))
    _, carried = await client.send(send, httpx.Request("GET", API))
    assert carried == (("X-Fresh", "a, b"),)
    assert "authorization" not in send.sent[1].headers


async def test_carried_headers_reach_the_paid_attempt_but_never_replace_its_credential() -> None:
    client = IdentityClient([header_prover("X-Proof")])
    send = Script(httpx.Response(200))
    paid = httpx.Request("GET", API, headers={"Payment-Authorization": "Payment eyJ"})
    await client.send(
        send,
        paid,
        challenge=challenge(header="Payment-Authorization"),
        carried=(("X-Fresh", "1"), ("Payment-Authorization", "evil"), ("Authorization", "evil")),
    )
    [sent] = send.sent
    assert sent.headers["X-Fresh"] == "1"
    assert sent.headers["Payment-Authorization"] == "Payment eyJ"
    assert "authorization" not in sent.headers


async def test_a_streaming_body_is_not_resent() -> None:
    client = IdentityClient([header_prover("X-Proof", retry=resend_with({"X-Fresh": "1"}))])
    send = Script(httpx.Response(401))
    await client.send(send, httpx.Request("GET", API), replayable=False)
    assert len(send.sent) == 1


# --- Preparing ----------------------------------------------------------------------------------


async def test_prepare_gets_the_challenge_and_the_parsed_requirements() -> None:
    prepared: list[PrepareContext] = []

    async def prepare(response: httpx.Response, context: PrepareContext) -> None:
        prepared.append(context)

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return request

    client = IdentityClient([Prover(scope=(API,), prove=prove, prepare=prepare)])
    response = httpx.Response(
        402, headers={"Identity-Required": 'kyc;issuer="https://kyc.example", email'}
    )
    await client.prepare(response, challenge(), httpx.URL(f"{API}/x"))
    await client.prepare(response, challenge(), httpx.URL("https://other.example/x"))
    assert prepared == [
        PrepareContext(
            challenge=challenge(),
            requirements=(Requirement("kyc", "https://kyc.example"), Requirement("email")),
        )
    ]


# --- The full flow ----------------------------------------------------------------------------


class ServerTransport(httpx.AsyncBaseTransport):
    """Serves requests from a route handler, recording what reached the server."""

    def __init__(self, handler: Any, redirect_to: str | None = None) -> None:
        self.handler = handler
        self.redirect_to = redirect_to
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        await request.aread()
        if self.redirect_to and request.url.host == "api.example":
            return httpx.Response(302, headers={"Location": self.redirect_to})
        result = await self.handler(
            Request(
                request.method,
                str(request.url),
                headers=list(request.headers.multi_items()),
                body=request.content or None,
            )
        )
        response = (
            result.challenge
            if isinstance(result, PaymentRequired)
            else result.with_receipt(Response(200, body="paid"))
        )
        return httpx.Response(response.status, headers=response.headers, content=response.body)


def paying_method(source: str | None = None) -> ClientMethod:
    async def create(params: CredentialParams) -> str:
        echo = params.challenge.to_echo()
        return Credential(challenge=echo, payload={}, source=source).to_authorization()

    return ClientMethod(
        method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
        create_credential=create,
    )


def key_server(check: PaymentCheck[Any] | None = None) -> Any:
    async def lookup(request: Request) -> str | None:
        return request.headers.get("X-Api-Key")

    async def settle(context: VerifyContext) -> Any:
        from mpp import Receipt

        return Receipt.success("tx")

    method = server_method(request={"amount": "1"}, verify=settle)
    server = Server(methods=method, realm="api.example", secret_key="secret")
    return server.charge(identity=Route(request=(from_fn(lookup),), payment=check))


async def test_a_client_with_a_prover_pays_a_route_that_requires_identity() -> None:
    nonces: list[str] = []

    async def check(input: PaymentCheckInput) -> Verification[str]:
        nonces.append(input.request.headers["X-Nonce"])
        return Valid("ok")

    payment_check = PaymentCheck(requires=(Requirement("kyc"),), verify=check)
    transport = ServerTransport(key_server(payment_check))
    prover = header_prover("X-Api-Key", lambda _: "alice")
    nonce = header_prover(
        "X-Nonce", lambda context: context.challenge.id if context.challenge else "-"
    )
    mpp = Mpp(methods=[paying_method()], identity=[prover, nonce])
    mpp.payment_transport._inner = transport
    async with mpp:
        response = await mpp.fetch(f"{API}/paid")
    assert response.status_code == 200
    assert [r.headers["X-Api-Key"] for r in transport.requests] == ["alice", "alice"]
    unpaid, paid = transport.requests
    assert unpaid.headers["X-Nonce"] == "-"
    assert nonces == [paid.headers["X-Nonce"]], "the paid proof binds to the Challenge id"


async def test_without_a_prover_the_rejection_reaches_the_caller() -> None:
    transport = ServerTransport(key_server())
    mpp = Mpp(methods=[paying_method()])
    mpp.payment_transport._inner = transport
    async with mpp:
        response = await mpp.fetch(f"{API}/paid")
    assert response.status_code == 401
    assert len(transport.requests) == 1


async def test_a_rejected_paid_retry_is_final() -> None:
    async def check(input: PaymentCheckInput) -> Verification[str]:
        return Rejected("forbidden", "Not you.")

    retries: list[int] = []

    def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        retries.append(response.status_code)
        return {}

    transport = ServerTransport(key_server(PaymentCheck(requires=(), verify=check)))
    prover = header_prover("X-Api-Key", lambda _: "alice", retry=retry)
    mpp = Mpp(methods=[paying_method()], identity=[prover])
    mpp.payment_transport._inner = transport
    async with mpp:
        response = await mpp.fetch(f"{API}/paid")
    assert response.status_code == 403
    assert len(transport.requests) == 2 and retries == []


async def test_sensitive_identity_headers_never_follow_a_cross_origin_redirect() -> None:
    transport = ServerTransport(key_server(), redirect_to="https://evil.example/steal")
    prover = header_prover("X-Api-Key", lambda _: "alice")
    mpp = Mpp(methods=[paying_method()], identity=[prover])
    mpp.payment_transport._inner = transport
    async with mpp.client(follow_redirects=True) as client:
        await client.get(f"{API}/paid", headers={"Identity-Attestation": "bearer-proof"})
    first, redirected = transport.requests
    assert first.headers["X-Api-Key"] == "alice"
    assert first.headers["Identity-Attestation"] == "bearer-proof"
    assert "x-api-key" not in redirected.headers
    assert "identity-attestation" not in redirected.headers
