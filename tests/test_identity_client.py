"""Identity provers on the client: proving, preparing, retrying, and the full paid flow."""

from __future__ import annotations

import asyncio
import gzip
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential, PaymentOutcomeUnknownError
from mpp.client import Mpp
from mpp.client._identity import IdentityClient, _detach, is_paid
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


async def test_a_retry_hook_that_raises_closes_the_rejected_response() -> None:
    def retry(response: httpx.Response, context: RetryContext) -> None:
        raise RuntimeError("boom")

    rejected = httpx.Response(401, stream=httpx.ByteStream(b"no"))
    client = IdentityClient([header_prover("X-Proof", retry=retry)])
    with pytest.raises(RuntimeError, match="boom"):
        await client.send(Script(rejected), httpx.Request("GET", API))
    assert rejected.is_closed


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


# --- Resending a paid attempt after a 401 (mpp-specs §4.4.3) ----------------------------------


def live(id: str = "live", seconds: float = 60) -> Challenge:
    expires = (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return Challenge(
        id=id, realm="api.example", method="tempo", intent="charge", request={}, expires=expires
    )


def credential_for(target: Challenge) -> str:
    return Credential(challenge=target.to_echo(), payload={}).to_authorization()


async def test_a_paid_401_is_resent_once_with_the_same_credential_while_its_challenge_lives() -> (
    None
):
    log: list[Any] = []
    retries: list[int] = []

    def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        retries.append(response.status_code)
        return {"X-Token": "fresh"}

    client = IdentityClient([header_prover("X-Proof", retry=retry, log=log)])
    target = live()
    credential = credential_for(target)
    send = Script(httpx.Response(401), httpx.Response(401))
    paid = httpx.Request(
        "POST",
        API,
        content=b"x",
        headers={"Payment-Authorization": credential, "X-Token": "stale"},
    )
    response, carried = await client.send(send, paid, challenge=target)
    assert response.status_code == 401
    assert len(send.sent) == 2 and retries == [401], "resent once: a second 401 is final"
    assert carried == (("X-Token", "fresh"),)
    assert [r.headers["Payment-Authorization"] for r in send.sent] == [credential, credential]
    assert [r.headers["X-Token"] for r in send.sent] == ["stale", "fresh"]
    assert await send.sent[1].aread() == b"x"
    assert len({context.nonce for _, context in log}) == 2, "the resend is proved afresh"


async def test_a_paid_attempt_is_never_resent_after_a_403_or_once_its_challenge_expired() -> None:
    retries: list[int] = []

    def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        retries.append(response.status_code)
        return {"X-Token": "fresh"}

    client = IdentityClient([header_prover("X-Proof", retry=retry)])
    send = Script(httpx.Response(403), httpx.Response(401), httpx.Response(401))
    target, expired = live(), live(seconds=-1)
    await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(expired)}),
        challenge=expired,
    )
    # A credential whose Challenge is unknown (x402) is never resent.
    await client.send(send, httpx.Request("GET", API, headers={"Payment-Signature": "x"}))
    assert len(send.sent) == 3 and retries == []


@pytest.mark.parametrize("header", ["Payment-Receipt", "Payment-Response", "X-Payment-Response"])
async def test_a_paid_401_reporting_settlement_is_never_resent(header: str) -> None:
    retries: list[int] = []

    def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        retries.append(response.status_code)
        return {"X-Token": "fresh"}

    client = IdentityClient([header_prover("X-Proof", retry=retry)])
    target = live()
    send = Script(httpx.Response(401, headers={header: "r"}, content=b"denied"))
    response, _ = await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    assert len(send.sent) == 1 and retries == []
    assert response.headers[header] == "r"
    assert await response.aread() == b"denied"


async def test_a_paid_attempt_is_resent_only_for_the_credential_answering_its_challenge() -> None:
    client = IdentityClient([header_prover("X-Proof", retry=resend_with({"X-Token": "fresh"}))])
    transport, other = live("transport"), credential_for(live("other"))
    send = Script(httpx.Response(401), httpx.Response(401))
    # An x402 credential beside an unrelated Payment credential.
    await client.send(
        send,
        httpx.Request(
            "GET", API, headers={"Payment-Authorization": other, "Payment-Signature": "x402"}
        ),
        challenge=transport,
    )
    # A Payment credential for another Challenge than the transport's.
    await client.send(
        send, httpx.Request("GET", API, headers={"Authorization": other}), challenge=transport
    )
    assert len(send.sent) == 2


async def test_a_caller_supplied_credential_is_resent_for_its_own_challenge() -> None:
    client = IdentityClient([header_prover("X-Proof", retry=resend_with({"X-Token": "fresh"}))])
    send = Script(httpx.Response(401), httpx.Response(200))
    credential = credential_for(live())
    response, _ = await client.send(
        send, httpx.Request("GET", API, headers={"Authorization": credential})
    )
    assert response.status_code == 200
    assert [r.headers["Authorization"] for r in send.sent] == [credential, credential]


async def test_a_paid_401_is_returned_when_its_challenge_expires_while_identity_refreshes() -> None:
    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return request

    async def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        await asyncio.sleep(0.2)
        return {"X-Token": "fresh"}

    client = IdentityClient([Prover(scope=(API,), prove=prove, retry=retry)])
    target = live(seconds=0.1)
    send = Script(httpx.Response(401, content=b"stale"))
    response, carried = await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    assert len(send.sent) == 1 and carried == ()
    assert response.status_code == 401
    assert await response.aread() == b"stale"


async def test_a_paid_401_is_returned_when_a_retry_hook_or_re_proving_fails() -> None:
    target = live()
    paid = httpx.Request("GET", API, headers={"Authorization": credential_for(target)})

    async def failing_retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        raise RuntimeError("hook failed")

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return request

    client = IdentityClient([Prover(scope=(API,), prove=prove, retry=failing_retry)])
    send = Script(httpx.Response(401, content=b"denied"))
    response, _ = await client.send(send, paid, challenge=target)
    assert len(send.sent) == 1 and await response.aread() == b"denied"

    proves = 0

    async def failing_prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        nonlocal proves
        proves += 1
        if proves > 1:
            raise RuntimeError("prove failed")
        return request

    async def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        return {}

    client = IdentityClient([Prover(scope=(API,), prove=failing_prove, retry=retry)])
    send = Script(httpx.Response(401, content=b"denied"))
    response, _ = await client.send(send, paid, challenge=target)
    assert len(send.sent) == 1 and response.status_code == 401
    assert await response.aread() == b"denied"


async def test_a_large_paid_401_body_is_truncated_when_kept_for_a_resend_that_never_happens() -> (
    None
):
    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        if context.challenge is not None and proved:
            raise RuntimeError("prove failed")
        proved.append(True)
        return request

    proved: list[bool] = []

    async def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        return {}

    client = IdentityClient([Prover(scope=(API,), prove=prove, retry=retry)])
    target = live()
    send = Script(httpx.Response(401, content=b"a" * (64 * 1024 + 1)))
    response, _ = await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    assert response.headers["Mppx-Body-Truncated"] == "true"
    assert len(await response.aread()) == 64 * 1024


class ScriptedTransport(httpx.AsyncBaseTransport):
    """Answers with responses built per call, recording what it was sent."""

    def __init__(self, respond: Callable[[int], httpx.Response]) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        await request.aread()
        return self.respond(len(self.requests))


async def test_headers_a_paid_attempt_was_resent_with_reach_the_next_paid_attempt() -> None:
    def respond(call: int) -> httpx.Response:
        if call in (1, 3):
            offer = live(f"c{call}")
            return httpx.Response(
                402, headers={"WWW-Authenticate": offer.to_www_authenticate("api.example")}
            )
        # The paid attempt's identity expired: a 401, then a fresh 402 after the resend.
        if call == 2:
            return httpx.Response(401)
        return httpx.Response(200, content=b"ok")

    transport = ScriptedTransport(respond)
    prover = header_prover("X-Proof", retry=resend_with({"X-Token": "fresh"}))
    mpp = Mpp(methods=[paying_method()], identity=[prover])
    mpp.payment_transport._inner = transport
    async with mpp:
        response = await mpp.fetch(f"{API}/paid")
    assert response.status_code == 200
    assert [r.headers.get("X-Token") for r in transport.requests] == [None, None, "fresh", "fresh"]


async def test_a_paid_resend_that_fails_in_transport_propagates() -> None:
    client = IdentityClient([header_prover("X-Proof", retry=resend_with({"X-Token": "fresh"}))])
    target = live()
    calls = 0

    async def send(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(401, content=b"denied", request=request)
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(httpx.ReadTimeout):
        await client.send(
            send,
            httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
            challenge=target,
        )
    assert calls == 2


async def test_a_paid_resend_failing_in_transport_leaves_the_outcome_unknown() -> None:
    def respond(call: int) -> httpx.Response:
        if call == 1:
            return httpx.Response(
                402, headers={"WWW-Authenticate": live("c1").to_www_authenticate("api.example")}
            )
        if call == 2:
            return httpx.Response(401, content=b"denied")
        raise httpx.ReadTimeout("timed out")

    transport = ScriptedTransport(respond)
    prover = header_prover("X-Proof", retry=resend_with({"X-Token": "fresh"}))
    mpp = Mpp(methods=[paying_method()], identity=[prover])
    mpp.payment_transport._inner = transport
    async with mpp:
        with pytest.raises(PaymentOutcomeUnknownError):
            await mpp.fetch(f"{API}/paid")
    assert len(transport.requests) == 3


async def test_a_gzip_paid_401_read_by_a_retry_hook_is_returned_readable() -> None:
    proves = 0

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        nonlocal proves
        proves += 1
        if proves > 1:
            raise RuntimeError("prove failed")
        return request

    bodies: list[bytes] = []

    async def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str]:
        bodies.append(await response.aread())
        return {}

    client = IdentityClient([Prover(scope=(API,), prove=prove, retry=retry)])
    target = live()
    body = gzip.compress(b"denied")
    send = Script(
        httpx.Response(
            401,
            headers={"Content-Encoding": "gzip", "Content-Length": str(len(body))},
            stream=httpx.ByteStream(body),
        )
    )
    response, _ = await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    assert bodies == [b"denied"]
    assert response.status_code == 401
    assert await response.aread() == b"denied"
    assert response.text == "denied"


async def test_a_decoded_paid_401_is_copied_without_its_encoding() -> None:
    body = gzip.compress(b"denied")
    rejected = httpx.Response(
        401,
        headers={"Content-Encoding": "gzip", "Content-Length": str(len(body))},
        stream=httpx.ByteStream(body),
    )
    await rejected.aread()
    copy = await _detach(rejected)
    assert "content-encoding" not in copy.headers
    assert "content-length" not in copy.headers
    assert await copy.aread() == b"denied"


class TrackedStream(httpx.AsyncByteStream):
    """A response body that records when its connection is released."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.body

    async def aclose(self) -> None:
        self.closed = True


async def test_a_paid_401_is_released_before_retry_hooks_run() -> None:
    stream = TrackedStream(b"denied")
    released: list[bool] = []

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return request

    async def retry(response: httpx.Response, context: RetryContext) -> Mapping[str, str] | None:
        # A hook refreshing identity through the same pool needs the connection free.
        released.append(stream.closed)
        assert await response.aread() == b"denied"
        return None

    client = IdentityClient([Prover(scope=(API,), prove=prove, retry=retry)])
    target = live()
    send = Script(httpx.Response(401, stream=stream))
    response, _ = await client.send(
        send,
        httpx.Request("GET", API, headers={"Authorization": credential_for(target)}),
        challenge=target,
    )
    assert released == [True]
    assert len(send.sent) == 1
    assert await response.aread() == b"denied"


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


async def test_prepare_runs_after_the_402_releases_its_connection() -> None:
    seen: list[tuple[bool, int]] = []

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return with_headers(request, {"X-Api-Key": "alice"})

    async def prepare(response: httpx.Response, context: PrepareContext) -> None:
        seen.append((response.is_closed, response.status_code))

    mpp = Mpp(
        methods=[paying_method()],
        identity=[Prover(scope=(API,), prove=prove, prepare=prepare)],
    )
    mpp.payment_transport._inner = StreamingTransport(ServerTransport(key_server()))
    async with mpp:
        response = await mpp.fetch(f"{API}/paid")
    assert response.status_code == 200
    assert seen == [(True, 402)]


class StreamingTransport(httpx.AsyncBaseTransport):
    """Returns each response with an unread body, as a pooled connection does."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        body = await response.aread()

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield body

        return httpx.Response(
            response.status_code, headers=response.headers, stream=Body(), request=request
        )


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


async def test_auxiliary_requests_are_proved_too() -> None:
    from mpp.client import PaymentTransport

    seen: list[httpx.Request] = []

    async def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    transport = PaymentTransport(
        [paying_method()], identity=[header_prover("X-Api-Key", lambda _: "alice")]
    )
    transport._inner = httpx.MockTransport(record)
    await transport._send_auxiliary(httpx.Request("POST", f"{API}/session/top-up"))
    assert [request.headers["X-Api-Key"] for request in seen] == ["alice"]


@pytest.mark.parametrize(
    ("header", "challenge_header"),
    [("Authorization", None), ("Payment-Authorization", "Payment-Authorization")],
)
async def test_a_prover_never_replaces_the_payment_credential(
    header: str, challenge_header: str | None
) -> None:
    async def bearer(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return with_headers(request, {"Authorization": "Bearer token", header: "Bearer token"})

    client = IdentityClient([Prover(scope="*", prove=bearer)])
    send = Script(httpx.Response(200))
    paid = httpx.Request("GET", API, headers={header: "Payment eyJ"})
    await client.send(send, paid, challenge=challenge(header=challenge_header))
    [sent] = send.sent
    assert sent.headers[header] == "Payment eyJ"


@pytest.mark.parametrize(
    ("url", "covered"),
    [
        ("http://[2001:db8::1]:8080/a", True),
        ("http://[2001:DB8::1]:8080/", True),
        ("http://[2001:db8::1:8080]/", False),
        ("http://[2001:db8::1]/", False),
    ],
)
def test_a_prover_scope_keeps_ipv6_hosts_apart(url: str, covered: bool) -> None:
    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        return request

    assert Prover(scope=("http://[2001:db8::1]:8080",), prove=prove).covers(url) is covered
