import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from mpp import (
    Attempt,
    AttemptOutcome,
    Challenge,
    ClientMethod,
    CredentialParams,
    CredentialReplayedError,
    Method,
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    VerificationFailedError,
    expires,
)
from mpp.client import BODY_TRUNCATED_HEADER, Mpp
from mpp.server import Request as ServerRequest
from mpp.server import http as server_http


class Anything(BaseModel):
    pass


def method(
    name: str = "test",
    intent: str = "test",
    create: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> ClientMethod:
    async def default(_: CredentialParams[Any]) -> str:
        return "credential"

    return ClientMethod(
        method=Method(name=name, intent=intent, request_model=Anything, payload_model=Anything),
        create_credential=create or default,
        **kwargs,
    )


def make402(
    *, id: str = "abc", method: str = "test", intent: str = "test", expires: str | None = None
) -> httpx.Response:
    request = base64.urlsafe_b64encode(json.dumps({"amount": "1"}).encode()).decode().rstrip("=")
    header = f'Payment id="{id}", realm="test", method="{method}", intent="{intent}", request="{request}"'
    if expires:
        header += f', expires="{expires}"'
    return httpx.Response(402, headers={"WWW-Authenticate": header})


class Recorder:
    def __init__(self, respond: Callable[[httpx.Request, int], httpx.Response]) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.respond(request, len(self.requests))

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def first_402(request: httpx.Request, n: int) -> httpx.Response:
    return make402() if n == 1 else httpx.Response(200, text="OK")


def client(recorder: Recorder, *methods: ClientMethod, **kwargs: Any) -> Mpp:
    return Mpp(methods=list(methods) or [method()], inner=recorder.transport, **kwargs)


URL = "https://example.com/api"


async def test_passes_through_non_402() -> None:
    recorder = Recorder(lambda r, n: httpx.Response(200, text="free"))
    response = await client(recorder).fetch(URL)
    assert response.text == "free"
    assert len(recorder.requests) == 1
    assert recorder.requests[0].headers["Accept-Payment"] == "test/test"


async def test_adds_authorization_on_retry() -> None:
    recorder = Recorder(first_402)
    response = await client(recorder).fetch(
        URL, method="POST", content=b"body", headers={"X-Custom": "1"}
    )
    assert response.status_code == 200
    retry = recorder.requests[1]
    assert retry.headers["Authorization"] == "credential"
    assert retry.headers["X-Custom"] == "1"
    assert retry.method == "POST"
    assert retry.content == b"body"


async def test_preserves_application_authorization() -> None:
    recorder = Recorder(first_402)
    paid = method(intent="test")
    await client(recorder, paid).fetch(URL, headers={"Authorization": "Bearer app"})
    assert recorder.requests[1].headers["Authorization"] == "credential"


async def test_explicit_accept_payment_reprioritizes() -> None:
    def respond(request: httpx.Request, n: int) -> httpx.Response:
        if n > 1:
            return httpx.Response(200)
        first = make402(id="a", method="alpha", intent="charge").headers["WWW-Authenticate"]
        second = make402(id="b", method="beta", intent="charge").headers["WWW-Authenticate"]
        return httpx.Response(
            402, headers=[("WWW-Authenticate", first), ("WWW-Authenticate", second)]
        )

    seen: list[str] = []

    def creator(name: str) -> Callable[..., Any]:
        async def create(params: CredentialParams[Any]) -> str:
            seen.append(params.challenge.id)
            return f"cred-{name}"

        return create

    recorder = Recorder(respond)
    mppx = client(
        recorder,
        method("alpha", "charge", creator("alpha")),
        method("beta", "charge", creator("beta")),
    )
    await mppx.fetch(URL, headers={"Accept-Payment": "beta/charge, alpha/charge;q=0.5"})
    assert seen == ["b"]
    assert recorder.requests[0].headers["Accept-Payment"] == "beta/charge, alpha/charge;q=0.5"
    seen.clear()
    recorder.requests.clear()
    # Explicit opt-out beats a broader wildcard.
    await mppx.fetch(URL, headers={"Accept-Payment": "*/*, beta/charge;q=0"})
    assert seen == ["a"]
    seen.clear()
    recorder.requests.clear()
    # Invalid explicit headers fail open to configured preferences but stay on the wire.
    await mppx.fetch(URL, headers={"Accept-Payment": "not valid"})
    assert seen == ["a"]
    assert recorder.requests[0].headers["Accept-Payment"] == "not valid"


async def test_payment_preferences() -> None:
    def respond(request: httpx.Request, n: int) -> httpx.Response:
        if n > 1:
            return httpx.Response(200)
        first = make402(id="a", method="alpha", intent="charge").headers["WWW-Authenticate"]
        second = make402(id="b", method="beta", intent="charge").headers["WWW-Authenticate"]
        return httpx.Response(402, headers={"WWW-Authenticate": f"{first}, {second}"})

    seen: list[str] = []

    async def create(params: CredentialParams[Any]) -> str:
        seen.append(params.challenge.id)
        return "c"

    recorder = Recorder(respond)
    mppx = client(
        recorder,
        method("alpha", "charge", create),
        method("beta", "charge", create),
        payment_preferences=lambda keys: {keys["alpha"]["charge"]: 0.2},
    )
    await mppx.fetch(URL)
    assert recorder.requests[0].headers["Accept-Payment"] == "alpha/charge;q=0.2, beta/charge"
    assert seen == ["b"]


async def test_rejects_expired_challenge_before_hooks() -> None:
    created: list[int] = []

    async def create(_: Any) -> str:
        created.append(1)
        return "c"

    on_challenge_calls: list[int] = []

    async def on_challenge(*_: Any) -> None:
        on_challenge_calls.append(1)

    recorder = Recorder(lambda r, n: make402(expires=expires.seconds(-60)))
    with pytest.raises(PaymentExpiredError):
        await client(recorder, method(create=create), on_challenge=on_challenge).fetch(URL)
    assert created == []
    assert on_challenge_calls == []
    assert len(recorder.requests) == 1


async def test_context_is_passed_and_validated() -> None:
    class Context(BaseModel):
        account: str

    seen: list[Any] = []

    async def create(params: CredentialParams[Any]) -> str:
        seen.append(params.context)
        return "c"

    recorder = Recorder(first_402)
    await client(recorder, method(create=create, context=Context)).fetch(
        URL, context={"account": "0xabc"}
    )
    assert seen == [Context(account="0xabc")]


async def test_events_and_challenge_handler_credential() -> None:
    events: list[str] = []
    created: list[int] = []

    async def create(_: Any) -> str:
        created.append(1)
        return "method-credential"

    recorder = Recorder(first_402)
    mppx = client(recorder, method(create=create))
    mppx.on("*", lambda env: events.append(f"*:{env.name}"))

    async def challenge_received(payload: Any) -> str:
        events.append(f"challenge:{payload.challenge.id}")
        return "event-credential"

    mppx.on_challenge_received(challenge_received)

    def credential_created(payload: Any) -> None:
        events.append(f"credential:{payload.credential}")
        raise RuntimeError("observer failed")

    mppx.on_credential_created(credential_created)

    def payment_response(payload: Any) -> None:
        events.append(f"response:{payload.response.status_code}")
        raise RuntimeError("observer failed")

    mppx.on_payment_response(payment_response)
    response = await mppx.fetch(URL)
    assert response.status_code == 200
    assert created == []
    assert recorder.requests[1].headers["Authorization"] == "event-credential"
    assert events == [
        "challenge:abc",
        "*:challenge.received",
        "credential:event-credential",
        "*:credential.created",
        "response:200",
        "*:payment.response",
    ]


async def test_first_challenge_event_credential_wins() -> None:
    events: list[str] = []
    recorder = Recorder(first_402)
    mppx = client(recorder)
    mppx.on_challenge_received(lambda _: events.append("empty") and "")
    mppx.on_challenge_received(lambda _: (events.append("first"), "first-credential")[1])
    mppx.on_challenge_received(lambda _: (events.append("second"), "second-credential")[1])
    await mppx.fetch(URL)
    assert recorder.requests[1].headers["Authorization"] == "first-credential"
    assert events == ["empty", "first"]


async def test_on_challenge() -> None:
    async def on_challenge(challenge: Challenge, create: Callable[..., Any]) -> str:
        return f"custom:{await create()}"

    recorder = Recorder(first_402)
    await client(recorder, on_challenge=on_challenge).fetch(URL)
    assert recorder.requests[1].headers["Authorization"] == "custom:credential"


async def test_memoizes_create_credential() -> None:
    calls: list[int] = []

    async def create(_: Any) -> str:
        calls.append(1)
        return "c"

    async def observe(payload: Any) -> None:
        await payload.create_credential()

    recorder = Recorder(first_402)
    mppx = client(recorder, method(create=create))
    mppx.on_challenge_received(observe)
    mppx.on(
        "*",
        lambda env: env.payload.create_credential() if env.name == "challenge.received" else None,
    )
    await mppx.fetch(URL)
    assert calls == [1]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, ["payment.response"]),
        (201, ["payment.response"]),
        (400, []),
        (403, []),
        (404, []),
        (500, ["payment.failed"]),
        (503, ["payment.failed"]),
    ],
)
async def test_paid_retry_outcomes(status: int, expected: list[str]) -> None:
    recorder = Recorder(
        lambda r, n: (
            httpx.Response(status, text="body") if "authorization" in r.headers else make402()
        )
    )
    mppx = client(recorder, method(transaction_hash=lambda credential: f"hash:{credential}"))
    events: list[str] = []
    failures: list[Any] = []
    mppx.on("*", lambda env: events.append(env.name) if env.name.startswith("payment.") else None)
    mppx.on_payment_failed(failures.append)
    response = await mppx.fetch(URL)
    assert response.status_code == status
    assert len(recorder.requests) == 2
    assert events == expected
    for failure in failures:
        error = failure.error
        assert isinstance(error, PaymentOutcomeUnknownError)
        assert (error.challenge.id, error.credential, error.transaction_hash) == (
            "abc",
            "credential",
            "hash:credential",
        )
        assert failure.response.status_code == status
        assert failure.response.text == "body"


async def test_403_replay_is_not_unknown_outcome() -> None:
    replayed = CredentialReplayedError()
    recorder = Recorder(
        lambda r, n: (
            httpx.Response(403, json=replayed.to_problem_details())
            if "authorization" in r.headers
            else make402()
        )
    )
    events: list[str] = []
    mppx = client(recorder)
    mppx.on("*", lambda env: events.append(env.name))
    response = await mppx.fetch(URL)
    assert response.status_code == 403
    assert "www-authenticate" not in response.headers
    assert response.json()["status"] == 403
    assert events == ["challenge.received", "credential.created"]


async def test_hash_derivation_failure_is_ignored() -> None:
    def broken(_: str) -> str:
        raise ValueError("malformed")

    recorder = Recorder(lambda r, n: make402() if n == 1 else httpx.Response(500))
    mppx = client(recorder, method(transaction_hash=broken))
    failures: list[Any] = []
    mppx.on_payment_failed(lambda p: failures.append(p.error))
    assert (await mppx.fetch(URL)).status_code == 500
    assert isinstance(failures[0], PaymentOutcomeUnknownError)
    assert failures[0].transaction_hash is None


async def test_network_error_on_paid_retry() -> None:
    cause = httpx.ConnectError("fetch failed")

    def respond(request: httpx.Request, n: int) -> httpx.Response:
        if n == 1:
            return make402()
        raise cause

    recorder = Recorder(respond)
    mppx = client(recorder, method(transaction_hash=lambda c: f"hash:{c}"))
    failures: list[Any] = []
    mppx.on_payment_failed(lambda p: failures.append(p.error))
    with pytest.raises(httpx.ConnectError) as raised:
        await mppx.fetch(URL)
    assert raised.value is cause
    assert isinstance(failures[0], PaymentOutcomeUnknownError)
    assert failures[0].__cause__ is cause
    assert failures[0].transaction_hash == "hash:credential"


class StreamBody(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, hang: bool = False) -> None:
        self.chunks = chunks
        self.hang = hang
        self.closed = False

    async def __aiter__(self) -> Any:
        for chunk in self.chunks:
            yield chunk
        if self.hang:
            await asyncio.sleep(3600)

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("chunks", "hang", "expected", "truncated"),
    [
        ([b"settle failed"], False, b"settle failed", False),
        ([b"x" * 40_000, b"x" * 40_000], False, b"x" * (64 * 1024), True),
        ([b"partial"], True, b"partial", True),
    ],
)
async def test_buffers_5xx_bodies_within_bounds(
    chunks: list[bytes],
    hang: bool,
    expected: bytes,
    truncated: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mpp.client import _mpp

    monkeypatch.setattr(_mpp, "ERROR_BODY_TIMEOUT_SECONDS", 0.05)
    body = StreamBody(chunks, hang=hang)
    recorder = Recorder(
        lambda r, n: (
            httpx.Response(500, headers={"Content-Length": str(sum(map(len, chunks)))}, stream=body)
            if "authorization" in r.headers
            else make402()
        )
    )
    mppx = client(recorder)
    failures: list[Any] = []
    mppx.on_payment_failed(failures.append)
    response = await mppx.fetch(URL)
    assert response.content == expected
    assert response.headers.get(BODY_TRUNCATED_HEADER) == ("true" if truncated else None)
    # The original length no longer describes a truncated body (httpx re-frames the buffer).
    assert response.headers.get("content-length") == str(len(expected))
    assert failures[0].response.content == expected


async def test_payment_failed_when_handling_rejects() -> None:
    recorder = Recorder(lambda r, n: make402(method="stripe", intent="charge"))
    failures: list[Any] = []
    mppx = client(recorder)
    mppx.on_payment_failed(failures.append)
    with pytest.raises(
        ValueError, match=r"No method found for challenges: stripe.charge. Available: test.test"
    ):
        await mppx.fetch(URL)
    assert failures[0].response.status_code == 402


async def test_order_challenges() -> None:
    def respond(request: httpx.Request, n: int) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200)
        header = ", ".join(
            make402(id=i, method=m, intent="charge").headers["WWW-Authenticate"]
            for i, m in (("a", "alpha"), ("b", "beta"))
        )
        return httpx.Response(402, headers={"WWW-Authenticate": header})

    seen: list[str] = []

    async def create(params: CredentialParams[Any]) -> str:
        seen.append(params.challenge.id)
        return "c"

    recorder = Recorder(respond)
    mppx = client(
        recorder,
        method("alpha", "charge", create),
        method("beta", "charge", create),
        order_challenges=lambda candidates: list(reversed(candidates)),
    )
    await mppx.fetch(URL)
    assert seen == ["b"]
    seen.clear()
    await mppx.fetch(
        URL, order_challenges=lambda candidates: [c for c in candidates if c.method.name == "alpha"]
    )
    assert seen == ["a"]
    with pytest.raises(ValueError, match="No method found"):
        await mppx.fetch(URL, order_challenges=lambda candidates: [])


async def test_fresh_credential_per_incremental_challenge() -> None:
    ids = iter(["first", "second", "third"])

    async def create(params: CredentialParams[Any]) -> str:
        return f"credential-{params.challenge.id}"

    recorder = Recorder(lambda r, n: make402(id=next(ids)) if n <= 3 else httpx.Response(200))
    response = await client(recorder, method(create=create)).fetch(URL)
    assert response.status_code == 200
    assert [r.headers["Authorization"] for r in recorder.requests[1:]] == [
        "credential-first",
        "credential-second",
        "credential-third",
    ]


@pytest.mark.parametrize(
    ("error", "status", "payments"),
    [
        (CredentialReplayedError(reason="Transaction hash has already been used"), 403, 1),
        (VerificationFailedError(reason="amount mismatch"), 402, 3),
    ],
)
async def test_does_not_pay_again_after_final_answer(
    error: Any, status: int, payments: int
) -> None:
    created: list[int] = []

    async def create(_: Any) -> str:
        created.append(1)
        return "credential"

    transport = server_http()

    async def respond(request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            return make402(id="first")
        challenge = Challenge.from_response(make402(id="retry"))
        response = await transport.respond_challenge(
            challenge=challenge, error=error, input=ServerRequest("GET", str(request.url))
        )
        return httpx.Response(
            response.status,
            headers=list(response.headers.multi_items()),
            content=await response.read(),
        )

    mppx = Mpp(methods=[method(create=create)], inner=httpx.MockTransport(respond))
    response = await mppx.fetch(URL)
    assert response.status_code == status
    assert len(created) == payments


async def test_retry_caps() -> None:
    recorder = Recorder(lambda r, n: make402())
    response = await client(recorder).fetch(URL)
    assert len(recorder.requests) == 4
    assert response.status_code == 402
    recorder = Recorder(lambda r, n: make402())
    await client(recorder, max_payment_retries=1).fetch(URL)
    assert len(recorder.requests) == 2


async def test_challenge_less_402_after_payment() -> None:
    recorder = Recorder(
        lambda r, n: (
            make402() if n == 1 else httpx.Response(402, json={"title": "Verification Failed"})
        )
    )
    response = await client(recorder).fetch(URL)
    assert len(recorder.requests) == 2
    assert response.json() == {"title": "Verification Failed"}
    recorder = Recorder(
        lambda r, n: make402() if n == 1 else make402(method="stripe", intent="charge")
    )
    assert (await client(recorder).fetch(URL)).status_code == 402
    assert len(recorder.requests) == 2


class TestAttempts:
    def tracked(self, settlements: list[str]) -> ClientMethod:
        async def create(params: CredentialParams[Any]) -> str:
            attempt = params.attempt
            assert attempt is not None

            def settle(outcome: AttemptOutcome) -> bool:
                settlements.append(outcome.status)
                return outcome.status != "pending"

            attempt.settle = settle
            return "credential"

        return method(create=create, prepare=lambda _: None, handle_response=lambda p: p.response)

    async def test_accepted(self) -> None:
        settlements: list[str] = []
        recorder = Recorder(first_402)
        await client(recorder, self.tracked(settlements)).fetch(URL)
        assert settlements == ["accepted"]

    async def test_rejected(self) -> None:
        settlements: list[str] = []
        recorder = Recorder(lambda r, n: make402() if n == 1 else httpx.Response(400))
        await client(recorder, self.tracked(settlements)).fetch(URL)
        assert settlements == ["rejected"]

    async def test_reuses_pending_attempt_for_same_challenge(self) -> None:
        settlements: list[str] = []
        created: list[int] = []
        tracked = self.tracked(settlements)

        async def create(params: CredentialParams[Any]) -> str:
            created.append(1)
            return await tracked.create_credential(params)

        from dataclasses import replace

        recorder = Recorder(lambda r, n: make402() if n <= 2 else httpx.Response(200))
        await client(recorder, replace(tracked, create_credential=create)).fetch(URL)
        assert created == [1]
        assert settlements == ["pending", "accepted"]

    async def test_invalidates_across_generic_challenge(self) -> None:
        first_calls: list[int] = []

        async def first_create(_: Any) -> str:
            first_calls.append(1)
            return "first"

        first = method("first", create=first_create, prepare=lambda _: None)
        second = method("second", create=lambda _: _async("second"))
        responses = [
            make402(id="first", method="first"),
            make402(id="second", method="second"),
            make402(id="first", method="first"),
            httpx.Response(200),
        ]
        recorder = Recorder(lambda r, n: responses[n - 1])
        assert (await client(recorder, first, second).fetch(URL)).status_code == 200
        assert len(first_calls) == 2

    async def test_prepare_receives_raw_send(self) -> None:
        seen: list[Any] = []

        async def prepare(params: Any) -> None:
            response = await params.send(httpx.Request("GET", "https://example.com/topup"))
            seen.append((params.challenge.id, response.status_code))

        recorder = Recorder(
            lambda r, n: (
                httpx.Response(204)
                if r.url.path == "/topup"
                else first_402(r, n - (1 if n > 2 else 0))
            )
        )
        await client(recorder, method(prepare=prepare)).fetch(URL)
        assert seen == [("abc", 204)]

    async def test_handle_response_and_refetch(self) -> None:
        async def handle(params: Any) -> httpx.Response:
            assert params.refetch is not None
            await params.response.aread()
            return httpx.Response(200, text=f"handled:{params.response.text}")

        recorder = Recorder(lambda r, n: make402() if n == 1 else httpx.Response(200, text="paid"))
        response = await client(recorder, method(handle_response=handle)).fetch(URL)
        assert response.text == "handled:paid"
        free = Recorder(lambda r, n: httpx.Response(200, text="free"))
        assert (await client(free, method(handle_response=handle)).fetch(URL)).text == "free"


async def _async(value: str) -> str:
    return value


class TestRedirects:
    async def test_retries_same_origin_redirect_target(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.path == "/protected":
                return httpx.Response(302, headers={"Location": "/redirected-protected"})
            return make402() if "authorization" not in request.headers else httpx.Response(200)

        recorder = Recorder(respond)
        response = await client(recorder).fetch("https://api.example.com/protected")
        assert response.status_code == 200
        assert [str(r.url) for r in recorder.requests] == [
            "https://api.example.com/protected",
            "https://api.example.com/redirected-protected",
            "https://api.example.com/redirected-protected",
        ]
        assert recorder.requests[2].headers["Authorization"] == "credential"

    async def test_refuses_cross_origin_redirect_target(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.host == "api.example.com":
                return httpx.Response(
                    302, headers={"Location": "https://payments.example.com/protected"}
                )
            return make402()

        recorder = Recorder(respond)
        with pytest.raises(
            ValueError,
            match=r"Refusing to send payment credential across redirect from https://api.example.com to https://payments.example.com",
        ):
            await client(recorder).fetch("https://api.example.com/protected")
        assert all("authorization" not in r.headers for r in recorder.requests)

    async def test_paid_redirect_is_not_paid_again(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.path == "/pay":
                return (
                    make402()
                    if "authorization" not in request.headers
                    else httpx.Response(303, headers={"Location": "/result"})
                )
            return make402(id="second")

        # mppx.fetch: a redirect answering a paid request is returned, never followed.
        recorder = Recorder(respond)
        response = await client(recorder).fetch(URL.replace("/api", "/pay"), method="POST")
        assert response.status_code == 303
        assert [r.url.path for r in recorder.requests] == ["/pay", "/pay"]
        # mppx.client() behaves the same way.
        recorder = Recorder(respond)
        async with client(recorder).client() as http:
            response = await http.post(URL.replace("/api", "/pay"))
        assert response.status_code == 303
        assert [r.url.path for r in recorder.requests] == ["/pay", "/pay"]
        # A plain following httpx client goes on without the credential and never pays again.
        recorder = Recorder(respond)
        mppx = client(recorder)
        async with httpx.AsyncClient(
            transport=mppx.payment_transport, follow_redirects=True
        ) as http:
            response = await http.post(URL.replace("/api", "/pay"))
        assert response.status_code == 402
        assert [r.url.path for r in recorder.requests] == ["/pay", "/pay", "/result"]
        assert "authorization" not in recorder.requests[2].headers

    async def test_client_does_not_follow_cross_origin_paid_redirect(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.host == "other.example":
                return httpx.Response(200)
            if "authorization" not in request.headers:
                return make402()
            return httpx.Response(302, headers={"Location": "https://other.example/next"})

        recorder = Recorder(respond)
        async with client(recorder).client() as http:
            response = await http.get(URL)
        assert response.status_code == 302
        assert all(r.url.host != "other.example" for r in recorder.requests)


class TestAcceptPaymentPolicy:
    @pytest.mark.parametrize(
        ("policy", "url", "injected"),
        [
            ("always", "https://a.example.com/x", True),
            ("never", "https://a.example.com/x", False),
            ("same-origin", "https://a.example.com/x", True),
            (["https://a.example.com"], "https://a.example.com/deep/path", True),
            (["https://a.example.com"], "https://b.example.com/x", False),
            (["*.example.com"], "https://sub.example.com/x", True),
            (["*.example.com"], "https://example.com/x", True),
            (["*.example.com"], "https://example.org/x", False),
        ],
    )
    async def test_policies(self, policy: Any, url: str, injected: bool) -> None:
        recorder = Recorder(lambda r, n: httpx.Response(200))
        await client(recorder, accept_payment_policy=policy).fetch(url)
        assert ("accept-payment" in recorder.requests[0].headers) is injected

    async def test_never_still_pays_and_explicit_header_wins(self) -> None:
        recorder = Recorder(first_402)
        assert (await client(recorder, accept_payment_policy="never").fetch(URL)).status_code == 200
        recorder = Recorder(lambda r, n: httpx.Response(200))
        await client(recorder, accept_payment_policy="never").fetch(
            URL, headers={"Accept-Payment": "x/y"}
        )
        assert recorder.requests[0].headers["Accept-Payment"] == "x/y"


async def test_rejects_invalid_credential_values() -> None:
    for value in ("", "a\r\nb"):
        recorder = Recorder(first_402)
        with pytest.raises(ValueError, match="Credential header value"):
            await client(recorder, method(create=lambda _, v=value: _async(v))).fetch(URL)


async def test_streaming_client_usage() -> None:
    recorder = Recorder(first_402)
    mppx = client(recorder)
    async with mppx.client() as http, http.stream("GET", URL) as response:
        assert response.status_code == 200
        assert await response.aread() == b"OK"


_ = Attempt


class TestAuditRegressions:
    async def test_challenge_response_is_closed_before_paid_retry(self) -> None:
        closed: list[bool] = []

        class Tracked(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                yield b"{}"

            async def aclose(self) -> None:
                closed.append(True)

        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if "authorization" in request.headers:
                assert closed == [True], "402 must be released before the paid retry"
                return httpx.Response(200)
            response = make402()
            return httpx.Response(402, headers=response.headers, stream=Tracked())

        assert (await client(Recorder(respond)).fetch(URL)).status_code == 200

    async def test_pool_is_not_exhausted_by_payments(self) -> None:
        """With a pool of one connection, many sequential payments still succeed."""
        semaphore = asyncio.Semaphore(1)

        class OneConnection(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                await asyncio.wait_for(semaphore.acquire(), 1)
                body = (
                    make402()
                    if "authorization" not in request.headers
                    else httpx.Response(200, text="ok")
                )

                class Releasing(httpx.AsyncByteStream):
                    async def __aiter__(self) -> Any:
                        yield body.content

                    async def aclose(self) -> None:
                        semaphore.release()

                return httpx.Response(body.status_code, headers=body.headers, stream=Releasing())

        mppx = Mpp(methods=[method()], inner=OneConnection())
        for _ in range(5):
            assert (await mppx.fetch(URL)).status_code == 200

    async def test_pool_is_not_exhausted_by_failed_payments(self) -> None:
        """A 402 the client cannot pay is released before the error propagates."""
        semaphore = asyncio.Semaphore(1)

        class OneConnection(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                await asyncio.wait_for(semaphore.acquire(), 1)
                body = make402()

                class Releasing(httpx.AsyncByteStream):
                    async def __aiter__(self) -> Any:
                        yield body.content

                    async def aclose(self) -> None:
                        semaphore.release()

                return httpx.Response(body.status_code, headers=body.headers, stream=Releasing())

        async def fail(_: CredentialParams[Any]) -> str:
            raise RuntimeError("wallet unavailable")

        mppx = Mpp(methods=[method(create=fail)], inner=OneConnection())
        for _ in range(3):
            with pytest.raises(RuntimeError, match="wallet unavailable"):
                await mppx.fetch(URL)

    async def test_fetch_has_no_default_timeout(self) -> None:
        seen: list[Any] = []

        def respond(request: httpx.Request, n: int) -> httpx.Response:
            seen.append(request.extensions.get("timeout"))
            return first_402(request, n)

        await client(Recorder(respond)).fetch(URL)
        assert seen[0] == {"connect": None, "read": None, "write": None, "pool": None}
        seen.clear()
        await client(Recorder(respond)).fetch(URL, timeout=3)
        assert seen[0]["read"] == 3

    async def test_cancellation_after_credential_sent_is_reconciled(self) -> None:
        settlements: list[str] = []
        failures: list[Any] = []
        started = asyncio.Event()

        class Slow(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if "authorization" not in request.headers:
                    return make402()
                started.set()
                await asyncio.sleep(3600)
                raise AssertionError

        async def create(params: CredentialParams[Any]) -> str:
            assert params.attempt is not None

            def settle(outcome: AttemptOutcome) -> bool:
                settlements.append(outcome.status)
                return True

            params.attempt.settle = settle
            return "credential"

        tracked = method(
            create=create,
            prepare=lambda _: None,
            handle_response=lambda p: p.response,
            transaction_hash=lambda c: "0xhash",
        )
        mppx = Mpp(methods=[tracked], inner=Slow())
        mppx.on_payment_failed(failures.append)
        task = asyncio.create_task(mppx.fetch(URL))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert settlements == ["rejected"]
        assert isinstance(failures[0].error, PaymentOutcomeUnknownError)
        assert failures[0].error.transaction_hash == "0xhash"
        assert isinstance(failures[0].error.__cause__, asyncio.CancelledError)

    async def test_resent_request_pays_again(self) -> None:
        created: list[int] = []

        async def create(_: Any) -> str:
            created.append(1)
            return "credential"

        recorder = Recorder(
            lambda r, n: httpx.Response(200) if "authorization" in r.headers else make402()
        )
        async with client(recorder, method(create=create)).client() as http:
            request = http.build_request("GET", URL)
            assert (await http.send(request)).status_code == 200
            assert (await http.send(request)).status_code == 200
        assert len(created) == 2

    async def test_payment_response_observers_get_readable_copy(self) -> None:
        bodies: list[bytes] = []

        async def observe(payload: Any) -> None:
            bodies.append(await payload.response.aread())

        recorder = Recorder(
            lambda r, n: (
                make402() if n == 1 else httpx.Response(200, stream=StreamBody([b"pa", b"id"]))
            )
        )
        mppx = client(recorder)
        mppx.on_payment_response(observe)
        response = await mppx.fetch(URL)
        assert response.content == b"paid"
        assert bodies == [b"paid"]

    async def test_duplicate_handler_registration_is_idempotent(self) -> None:
        calls: list[str] = []

        def handler(payload: Any) -> None:
            calls.append(payload.credential)

        mppx = client(Recorder(first_402))
        off_first = mppx.on("credential.created", handler)
        mppx.on("credential.created", handler)
        await mppx.fetch(URL)
        assert calls == ["credential"]
        off_first()
        await mppx.fetch(URL)
        assert calls == ["credential"]


class TestAllowedOrigins:
    """pympp extension (pympp 0.14 ``allowed_origins``); mppx has no origin allowlist."""

    @staticmethod
    def events(mppx: Mpp) -> list[str]:
        seen: list[str] = []
        mppx.on("*", lambda envelope: seen.append(envelope.name))
        return seen

    @pytest.mark.parametrize(
        "allowed",
        [
            ["https://api.example.com"],
            ["https://API.example.com:443/"],
            ["https://other.example", "https://api.example.com"],
        ],
    )
    async def test_pays_allowed_origins(self, allowed: list[str]) -> None:
        recorder = Recorder(first_402)
        mppx = client(recorder, allowed_origins=allowed)
        seen = self.events(mppx)
        response = await mppx.fetch("https://api.example.com/paid")
        assert response.status_code == 200
        assert recorder.requests[1].headers["Authorization"] == "credential"
        assert "credential.created" in seen

    @pytest.mark.parametrize(
        "allowed",
        [
            [],
            ["https://other.example"],
            ["http://api.example.com"],
            ["https://api.example.com:8443"],
        ],
    )
    async def test_returns_disallowed_challenges_unpaid(self, allowed: list[str]) -> None:
        created: list[str] = []

        async def create(_: CredentialParams[Any]) -> str:
            created.append("created")
            return "credential"

        recorder = Recorder(first_402)
        mppx = client(recorder, method(create=create), allowed_origins=allowed)
        seen = self.events(mppx)
        response = await mppx.fetch("https://api.example.com/paid")
        assert response.status_code == 402
        assert "www-authenticate" in response.headers
        assert len(recorder.requests) == 1
        assert created == []
        assert seen == []

    async def test_redirect_to_a_disallowed_origin_is_not_paid(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.host == "api.example.com":
                return httpx.Response(302, headers={"Location": "https://evil.example/paid"})
            return make402()

        recorder = Recorder(respond)
        mppx = client(recorder, allowed_origins=["https://api.example.com"])
        seen = self.events(mppx)
        response = await mppx.fetch("https://api.example.com/start")
        assert response.status_code == 402
        assert [str(r.url) for r in recorder.requests] == [
            "https://api.example.com/start",
            "https://evil.example/paid",
        ]
        assert all("authorization" not in r.headers for r in recorder.requests)
        assert seen == []

    async def test_same_origin_redirect_is_paid(self) -> None:
        def respond(request: httpx.Request, n: int) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(302, headers={"Location": "/paid"})
            return make402() if "authorization" not in request.headers else httpx.Response(200)

        recorder = Recorder(respond)
        mppx = client(recorder, allowed_origins=["https://api.example.com"])
        assert (await mppx.fetch("https://api.example.com/start")).status_code == 200

    @pytest.mark.parametrize(
        "origin",
        [
            "https://api.example.com/path",
            "https://user:pass@api.example.com",
            "https://api.example.com?q=1",
            "ftp://api.example.com",
            "api.example.com",
        ],
    )
    def test_rejects_entries_that_are_not_origins(self, origin: str) -> None:
        with pytest.raises(ValueError, match="allowed_origins"):
            Mpp(methods=[method()], allowed_origins=[origin])

    def test_rejects_a_bare_string(self) -> None:
        with pytest.raises(TypeError, match="allowed_origins"):
            Mpp(methods=[method()], allowed_origins="https://api.example.com")
