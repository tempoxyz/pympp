from __future__ import annotations

import inspect
import io
import threading
from contextlib import asynccontextmanager
from typing import Any, Literal, cast
from unittest.mock import AsyncMock

import httpx
import pytest

import mpp._httpx as httpx_adapter
from mpp import Challenge, Credential
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.runtime import HTTPX_ADAPTER_VERSIONS, HttpxCompatibilityError, OwnedPaymentRuntime

Kind = Literal["sync", "async"]


class Method:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.create_credential = AsyncMock(side_effect=self._create_credential)

    async def _create_credential(self, challenge: Challenge) -> Credential:
        return Credential(challenge=challenge.to_echo(), payload={"hash": "0xabc"})


def required(challenge_id: str = "challenge", **kwargs: Any) -> httpx.Response:
    challenge = Challenge(id=challenge_id, method="tempo", intent="charge", request={})
    headers = httpx.Headers(kwargs.pop("headers", {}))
    headers["www-authenticate"] = challenge.to_www_authenticate("example.com")
    return httpx.Response(402, headers=headers, **kwargs)


def make_client(
    kind: Kind,
    runtime: OwnedPaymentRuntime,
    handler: Any,
    **kwargs: Any,
) -> httpx.Client | httpx.AsyncClient:
    if kind == "sync":
        return runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(handler), **kwargs))
    return runtime.wrap_async_client(
        httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)
    )


async def send(
    kind: Kind,
    client: httpx.Client | httpx.AsyncClient,
    method: str = "GET",
    url: str = "https://example.com/paid",
    **kwargs: Any,
) -> httpx.Response:
    if kind == "sync":
        return cast(httpx.Client, client).request(method, url, **kwargs)
    return await cast(httpx.AsyncClient, client).request(method, url, **kwargs)


async def send_request(
    kind: Kind,
    client: httpx.Client | httpx.AsyncClient,
    request: httpx.Request,
) -> httpx.Response:
    if kind == "sync":
        return cast(httpx.Client, client).send(request)
    return await cast(httpx.AsyncClient, client).send(request)


async def close(kind: Kind, client: httpx.Client | httpx.AsyncClient) -> None:
    if kind == "sync":
        cast(httpx.Client, client).close()
    else:
        await cast(httpx.AsyncClient, client).aclose()


class TwoRequestAuth(httpx.Auth):
    def auth_flow(self, request: httpx.Request):
        response = yield request
        assert response.status_code == 200
        yield httpx.Request("GET", "https://example.com/second")


@pytest.mark.parametrize("kind", ["sync", "async"])
@pytest.mark.parametrize("cached", [False, True], ids=["lookup", "cached"])
async def test_one_public_send_never_pays_twice(kind: Kind, cached: bool) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200)
        return required(request.url.path)

    client = make_client(kind, runtime, handler, auth=TwoRequestAuth())
    owner: Any = httpx.Client if kind == "sync" else httpx.AsyncClient
    # Model a bound send cached before the instance adapter was installed.
    sender: Any = owner.send.__get__(client) if cached else client.send
    try:
        response = sender(client.build_request("GET", "https://example.com/first"))
        if kind == "async":
            response = await response
    finally:
        await close(kind, client)
        runtime.close()

    assert response.status_code == 402
    method.create_credential.assert_awaited_once()


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_each_public_send_gets_a_fresh_payment_budget(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").startswith("Payment "):
            if request.url.path == "/first":
                return httpx.Response(302, headers={"location": "/second"})
            return httpx.Response(200)
        return required(request.url.path)

    client = make_client(kind, runtime, handler)
    request = client.build_request("GET", "https://example.com/first")
    try:
        first = await send_request(kind, client, request)
        assert first.status_code == 302
        assert first.next_request is not None
        assert (await send_request(kind, client, first.next_request)).is_success
        assert (await send_request(kind, client, request)).status_code == 302
    finally:
        await close(kind, client)
        runtime.close()

    assert method.create_credential.await_count == 3


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_auth_redirect_cookies_and_hooks(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    requests: list[tuple[str, str, str]] = []
    hooks: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (
                request.url.path,
                request.headers.get("authorization", ""),
                request.headers.get("cookie", ""),
            )
        )
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"location": "/paid", "set-cookie": "redirect=yes; Path=/"},
            )
        if request.headers.get("authorization", "").startswith("Payment "):
            return httpx.Response(200, content=b"paid")
        return required(headers={"set-cookie": "challenge=yes; Path=/"})

    if kind == "sync":

        def sync_hook(response: httpx.Response) -> None:
            hooks.append(response.status_code)

        hook = sync_hook
    else:

        async def async_hook(response: httpx.Response) -> None:
            hooks.append(response.status_code)

        hook = async_hook
    client = make_client(
        kind,
        runtime,
        handler,
        auth=("user", "password"),
        event_hooks={"response": [hook]},
        follow_redirects=True,
    )
    try:
        response = await send(kind, client, url="https://example.com/start")
    finally:
        await close(kind, client)
        runtime.close()

    assert response.content == b"paid"
    assert [item[0] for item in requests] == ["/start", "/paid", "/paid"]
    assert requests[0][1].startswith("Basic ")
    assert requests[1][1].startswith("Basic ")
    assert requests[2][1].startswith("Payment ")
    assert "redirect=yes" in requests[1][2]
    assert "challenge=yes" in requests[2][2]
    assert hooks == [302, 200]


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_free_and_disallowed_requests_do_not_start_runtime(kind: Kind) -> None:
    entered: list[bool] = []

    @asynccontextmanager
    async def factory():
        entered.append(True)
        yield Method()

    runtime = OwnedPaymentRuntime(
        method_factories=[factory],
        allowed_origins=["https://allowed.example"],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200) if request.url.path == "/free" else required()

    client = make_client(kind, runtime, handler)
    try:
        assert (await send(kind, client, url="https://allowed.example/free")).status_code == 200
        assert (await send(kind, client, url="https://blocked.example/paid")).status_code == 402
        assert entered == []
    finally:
        await close(kind, client)
        runtime.close()


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_multipart_is_replayed_byte_for_byte(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        return httpx.Response(200, content=b"paid") if len(bodies) == 2 else required()

    client = make_client(kind, runtime, handler)
    try:
        response = await send(
            kind,
            client,
            "POST",
            files={"upload": ("data.txt", io.BytesIO(b"file-content"))},
        )
    finally:
        await close(kind, client)
        runtime.close()

    assert response.content == b"paid"
    assert bodies[0] == bodies[1]
    assert b"file-content" in bodies[0]


class ConsumingSyncTransport(httpx.BaseTransport):
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(b"".join(cast(httpx.SyncByteStream, request.stream)))
        return required()


class ConsumingAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        stream = cast(httpx.AsyncByteStream, request.stream)
        self.bodies.append(b"".join([chunk async for chunk in stream]))
        return required()


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_one_shot_paid_upload_fails_before_credential(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    bodies: list[bytes] = []
    if kind == "sync":
        client: httpx.Client | httpx.AsyncClient = httpx.Client(
            transport=ConsumingSyncTransport(bodies)
        )

        def sync_content():
            yield b"one-shot"

        content = sync_content
        client = runtime.wrap_client(client)
    else:
        client = httpx.AsyncClient(transport=ConsumingAsyncTransport(bodies))

        async def async_content():
            yield b"one-shot"

        content = async_content
        client = runtime.wrap_async_client(client)

    try:
        with pytest.raises(PaymentError, match="cannot be replayed"):
            await send(kind, client, "POST", content=content())
    finally:
        await close(kind, client)
        runtime.close()

    assert bodies == [b"one-shot"]
    method.create_credential.assert_not_awaited()


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_hook_failure_does_not_change_known_payment(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in request.headers:
            return httpx.Response(200, content=b"paid")
        return required()

    if kind == "sync":

        def sync_hook(response: httpx.Response) -> None:
            response.read()
            raise RuntimeError("hook failed")

        hook = sync_hook
    else:

        async def async_hook(response: httpx.Response) -> None:
            await response.aread()
            raise RuntimeError("hook failed")

        hook = async_hook
    client = make_client(kind, runtime, handler, event_hooks={"response": [hook]})
    try:
        with pytest.raises(RuntimeError, match="hook failed"):
            await send(kind, client)
        client.event_hooks["response"].clear()
        assert (await send(kind, client)).is_success
    finally:
        await close(kind, client)
        runtime.close()
    assert method.create_credential.await_count == 2


class BrokenSyncStream(httpx.SyncByteStream):
    def __iter__(self):
        raise httpx.ReadError("body lost")
        yield b""  # pragma: no cover


class BrokenAsyncStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise httpx.ReadError("body lost")
        yield b""  # pragma: no cover


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_only_send_failure_retains_unknown_outcome(
    kind: Kind,
) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    failure = "body"

    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" not in request.headers:
            return required()
        if failure == "send":
            raise httpx.ReadTimeout("response lost", request=request)
        if failure == "body":
            stream = BrokenSyncStream() if kind == "sync" else BrokenAsyncStream()
            return httpx.Response(200, stream=stream)
        return httpx.Response(200, content=b"paid")

    client = make_client(kind, runtime, handler)
    try:
        request = client.build_request("GET", "https://example.com/paid")
        if kind == "sync":
            response = cast(httpx.Client, client).send(request, stream=True)
            with pytest.raises(httpx.ReadError, match="body lost"):
                response.read()
            response.close()
        else:
            response = await cast(httpx.AsyncClient, client).send(request, stream=True)
            with pytest.raises(httpx.ReadError, match="body lost"):
                await response.aread()
            await response.aclose()
        failure = "ok"
        assert (await send(kind, client)).is_success
        failure = "send"
        with pytest.raises(PaymentOutcomeUnknownError):
            await send(kind, client)
        with pytest.raises(PaymentOutcomeUnknownError):
            await send(kind, client)
    finally:
        await close(kind, client)
        runtime.close()
    assert method.create_credential.await_count == 3


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_repeated_challenge_and_redirect_never_pay_twice(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    mode = "repeat"

    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "repeat":
            return required("repeat")
        if request.url.path == "/first":
            return (
                httpx.Response(302, headers={"location": "/second"})
                if "authorization" in request.headers
                else required("first")
            )
        return required("second")

    client = make_client(kind, runtime, handler, follow_redirects=True)
    try:
        with pytest.raises(PaymentOutcomeUnknownError):
            await send(kind, client)
        runtime.reset_unknown_outcomes(reconciled=True)
        mode = "redirect"
        response = await send(kind, client, url="https://example.com/first")
        assert response.status_code == 402
    finally:
        await close(kind, client)
        runtime.close()
    assert method.create_credential.await_count == 2


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_nested_hook_send_is_a_fresh_operation(kind: Kind) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method])
    client: httpx.Client | httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return (
            httpx.Response(200, content=request.url.path.encode())
            if "authorization" in request.headers
            else required(request.url.path)
        )

    if kind == "sync":

        def sync_hook(response: httpx.Response) -> None:
            if response.request.url.path == "/outer":
                assert cast(httpx.Client, client).get("https://example.com/inner").is_success

        hook = sync_hook
    else:

        async def async_hook(response: httpx.Response) -> None:
            if response.request.url.path == "/outer":
                nested = await cast(httpx.AsyncClient, client).get("https://example.com/inner")
                assert nested.is_success

        hook = async_hook
    client = make_client(kind, runtime, handler, event_hooks={"response": [hook]})
    try:
        assert (await send(kind, client, url="https://example.com/outer")).is_success
    finally:
        await close(kind, client)
        runtime.close()
    assert method.create_credential.await_count == 2


def test_idempotence_signatures_and_stale_adapter_rejection() -> None:
    runtime = OwnedPaymentRuntime()
    other = OwnedPaymentRuntime()
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    signatures = (
        inspect.signature(client._send_single_request),
        inspect.signature(client._send_handling_auth),
    )
    original_public = inspect.getattr_static(client, "send")
    client = runtime.wrap_client(client)
    private = inspect.getattr_static(client, "_send_single_request")
    auth = inspect.getattr_static(client, "_send_handling_auth")
    try:
        assert runtime.wrap_client(client) is client
        assert inspect.signature(client._send_single_request) == signatures[0]
        assert inspect.signature(client._send_handling_auth) == signatures[1]
        assert inspect.getattr_static(client, "send") is original_public
        with pytest.raises(RuntimeError, match="another payment runtime"):
            other.wrap_client(client)
        client._send_single_request = lambda _request: httpx.Response(200)  # type: ignore[method-assign]
        with pytest.raises(HttpxCompatibilityError, match="replaced"):
            runtime.wrap_client(client)
    finally:
        client._send_single_request = private
        client._send_handling_auth = auth
        client.close()
        runtime.close()
        other.close()


def test_concurrent_rebind_has_one_fixed_runtime() -> None:
    methods = [Method(), Method()]
    runtimes = [OwnedPaymentRuntime([method]) for method in methods]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200) if "authorization" in request.headers else required()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    barrier = threading.Barrier(3)
    outcomes: list[int | Exception] = []

    def bind(index: int) -> None:
        barrier.wait()
        try:
            runtimes[index].wrap_client(client)
            outcomes.append(index)
        except Exception as error:
            outcomes.append(error)

    threads = [threading.Thread(target=bind, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    try:
        assert client.get("https://example.com").is_success
    finally:
        client.close()
        for runtime in runtimes:
            runtime.close()

    winner = next(cast(int, value) for value in outcomes if isinstance(value, int))
    assert sum(isinstance(value, RuntimeError) for value in outcomes) == 1
    assert methods[winner].create_credential.await_count == 1
    assert methods[1 - winner].create_credential.await_count == 0


def test_compatibility_failures_do_not_mutate_client(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = OwnedPaymentRuntime()
    client = httpx.Client()
    before = {
        name: inspect.getattr_static(client, name)
        for name in ("_send_handling_auth", "_send_single_request")
    }
    monkeypatch.setattr(httpx_adapter, "version", lambda _: "0.29.0")
    try:
        with pytest.raises(HttpxCompatibilityError, match=r">=0.27,<0.29"):
            runtime.wrap_client(client)
    finally:
        client.close()
        runtime.close()
    assert HTTPX_ADAPTER_VERSIONS == ">=0.27,<0.29"
    assert all(inspect.getattr_static(client, name) is value for name, value in before.items())
    assert httpx_adapter._MARKER not in client.__dict__


def test_seam_and_assignment_failures_roll_back() -> None:
    runtime = OwnedPaymentRuntime()
    client = httpx.Client()
    original_private = inspect.getattr_static(client, "_send_single_request")

    def incompatible(request: httpx.Request, extra: object) -> httpx.Response:
        raise AssertionError

    client._send_single_request = incompatible  # type: ignore[method-assign]
    with pytest.raises(HttpxCompatibilityError, match="instance._send_single_request"):
        runtime.wrap_client(client)
    assert inspect.getattr_static(client, "_send_single_request") is incompatible
    client._send_single_request = original_private
    client.close()

    class RejectingClient(httpx.Client):
        def __setattr__(self, name: str, value: object) -> None:
            if name == httpx_adapter._MARKER:
                raise RuntimeError("assignment rejected")
            super().__setattr__(name, value)

    rejecting = RejectingClient()
    before = {
        name: inspect.getattr_static(rejecting, name)
        for name in ("_send_handling_auth", "_send_single_request")
    }
    try:
        with pytest.raises(RuntimeError, match="assignment rejected"):
            runtime.wrap_client(rejecting)
    finally:
        rejecting.close()
        runtime.close()
    assert all(inspect.getattr_static(rejecting, name) is value for name, value in before.items())
    assert httpx_adapter._MARKER not in rejecting.__dict__
