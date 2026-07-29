from __future__ import annotations

import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, Literal, cast
from unittest.mock import AsyncMock

import httpx
import pytest

import mpp._httpx as httpx_adapter
import mpp.instrumentation as instrumentation
from mpp import Challenge, Credential
from mpp.instrumentation import instrument
from mpp.runtime import OwnedPaymentRuntime, PaymentRuntime

Kind = Literal["sync", "async"]
SEAMS = (
    (httpx.Client, "_send_handling_auth"),
    (httpx.Client, "_send_single_request"),
    (httpx.AsyncClient, "_send_handling_auth"),
    (httpx.AsyncClient, "_send_single_request"),
)


@pytest.fixture(autouse=True)
def restore_httpx_classes():
    originals = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    yield
    instrumentation._binding = None
    for (owner, name), original in zip(SEAMS, originals, strict=True):
        setattr(owner, name, original)


class Method:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.create_credential = AsyncMock(side_effect=self._create_credential)

    async def _create_credential(self, challenge: Challenge) -> Credential:
        return Credential(challenge=challenge.to_echo(), payload={"hash": "0xabc"})


class TwoRequestAuth(httpx.Auth):
    def auth_flow(self, request: httpx.Request):
        response = yield request
        assert response.status_code == 200
        yield httpx.Request("GET", "https://example.com/second")


def required(challenge_id: str = "challenge") -> httpx.Response:
    challenge = Challenge(id=challenge_id, method="tempo", intent="charge", request={})
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
    )


def handler(request: httpx.Request) -> httpx.Response:
    if request.headers.get("authorization", "").startswith("Payment "):
        return httpx.Response(200, content=b"paid")
    return required(request.url.path)


def make_client(kind: Kind, **kwargs: Any) -> httpx.Client | httpx.AsyncClient:
    client = httpx.Client if kind == "sync" else httpx.AsyncClient
    return client(transport=httpx.MockTransport(handler), **kwargs)


async def get(kind: Kind, client: httpx.Client | httpx.AsyncClient) -> httpx.Response:
    if kind == "sync":
        return cast(httpx.Client, client).get("https://example.com/paid")
    return await cast(httpx.AsyncClient, client).get("https://example.com/paid")


async def close(kind: Kind, client: httpx.Client | httpx.AsyncClient) -> None:
    if kind == "sync":
        cast(httpx.Client, client).close()
    else:
        await cast(httpx.AsyncClient, client).aclose()


async def test_global_sync_async_and_raw_thread() -> None:
    originals = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    signatures = tuple(inspect.signature(value) for value in originals)
    thread_start = threading.Thread.start
    executor_submit = ThreadPoolExecutor.submit
    method = Method()
    runtime = OwnedPaymentRuntime([method], allowed_origins=["https://example.com"])
    handle = instrument(runtime)
    statuses: list[int] = []

    def in_thread() -> None:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            statuses.append(client.get("https://example.com/paid").status_code)

    worker = threading.Thread(target=in_thread)
    worker.start()
    worker.join()
    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            statuses.append((await client.get("https://example.com/paid")).status_code)
        patched = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
        assert all(
            current is not original for current, original in zip(patched, originals, strict=True)
        )
        assert tuple(inspect.signature(value) for value in patched) == signatures
        assert threading.Thread.start is thread_start
        assert ThreadPoolExecutor.submit is executor_submit
    finally:
        handle.disable()
        runtime.close()

    assert statuses == [200, 200]
    assert method.create_credential.await_count == 2
    assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == originals


def test_origin_policy_lazy_start_and_unrestricted_opt_in() -> None:
    originals = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    unrestricted = OwnedPaymentRuntime()
    with pytest.raises(ValueError, match="allowed_origins"):
        instrument(unrestricted)
    assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == originals
    instrument(unrestricted, allow_unrestricted=True).disable()
    unrestricted.close()

    entered: list[bool] = []

    @asynccontextmanager
    async def factory():
        entered.append(True)
        yield Method()

    runtime = OwnedPaymentRuntime(
        method_factories=[factory],
        allowed_origins=["https://allowed.example"],
    )
    handle = instrument(runtime)
    try:
        with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
            assert client.get("https://allowed.example/free").status_code == 200
        with httpx.Client(transport=httpx.MockTransport(lambda _: required())) as client:
            assert client.get("https://blocked.example/paid").status_code == 402
        assert entered == []
    finally:
        handle.disable()
        handle.disable()
        runtime.close()

    with pytest.raises(TypeError, match="OwnedPaymentRuntime"):
        instrument(cast(Any, PaymentRuntime()))


def test_reference_count_context_manager_and_runtime_exclusivity() -> None:
    runtime = OwnedPaymentRuntime(allowed_origins=[])
    other = OwnedPaymentRuntime(allowed_origins=[])
    first = instrument(runtime)
    second = instrument(runtime)
    wrappers = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    try:
        with pytest.raises(RuntimeError, match="Another payment runtime"):
            instrument(other)
        first.disable()
        first.disable()
        assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == wrappers
        second.disable()
        restored = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
        assert restored != wrappers
        with instrument(runtime):
            assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) != restored
        assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == restored
    finally:
        first.disable()
        second.disable()
        runtime.close()
        other.close()


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_per_client_adapter_overrides_global(kind: Kind) -> None:
    global_method = Method()
    local_method = Method()
    global_runtime = OwnedPaymentRuntime(
        [global_method],
        allowed_origins=["https://example.com"],
    )
    local_runtime = OwnedPaymentRuntime(
        [local_method],
        allowed_origins=["https://example.com"],
    )
    handle = instrument(global_runtime)
    client = make_client(kind)
    client = (
        local_runtime.wrap_client(cast(httpx.Client, client))
        if kind == "sync"
        else local_runtime.wrap_async_client(cast(httpx.AsyncClient, client))
    )
    try:
        assert (await get(kind, client)).status_code == 200
    finally:
        await close(kind, client)
        handle.disable()
        global_runtime.close()
        local_runtime.close()
    global_method.create_credential.assert_not_awaited()
    local_method.create_credential.assert_awaited_once()


async def test_method_internal_httpx_is_not_recursively_instrumented() -> None:
    internal_statuses: list[int] = []

    class RecursiveMethod:
        name = "tempo"
        _intents = {"charge": True}

        async def create_credential(self, challenge: Challenge) -> Credential:
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _: required("internal"))
            ) as client:
                internal_statuses.append(
                    (await client.get("https://example.com/internal")).status_code
                )
            return Credential(challenge=challenge.to_echo(), payload={})

    method = RecursiveMethod()
    runtime = OwnedPaymentRuntime([method], allowed_origins=["https://example.com"])
    try:
        with instrument(runtime):
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                assert client.get("https://example.com/paid").status_code == 200
    finally:
        runtime.close()
    assert internal_statuses == [402]


def test_factory_internal_httpx_is_not_recursively_instrumented() -> None:
    internal_statuses: list[int] = []

    @asynccontextmanager
    async def factory():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: required("internal"))
        ) as client:
            internal_statuses.append((await client.get("https://example.com/enter")).status_code)
            try:
                yield Method()
            finally:
                internal_statuses.append((await client.get("https://example.com/exit")).status_code)

    runtime = OwnedPaymentRuntime(
        method_factories=[factory],
        allowed_origins=["https://example.com"],
    )
    try:
        with instrument(runtime):
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                assert client.get("https://example.com/paid").status_code == 200
            runtime.close()
    finally:
        runtime.close()
    assert internal_statuses == [402, 402]


@pytest.mark.parametrize("kind", ["sync", "async"])
@pytest.mark.parametrize("cached", [False, True], ids=["lookup", "cached"])
async def test_one_global_send_never_pays_twice(kind: Kind, cached: bool) -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method], allowed_origins=["https://example.com"])
    client = make_client(kind, auth=TwoRequestAuth())
    cached_send: Any = client.send
    try:
        with instrument(runtime):
            if cached:
                response = cached_send(client.build_request("GET", "https://example.com/paid"))
                if kind == "async":
                    response = await response
            else:
                response = await get(kind, client)
    finally:
        await close(kind, client)
        runtime.close()
    assert response.status_code == 402
    method.create_credential.assert_awaited_once()


def test_redirected_send_has_one_payment_budget() -> None:
    method = Method()
    runtime = OwnedPaymentRuntime([method], allowed_origins=["https://example.com"])

    def redirect(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/first":
            if request.headers.get("authorization", "").startswith("Payment "):
                return httpx.Response(302, headers={"location": "/second"})
            return required("first")
        return required("second")

    try:
        with instrument(runtime):
            with httpx.Client(
                transport=httpx.MockTransport(redirect),
                follow_redirects=True,
            ) as client:
                assert client.get("https://example.com/first").status_code == 402
    finally:
        runtime.close()
    method.create_credential.assert_awaited_once()


def test_validation_and_install_failure_leave_httpx_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    originals = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    runtime = OwnedPaymentRuntime(allowed_origins=[])
    monkeypatch.setattr(httpx_adapter, "version", lambda _: "0.29.0")
    with pytest.raises(httpx_adapter.HttpxCompatibilityError):
        instrument(runtime)
    assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == originals
    monkeypatch.undo()

    calls = 0

    def fail_once(owner: type[Any], name: str, value: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            setattr(owner, name, value)
            raise RuntimeError("assignment failed")
        setattr(owner, name, value)

    monkeypatch.setattr(instrumentation, "_assign", fail_once)
    with pytest.raises(RuntimeError, match="assignment failed"):
        instrument(runtime)
    assert instrumentation._binding is None
    assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == originals
    runtime.close()


def test_restore_is_transactional_and_preserves_later_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = OwnedPaymentRuntime(allowed_origins=[])
    handle = instrument(runtime)
    wrappers = tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS)
    calls = 0

    def fail_once(owner: type[Any], name: str, value: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            setattr(owner, name, value)
            raise RuntimeError("restore failed")
        setattr(owner, name, value)

    monkeypatch.setattr(instrumentation, "_assign", fail_once)
    with pytest.raises(RuntimeError, match="restore failed"):
        handle.disable()
    assert tuple(inspect.getattr_static(owner, name) for owner, name in SEAMS) == wrappers
    monkeypatch.setattr(instrumentation, "_assign", setattr)

    wrapped_auth = httpx.Client._send_handling_auth

    @wraps(wrapped_auth)
    def third_party(client: httpx.Client, *args: Any, **kwargs: Any) -> httpx.Response:
        return wrapped_auth(client, *args, **kwargs)

    httpx.Client._send_handling_auth = third_party  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="modified while active"):
        instrument(runtime)
    handle.disable()
    try:
        assert httpx.Client._send_handling_auth is third_party
        with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
            assert client.get("https://example.com/free").status_code == 200
    finally:
        runtime.close()
