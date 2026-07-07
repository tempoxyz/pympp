"""Shared payment runtime for HTTP and MCP clients."""

from __future__ import annotations

import asyncio
import threading
from contextvars import ContextVar, copy_context
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, runtime_checkable
from urllib.parse import urlparse

import httpx

from mpp import Challenge, Credential
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    PAYMENT_FAILED,
    PAYMENT_RESPONSE,
    EventDispatcher,
    EventPayload,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Sequence

    from mpp.client import PaymentTransport, SyncPaymentTransport

_T = TypeVar("_T")
_PAYMENT_FLOW_ACTIVE: ContextVar[bool] = ContextVar("mpp_payment_flow_active", default=False)
_MCP_FLOW_ACTIVE: ContextVar[bool] = ContextVar("mpp_mcp_flow_active", default=False)
_payment_flow_count = 0
_payment_flow_lock = threading.Lock()


def payment_flow_active() -> bool:
    """Return whether the current context is creating a payment credential."""
    return _PAYMENT_FLOW_ACTIVE.get()


def payment_flow_active_in_process() -> bool:
    """Return whether any context is creating a payment credential."""
    with _payment_flow_lock:
        return _payment_flow_count > 0


def mcp_payment_flow_active() -> bool:
    """Return whether the current context is inside an MCP payment adapter."""
    return _MCP_FLOW_ACTIVE.get()


@runtime_checkable
class Method(Protocol):
    """Payment method interface for client-side credential creation."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge."""
        ...


class _BoundSendTransport(httpx.AsyncBaseTransport):
    def __init__(self, send: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        self._send = send
        self._args = args
        self._kwargs = kwargs

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        kwargs = dict(self._kwargs)
        if request.headers.get("authorization", "").startswith("Payment "):
            kwargs["auth"] = None
        return await self._send(request, *self._args, **kwargs)

    async def aclose(self) -> None:
        return None


class _BoundSyncSendTransport(httpx.BaseTransport):
    def __init__(self, send: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        self._send = send
        self._args = args
        self._kwargs = kwargs

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        kwargs = dict(self._kwargs)
        if request.headers.get("authorization", "").startswith("Payment "):
            kwargs["auth"] = None
        return self._send(request, *self._args, **kwargs)

    def close(self) -> None:
        return None


class _AsyncBridge:
    """Own one lazy event loop for synchronous payment-method calls."""

    def __init__(self) -> None:
        self._closed = False
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._start_error: BaseException | None = None
        self._thread: threading.Thread | None = None

    def _submit(self, coroutine: Coroutine[Any, Any, _T]) -> Any:
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="pympp-payment-runtime",
                    daemon=True,
                )
                self._thread.start()
        self._ready.wait()
        with self._lock:
            if self._closed:
                raise RuntimeError("PaymentRuntime is closed")
            if self._start_error is not None:
                raise RuntimeError("PaymentRuntime background loop failed to start") from (
                    self._start_error
                )
            if self._loop is None:
                raise RuntimeError("PaymentRuntime background loop failed to start")
            if threading.current_thread() is self._thread:
                raise RuntimeError("Cannot block the PaymentRuntime background loop")
            return copy_context().run(
                asyncio.run_coroutine_threadsafe,
                coroutine,
                self._loop,
            )

    def _run(self) -> None:
        try:
            loop = asyncio.new_event_loop()
        except BaseException as error:
            self._start_error = error
            self._ready.set()
            return
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def run(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run an async payment operation from synchronous code."""
        try:
            future = self._submit(coroutine)
        except BaseException:
            coroutine.close()
            raise
        try:
            return future.result()
        except BaseException:
            future.cancel()
            raise

    async def _cancel_pending(self) -> None:
        current = asyncio.current_task()
        pending = [task for task in asyncio.all_tasks() if task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def close(self) -> None:
        """Stop the runtime loop, if it was started."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            thread = self._thread
        if thread is None:
            return
        if self._loop is None:
            self._ready.wait()
        loop = self._loop
        if loop is None:
            thread.join()
            return
        if threading.current_thread() is thread:

            async def shutdown() -> None:
                await self._cancel_pending()
                loop.stop()

            loop.create_task(shutdown())
            return
        if thread.is_alive():
            future = asyncio.run_coroutine_threadsafe(self._cancel_pending(), loop)
            future.result()
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        thread.join()


class PaymentRuntime:
    """Reusable payment runtime for HTTP and MCP payment handling."""

    def __init__(
        self,
        methods: Sequence[Method],
        *,
        events: EventDispatcher | None = None,
        allowed_origins: Sequence[str] | None = None,
    ) -> None:
        self.methods = tuple(methods)
        self.events = events or EventDispatcher()
        self._allowed = _AllowedOrigins(allowed_origins)
        self._bridge = _AsyncBridge()

    def payment_transport(self, inner: httpx.AsyncBaseTransport | None = None) -> PaymentTransport:
        """Create an httpx transport using this runtime's payment methods."""
        from mpp.client import PaymentTransport

        return PaymentTransport(
            inner=inner,
            runtime=self,
        )

    def sync_payment_transport(
        self, inner: httpx.BaseTransport | None = None
    ) -> SyncPaymentTransport:
        """Create a synchronous httpx transport using this runtime."""
        from mpp.client import SyncPaymentTransport

        return SyncPaymentTransport(inner=inner, runtime=self)

    def wrap_client(self, client: httpx.Client) -> httpx.Client:
        """Make one existing Client payment-aware without global instrumentation."""
        client._mpp_payment_runtime = self  # type: ignore[attr-defined]
        if getattr(client, "_mpp_payment_wrapped", False):
            return client

        original_send = client.send

        def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            return runtime.send_httpx_sync(original_send, request, *args, **kwargs)

        client._mpp_payment_original_send = original_send  # type: ignore[attr-defined]
        client._mpp_payment_wrapped = True  # type: ignore[attr-defined]
        client.send = send  # type: ignore[method-assign]
        return client

    def wrap_async_client(self, client: httpx.AsyncClient) -> httpx.AsyncClient:
        """Make one existing AsyncClient payment-aware without global instrumentation."""
        client._mpp_payment_runtime = self  # type: ignore[attr-defined]
        if getattr(client, "_mpp_payment_wrapped", False):
            return client

        original_send = client.send

        async def send(request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
            runtime = getattr(client, "_mpp_payment_runtime", self)
            return await runtime.send_httpx(original_send, request, *args, **kwargs)

        client._mpp_payment_original_send = original_send  # type: ignore[attr-defined]
        client._mpp_payment_wrapped = True  # type: ignore[attr-defined]
        client.send = send  # type: ignore[method-assign]
        return client

    def httpx_client_factory(
        self,
        base_factory: Any = httpx.AsyncClient,
    ) -> Callable[..., httpx.AsyncClient]:
        """Return an AsyncClient factory suitable for MCP SDK framework hooks."""

        def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            return self.wrap_async_client(base_factory(*args, **kwargs))

        return factory

    async def send_httpx(
        self,
        send: Any,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send one httpx request with automatic 402 payment handling."""
        transport = _BoundSendTransport(send, args, dict(kwargs))
        return await self.payment_transport(inner=transport).handle_async_request(request)

    def send_httpx_sync(
        self,
        send: Any,
        request: httpx.Request,
        *args: Any,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send one sync httpx request with automatic 402 payment handling."""
        transport = _BoundSyncSendTransport(send, args, dict(kwargs))
        return self.sync_payment_transport(inner=transport).handle_request(request)

    async def call_mcp_tool(
        self,
        call_tool: Any,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call an MCP tool with automatic payment handling, preserving result type."""
        token = _MCP_FLOW_ACTIVE.set(True)
        try:
            return await self._call_mcp_tool(call_tool, name, arguments, *args, **kwargs)
        finally:
            _MCP_FLOW_ACTIVE.reset(token)

    async def _call_mcp_tool(
        self,
        call_tool: Any,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        from mpp.extensions.mcp.client import (
            PaymentOutcomeUnknownError,
            _extract_challenges,
            _extract_result_challenges,
            _is_payment_required_error,
        )
        from mpp.extensions.mcp.types import MCPCredential

        try:
            result = await call_tool(name, arguments, *args, **kwargs)
        except Exception as error:
            if not _is_payment_required_error(error):
                raise
            challenges = _extract_challenges(error)
            cause: Any = error
        else:
            challenges = _extract_result_challenges(result)
            if not challenges:
                return result
            cause = result

        allowed_challenges = [
            challenge for challenge in challenges if self._allowed.mcp_realm(challenge.realm)
        ]
        if not allowed_challenges:
            error = ValueError(
                "Server returned malformed payment challenges or disallowed payment origins"
            )
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": None,
                    "challenges": [],
                    "credential": None,
                    "error": error,
                    "method": None,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            if isinstance(cause, Exception):
                raise error from cause
            raise error

        try:
            challenge, method = self.match_challenge(allowed_challenges)
            core_challenges = [item.to_core() for item in allowed_challenges]
            core_challenge = challenge.to_core()
            core_credential = await self.create_credential(
                core_challenge,
                method,
                event_payload={
                    "challenges": core_challenges,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            mcp_credential = MCPCredential.from_core(core_credential, challenge)
        except Exception as error:
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": locals().get("core_challenge"),
                    "challenges": locals().get("core_challenges", []),
                    "credential": None,
                    "error": error,
                    "method": locals().get("method"),
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            raise

        retry_kwargs = dict(kwargs)
        retry_meta = dict(retry_kwargs.get("meta") or {})
        retry_meta.update(mcp_credential.to_meta())
        retry_kwargs["meta"] = retry_meta

        try:
            payment_response = await call_tool(name, arguments, *args, **retry_kwargs)
        except Exception as error:
            outcome_error = PaymentOutcomeUnknownError(challenge, error)
            await self.emit_event(
                PAYMENT_FAILED,
                {
                    "challenge": core_challenge,
                    "challenges": core_challenges,
                    "credential": core_credential,
                    "error": outcome_error,
                    "method": method,
                    "response": cause,
                    "protocol": "mcp",
                },
            )
            raise outcome_error from error

        await self.emit_event(
            PAYMENT_RESPONSE,
            {
                "challenge": core_challenge,
                "challenges": core_challenges,
                "credential": core_credential,
                "method": method,
                "response": payment_response,
                "protocol": "mcp",
            },
        )
        return payment_response

    def match_challenge(
        self,
        challenges: list[Any],
        *,
        prefer_method_order: bool = True,
    ) -> tuple[Any, Method]:
        """Match payment challenges against configured methods."""
        if prefer_method_order:
            for method in self.methods:
                for challenge in challenges:
                    if challenge.method != method.name:
                        continue
                    if challenge.intent not in _intent_names(method):
                        continue
                    return challenge, method
        else:
            for challenge in challenges:
                for method in self.methods:
                    if challenge.method != method.name:
                        continue
                    if challenge.intent not in _intent_names(method):
                        continue
                    return challenge, method

        available = [challenge.method for challenge in challenges]
        installed = [method.name for method in self.methods]
        raise ValueError(
            f"No compatible payment method. Server offered: {available}, client has: {installed}"
        )

    def match_mcp_challenge(self, challenges: list[Any]) -> tuple[Any, Method]:
        """Match MCP payment challenges against configured methods."""
        return self.match_challenge(challenges)

    async def create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Create a credential on the caller event loop."""
        return await self._create_credential(challenge, method, event_payload=event_payload)

    def create_credential_sync(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        """Synchronously create a credential on the runtime-owned event loop."""
        return self._bridge.run(
            self._create_credential(challenge, method, event_payload=event_payload)
        )

    async def _create_credential(
        self,
        challenge: Challenge,
        method: Method,
        *,
        event_payload: dict[str, Any] | None = None,
    ) -> Credential:
        global _payment_flow_count

        token = _PAYMENT_FLOW_ACTIVE.set(True)
        with _payment_flow_lock:
            _payment_flow_count += 1
        try:
            payload = {
                "challenge": challenge,
                "challenges": [challenge],
                "method": method,
                **(event_payload or {}),
            }
            event_credential = await self.events.emit(
                CHALLENGE_RECEIVED,
                payload,
                first_result=True,
            )
            credential = (
                event_credential
                if isinstance(event_credential, Credential)
                else await method.create_credential(challenge)
            )
            await self.events.emit(
                CREDENTIAL_CREATED,
                {**payload, "credential": credential},
            )
            return credential
        finally:
            with _payment_flow_lock:
                _payment_flow_count -= 1
            _PAYMENT_FLOW_ACTIVE.reset(token)

    async def emit_event(self, name: str, payload: EventPayload) -> Any:
        """Emit an asynchronous lifecycle event on the caller event loop."""
        return await self.events.emit(name, payload)

    def emit_event_sync(self, name: str, payload: EventPayload) -> Any:
        """Synchronously emit a lifecycle event on the runtime-owned event loop."""
        return self._bridge.run(self.events.emit(name, payload))

    def close(self) -> None:
        """Release the runtime background loop."""
        self._bridge.close()

    async def aclose(self) -> None:
        """Asynchronously release the runtime background loop."""
        await asyncio.to_thread(self.close)

    def allows_http_payment(self, url: httpx.URL) -> bool:
        """Return whether credentials may be created for an HTTP origin."""
        return self._allowed.http_url(url)


def _intent_names(method: Method) -> set[str]:
    intents = getattr(method, "intents", None) or getattr(method, "_intents", None)
    if isinstance(intents, dict):
        return set(intents.keys())
    return {"charge"}


class _AllowedOrigins:
    def __init__(self, allowed_origins: Sequence[str] | None) -> None:
        self._allow_all = allowed_origins is None
        self._origins = set[str]()
        self._realms = set[str]()
        if allowed_origins is None:
            return
        for value in allowed_origins:
            parsed = urlparse(str(value))
            if parsed.scheme and parsed.netloc:
                self._origins.add(f"{parsed.scheme}://{parsed.netloc}")
            else:
                self._realms.add(str(value))

    def http_url(self, url: httpx.URL) -> bool:
        if self._allow_all:
            return True
        origin = f"{url.scheme}://{url.host}"
        if url.port is not None:
            origin = f"{origin}:{url.port}"
        return origin in self._origins or url.host in self._realms

    def mcp_realm(self, realm: str) -> bool:
        if self._allow_all:
            return True
        parsed = urlparse(realm)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            return origin in self._origins or parsed.netloc in self._realms
        return realm in self._realms
