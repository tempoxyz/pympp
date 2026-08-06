"""Sync and async HTTPX transports that drive Tempo session payments."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from collections.abc import Coroutine
from contextlib import suppress
from typing import Any, TypeVar

import httpx

from mpp import Challenge
from mpp._parsing import ParseError
from mpp.client.transport import _payment_challenges

from .manager import (
    SessionRecoveryRequiredError,
    TempoSessionManager,
    is_tip1034_session_challenge,
)
from .models import SessionSnapshot
from .protocol import decode_session_snapshot
from .sse import NeedVoucherEvent, SseParser, parse_need_voucher, parse_receipt

_T = TypeVar("_T")


def _run_sync(coroutine: Coroutine[Any, Any, _T]) -> _T:
    """Run manager IO from a sync HTTPX path, including inside a live loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    result: list[_T] = []
    failure: list[BaseException] = []
    context = contextvars.copy_context()

    def run() -> None:
        try:
            result.append(context.run(asyncio.run, coroutine))
        except BaseException as error:
            failure.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join()
    if failure:
        raise failure[0]
    return result[0]


def _session_challenge(response: httpx.Response) -> Challenge | None:
    for header in response.headers.get_list("www-authenticate"):
        for field in _payment_challenges(header):
            try:
                challenge = Challenge.from_www_authenticate(field)
            except ParseError:
                continue
            if is_tip1034_session_challenge(challenge):
                return challenge
    return None


def _snapshot(response: httpx.Response) -> SessionSnapshot | None:
    value = response.headers.get("payment-session-snapshot")
    return None if value is None else decode_session_snapshot(value)


def _copy_request(
    request: httpx.Request,
    *,
    authorization: str | None = None,
    channel_id: str | None = None,
    management: bool = False,
) -> httpx.Request:
    headers = httpx.Headers(request.headers)
    if "text/event-stream" in headers.get("accept", "").lower():
        # Session control frames must be parsed before HTTPX's response decoder
        # runs, so ask the server for an uncompressed event stream.
        headers["accept-encoding"] = "identity"
    if authorization is not None:
        headers["Authorization"] = authorization
    if channel_id is not None and "Payment-Session" not in headers:
        headers["Payment-Session"] = channel_id
    method = request.method
    content = request.content
    if management:
        method = "POST"
        content = b""
        for name in ("content-length", "content-type", "transfer-encoding"):
            headers.pop(name, None)
    return httpx.Request(
        method=method,
        url=request.url,
        headers=headers,
        content=content,
        extensions=dict(request.extensions),
    )


def _close_probe(channel_id: str, resource_url: str) -> httpx.Request:
    return httpx.Request(
        "HEAD",
        resource_url,
        headers={"Payment-Session": channel_id},
    )


def _is_event_stream(response: httpx.Response) -> bool:
    return response.headers.get("content-type", "").lower().startswith("text/event-stream")


def _accepts_event_stream(request: httpx.Request) -> bool:
    return "text/event-stream" in request.headers.get("accept", "").lower()


class _AsyncSessionStream(httpx.AsyncByteStream):
    def __init__(
        self,
        stream: httpx.AsyncByteStream,
        *,
        manager: TempoSessionManager,
        on_need_voucher: Any,
    ) -> None:
        self._stream = stream
        self._manager = manager
        self._on_need_voucher = on_need_voucher

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        parser = SseParser()
        async for chunk in self._stream:
            for frame in parser.feed(chunk):
                event = parse_need_voucher(frame)
                receipt = parse_receipt(frame)
                if event is not None:
                    await self._on_need_voucher(event)
                elif receipt is not None:
                    await self._manager.observe_stream_receipt(receipt)
                else:
                    yield frame.raw.encode()
        for frame in parser.feed(b"", final=True):
            event = parse_need_voucher(frame)
            receipt = parse_receipt(frame)
            if event is not None:
                await self._on_need_voucher(event)
            elif receipt is not None:
                await self._manager.observe_stream_receipt(receipt)
            else:
                yield frame.raw.encode()

    async def aclose(self) -> None:
        await self._stream.aclose()


class _SyncSessionStream(httpx.SyncByteStream):
    def __init__(
        self,
        stream: httpx.SyncByteStream,
        *,
        manager: TempoSessionManager,
        on_need_voucher: Any,
    ) -> None:
        self._stream = stream
        self._manager = manager
        self._on_need_voucher = on_need_voucher

    def __iter__(self):  # type: ignore[no-untyped-def]
        parser = SseParser()
        for chunk in self._stream:
            for frame in parser.feed(chunk):
                event = parse_need_voucher(frame)
                receipt = parse_receipt(frame)
                if event is not None:
                    self._on_need_voucher(event)
                elif receipt is not None:
                    _run_sync(self._manager.observe_stream_receipt(receipt))
                else:
                    yield frame.raw.encode()
        for frame in parser.feed(b"", final=True):
            event = parse_need_voucher(frame)
            receipt = parse_receipt(frame)
            if event is not None:
                self._on_need_voucher(event)
            elif receipt is not None:
                _run_sync(self._manager.observe_stream_receipt(receipt))
            else:
                yield frame.raw.encode()

    def close(self) -> None:
        self._stream.close()


class AsyncSessionPaymentTransport(httpx.AsyncBaseTransport):
    """HTTPX async transport with restart-safe TIP-1034 session handling."""

    def __init__(
        self,
        manager: TempoSessionManager,
        *,
        inner: httpx.AsyncBaseTransport | None = None,
        max_rounds: int = 8,
    ) -> None:
        self.manager = manager
        self.inner = inner or httpx.AsyncHTTPTransport()
        self.max_rounds = max_rounds

    async def _management(
        self,
        original: httpx.Request,
        challenge: Challenge,
        event: NeedVoucherEvent,
        expected_channel_id: str,
    ) -> None:
        if event.channel_id != expected_channel_id.lower():
            raise ValueError("payment-need-voucher channel does not match the stream")
        await self.manager.observe_need_voucher(event)
        current = challenge
        for _ in range(self.max_rounds):
            credential = await self.manager.prepare(
                current,
                resource_url=str(original.url),
                required_cumulative=event.required_cumulative,
            )
            request = _copy_request(
                original,
                authorization=credential.to_authorization(),
                channel_id=event.channel_id,
                management=True,
            )
            try:
                response = await self.inner.handle_async_request(request)
            except BaseException:
                await self.manager.handle_unknown(credential)
                raise
            await response.aread()
            await self.manager.handle_response(
                credential,
                status_code=response.status_code,
                headers=response.headers,
            )
            action = credential.payload.get("action")
            if response.is_success and action == "voucher":
                return
            if response.is_success and action == "topUp":
                continue
            if response.status_code == 402:
                refreshed = _session_challenge(response)
                if refreshed is not None:
                    current = refreshed
                    continue
            raise SessionRecoveryRequiredError(
                f"session management request failed with status {response.status_code}"
            )
        raise SessionRecoveryRequiredError("session management retry limit exceeded")

    def _wrap_sse(
        self,
        response: httpx.Response,
        original: httpx.Request,
        challenge: Challenge,
        channel_id: str,
    ) -> httpx.Response:
        if not _is_event_stream(response):
            return response
        if not isinstance(response.stream, httpx.AsyncByteStream):
            return response
        response.headers.pop("content-length", None)
        response.stream = _AsyncSessionStream(
            response.stream,
            manager=self.manager,
            on_need_voucher=lambda event: self._management(original, challenge, event, channel_id),
        )
        return response

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        replayable = not (
            isinstance(request.stream, httpx.AsyncByteStream)
            and not isinstance(request.stream, httpx.SyncByteStream)
        )
        if replayable:
            await request.aread()
        hint = await self.manager.session_hint(str(request.url))
        if replayable:
            initial = _copy_request(request, channel_id=hint)
        else:
            if hint is not None and "Payment-Session" not in request.headers:
                request.headers["Payment-Session"] = hint
            initial = request
        response = await self.inner.handle_async_request(initial)
        if response.status_code != 402:
            return response
        return await self.handle_payment_required(
            request,
            response,
            replayable=replayable,
        )

    async def handle_payment_required(
        self,
        request: httpx.Request,
        response: httpx.Response,
        *,
        replayable: bool = True,
    ) -> httpx.Response:
        """Drive an already-received 402, for integration with `PaymentTransport`."""

        if not replayable:
            await response.aclose()
            raise ValueError(
                "streaming request bodies cannot be replayed after a session challenge"
            )

        challenge: Challenge | None = None
        snapshot: SessionSnapshot | None = None
        for _ in range(self.max_rounds):
            if response.status_code == 402:
                await response.aread()
                challenge = _session_challenge(response)
                if challenge is None:
                    return response
                snapshot = _snapshot(response)
            assert challenge is not None
            credential = await self.manager.prepare(
                challenge,
                resource_url=str(request.url),
                snapshot=snapshot,
            )
            action = credential.payload.get("action")
            submit = _copy_request(
                request,
                authorization=credential.to_authorization(),
                channel_id=str(credential.payload["channelId"]),
                management=action == "topUp",
            )
            try:
                response = await self.inner.handle_async_request(submit)
            except BaseException:
                await self.manager.handle_unknown(credential)
                raise
            await self.manager.handle_response(
                credential,
                status_code=response.status_code,
                headers=response.headers,
            )
            if response.is_success and action == "topUp":
                await response.aread()
                snapshot = None
                continue
            if response.status_code == 402:
                continue
            if response.is_success:
                if (
                    action == "open"
                    and _accepts_event_stream(request)
                    and not _is_event_stream(response)
                ):
                    # A server may classify the open as a management-only
                    # request. Once its receipt commits the exact open, make a
                    # fresh hinted request so the next credential can serve
                    # the event stream, matching mppx's current SSE behavior.
                    await response.aread()
                    await response.aclose()
                    response = await self.inner.handle_async_request(
                        _copy_request(
                            request,
                            channel_id=str(credential.payload["channelId"]),
                        )
                    )
                    if response.status_code == 402:
                        snapshot = None
                        continue
                return self._wrap_sse(
                    response,
                    request,
                    challenge,
                    str(credential.payload["channelId"]),
                )
            return response
        raise SessionRecoveryRequiredError("session payment retry limit exceeded")

    async def close_session(self, channel_id: str, resource_url: str) -> httpx.Response:
        """Probe for a fresh challenge and cooperatively close a channel."""

        response = await self.inner.handle_async_request(_close_probe(channel_id, resource_url))
        current: Challenge | None = None
        for _ in range(self.max_rounds):
            if response.status_code == 402:
                await response.aread()
                current = _session_challenge(response)
            if current is None:
                raise SessionRecoveryRequiredError(
                    "session close probe did not return a tempo/session challenge"
                )
            credential = await self.manager.prepare_close(current, channel_id)
            request = _copy_request(
                httpx.Request("POST", resource_url),
                authorization=credential.to_authorization(),
                channel_id=channel_id,
                management=True,
            )
            try:
                response = await self.inner.handle_async_request(request)
            except BaseException:
                await self.manager.handle_unknown(credential)
                raise
            await self.manager.handle_response(
                credential,
                status_code=response.status_code,
                headers=response.headers,
            )
            action = credential.payload.get("action")
            if response.is_success and action != "close":
                await response.aread()
                response = await self.inner.handle_async_request(
                    _close_probe(channel_id, resource_url)
                )
                current = None
                continue
            if response.status_code != 402:
                return response
        raise SessionRecoveryRequiredError("session close retry limit exceeded")

    async def aclose(self) -> None:
        await self.inner.aclose()


class SessionPaymentTransport(httpx.BaseTransport):
    """HTTPX sync transport with the same session semantics as the async path."""

    def __init__(
        self,
        manager: TempoSessionManager,
        *,
        inner: httpx.BaseTransport | None = None,
        max_rounds: int = 8,
    ) -> None:
        self.manager = manager
        self.inner = inner or httpx.HTTPTransport()
        self.max_rounds = max_rounds

    def _management(
        self,
        original: httpx.Request,
        challenge: Challenge,
        event: NeedVoucherEvent,
        expected_channel_id: str,
    ) -> None:
        if event.channel_id != expected_channel_id.lower():
            raise ValueError("payment-need-voucher channel does not match the stream")
        _run_sync(self.manager.observe_need_voucher(event))
        current = challenge
        for _ in range(self.max_rounds):
            credential = _run_sync(
                self.manager.prepare(
                    current,
                    resource_url=str(original.url),
                    required_cumulative=event.required_cumulative,
                )
            )
            request = _copy_request(
                original,
                authorization=credential.to_authorization(),
                channel_id=event.channel_id,
                management=True,
            )
            try:
                response = self.inner.handle_request(request)
            except BaseException:
                _run_sync(self.manager.handle_unknown(credential))
                raise
            response.read()
            _run_sync(
                self.manager.handle_response(
                    credential,
                    status_code=response.status_code,
                    headers=response.headers,
                )
            )
            action = credential.payload.get("action")
            if response.is_success and action == "voucher":
                return
            if response.is_success and action == "topUp":
                continue
            if response.status_code == 402:
                refreshed = _session_challenge(response)
                if refreshed is not None:
                    current = refreshed
                    continue
            raise SessionRecoveryRequiredError(
                f"session management request failed with status {response.status_code}"
            )
        raise SessionRecoveryRequiredError("session management retry limit exceeded")

    def _wrap_sse(
        self,
        response: httpx.Response,
        original: httpx.Request,
        challenge: Challenge,
        channel_id: str,
    ) -> httpx.Response:
        if not _is_event_stream(response):
            return response
        if not isinstance(response.stream, httpx.SyncByteStream):
            return response
        response.headers.pop("content-length", None)
        response.stream = _SyncSessionStream(
            response.stream,
            manager=self.manager,
            on_need_voucher=lambda event: self._management(original, challenge, event, channel_id),
        )
        return response

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            request.read()
        except httpx.StreamConsumed as error:
            raise ValueError(
                "streaming request bodies cannot be replayed after a session challenge"
            ) from error
        hint = _run_sync(self.manager.session_hint(str(request.url)))
        initial = _copy_request(request, channel_id=hint)
        response = self.inner.handle_request(initial)
        if response.status_code != 402:
            return response
        return self.handle_payment_required(request, response)

    def handle_payment_required(
        self,
        request: httpx.Request,
        response: httpx.Response,
    ) -> httpx.Response:
        """Drive an already-received 402, for host HTTPX instrumentation."""

        challenge: Challenge | None = None
        snapshot: SessionSnapshot | None = None
        for _ in range(self.max_rounds):
            if response.status_code == 402:
                response.read()
                challenge = _session_challenge(response)
                if challenge is None:
                    return response
                snapshot = _snapshot(response)
            assert challenge is not None
            credential = _run_sync(
                self.manager.prepare(
                    challenge,
                    resource_url=str(request.url),
                    snapshot=snapshot,
                )
            )
            action = credential.payload.get("action")
            submit = _copy_request(
                request,
                authorization=credential.to_authorization(),
                channel_id=str(credential.payload["channelId"]),
                management=action == "topUp",
            )
            try:
                response = self.inner.handle_request(submit)
            except BaseException:
                _run_sync(self.manager.handle_unknown(credential))
                raise
            _run_sync(
                self.manager.handle_response(
                    credential,
                    status_code=response.status_code,
                    headers=response.headers,
                )
            )
            if response.is_success and action == "topUp":
                response.read()
                snapshot = None
                continue
            if response.status_code == 402:
                continue
            if response.is_success:
                if (
                    action == "open"
                    and _accepts_event_stream(request)
                    and not _is_event_stream(response)
                ):
                    # See the async path above. The follow-up is not a new
                    # payment submission; it only asks for the fresh voucher
                    # challenge after a management-only open response.
                    response.read()
                    response.close()
                    response = self.inner.handle_request(
                        _copy_request(
                            request,
                            channel_id=str(credential.payload["channelId"]),
                        )
                    )
                    if response.status_code == 402:
                        snapshot = None
                        continue
                return self._wrap_sse(
                    response,
                    request,
                    challenge,
                    str(credential.payload["channelId"]),
                )
            return response
        raise SessionRecoveryRequiredError("session payment retry limit exceeded")

    def close_session(self, channel_id: str, resource_url: str) -> httpx.Response:
        """Probe for a fresh challenge and cooperatively close a channel."""

        response = self.inner.handle_request(_close_probe(channel_id, resource_url))
        current: Challenge | None = None
        for _ in range(self.max_rounds):
            if response.status_code == 402:
                response.read()
                current = _session_challenge(response)
            if current is None:
                raise SessionRecoveryRequiredError(
                    "session close probe did not return a tempo/session challenge"
                )
            credential = _run_sync(self.manager.prepare_close(current, channel_id))
            request = _copy_request(
                httpx.Request("POST", resource_url),
                authorization=credential.to_authorization(),
                channel_id=channel_id,
                management=True,
            )
            try:
                response = self.inner.handle_request(request)
            except BaseException:
                _run_sync(self.manager.handle_unknown(credential))
                raise
            _run_sync(
                self.manager.handle_response(
                    credential,
                    status_code=response.status_code,
                    headers=response.headers,
                )
            )
            action = credential.payload.get("action")
            if response.is_success and action != "close":
                response.read()
                response = self.inner.handle_request(_close_probe(channel_id, resource_url))
                current = None
                continue
            if response.status_code != 402:
                return response
        raise SessionRecoveryRequiredError("session close retry limit exceeded")

    def close(self) -> None:
        with suppress(Exception):
            self.inner.close()
