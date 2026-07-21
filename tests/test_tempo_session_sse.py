"""Tests for Tempo session SSE control-frame filtering."""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest

from mpp.methods.tempo._session_sse import (
    wrap_async_sse_response,
    wrap_sync_sse_response,
)

NEED_VOUCHER = {
    "channelId": "0xchannel",
    "requiredCumulative": "20",
    "acceptedCumulative": "10",
    "deposit": "100",
}
RECEIPT = {
    "method": "tempo",
    "intent": "session",
    "status": "success",
    "timestamp": "2025-01-01T00:00:00Z",
    "reference": "0xchannel",
    "challengeId": "challenge-1",
    "channelId": "0xchannel",
    "acceptedCumulative": "20",
    "spent": "12",
    "units": 3,
}


def _event(name: str, payload: object, newline: str = "\n") -> bytes:
    return f"event: {name}{newline}data: {json.dumps(payload)}{newline}{newline}".encode()


class TrackingSyncStream(httpx.SyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.chunks = [content[index : index + 1] for index in range(len(content))]
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


class TrackingAsyncStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.chunks = [content[index : index + 1] for index in range(len(content))]
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class BlockingAsyncStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.waiting = asyncio.Event()
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"data: first\n\n"
        self.waiting.set()
        await asyncio.Event().wait()

    async def aclose(self) -> None:
        self.closed = True


def _mixed_stream() -> tuple[bytes, bytes]:
    application = "event: custom\r\ndata: café\r\n\r\n".encode()
    comment = b": keepalive\r\r"
    malformed = b'event: payment-receipt\ndata: {"status":"success"}\n\n'
    malformed_json = b"event: payment-need-voucher\ndata: {nope}\n\n"
    unknown = _event("custom-payment", RECEIPT)
    need = _event("payment-need-voucher", NEED_VOUCHER, "\r")
    receipt = _event("payment-receipt", RECEIPT, "\r\n")
    unterminated = b'event: payment-receipt\ndata: {"still":"application"}'
    source = (
        application + need + comment + malformed + malformed_json + receipt + unknown + unterminated
    )
    expected = application + comment + malformed + malformed_json + unknown + unterminated
    return source, expected


def test_sync_wrapper_filters_controls_and_preserves_other_bytes() -> None:
    content, expected = _mixed_stream()
    stream = TrackingSyncStream(content)
    request = httpx.Request("GET", "https://example.com/stream")
    response = httpx.Response(
        201,
        headers={"content-type": "text/event-stream", "content-length": str(len(content))},
        stream=stream,
        request=request,
        extensions={"reason_phrase": b"Created"},
    )
    controls: list[tuple[str, dict[str, Any]]] = []

    wrapped = wrap_sync_sse_response(
        response,
        on_need_voucher=lambda value: controls.append(("need", value)),
        on_receipt=lambda value: controls.append(("receipt", value)),
    )

    assert wrapped.status_code == 201
    assert wrapped.reason_phrase == "Created"
    assert wrapped.request is request
    assert wrapped.headers["content-type"] == "text/event-stream"
    assert "content-length" not in wrapped.headers
    assert b"".join(wrapped.iter_raw()) == expected
    assert controls == [("need", NEED_VOUCHER), ("receipt", RECEIPT)]
    assert stream.closed


def test_sync_wrapper_decodes_compressed_sse_before_filtering() -> None:
    application = b"data: application\n\n"
    compressed = gzip.compress(_event("payment-need-voucher", NEED_VOUCHER) + application)
    stream = TrackingSyncStream(compressed)
    controls: list[dict[str, Any]] = []
    wrapped = wrap_sync_sse_response(
        httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
            stream=stream,
        ),
        on_need_voucher=controls.append,
        on_receipt=lambda _: None,
    )

    assert b"".join(wrapped.iter_raw()) == application
    assert controls == [NEED_VOUCHER]
    assert "content-encoding" not in wrapped.headers
    assert "content-length" not in wrapped.headers
    assert stream.closed


@pytest.mark.asyncio
async def test_async_wrapper_awaits_handlers_and_preserves_other_bytes() -> None:
    need = _event("payment-need-voucher", NEED_VOUCHER)
    application = b"data: after\n\n"
    stream = TrackingAsyncStream(need + application)
    response = httpx.Response(200, stream=stream)
    started = asyncio.Event()
    release = asyncio.Event()

    async def on_need_voucher(value: dict[str, Any]) -> None:
        assert value == NEED_VOUCHER
        started.set()
        await release.wait()

    async def on_receipt(value: dict[str, Any]) -> None:
        raise AssertionError(f"unexpected receipt: {value}")

    wrapped = wrap_async_sse_response(
        response,
        on_need_voucher=on_need_voucher,
        on_receipt=on_receipt,
    )
    iterator = wrapped.aiter_raw()

    async def read_next() -> bytes:
        return await anext(iterator)

    next_frame = asyncio.create_task(read_next())

    await started.wait()
    assert not next_frame.done()
    release.set()
    assert await next_frame == application
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)
    assert stream.closed


@pytest.mark.asyncio
async def test_async_wrapper_handles_mixed_boundaries_and_split_utf8() -> None:
    content, expected = _mixed_stream()
    stream = TrackingAsyncStream(content)
    controls: list[tuple[str, dict[str, Any]]] = []

    async def on_need_voucher(value: dict[str, Any]) -> None:
        controls.append(("need", value))

    async def on_receipt(value: dict[str, Any]) -> None:
        controls.append(("receipt", value))

    wrapped = wrap_async_sse_response(
        httpx.Response(
            200,
            headers={"content-length": str(len(content))},
            stream=stream,
        ),
        on_need_voucher=on_need_voucher,
        on_receipt=on_receipt,
    )

    assert b"".join([chunk async for chunk in wrapped.aiter_raw()]) == expected
    assert controls == [("need", NEED_VOUCHER), ("receipt", RECEIPT)]
    assert "content-length" not in wrapped.headers
    assert stream.closed


@pytest.mark.asyncio
async def test_async_wrapper_decodes_compressed_sse_before_filtering() -> None:
    application = b"data: application\n\n"
    compressed = gzip.compress(_event("payment-receipt", RECEIPT) + application)
    stream = TrackingAsyncStream(compressed)
    controls: list[dict[str, Any]] = []

    async def on_receipt(value: dict[str, Any]) -> None:
        controls.append(value)

    async def ignore(_: dict[str, Any]) -> None:
        return None

    wrapped = wrap_async_sse_response(
        httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
            stream=stream,
        ),
        on_need_voucher=ignore,
        on_receipt=on_receipt,
    )

    assert b"".join([chunk async for chunk in wrapped.aiter_raw()]) == application
    assert controls == [RECEIPT]
    assert "content-encoding" not in wrapped.headers
    assert "content-length" not in wrapped.headers
    assert stream.closed


def test_sync_close_closes_source_without_consuming_it() -> None:
    stream = TrackingSyncStream(b"data: pending\n\n")
    wrapped = wrap_sync_sse_response(
        httpx.Response(200, stream=stream),
        on_need_voucher=lambda _: None,
        on_receipt=lambda _: None,
    )

    wrapped.close()

    assert stream.closed


@pytest.mark.asyncio
async def test_async_close_closes_source_without_consuming_it() -> None:
    stream = TrackingAsyncStream(b"data: pending\n\n")

    async def ignore(_: dict[str, Any]) -> None:
        return None

    wrapped = wrap_async_sse_response(
        httpx.Response(200, stream=stream),
        on_need_voucher=ignore,
        on_receipt=ignore,
    )

    await wrapped.aclose()

    assert stream.closed


@pytest.mark.asyncio
async def test_cancelling_iteration_closes_source() -> None:
    stream = BlockingAsyncStream()

    async def ignore(_: dict[str, Any]) -> None:
        return None

    wrapped = wrap_async_sse_response(
        httpx.Response(200, stream=stream),
        on_need_voucher=ignore,
        on_receipt=ignore,
    )
    iterator = wrapped.aiter_raw()
    assert await anext(iterator) == b"data: first\n\n"

    async def read_next() -> bytes:
        return await anext(iterator)

    task = asyncio.create_task(read_next())
    await stream.waiting.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert stream.closed
