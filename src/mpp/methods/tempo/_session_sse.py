"""SSE filtering for Tempo session payment control frames."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, cast

import httpx

ControlPayload: TypeAlias = dict[str, Any]
SyncControlHandler: TypeAlias = Callable[[ControlPayload], None]
AsyncControlHandler: TypeAlias = Callable[[ControlPayload], Awaitable[None]]
ControlKind: TypeAlias = Literal["payment-need-voucher", "payment-receipt"]


@dataclass(frozen=True, slots=True)
class _Frame:
    raw: bytes
    control: tuple[ControlKind, ControlPayload] | None = None


class _FrameDecoder:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[_Frame]:
        self._buffer.extend(chunk)
        return self._drain(complete=False)

    def finish(self) -> list[_Frame]:
        frames = self._drain(complete=True)
        if self._buffer:
            frames.append(_Frame(bytes(self._buffer)))
            self._buffer.clear()
        return frames

    def _drain(self, *, complete: bool) -> list[_Frame]:
        frames: list[_Frame] = []
        while separator := _find_separator(self._buffer, complete=complete):
            index, length = separator
            end = index + length
            body = bytes(self._buffer[:index])
            raw = bytes(self._buffer[:end])
            del self._buffer[:end]
            frames.append(_Frame(raw, _parse_control(body)))
        return frames


class _SyncSseStream(httpx.SyncByteStream):
    def __init__(
        self,
        response: httpx.Response,
        on_need_voucher: SyncControlHandler,
        on_receipt: SyncControlHandler,
    ) -> None:
        self._response = response
        self._on_need_voucher = on_need_voucher
        self._on_receipt = on_receipt
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        decoder = _FrameDecoder()
        try:
            for chunk in self._response.iter_bytes():
                yield from self._handle(decoder.feed(chunk))
            yield from self._handle(decoder.finish())
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._response.close()

    def _handle(self, frames: list[_Frame]) -> Iterator[bytes]:
        for frame in frames:
            if frame.control is None:
                yield frame.raw
                continue
            kind, payload = frame.control
            if kind == "payment-need-voucher":
                self._on_need_voucher(payload)
            else:
                self._on_receipt(payload)


class _AsyncSseStream(httpx.AsyncByteStream):
    def __init__(
        self,
        response: httpx.Response,
        on_need_voucher: AsyncControlHandler,
        on_receipt: AsyncControlHandler,
    ) -> None:
        self._response = response
        self._on_need_voucher = on_need_voucher
        self._on_receipt = on_receipt
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        decoder = _FrameDecoder()
        try:
            async for chunk in self._response.aiter_bytes():
                async for raw in self._handle(decoder.feed(chunk)):
                    yield raw
            async for raw in self._handle(decoder.finish()):
                yield raw
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._response.aclose()

    async def _handle(self, frames: list[_Frame]) -> AsyncIterator[bytes]:
        for frame in frames:
            if frame.control is None:
                yield frame.raw
                continue
            kind, payload = frame.control
            if kind == "payment-need-voucher":
                await self._on_need_voucher(payload)
            else:
                await self._on_receipt(payload)


def wrap_sync_sse_response(
    response: httpx.Response,
    *,
    on_need_voucher: SyncControlHandler,
    on_receipt: SyncControlHandler,
) -> httpx.Response:
    """Wrap a sync SSE response and consume valid payment control frames inline."""
    if not isinstance(response.stream, httpx.SyncByteStream):
        raise TypeError("Expected a synchronous response stream")
    source = _take_source(response)
    response.stream = _SyncSseStream(source, on_need_voucher, on_receipt)
    return response


def wrap_async_sse_response(
    response: httpx.Response,
    *,
    on_need_voucher: AsyncControlHandler,
    on_receipt: AsyncControlHandler,
) -> httpx.Response:
    """Wrap an async SSE response and consume valid payment control frames inline."""
    if not isinstance(response.stream, httpx.AsyncByteStream):
        raise TypeError("Expected an asynchronous response stream")
    source = _take_source(response)
    response.stream = _AsyncSseStream(source, on_need_voucher, on_receipt)
    return response


def _take_source(response: httpx.Response) -> httpx.Response:
    try:
        request = response.request
    except RuntimeError:
        request = None
    source = httpx.Response(
        response.status_code,
        headers=response.headers,
        stream=response.stream,
        request=request,
        extensions=dict(response.extensions),
        history=list(response.history),
        default_encoding=response.default_encoding,
    )
    response.headers.pop("content-length", None)
    response.headers.pop("content-encoding", None)
    return source


def _find_separator(buffer: bytearray, *, complete: bool) -> tuple[int, int] | None:
    index = 0
    while index < len(buffer):
        first = _line_ending_length(buffer, index, complete=complete)
        if first:
            second = _line_ending_length(buffer, index + first, complete=complete)
            if second:
                return index, first + second
            index += first
        else:
            index += 1
    return None


def _line_ending_length(buffer: bytearray, index: int, *, complete: bool) -> int:
    if index >= len(buffer):
        return 0
    if buffer[index] == 0x0A:
        return 1
    if buffer[index] != 0x0D:
        return 0
    if index + 1 < len(buffer) and buffer[index + 1] == 0x0A:
        return 2
    if index + 1 == len(buffer) and not complete:
        return 0
    return 1


def _parse_control(body: bytes) -> tuple[ControlKind, ControlPayload] | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None

    event = "message"
    data: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event = value
        elif field == "data":
            data.append(value)

    if event not in {"payment-need-voucher", "payment-receipt"} or not data:
        return None
    try:
        value = json.loads("\n".join(data), parse_constant=_reject_json_constant)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    payload = cast(ControlPayload, value)
    if event == "payment-need-voucher" and _is_need_voucher(payload):
        return event, payload
    if event == "payment-receipt" and _is_receipt(payload):
        return event, payload
    return None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _is_need_voucher(value: ControlPayload) -> bool:
    return all(
        isinstance(value.get(field), str)
        for field in ("channelId", "requiredCumulative", "acceptedCumulative", "deposit")
    )


def _is_receipt(value: ControlPayload) -> bool:
    required_strings = (
        "timestamp",
        "reference",
        "challengeId",
        "channelId",
        "acceptedCumulative",
        "spent",
    )
    units = value.get("units")
    return (
        value.get("method") == "tempo"
        and value.get("intent") == "session"
        and value.get("status") == "success"
        and all(isinstance(value.get(field), str) for field in required_strings)
        and (
            "units" not in value or isinstance(units, (int, float)) and not isinstance(units, bool)
        )
        and ("txHash" not in value or isinstance(value.get("txHash"), str))
    )
