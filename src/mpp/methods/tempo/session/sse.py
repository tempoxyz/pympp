"""Incremental SSE parsing for TIP-1034 payment control frames."""

from __future__ import annotations

import codecs
import json
from dataclasses import dataclass
from typing import Any

from .models import MAX_UINT96, SessionReceipt, normalize_hash


@dataclass(frozen=True, slots=True)
class NeedVoucherEvent:
    """Validated `payment-need-voucher` event data."""

    channel_id: str
    required_cumulative: int
    accepted_cumulative: int
    deposit: int

    @classmethod
    def from_wire(cls, value: Any) -> NeedVoucherEvent:
        if not isinstance(value, dict):
            raise ValueError("payment-need-voucher data must be an object")
        try:
            required = int(value["requiredCumulative"])
            accepted = int(value["acceptedCumulative"])
            deposit = int(value["deposit"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid payment-need-voucher amounts") from error
        if min(required, accepted, deposit) < 0 or max(required, accepted, deposit) > MAX_UINT96:
            raise ValueError("payment-need-voucher amounts are outside uint96 bounds")
        return cls(
            normalize_hash(value.get("channelId"), "channelId"),
            required,
            accepted,
            deposit,
        )


@dataclass(frozen=True, slots=True)
class SseFrame:
    """One complete SSE frame, retaining its original wire text."""

    event: str
    data: str | None
    raw: str


def _line_ending_length(value: str, index: int, complete: bool) -> int:
    if value[index : index + 1] == "\n":
        return 1
    if value[index : index + 1] != "\r":
        return 0
    if value[index + 1 : index + 2] == "\n":
        return 2
    if index + 1 == len(value) and not complete:
        return 0
    return 1


def _find_separator(value: str, complete: bool) -> tuple[int, int] | None:
    index = 0
    while index < len(value):
        first = _line_ending_length(value, index, complete)
        if first:
            second = _line_ending_length(value, index + first, complete)
            if second:
                return index, first + second
            index += first
        else:
            index += 1
    return None


def _parse_frame(part: str, raw: str) -> SseFrame:
    event = "message"
    data: list[str] = []
    for line in part.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith("event:"):
            event = line[6:].lstrip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    return SseFrame(event=event, data=None if not data else "\n".join(data), raw=raw)


class SseParser:
    """UTF-8 and frame-boundary-safe incremental SSE parser."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._buffer = ""

    def feed(self, chunk: bytes, *, final: bool = False) -> list[SseFrame]:
        self._buffer += self._decoder.decode(chunk, final=final)
        frames: list[SseFrame] = []
        while separator := _find_separator(self._buffer, final):
            index, length = separator
            end = index + length
            part = self._buffer[:index]
            raw = self._buffer[:end]
            self._buffer = self._buffer[end:]
            if part.strip():
                frames.append(_parse_frame(part, raw))
        if final and self._buffer.strip():
            raw = self._buffer
            self._buffer = ""
            frames.append(_parse_frame(raw, raw))
        return frames


def parse_need_voucher(frame: SseFrame) -> NeedVoucherEvent | None:
    """Return typed control data when `frame` requests more authorization."""

    if frame.event != "payment-need-voucher" or frame.data is None:
        return None
    try:
        return NeedVoucherEvent.from_wire(json.loads(frame.data))
    except json.JSONDecodeError as error:
        raise ValueError("invalid payment-need-voucher JSON") from error


def parse_receipt(frame: SseFrame) -> SessionReceipt | None:
    """Return a typed in-band payment receipt when present."""

    if frame.event != "payment-receipt" or frame.data is None:
        return None
    try:
        return SessionReceipt.from_wire(json.loads(frame.data))
    except json.JSONDecodeError as error:
        raise ValueError("invalid payment-receipt JSON") from error
