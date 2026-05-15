"""Tests for payment event dispatch."""

import pytest

from mpp.events import EventDispatcher, PaymentEvent


class TestEventDispatcher:
    @pytest.mark.asyncio
    async def test_named_and_wildcard_handlers(self) -> None:
        events: list[str] = []
        dispatcher = EventDispatcher()

        dispatcher.on("payment.success", lambda payload: events.append(payload["reference"]))
        dispatcher.on("*", lambda event: events.append(event.name))

        await dispatcher.emit("payment.success", {"reference": "tx_123"})

        assert events == ["tx_123", "payment.success"]

    @pytest.mark.asyncio
    async def test_returns_first_named_handler_value(self) -> None:
        dispatcher = EventDispatcher()

        dispatcher.on("challenge.received", lambda payload: "credential")
        dispatcher.on("challenge.received", lambda payload: "ignored")

        assert await dispatcher.emit("challenge.received", {}) == "credential"

    @pytest.mark.asyncio
    async def test_unsubscribe(self) -> None:
        events: list[str] = []
        dispatcher = EventDispatcher()

        unsubscribe = dispatcher.on("payment.failed", lambda payload: events.append("called"))
        unsubscribe()

        await dispatcher.emit("payment.failed", {})

        assert events == []

    @pytest.mark.asyncio
    async def test_handler_errors_are_swallowed(self) -> None:
        events: list[str] = []
        dispatcher = EventDispatcher()

        def fail(payload: object) -> None:
            raise RuntimeError("listener failed")

        async def record(event: PaymentEvent) -> None:
            events.append(event.name)

        dispatcher.on("payment.success", fail)
        dispatcher.on("*", record)

        await dispatcher.emit("payment.success", {})

        assert events == ["payment.success"]
