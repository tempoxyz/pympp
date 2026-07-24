"""Tests for MCP client wrapper (McpClient)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest

from mpp import Challenge, Credential
from mpp.extensions.mcp import (
    META_CREDENTIAL,
    META_RECEIPT,
    McpClient,
    McpToolResult,
    PaymentOutcomeUnknownError,
)
from mpp.extensions.mcp.client import _extract_challenges, _is_payment_required_error
from mpp.extensions.mcp.types import MCPChallenge, MCPReceipt
from mpp.runtime import PaymentRuntime

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeCallToolResult:
    """Mimics mcp.types.CallToolResult."""

    def __init__(self, content: list[dict] | None = None, meta: dict | None = None):
        self.content = content or [{"type": "text", "text": "ok"}]
        self.meta = meta


class FakeMcpError(Exception):
    """Mimics mcp.shared.exceptions.McpError with code/data attributes."""

    def __init__(self, code: int, message: str = "", data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass
class FakeMcpErrorData:
    """Mimics current mcp.types.ErrorData."""

    code: int
    message: str = ""
    data: Any = None


class FakeCurrentMcpError(Exception):
    """Mimics current mcp.shared.exceptions.McpError with nested ErrorData."""

    def __init__(self, error: FakeMcpErrorData):
        super().__init__(error.message)
        self.error = error


@dataclass
class FakeMethod:
    """Fake payment method for testing."""

    name: str = "tempo"
    _intents: dict[str, Any] | None = None
    _credential_to_return: Credential | None = None

    def __post_init__(self):
        if self._intents is None:
            self._intents = {"charge": True}
        if self._credential_to_return is None:
            from mpp import ChallengeEcho

            echo = ChallengeEcho(
                id="test-id",
                realm="test.example.com",
                method="tempo",
                intent="charge",
                request="e30",
            )
            self._credential_to_return = Credential(
                challenge=echo,
                payload={"type": "transaction", "signature": "0xabc"},
                source="did:pkh:eip155:42431:0x1234",
            )

    async def create_credential(self, challenge: Challenge) -> Credential:
        return self._credential_to_return  # type: ignore[return-value]


def _make_challenge_dict(
    method: str = "tempo",
    intent: str = "charge",
) -> dict[str, Any]:
    return {
        "id": "ch_test123",
        "realm": "api.example.com",
        "method": method,
        "intent": intent,
        "request": {"amount": "1000", "currency": "0x20c0", "recipient": "0xdead"},
        "expires": "2099-01-01T00:00:00Z",
    }


def _make_receipt_meta() -> dict[str, Any]:
    return {
        META_RECEIPT: {
            "status": "success",
            "challengeId": "ch_test123",
            "method": "tempo",
            "timestamp": "2025-06-15T12:00:00Z",
            "reference": "0xtxhash",
        }
    }


def _make_challenge(
    method: str = "tempo",
    intent: str = "charge",
) -> MCPChallenge:
    return MCPChallenge.from_dict(_make_challenge_dict(method=method, intent=intent))


# ---------------------------------------------------------------------------
# _is_payment_required_error
# ---------------------------------------------------------------------------


class TestIsPaymentRequiredError:
    def test_correct_error(self) -> None:
        err = FakeMcpError(-32042, data={"challenges": [_make_challenge_dict()]})
        assert _is_payment_required_error(err) is True

    def test_real_current_mcp_sdk_error_data(self) -> None:
        exceptions = pytest.importorskip("mcp.shared.exceptions")
        types = pytest.importorskip("mcp.types")
        err = exceptions.McpError(
            types.ErrorData(
                code=-32042,
                message="Payment Required",
                data={"challenges": [_make_challenge_dict()]},
            )
        )

        assert _is_payment_required_error(err) is True
        assert _extract_challenges(err) == [_make_challenge()]

    def test_mcp_1_1_args_error_data(self) -> None:
        types = pytest.importorskip("mcp.types")
        err = Exception(
            types.ErrorData(
                code=-32042,
                message="Payment Required",
                data={"challenges": [_make_challenge_dict()]},
            )
        )

        assert _is_payment_required_error(err) is True
        assert _extract_challenges(err) == [_make_challenge()]

    def test_wrong_code(self) -> None:
        err = FakeMcpError(-32000, data={"challenges": [_make_challenge_dict()]})
        assert _is_payment_required_error(err) is False

    def test_no_challenges(self) -> None:
        err = FakeMcpError(-32042, data={})
        assert _is_payment_required_error(err) is False

    def test_empty_challenges(self) -> None:
        err = FakeMcpError(-32042, data={"challenges": []})
        assert _is_payment_required_error(err) is False

    def test_no_dict_challenges(self) -> None:
        err = FakeMcpError(-32042, data={"challenges": ["bad"]})
        assert _is_payment_required_error(err) is False

    def test_no_data(self) -> None:
        err = FakeMcpError(-32042)
        assert _is_payment_required_error(err) is False

    def test_plain_exception(self) -> None:
        err = Exception("not an MCP error")
        assert _is_payment_required_error(err) is False


# ---------------------------------------------------------------------------
# McpClient
# ---------------------------------------------------------------------------


class TestMcpClientFreeTool:
    """Free tool calls pass through without payment handling."""

    @pytest.mark.asyncio
    async def test_free_tool_returns_result(self) -> None:
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult())

        client = McpClient(session, methods=[FakeMethod()])
        result = await client.call_tool("echo", {"message": "hi"})

        assert isinstance(result, McpToolResult)
        assert result.content[0]["text"] == "ok"
        assert result.receipt is None
        session.call_tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_free_tool_with_receipt(self) -> None:
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult(meta=_make_receipt_meta()))

        client = McpClient(session, methods=[FakeMethod()])
        result = await client.call_tool("tool", {})

        assert result.content[0]["text"] == "ok"
        assert result.receipt is not None
        assert isinstance(result.receipt, MCPReceipt)
        assert result.receipt.reference == "0xtxhash"
        assert result.receipt.challenge_id == "ch_test123"

    @pytest.mark.asyncio
    async def test_session_methods_are_proxied(self) -> None:
        session = AsyncMock()
        session.list_tools = AsyncMock(return_value="tools")

        client = McpClient(session, methods=[FakeMethod()])

        assert await client.list_tools() == "tools"


class TestMcpClientPaidTool:
    """Paid tool calls handle the -32042 → credential → retry flow."""

    @pytest.mark.asyncio
    async def test_payment_flow(self) -> None:
        """First call raises -32042, retry succeeds with receipt."""
        session = AsyncMock()
        payment_error = FakeMcpError(
            -32042,
            message="Payment Required",
            data={
                "httpStatus": 402,
                "challenges": [_make_challenge_dict()],
            },
        )
        retry_result = FakeCallToolResult(
            content=[{"type": "text", "text": "premium result"}],
            meta=_make_receipt_meta(),
        )
        session.call_tool = AsyncMock(side_effect=[payment_error, retry_result])

        client = McpClient(session, methods=[FakeMethod()])
        result = await client.call_tool("premium_tool", {"query": "test"})

        assert result.content[0]["text"] == "premium result"
        assert result.receipt is not None
        assert result.receipt.status == "success"
        assert result.receipt.reference == "0xtxhash"
        assert session.call_tool.call_count == 2

        retry_call = session.call_tool.call_args_list[1]
        retry_meta = retry_call.kwargs.get("meta") or retry_call[1].get("meta")
        assert META_CREDENTIAL in retry_meta

    @pytest.mark.asyncio
    async def test_payment_flow_with_current_sdk_error_shape(self) -> None:
        """Current mcp SDK stores ErrorData on McpError.error."""
        session = AsyncMock()
        payment_error = FakeCurrentMcpError(
            FakeMcpErrorData(
                -32042,
                message="Payment Required",
                data={
                    "httpStatus": 402,
                    "challenges": [_make_challenge_dict()],
                },
            )
        )
        retry_result = FakeCallToolResult(
            content=[{"type": "text", "text": "premium result"}],
            meta=_make_receipt_meta(),
        )
        session.call_tool = AsyncMock(side_effect=[payment_error, retry_result])

        client = McpClient(session, methods=[FakeMethod()])
        result = await client.call_tool("premium_tool", {"query": "test"})

        assert result.content[0]["text"] == "premium result"
        assert result.receipt is not None
        assert result.receipt.reference == "0xtxhash"
        retry_meta = session.call_tool.call_args_list[1].kwargs.get("meta", {})
        assert META_CREDENTIAL in retry_meta

    @pytest.mark.asyncio
    async def test_no_matching_method_raises(self) -> None:
        """Raises ValueError when no installed method matches the challenge."""
        session = AsyncMock()
        runtime = PaymentRuntime([FakeMethod(name="tempo")])
        failed: list[dict[str, Any]] = []
        runtime.events.on("payment.failed", failed.append)

        try:
            payment_error = FakeMcpError(
                -32042,
                data={"challenges": [_make_challenge_dict(method="stripe")]},
            )
            session.call_tool = AsyncMock(side_effect=payment_error)

            client = McpClient(session, runtime=runtime)

            with pytest.raises(ValueError, match="No compatible payment method"):
                await client.call_tool("tool", {})

            assert failed[0]["challenge"] is None
            assert [challenge.id for challenge in failed[0]["challenges"]] == ["ch_test123"]
            assert failed[0]["method"] is None
            assert failed[0]["protocol"] == "mcp"
        finally:
            runtime.close()

    @pytest.mark.asyncio
    async def test_non_payment_error_propagates(self) -> None:
        """Non-payment McpErrors propagate unchanged."""
        session = AsyncMock()
        other_error = FakeMcpError(-32601, message="Method not found")
        session.call_tool = AsyncMock(side_effect=other_error)

        client = McpClient(session, methods=[FakeMethod()])

        with pytest.raises(FakeMcpError) as exc_info:
            await client.call_tool("tool", {})
        assert exc_info.value.code == -32601

    @pytest.mark.asyncio
    async def test_timeout_forwarded(self) -> None:
        """Timeout is forwarded as read_timeout_seconds to session.call_tool."""
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult())

        client = McpClient(session, methods=[FakeMethod()])
        await client.call_tool("tool", {}, timeout=60.0)

        _, kwargs = session.call_tool.call_args
        assert kwargs.get("read_timeout_seconds") == timedelta(seconds=60)

    @pytest.mark.asyncio
    async def test_mcp_119_call_shape_is_forwarded(self) -> None:
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult())
        read_timeout = timedelta(seconds=30)
        progress_callback = AsyncMock()
        client = McpClient(session, methods=[FakeMethod()])

        await client.call_tool(
            "tool",
            {},
            read_timeout,
            progress_callback,
            meta={"trace": "abc"},
        )

        args, kwargs = session.call_tool.call_args
        assert args == ("tool", {}, read_timeout, progress_callback)
        assert kwargs == {"meta": {"trace": "abc"}}

    @pytest.mark.asyncio
    async def test_mcp_119_keyword_arguments_are_forwarded(self) -> None:
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult())
        read_timeout = timedelta(seconds=30)
        progress_callback = AsyncMock()
        client = McpClient(session, methods=[FakeMethod()])

        await client.call_tool(
            "tool",
            {},
            read_timeout_seconds=read_timeout,
            progress_callback=progress_callback,
        )

        _, kwargs = session.call_tool.call_args
        assert kwargs == {
            "read_timeout_seconds": read_timeout,
            "progress_callback": progress_callback,
        }

    @pytest.mark.asyncio
    async def test_meta_forwarded(self) -> None:
        """Custom meta is forwarded to the session."""
        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=FakeCallToolResult())

        client = McpClient(session, methods=[FakeMethod()])
        await client.call_tool("tool", {}, meta={"custom": "value"})

        _, kwargs = session.call_tool.call_args
        assert kwargs["meta"]["custom"] == "value"

    @pytest.mark.asyncio
    async def test_meta_preserved_on_retry(self) -> None:
        """Custom meta is preserved and merged with credential on retry."""
        session = AsyncMock()
        payment_error = FakeMcpError(
            -32042,
            data={"challenges": [_make_challenge_dict()]},
        )
        retry_result = FakeCallToolResult(meta=_make_receipt_meta())
        session.call_tool = AsyncMock(side_effect=[payment_error, retry_result])

        client = McpClient(session, methods=[FakeMethod()])
        await client.call_tool("tool", {}, meta={"trace_id": "abc"})

        retry_kwargs = session.call_tool.call_args_list[1].kwargs
        retry_meta = retry_kwargs.get("meta", {})
        assert retry_meta.get("trace_id") == "abc"
        assert META_CREDENTIAL in retry_meta

    @pytest.mark.asyncio
    async def test_malformed_server_challenges_raise_clean_error(self) -> None:
        session = AsyncMock()
        payment_error = FakeMcpError(
            -32042,
            data={"challenges": ["bad", {"id": "missing-fields"}]},
        )
        session.call_tool = AsyncMock(side_effect=payment_error)

        client = McpClient(session, methods=[FakeMethod()])

        with pytest.raises(ValueError, match="Server returned malformed payment challenges"):
            await client.call_tool("tool", {})

    @pytest.mark.asyncio
    async def test_retry_failure_raises_payment_outcome_unknown(self) -> None:
        session = AsyncMock()
        payment_error = FakeMcpError(
            -32042,
            data={"challenges": [_make_challenge_dict()]},
        )
        session.call_tool = AsyncMock(side_effect=[payment_error, TimeoutError("timed out")])

        client = McpClient(session, methods=[FakeMethod()])

        with pytest.raises(PaymentOutcomeUnknownError) as exc_info:
            await client.call_tool("premium_tool", {"query": "test"})

        assert exc_info.value.challenge.id == "ch_test123"
        assert isinstance(exc_info.value.__cause__, TimeoutError)


class TestPaymentRuntimeMethodMatching:
    """Tests for challenge-to-method matching logic."""

    def test_match_by_method_and_intent(self) -> None:
        method = FakeMethod(name="tempo", _intents={"charge": True})
        runtime = PaymentRuntime([method])

        challenge, matched = runtime.match_challenge([_make_challenge()])
        assert isinstance(challenge, MCPChallenge)
        assert matched is method

    def test_match_prefers_client_order(self) -> None:
        """Methods are matched in client-preference order."""
        stripe_method = FakeMethod(name="stripe", _intents={"charge": True})
        tempo_method = FakeMethod(name="tempo", _intents={"charge": True})

        runtime = PaymentRuntime([stripe_method, tempo_method])

        challenges = [
            _make_challenge(method="tempo"),
            _make_challenge(method="stripe"),
        ]
        _, matched = runtime.match_challenge(challenges)
        assert matched is stripe_method

    def test_no_match_raises(self) -> None:
        method = FakeMethod(name="tempo", _intents={"charge": True})
        runtime = PaymentRuntime([method])

        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([_make_challenge(method="stripe")])

    def test_intent_mismatch(self) -> None:
        method = FakeMethod(name="tempo", _intents={"session": True})
        runtime = PaymentRuntime([method])

        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([_make_challenge(method="tempo", intent="charge")])

    def test_extract_challenges_skips_malformed_entries(self) -> None:
        err = FakeMcpError(
            -32042,
            data={
                "challenges": [
                    "bad",
                    {"id": "missing-fields"},
                    _make_challenge_dict(),
                ]
            },
        )

        challenges = _extract_challenges(err)

        assert challenges == [_make_challenge()]


class TestMcpClientReceiptExtraction:
    """Tests for receipt extraction from _meta."""

    def test_extracts_receipt(self) -> None:
        result = FakeCallToolResult(meta=_make_receipt_meta())
        receipt = McpClient._extract_receipt(result)
        assert receipt is not None
        assert receipt.status == "success"

    def test_no_meta(self) -> None:
        result = FakeCallToolResult(meta=None)
        assert McpClient._extract_receipt(result) is None

    def test_no_receipt_key(self) -> None:
        result = FakeCallToolResult(meta={"other": "data"})
        assert McpClient._extract_receipt(result) is None

    def test_malformed_receipt(self) -> None:
        result = FakeCallToolResult(meta={META_RECEIPT: "not a dict"})
        assert McpClient._extract_receipt(result) is None


class TestMcpToolResult:
    def test_proxies_underlying_result_attributes(self) -> None:
        result = McpToolResult(result=FakeCallToolResult(), receipt=None)

        assert result.content[0]["text"] == "ok"
