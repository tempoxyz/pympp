"""Payment-aware MCP client wrapper.

Wraps an MCP SDK ``ClientSession`` with automatic payment handling.
When a tool call returns a ``-32042`` payment required error, the wrapper
creates a Credential and retries the call—mirroring the TypeScript
``McpClient.wrap`` API.

Example:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    from mpp.extensions.mcp import McpClient
    from mpp.methods.tempo import tempo, TempoAccount, ChargeIntent

    account = TempoAccount.from_key("0x...")
    method = tempo(account=account, intents={"charge": ChargeIntent()})

    async with sse_client("http://localhost:8000/sse") as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()

            async with McpClient(session, methods=[method]) as client:
                result = await client.call_tool("premium_tool", {"query": "hello"})
                print(result.receipt)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from mpp.extensions.mcp.constants import (
    CODE_PAYMENT_REQUIRED,
    META_PAYMENT_REQUIRED,
    META_RECEIPT,
)
from mpp.extensions.mcp.types import MCPChallenge, MCPReceipt
from mpp.runtime import Method, PaymentRuntime

logger = logging.getLogger(__name__)


class PaymentOutcomeUnknownError(RuntimeError):
    """Raised when a paid retry fails after a credential was attached."""

    def __init__(self, challenge: MCPChallenge, cause: Exception) -> None:
        self.challenge = challenge
        self.cause = cause
        super().__init__(
            "Tool call failed after sending a payment credential; "
            f"payment outcome is unknown for challenge {challenge.id}. "
            "Do not blindly retry."
        )


def _error_detail(error: Exception) -> Any:
    nested = getattr(error, "error", None)
    return nested if nested is not None else (error.args[0] if error.args else None)


def _error_code(error: Exception) -> int | None:
    code = getattr(error, "code", None)
    if code is not None:
        return code
    return getattr(_error_detail(error), "code", None)


def _error_data(error: Exception) -> Any:
    data = getattr(error, "data", None)
    if data is not None:
        return data
    return getattr(_error_detail(error), "data", None)


def _is_payment_required_error(error: Exception) -> bool:
    """Check whether an MCP error is a -32042 payment required error.

    Distinguishes payment errors from other uses of -32042 (such as
    URL elicitation) by checking for a ``challenges`` array in ``error.data``.
    """
    if _error_code(error) != CODE_PAYMENT_REQUIRED:
        return False
    data = _error_data(error)
    if not isinstance(data, dict):
        return False
    challenges = data.get("challenges")
    return isinstance(challenges, list) and any(
        isinstance(challenge, dict) for challenge in challenges
    )


def _parse_challenge(raw_challenge: Any) -> MCPChallenge | None:
    """Parse a server-provided challenge, skipping malformed entries."""
    if not isinstance(raw_challenge, dict):
        logger.warning(
            "Ignoring malformed MCP challenge: expected dict, got %s",
            type(raw_challenge).__name__,
        )
        return None

    for field in ("id", "realm", "method", "intent"):
        value = raw_challenge.get(field)
        if not isinstance(value, str) or not value:
            logger.warning("Ignoring malformed MCP challenge: invalid %s", field)
            return None

    if not isinstance(raw_challenge.get("request"), dict):
        logger.warning("Ignoring malformed MCP challenge: invalid request")
        return None

    try:
        return MCPChallenge.from_dict(raw_challenge)
    except (KeyError, TypeError, ValueError):
        logger.warning("Ignoring malformed MCP challenge payload", exc_info=True)
        return None


def _extract_challenges_from_data(data: Any) -> list[MCPChallenge]:
    """Extract valid payment challenges from payment-required data."""
    if not isinstance(data, dict):
        return []

    raw_challenges = data.get("challenges")
    if not isinstance(raw_challenges, list):
        return []

    challenges: list[MCPChallenge] = []
    for raw_challenge in raw_challenges:
        challenge = _parse_challenge(raw_challenge)
        if challenge is not None:
            challenges.append(challenge)
    return challenges


def _extract_challenges(error: Exception) -> list[MCPChallenge]:
    """Extract valid payment challenges from a payment required error."""
    return _extract_challenges_from_data(_error_data(error))


def _result_meta(result: Any) -> dict[str, Any] | None:
    """Read MCP result metadata from SDK objects or raw wire dictionaries."""
    if isinstance(result, dict):
        meta = result.get("_meta") or result.get("meta")
    else:
        meta = getattr(result, "meta", None) or getattr(result, "_meta", None)
    return meta if isinstance(meta, dict) else None


def _extract_result_challenges(result: Any) -> list[MCPChallenge]:
    """Extract payment challenges returned as MCP tool-result metadata."""
    meta = _result_meta(result)
    if meta is None:
        return []
    return _extract_challenges_from_data(meta.get(META_PAYMENT_REQUIRED))


@dataclass(frozen=True, slots=True)
class McpToolResult:
    """Result of a payment-aware tool call.

    Wraps the raw MCP ``CallToolResult`` and surfaces the payment receipt.
    """

    result: Any
    receipt: MCPReceipt | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.result, name)


class McpClient:
    """Payment-aware MCP client wrapper.

    Wraps an MCP SDK ``ClientSession`` and overrides ``call_tool`` with
    automatic payment handling. When a tool call returns ``-32042``, the
    wrapper matches the challenge to an installed payment method, creates
    a credential, and retries.

    Args:
        session: An initialized ``mcp.ClientSession``.
        methods: Payment methods available for credential creation.

    Example:
        async with McpClient(session, methods=[tempo(...)]) as client:
            result = await client.call_tool("premium_tool", {"query": "hello"})
            print(result.receipt)
    """

    def __init__(
        self,
        session: Any,
        methods: list[Method] | None = None,
        *,
        runtime: PaymentRuntime | None = None,
    ) -> None:
        self._session = session
        self._owns_runtime = runtime is None
        if runtime is not None:
            if methods is not None:
                raise ValueError("Pass either methods or runtime, not both")
            self._runtime = runtime
        else:
            if methods is None:
                raise ValueError("Pass methods or runtime")
            self._runtime = PaymentRuntime(methods)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    async def __aenter__(self) -> McpClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.aclose()

    def close(self) -> None:
        """Close the runtime created by this client, if any."""
        if self._owns_runtime:
            self._runtime.close()

    async def aclose(self) -> None:
        """Asynchronously close the runtime created by this client, if any."""
        if self._owns_runtime:
            await self._runtime.aclose()

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        timeout: float | None = None,
        meta: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> McpToolResult:
        """Call an MCP tool with automatic payment handling.

        On a ``-32042`` error, matches the challenge to an installed method,
        creates a credential, and retries the call with the credential in
        ``params._meta``.

        Args:
            name: Tool name.
            arguments: Tool arguments.
            timeout: Per-call timeout override (passed as ``read_timeout_seconds``).
            meta: Additional ``_meta`` fields to include in the request.
            *args: Positional arguments accepted by the underlying MCP session.
            **kwargs: Keyword arguments accepted by the underlying MCP session.

        Returns:
            An ``McpToolResult`` with the tool result and an optional receipt.

        Raises:
            McpError: If the error is not payment-related or no method matches.
            PaymentOutcomeUnknownError: If the paid retry fails after sending a credential.
            ValueError: If no installed method matches the server's challenge.
        """
        call_kwargs = dict(kwargs)
        if timeout is not None:
            if args or "read_timeout_seconds" in call_kwargs:
                raise TypeError("Pass either timeout or read_timeout_seconds, not both")
            call_kwargs["read_timeout_seconds"] = timedelta(seconds=timeout)
        if meta is not None:
            call_kwargs["meta"] = meta

        result = await self._runtime.call_mcp_tool(
            self._session.call_tool,
            name,
            arguments,
            *args,
            **call_kwargs,
        )
        receipt = self._extract_receipt(result)
        return McpToolResult(result=result, receipt=receipt)

    @staticmethod
    def _extract_receipt(result: Any) -> MCPReceipt | None:
        """Extract a payment receipt from a tool result's _meta."""
        meta = _result_meta(result)
        if not meta or not isinstance(meta, dict):
            return None
        receipt_data = meta.get(META_RECEIPT)
        if receipt_data is None:
            return None
        try:
            return MCPReceipt.from_dict(receipt_data)
        except (KeyError, TypeError):
            logger.warning("Failed to parse receipt from _meta")
            return None
