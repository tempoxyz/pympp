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

            client = McpClient(session, methods=[method])
            result = await client.call_tool("premium_tool", {"query": "hello"})
            print(result.receipt)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mpp.extensions.mcp.constants import CODE_PAYMENT_REQUIRED, META_RECEIPT
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt

if TYPE_CHECKING:
    from mpp import Challenge, Credential

logger = logging.getLogger(__name__)


@runtime_checkable
class Method(Protocol):
    """Payment method interface for MCP client credential creation."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge."""
        ...


def _is_payment_required_error(error: Exception) -> bool:
    """Check whether an MCP error is a -32042 payment required error.

    Distinguishes payment errors from other uses of -32042 (such as
    URL elicitation) by checking for a ``challenges`` array in ``error.data``.
    """
    code = getattr(error, "code", None)
    if code != CODE_PAYMENT_REQUIRED:
        return False
    data = getattr(error, "data", None)
    if not isinstance(data, dict):
        return False
    challenges = data.get("challenges")
    return isinstance(challenges, list) and len(challenges) > 0


def _extract_challenges(error: Exception) -> list[dict[str, Any]]:
    """Extract the challenges array from a payment required error."""
    data = getattr(error, "data", {})
    return data.get("challenges", []) if isinstance(data, dict) else []


@dataclass(frozen=True, slots=True)
class McpToolResult:
    """Result of a payment-aware tool call.

    Wraps the raw MCP ``CallToolResult`` and surfaces the payment receipt.
    """

    result: Any
    receipt: MCPReceipt | None = None


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
        client = McpClient(session, methods=[tempo(...)])
        result = await client.call_tool("premium_tool", {"query": "hello"})
        print(result.receipt)
    """

    def __init__(self, session: Any, methods: list[Method]) -> None:
        self._session = session
        self._methods = methods

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        meta: dict[str, Any] | None = None,
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

        Returns:
            An ``McpToolResult`` with the tool result and an optional receipt.

        Raises:
            McpError: If the error is not payment-related or no method matches.
            ValueError: If no installed method matches the server's challenge.
        """
        from mcp.shared.exceptions import McpError

        call_kwargs: dict[str, Any] = {}
        if timeout is not None:
            call_kwargs["read_timeout_seconds"] = timeout
        if meta is not None:
            call_kwargs["meta"] = meta

        try:
            result = await self._session.call_tool(name, arguments, **call_kwargs)
            receipt = self._extract_receipt(result)
            return McpToolResult(result=result, receipt=receipt)

        except McpError as e:
            if not _is_payment_required_error(e):
                raise

            challenges_data = _extract_challenges(e)
            challenge, method = self._match_challenge(challenges_data)

            core_credential = await method.create_credential(challenge.to_core())
            mcp_credential = MCPCredential.from_core(core_credential, challenge)

            retry_meta = dict(meta) if meta else {}
            retry_meta.update(mcp_credential.to_meta())

            retry_kwargs: dict[str, Any] = {"meta": retry_meta}
            if timeout is not None:
                retry_kwargs["read_timeout_seconds"] = timeout

            retry_result = await self._session.call_tool(name, arguments, **retry_kwargs)
            receipt = self._extract_receipt(retry_result)
            return McpToolResult(result=retry_result, receipt=receipt)

    def _match_challenge(
        self, challenges_data: list[dict[str, Any]]
    ) -> tuple[MCPChallenge, Method]:
        """Match a challenge to an installed method.

        Iterates installed methods in order (client preference) and returns
        the first match by ``name`` and ``intent``.
        """
        for method in self._methods:
            for cd in challenges_data:
                if cd.get("method") == method.name and cd.get("intent") in self._intent_names(
                    method
                ):
                    return MCPChallenge.from_dict(cd), method

        available = [cd.get("method") for cd in challenges_data]
        installed = [m.name for m in self._methods]
        raise ValueError(
            f"No compatible payment method. Server offered: {available}, client has: {installed}"
        )

    @staticmethod
    def _intent_names(method: Method) -> set[str]:
        """Get intent names supported by a method."""
        intents = getattr(method, "intents", None) or getattr(method, "_intents", None)
        if isinstance(intents, dict):
            return set(intents.keys())
        return {"charge"}

    @staticmethod
    def _extract_receipt(result: Any) -> MCPReceipt | None:
        """Extract a payment receipt from a tool result's _meta."""
        meta = getattr(result, "meta", None)
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
