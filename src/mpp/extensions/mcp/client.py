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


def _extract_challenges(error: Exception) -> list[MCPChallenge]:
    """Extract valid payment challenges from a payment required error."""
    data = getattr(error, "data", None)
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
        client = McpClient(session, methods=[tempo(...)])
        result = await client.call_tool("premium_tool", {"query": "hello"})
        print(result.receipt)
    """

    def __init__(self, session: Any, methods: list[Method]) -> None:
        self._session = session
        self._methods = methods

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

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
            PaymentOutcomeUnknownError: If the paid retry fails after sending a credential.
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

            challenges = _extract_challenges(e)
            if not challenges:
                raise ValueError("Server returned malformed payment challenges") from e

            challenge, method = self._match_challenge(challenges)

            core_credential = await method.create_credential(challenge.to_core())
            mcp_credential = MCPCredential.from_core(core_credential, challenge)

            retry_meta = dict(meta) if meta else {}
            retry_meta.update(mcp_credential.to_meta())

            retry_kwargs: dict[str, Any] = {"meta": retry_meta}
            if timeout is not None:
                retry_kwargs["read_timeout_seconds"] = timeout

            try:
                retry_result = await self._session.call_tool(name, arguments, **retry_kwargs)
            except Exception as exc:
                raise PaymentOutcomeUnknownError(challenge, exc) from exc

            receipt = self._extract_receipt(retry_result)
            return McpToolResult(result=retry_result, receipt=receipt)

    def _match_challenge(self, challenges: list[MCPChallenge]) -> tuple[MCPChallenge, Method]:
        """Match a challenge to an installed method.

        Iterates installed methods in order (client preference) and returns
        the first match by ``name`` and ``intent``.
        """
        for method in self._methods:
            supported_intents = self._intent_names(method)
            for challenge in challenges:
                if challenge.method == method.name and challenge.intent in supported_intents:
                    return challenge, method

        available = [challenge.method for challenge in challenges]
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
