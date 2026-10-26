"""Decorator for payment-protected MCP tools.

The @pay decorator is a convenience wrapper for FastMCP-style
frameworks where tool params are unpacked as **kwargs.

For other MCP server implementations, use verify_or_challenge() directly:

    from mpp.extensions.mcp import PaymentRequiredError, verify_or_challenge

    async def handle_tool(params: dict):
        result = await verify_or_challenge(
            mpp.charge(amount="0.01"),
            tool="expensive_tool",
            meta=params.get("_meta"),
        )
        if isinstance(result, list):
            raise PaymentRequiredError(challenges=result)
        credential, receipt = result
        # ... execute tool
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from mpp.extensions.mcp.errors import PaymentRequiredError
from mpp.extensions.mcp.verify import verify_or_challenge as mcp_verify_or_challenge
from mpp.server import ComposedHandler

P = ParamSpec("P")
R = TypeVar("R")

HandlerType = ComposedHandler | Callable[..., ComposedHandler]


def pay(
    handler: HandlerType,
    *,
    tool: str,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorator to require payment for an MCP tool (FastMCP-style).

    This decorator is designed for FastMCP and similar frameworks where tool
    parameters are unpacked as **kwargs. For other MCP server implementations,
    use verify_or_challenge() directly.

    Handles the full 402 challenge flow:
    1. Extracts _meta from kwargs
    2. Checks for org.paymentauth/credential in _meta
    3. If missing or invalid, raises PaymentRequiredError with the challenges
    4. If valid, verifies credential and injects credential + receipt into handler

    The decorated function receives two additional keyword arguments:
    - credential: MCPCredential with the verified payment credential
    - receipt: MCPReceipt confirming the payment

    Args:
        handler: A configured payment handler of a server ``Mpp``, such as
            ``mpp.charge(amount="0.01")``, or a callable taking the tool's arguments
            and returning one (for pricing that depends on the call).
        tool: Explicit stable identity, unique to this paid tool within the realm.
            Use the registered MCP tool name, including for generated handlers.

    Example:
        mpp = Mpp(methods=tempo.charge(recipient="0x..."))

        @mcp.tool()
        @pay(mpp.charge(amount="0.01"), tool="expensive_tool")
        async def expensive_tool(query: str, *, credential, receipt) -> str:
            return f"Result for {query}, paid by {credential.source}"

        # With dynamic pricing:
        @mcp.tool()
        @pay(lambda query, **kw: mpp.charge(amount=f"{len(query) * 0.01:.2f}"), tool="dynamic")
        async def dynamic(query: str, *, credential, receipt) -> str:
            return f"Result for {query}"

    Raises:
        PaymentRequiredError: When no credential provided (returns -32042).
        PaymentVerificationError: When credential verification fails (-32043).
        MalformedCredentialError: When credential structure is invalid (-32602).
    """
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty stable identifier")

    def decorator(
        fn: Callable[P, Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        @wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            meta: dict[str, Any] | None = kwargs.pop("_meta", None)  # type: ignore[arg-type]

            route = handler if isinstance(handler, ComposedHandler) else handler(*args, **kwargs)
            result = await mcp_verify_or_challenge(route, tool=tool, meta=meta)

            if isinstance(result, list):
                raise PaymentRequiredError(challenges=result)

            credential, receipt = result
            kwargs["credential"] = credential
            kwargs["receipt"] = receipt
            return await fn(*args, **kwargs)

        return wrapper

    return decorator
