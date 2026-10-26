"""MCP transport support for HTTP 402 Payment Authentication.

This module implements the Payment Authentication Scheme for the Model Context
Protocol (MCP) per draft-payment-transport-mcp-00.

## Framework-Agnostic Usage

Gate tool calls with a route handler of a server ``Mpp``. For any MCP server,
use verify_or_challenge() directly:

    from mpp.extensions.mcp import PaymentRequiredError, verify_or_challenge
    from mpp.server import Mpp

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))

    async def handle_tool_call(params: dict):
        result = await verify_or_challenge(
            mpp.charge(amount="0.01"),
            tool="expensive_tool",
            meta=params.get("_meta"),
        )

        if isinstance(result, list):
            # Return -32042 Payment Required error
            error = PaymentRequiredError(challenges=result)
            return {"error": error.to_jsonrpc_error()}

        credential, receipt = result
        # Execute tool and include receipt in response
        return {
            "result": {
                "content": [...],
                "_meta": receipt.to_meta(),
            }
        }

## FastMCP Decorator

For FastMCP-style frameworks, use the @pay decorator:

    from mcp.server.fastmcp import FastMCP
    from mpp.extensions.mcp import pay, payment_capabilities

    mcp = FastMCP(
        "paid-api",
        capabilities={"experimental": payment_capabilities(mpp)},
    )

    @mcp.tool()
    @pay(mpp.charge(amount="0.01"), tool="expensive_tool")
    async def expensive_tool(query: str, *, credential, receipt) -> str:
        return f"Result for {query}, paid by {credential.source}"
"""

from typing import Any

from mpp._lazy_exports import load_lazy_attr
from mpp.extensions.mcp.constants import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    META_CREDENTIAL,
    META_RECEIPT,
)

_EXTRA_INSTALL_HINT = 'Install the "mcp" extra to use this module: pip install "pympp[mcp]"'

_LAZY_EXPORTS = {
    "mpp.extensions.mcp.capabilities": ("payment_capabilities",),
    "mpp.extensions.mcp.client": (
        "McpClient",
        "McpToolResult",
        "PaymentOutcomeUnknownError",
    ),
    "mpp.extensions.mcp.decorator": ("pay",),
    "mpp.extensions.mcp.errors": (
        "MalformedCredentialError",
        "PaymentRequiredError",
        "PaymentVerificationError",
    ),
    "mpp.extensions.mcp.types": ("MCPChallenge", "MCPCredential", "MCPReceipt"),
    "mpp.extensions.mcp.verify": ("verify_or_challenge",),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)


__all__ = [
    "CODE_MALFORMED_CREDENTIAL",
    "CODE_PAYMENT_REQUIRED",
    "CODE_PAYMENT_VERIFICATION_FAILED",
    "META_CREDENTIAL",
    "META_RECEIPT",
]
