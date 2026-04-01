"""MCP transport support for HTTP 402 Payment Authentication.

This module implements the Payment Authentication Scheme for the Model Context
Protocol (MCP) per draft-payment-transport-mcp-00.

## Framework-Agnostic Usage

For any MCP server, use verify_or_challenge() directly:

    from mpp.extensions.mcp import (
        verify_or_challenge,
        create_challenge,
        MCPChallenge,
        PaymentRequiredError,
    )

    async def handle_tool_call(params: dict):
        result = await verify_or_challenge(
            meta=params.get("_meta"),
            intent=intent,
            request={"amount": "1000", ...},
            realm="api.example.com",
        )

        if isinstance(result, MCPChallenge):
            # Return -32042 Payment Required error
            error = PaymentRequiredError(challenges=[result])
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
        capabilities={"experimental": payment_capabilities(["tempo"], ["charge"])},
    )

    @mcp.tool()
    @pay(
        intent=intent,
        request={"amount": "1000", ...},
        realm="api.example.com",
    )
    async def expensive_tool(query: str, *, credential, receipt) -> str:
        return f"Result for {query}, paid by {credential.source}"
"""

from mpp.extensions.mcp.constants import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    META_CREDENTIAL,
    META_RECEIPT,
)

_EXTRA_INSTALL_HINT = 'Install the "mcp" extra to use this module: pip install "pympp[mcp]"'

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "payment_capabilities": ("mpp.extensions.mcp.capabilities", "payment_capabilities"),
    "McpClient": ("mpp.extensions.mcp.client", "McpClient"),
    "McpToolResult": ("mpp.extensions.mcp.client", "McpToolResult"),
    "PaymentOutcomeUnknownError": ("mpp.extensions.mcp.client", "PaymentOutcomeUnknownError"),
    "pay": ("mpp.extensions.mcp.decorator", "pay"),
    "MalformedCredentialError": ("mpp.extensions.mcp.errors", "MalformedCredentialError"),
    "PaymentRequiredError": ("mpp.extensions.mcp.errors", "PaymentRequiredError"),
    "PaymentVerificationError": ("mpp.extensions.mcp.errors", "PaymentVerificationError"),
    "MCPChallenge": ("mpp.extensions.mcp.types", "MCPChallenge"),
    "MCPCredential": ("mpp.extensions.mcp.types", "MCPCredential"),
    "MCPReceipt": ("mpp.extensions.mcp.types", "MCPReceipt"),
    "create_challenge": ("mpp.extensions.mcp.verify", "create_challenge"),
    "verify_or_challenge": ("mpp.extensions.mcp.verify", "verify_or_challenge"),
}

__all__ = [
    "CODE_MALFORMED_CREDENTIAL",
    "CODE_PAYMENT_REQUIRED",
    "CODE_PAYMENT_VERIFICATION_FAILED",
    "META_CREDENTIAL",
    "META_RECEIPT",
    *_LAZY_IMPORTS,
]


def __getattr__(name: str):  # type: ignore[reportReturnType]
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        try:
            import importlib

            mod = importlib.import_module(module_path)
        except ImportError as exc:
            raise ImportError(
                f"Cannot import {name!r} from mpp.extensions.mcp: {exc}. {_EXTRA_INSTALL_HINT}"
            ) from exc
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
