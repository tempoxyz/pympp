"""MCP transport support for HTTP 402 Payment Authentication.

This module implements the Payment Authentication Scheme for the Model Context
Protocol (MCP) per draft-payment-transport-mcp-00.

## Framework-Agnostic Usage

For any MCP server, use verify_or_challenge() directly:

    from mpay.extensions.mcp import (
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

For FastMCP-style frameworks, use the @requires_payment decorator:

    from mcp.server.fastmcp import FastMCP
    from mpay.extensions.mcp import requires_payment, payment_capabilities

    mcp = FastMCP(
        "paid-api",
        capabilities={"experimental": payment_capabilities(["tempo"], ["charge"])},
    )

    @mcp.tool()
    @requires_payment(
        intent=intent,
        request={"amount": "1000", ...},
        realm="api.example.com",
    )
    async def expensive_tool(query: str, *, credential, receipt) -> str:
        return f"Result for {query}, paid by {credential.source}"
"""

from mpay.extensions.mcp.capabilities import payment_capabilities
from mpay.extensions.mcp.constants import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    META_CREDENTIAL,
    META_RECEIPT,
)
from mpay.extensions.mcp.decorator import requires_payment
from mpay.extensions.mcp.errors import (
    MalformedCredentialError,
    PaymentRequiredError,
    PaymentVerificationError,
)
from mpay.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt
from mpay.extensions.mcp.verify import create_challenge, verify_or_challenge

__all__ = [
    "CODE_MALFORMED_CREDENTIAL",
    "CODE_PAYMENT_REQUIRED",
    "CODE_PAYMENT_VERIFICATION_FAILED",
    "MCPChallenge",
    "MCPCredential",
    "MCPReceipt",
    "META_CREDENTIAL",
    "META_RECEIPT",
    "MalformedCredentialError",
    "PaymentRequiredError",
    "PaymentVerificationError",
    "create_challenge",
    "payment_capabilities",
    "requires_payment",
    "verify_or_challenge",
]
