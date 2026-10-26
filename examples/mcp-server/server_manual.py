#!/usr/bin/env python3
"""MCP server with payment-protected tools using manual verify_or_challenge().

This example demonstrates the manual pattern for complete control over the
payment flow. Runs as an SSE server that clients can connect to independently.

Usage:
    python server_manual.py

Environment:
    TEMPO_RPC_URL: Tempo RPC endpoint (default: https://rpc.moderato.tempo.xyz)
    DESTINATION_ADDRESS: Payment recipient address (required)
    MCP_PORT: Port for SSE server (default: 8000)
    FEE_PAYER_KEY: Private key of an account that sponsors clients' gas (optional)
    MPP_SECRET_KEY: Secret that signs challenges (required)
"""

from __future__ import annotations

import os
from typing import Any

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import CallToolRequest, CallToolResult, ServerResult, TextContent, Tool
from starlette.applications import Starlette
from starlette.routing import Route

from mpp.extensions.mcp import PaymentRequiredError, verify_or_challenge
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID, TESTNET_RPC_URL
from mpp.server import Mpp

RPC_URL = os.environ.get("TEMPO_RPC_URL", TESTNET_RPC_URL)
DESTINATION = os.environ.get("DESTINATION_ADDRESS", "")
PORT = int(os.environ.get("MCP_PORT", "8000"))

if not DESTINATION:
    raise ValueError("DESTINATION_ADDRESS environment variable is required")

# Optional: set FEE_PAYER_KEY to sponsor gas for clients.
fee_payer_key = os.environ.get("FEE_PAYER_KEY")
fee_payer = TempoAccount.from_key(fee_payer_key) if fee_payer_key else None

mpp = Mpp(
    methods=tempo.charge(
        chain_id=TESTNET_CHAIN_ID,
        rpc_url=RPC_URL,
        currency=PATH_USD,
        recipient=DESTINATION,
        fee_payer=fee_payer,
    ),
    realm="echo.example.com",
    secret_key=os.environ["MPP_SECRET_KEY"],
)
server = Server("paid-echo-server-manual")
sse = SseServerTransport("/messages/")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="echo",
            description="Echo a message back (free tool)",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to echo"}
                },
                "required": ["message"],
            },
        ),
        Tool(
            name="premium_echo",
            description="Echo a message with style (paid tool - 100 units)",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message to echo"}
                },
                "required": ["message"],
            },
        ),
    ]


async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    """Handle tool calls with manual payment verification."""
    if name == "echo":
        message = arguments.get("message", "")
        return CallToolResult(content=[TextContent(type="text", text=f"Echo: {message}")])

    elif name == "premium_echo":
        message = arguments.get("message", "")

        meta_dict: dict[str, Any] | None = None
        request_context = server.request_context
        if (
            request_context
            and hasattr(request_context, "meta")
            and request_context.meta
        ):
            meta_dict = (
                request_context.meta.model_dump()
                if hasattr(request_context.meta, "model_dump")
                else dict(request_context.meta)
            )

        result = await verify_or_challenge(
            mpp.charge(
                amount="0.0001",
                description="Premium echo service",
                fee_payer=fee_payer is not None,
            ),
            tool=name,
            meta=meta_dict,
        )

        if isinstance(result, list):
            raise PaymentRequiredError(challenges=result)

        credential, receipt = result
        payer = credential.source
        tx = receipt.reference
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"✨ Premium Echo ✨: {message} (paid by {payer}, tx: {tx})",
                )
            ],
            # The client reads the receipt from the result's _meta.
            _meta=receipt.to_meta(),
        )

    else:
        return CallToolResult(content=[TextContent(type="text", text=f"Unknown tool: {name}")])


async def handle_call_tool(request: CallToolRequest) -> ServerResult:
    """Route tools/call to call_tool().

    Registered directly instead of with ``@server.call_tool()``: that decorator
    turns every exception into an ``isError`` tool result, which would drop the
    ``-32042`` error PaymentRequiredError sends for the client to pay.
    """
    return ServerResult(await call_tool(request.params.name, request.params.arguments or {}))


server.request_handlers[CallToolRequest] = handle_call_tool


class SSEApp:
    """ASGI app wrapper for SSE endpoint."""

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            async with sse.connect_sse(scope, receive, send) as streams:
                await server.run(
                    streams[0],
                    streams[1],
                    server.create_initialization_options(),
                )


class MessagesApp:
    """ASGI app wrapper for POST messages endpoint."""

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await sse.handle_post_message(scope, receive, send)


app = Starlette(
    routes=[
        Route("/sse", endpoint=SSEApp()),
        Route("/messages/", endpoint=MessagesApp(), methods=["POST"]),
    ],
)


def main() -> None:
    """Run the MCP server."""
    print(f"Starting MCP server on http://127.0.0.1:{PORT}/sse")
    print(f"Destination: {DESTINATION}")
    uvicorn.run(app, host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
