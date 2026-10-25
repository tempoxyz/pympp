#!/usr/bin/env python3
"""MCP server with payment-protected tools using manual verify_or_challenge().

This example demonstrates the manual pattern for complete control over the
payment flow. Runs as an SSE server that clients can connect to independently.

Usage:
    python server_manual.py

Environment:
    TEMPO_RPC_URL: Tempo RPC endpoint (default: https://rpc.testnet.tempo.xyz/)
    DESTINATION_ADDRESS: Payment recipient address (required)
    MCP_PORT: Port for SSE server (default: 8000)
"""

from __future__ import annotations

import os
from typing import Any

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.routing import Route

from mpp.extensions.mcp import PaymentRequiredError, verify_or_challenge
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo._defaults import PATH_USD, TESTNET_CHAIN_ID, TESTNET_RPC_URL
from mpp.server import Mpp

RPC_URL = os.environ.get("TEMPO_RPC_URL", TESTNET_RPC_URL)
DESTINATION = os.environ.get("DESTINATION_ADDRESS", "")
PORT = int(os.environ.get("MCP_PORT", "8000"))

if not DESTINATION:
    raise ValueError("DESTINATION_ADDRESS environment variable is required")

mpp = Mpp(
    methods=tempo.charge(
        chain_id=TESTNET_CHAIN_ID, rpc_url=RPC_URL, currency=PATH_USD, recipient=DESTINATION
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


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls with manual payment verification."""
    if name == "echo":
        message = arguments.get("message", "")
        return [TextContent(type="text", text=f"Echo: {message}")]

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
            mpp.charge(amount="0.0001", fee_payer=True, description="Premium echo service"),
            tool=name,
            meta=meta_dict,
        )

        if isinstance(result, list):
            raise PaymentRequiredError(challenges=result)

        credential, receipt = result
        payer = credential.source
        tx = receipt.reference
        return [
            TextContent(
                type="text",
                text=f"✨ Premium Echo ✨: {message} (paid by {payer}, tx: {tx})",
            )
        ]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


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
