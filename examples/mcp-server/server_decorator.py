#!/usr/bin/env python3
"""MCP server with payment-protected tools using the decorator pattern.

Runs as an SSE server that clients can connect to independently.

Usage:
    python server_decorator.py

Environment:
    TEMPO_RPC_URL: Tempo RPC endpoint (default: https://rpc.testnet.tempo.xyz/)
    DESTINATION_ADDRESS: Payment recipient address (required)
    MCP_PORT: Port for SSE server (default: 8000)
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.routing import Route

from mpay.extensions.mcp import (
    MCPChallenge,
    PaymentRequiredError,
    verify_or_challenge,
)
from mpay.methods.tempo import ChargeIntent
from mpay.methods.tempo._defaults import ALPHA_USD, TESTNET_RPC_URL

RPC_URL = os.environ.get("TEMPO_RPC_URL", TESTNET_RPC_URL)
DESTINATION = os.environ.get("DESTINATION_ADDRESS", "")
PORT = int(os.environ.get("MCP_PORT", "8000"))

if not DESTINATION:
    raise ValueError("DESTINATION_ADDRESS environment variable is required")

intent = ChargeIntent(rpc_url=RPC_URL)
server = Server("paid-echo-server")
sse = SseServerTransport("/messages/")


def get_payment_request() -> dict:
    """Build the payment request with fresh expiration."""
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    if expires.endswith("+00:00"):
        expires = expires[:-6] + "Z"

    return {
        "amount": "100",
        "currency": ALPHA_USD,
        "recipient": DESTINATION,
        "expires": expires,
        "methodDetails": {"feePayer": True},
    }


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
    """Handle tool calls."""
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
            meta=meta_dict,
            intent=intent,
            request=get_payment_request(),
            realm="echo.example.com",
            description="Premium echo service",
        )

        if isinstance(result, MCPChallenge):
            raise PaymentRequiredError(challenges=[result])

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
