#!/usr/bin/env python3
"""MCP client demonstrating the payment flow.

Connects to an already-running MCP server via SSE and demonstrates:
1. Calling a free tool (echo)
2. Calling a paid tool without credentials (gets -32042 error)
3. Parsing the challenge, creating a credential, and retrying

Usage:
    # Terminal 1: Start the server
    python server_decorator.py

    # Terminal 2: Run the client
    python client.py

Environment:
    TEMPO_PRIVATE_KEY: Private key for signing payment transactions (required)
    MCP_SERVER_URL: Server SSE endpoint (default: http://127.0.0.1:8000/sse)
"""

from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession
from mcp.client.sse import sse_client

from mpp.extensions.mcp import (
    CODE_PAYMENT_REQUIRED,
    MCPChallenge,
    MCPCredential,
)
from mpp.methods.tempo import ChargeIntent, TempoAccount, tempo

SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/sse")


async def run_client() -> None:
    """Run the MCP client demonstration."""
    print(f"Connecting to MCP server at {SERVER_URL}")
    print("=" * 60)

    private_key = os.environ.get("TEMPO_PRIVATE_KEY")
    if not private_key:
        print("Error: TEMPO_PRIVATE_KEY environment variable is required")
        sys.exit(1)

    account = TempoAccount.from_key(private_key)
    method = tempo(account=account, intents={"charge": ChargeIntent()})

    print(f"Client address: {account.address}")
    print()

    async with sse_client(SERVER_URL) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")
            print()

            print("1. Calling free tool (echo)...")
            result = await session.call_tool("echo", {"message": "Hello, world!"})
            print(f"   Result: {result.content[0].text}")
            print()

            print("2. Calling paid tool without credential (premium_echo)...")
            try:
                result = await session.call_tool(
                    "premium_echo", {"message": "Hello, premium!"}
                )
                print(f"   Result: {result.content[0].text}")
            except Exception as e:
                error_data = getattr(e, "error", None) or {}
                error_code = (
                    error_data.get("code")
                    if isinstance(error_data, dict)
                    else getattr(error_data, "code", None)
                )

                print(f"   Got error code: {error_code}")

                if error_code == CODE_PAYMENT_REQUIRED:
                    data = (
                        error_data.get("data", {})
                        if isinstance(error_data, dict)
                        else getattr(error_data, "data", {})
                    )
                    challenges = (
                        data.get("challenges", []) if isinstance(data, dict) else []
                    )

                    if challenges:
                        challenge_data = challenges[0]
                        print(f"   Challenge ID: {challenge_data.get('id', 'unknown')}")
                        print()

                        print("3. Creating payment credential...")
                        challenge = MCPChallenge.from_dict(challenge_data)
                        core_credential = await method.create_credential(
                            challenge.to_core()
                        )

                        mcp_credential = MCPCredential.from_core(
                            core_credential, challenge
                        )
                        print(f"   Credential created for challenge: {challenge.id}")
                        print()

                        print("4. Retrying with credential...")
                        result = await session.call_tool(
                            "premium_echo",
                            {"message": "Hello, premium!"},
                            meta=mcp_credential.to_meta(),
                        )
                        print(f"   Result: {result.content[0].text}")
                else:
                    print(f"   Unexpected error: {e}")


def main() -> None:
    """Run the client."""
    asyncio.run(run_client())


if __name__ == "__main__":
    main()
