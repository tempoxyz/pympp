#!/usr/bin/env python3
"""CLI tool for fetching URLs with automatic payment handling."""

import argparse
import asyncio
import os
import sys

from mpay.client import Client
from mpay.methods.tempo import ChargeIntent, TempoAccount, tempo


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fetch",
        description="Fetch URLs with automatic payment handling",
    )
    parser.add_argument("url", help="URL to fetch")
    parser.add_argument(
        "-X",
        "--method",
        default="GET",
        help="HTTP method (default: GET)",
    )
    parser.add_argument(
        "-d",
        "--data",
        help="Request body data",
    )
    parser.add_argument(
        "--key",
        help="Tempo private key (or set TEMPO_PRIVATE_KEY)",
    )
    parser.add_argument(
        "--rpc-url",
        help="Tempo RPC URL (or set TEMPO_RPC_URL, default: rpc.testnet.tempo.xyz)",
    )
    return parser.parse_args()


async def run(args: argparse.Namespace) -> int:
    key = args.key or os.environ.get("TEMPO_PRIVATE_KEY")
    if not key:
        print("Error: --key or TEMPO_PRIVATE_KEY required", file=sys.stderr)
        return 2

    account = TempoAccount.from_key(key)

    rpc_url = args.rpc_url or os.environ.get("TEMPO_RPC_URL")
    method = tempo(account=account, rpc_url=rpc_url or "https://rpc.tempo.xyz", intents={"charge": ChargeIntent()})

    async with Client(methods=[method]) as client:
        response = await client.request(
            args.method,
            args.url,
            content=args.data,
        )

        if response.status_code >= 400:
            print(response.text, file=sys.stderr)
            return 1

        print(response.text)
        return 0


def main() -> None:
    sys.exit(asyncio.run(run(parse_args())))


if __name__ == "__main__":
    main()
