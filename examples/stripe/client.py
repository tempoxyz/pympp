#!/usr/bin/env python3
"""CLI client that pays for a fortune using Stripe SPTs.

Uses a test card (pm_card_visa) for headless operation — no browser needed.

Usage:
    export STRIPE_SECRET_KEY=sk_test_...
    python client.py [--server http://localhost:8000]
"""

import argparse
import asyncio
import sys

import httpx

from mpp.client import Client
from mpp.methods.stripe import stripe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="stripe-fortune",
        description="Fetch a fortune with automatic Stripe payment",
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8000",
        help="Server base URL (default: http://localhost:8000)",
    )
    return parser.parse_args()


async def run(args: argparse.Namespace) -> int:
    server_url = args.server.rstrip("/")

    async def create_token(params):
        """Proxy SPT creation through the server."""
        async with httpx.AsyncClient() as http:
            response = await http.post(
                f"{server_url}/api/create-spt",
                json={
                    "paymentMethod": params.payment_method,
                    "amount": params.amount,
                    "currency": params.currency,
                    "expiresAt": params.expires_at,
                    "networkId": params.network_id,
                    "metadata": params.metadata,
                },
            )
            response.raise_for_status()
            return response.json()["spt"]

    method = stripe(
        create_token=create_token,
        payment_method="pm_card_visa",
        intents={},
    )

    async with Client(methods=[method]) as client:
        response = await client.get(f"{server_url}/api/fortune")

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            return 1

        data = response.json()
        print(f"🥠 {data['fortune']}")
        print(f"📝 Receipt: {data['receipt']}")
        return 0


def main() -> None:
    sys.exit(asyncio.run(run(parse_args())))


if __name__ == "__main__":
    main()
