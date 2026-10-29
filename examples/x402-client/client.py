"""A pympp client paying the official x402 server.

pympp parses the server's PAYMENT-REQUIRED offer, signs an EIP-3009
authorization with the payer's key and retries with PAYMENT-SIGNATURE.
Exits non-zero unless the request succeeds and the payment moved on-chain.
"""

import asyncio
import json
import os

from common import RPC_URL, asset, payer, recipient, token_contract
from web3 import Web3

import mpp.x402
from mpp.client import Mpp
from mpp.methods.evm import client as evm

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:4021")


def usdc(units: int) -> str:
    return f"{units / 10**6:.6f} USDC"


async def main() -> None:
    token = token_contract(Web3(Web3.HTTPProvider(RPC_URL)))

    def balances() -> tuple[int, int]:
        return (
            token.functions.balanceOf(payer.address).call(),
            token.functions.balanceOf(recipient.address).call(),
        )

    payer_before, recipient_before = balances()
    method = evm.charge(currency=asset(), account=payer, max_amount="0.01")
    async with Mpp(methods=[method]) as client:
        response = await client.fetch(f"{SERVER_URL}/weather")

    print(f"status: {response.status_code}")
    print(f"body: {response.text}")
    settlement = mpp.x402.payment_response(response)
    print(f"PAYMENT-RESPONSE: {json.dumps(settlement, indent=2)}")

    payer_after, recipient_after = balances()
    print(f"payer     {payer.address}: {usdc(payer_before)} -> {usdc(payer_after)}")
    print(f"recipient {recipient.address}: {usdc(recipient_before)} -> {usdc(recipient_after)}")

    paid = recipient_after - recipient_before
    if response.status_code != 200 or not settlement or paid <= 0:
        raise SystemExit("payment failed")
    print(f"paid {usdc(paid)} over x402")


if __name__ == "__main__":
    asyncio.run(main())
