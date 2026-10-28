"""An agent that makes many sub-cent API calls through one MPP session, then closes it."""

import asyncio
import os
import sys
import time

from localnet import balance, fund_on_localnet, rpc

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.session import _chain as chain

RPC_URL = os.environ.get("TEMPO_RPC_URL", "http://localhost:18645")
CURRENCY = os.environ.get("TEMPO_CURRENCY", PATH_USD)
URL = os.environ.get("SERVER_URL", "http://localhost:8000") + "/api/quote"
CALLS = int(os.environ.get("CALLS", "500"))
MAX_DEPOSIT = os.environ.get("MAX_DEPOSIT", "0.05")


def usd(raw: int) -> str:
    return f"{raw / 1_000_000:.6f}"


async def main() -> None:
    payer = TempoAccount.from_key(os.environ.get("PAYER_KEY") or "0x" + os.urandom(32).hex())
    await fund_on_localnet(RPC_URL, CURRENCY, payer.address)
    payer_before = await balance(RPC_URL, CURRENCY, payer.address)
    print(f"agent {payer.address}: {CALLS} calls to {URL}")

    started = time.monotonic()
    async with tempo.session_manager(
        account=payer, max_deposit=MAX_DEPOSIT, rpc_url=RPC_URL
    ) as manager:
        deposit = 0
        payee = ""
        payee_before = 0
        for call in range(1, CALLS + 1):
            response = await manager.fetch(URL)
            if response.status_code != 200:
                sys.exit(f"call {call} failed: {response.status_code} {response.text}")
            if call == 1:
                challenge = manager.last_challenge
                assert challenge is not None
                payee = str(challenge.request["recipient"])
                payee_before = await balance(RPC_URL, CURRENCY, payee)
                print(f"opened channel {manager.channel_id} with deposit {usd(manager.deposit)}")
            elif manager.deposit > deposit:
                print(f"call {call}: topped up to {usd(manager.deposit)}")
            deposit = manager.deposit
            if call % 100 == 0 or call == CALLS:
                print(f"call {call}: spent {usd(manager.spent)} of {usd(deposit)}")
        elapsed = time.monotonic() - started

        closed = await manager.close()
        assert closed is not None and closed.tx_hash is not None
        channel_id = closed.channel_id

    receipt = await rpc(RPC_URL, "eth_getTransactionReceipt", closed.tx_hash)
    event = chain.get_channel_event(receipt, "ChannelClosed", channel_id)
    state = await chain.get_channel_state(RPC_URL, channel_id)
    paid = payer_before - await balance(RPC_URL, CURRENCY, payer.address)
    received = await balance(RPC_URL, CURRENCY, payee) - payee_before

    print(f"\n{CALLS} calls in {elapsed:.1f}s ({CALLS / elapsed:.0f}/s) on one channel")
    print(f"closed in tx {closed.tx_hash}")
    print(f"  deposit   {usd(deposit)}")
    print(f"  spent     {usd(int(closed.spent))} ({CALLS} x 0.00001)")
    print(f"  refunded  {usd(int(event['refundedToPayer']))}")
    print(f"on chain: payer paid {usd(paid)}, payee received {usd(received)}, ", end="")
    print(f"channel deposit now {usd(state.deposit)}")


if __name__ == "__main__":
    asyncio.run(main())
