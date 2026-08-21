from __future__ import annotations

import os
import time

import httpx
import pytest

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.intents import ChargeIntent


@pytest.fixture(scope="session")
def rpc_url():
    return os.environ["TEMPO_RPC_URL"]


@pytest.fixture(scope="session")
def is_local_node(rpc_url):
    return "localhost" in rpc_url or "127.0.0.1" in rpc_url


@pytest.fixture(scope="session")
def chain_id(rpc_url):
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
        )
        return int(resp.json()["result"], 16)


@pytest.fixture(scope="session")
def currency():
    if os.environ.get("TEMPO_CURRENCY"):
        return os.environ["TEMPO_CURRENCY"]
    return PATH_USD


@pytest.fixture
def charge_intent(rpc_url):
    return ChargeIntent(rpc_url=rpc_url)


def _tip20_balance(rpc_url: str, token: str, address: str, client: httpx.Client) -> int:
    call_data = "0x70a08231" + "0" * 24 + address[2:].lower()
    resp = client.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": token, "data": call_data}, "latest"],
            "id": 1,
        },
    )
    return int(resp.json()["result"], 16)


def _fund_account(rpc_url: str, address: str, currency: str) -> None:
    """Fund an account using the localnet faucet."""
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "tempo_fundAddress",
                "params": [address],
                "id": 1,
            },
        )
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"tempo_fundAddress failed: {result['error']}")
        if not result.get("result"):
            raise RuntimeError("tempo_fundAddress returned no transaction hashes")
        for _ in range(100):
            if _tip20_balance(rpc_url, currency, address, client) > 0:
                return
            time.sleep(0.2)
    raise RuntimeError(f"Account {address} not funded after tempo_fundAddress")


@pytest.fixture(scope="session")
def funded_payer(rpc_url, is_local_node, currency):
    if is_local_node:
        key = "0x" + os.urandom(32).hex()
        account = TempoAccount.from_key(key)
        _fund_account(rpc_url, account.address, currency)
        return account
    return TempoAccount.from_env("TEMPO_TEST_PRIVATE_KEY")


@pytest.fixture(scope="session")
def funded_recipient(rpc_url, is_local_node, currency):
    if is_local_node:
        key = "0x" + os.urandom(32).hex()
        account = TempoAccount.from_key(key)
        _fund_account(rpc_url, account.address, currency)
        return account
    return TempoAccount.from_env("TEMPO_TEST_RECIPIENT_KEY")
