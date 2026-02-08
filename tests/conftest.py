from __future__ import annotations

import os
import time

import httpx
import pytest

from mpay.methods.tempo import TempoAccount
from mpay.methods.tempo.intents import ChargeIntent

PATH_USD = "0x20c0000000000000000000000000000000000000"
ALPHA_USD = "0x20c0000000000000000000000000000000000001"

INTEGRATION = pytest.mark.skipif(
    not os.environ.get("TEMPO_RPC_URL"),
    reason="TEMPO_RPC_URL not set (no local node)",
)


@pytest.fixture(scope="session")
def rpc_url():
    return os.environ["TEMPO_RPC_URL"]


@pytest.fixture(scope="session")
def is_local_node(rpc_url):
    return "localhost" in rpc_url or "127.0.0.1" in rpc_url


@pytest.fixture(scope="session")
def tx_timeout(is_local_node):
    return int(os.environ.get("TEMPO_TEST_TIMEOUT", "10" if is_local_node else "60"))


@pytest.fixture(scope="session")
def chain_id(rpc_url):
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
        )
        return int(resp.json()["result"], 16)


@pytest.fixture(scope="session")
def currency(is_local_node):
    if os.environ.get("TEMPO_CURRENCY"):
        return os.environ["TEMPO_CURRENCY"]
    return PATH_USD if is_local_node else ALPHA_USD


@pytest.fixture(scope="session")
def escrow_contract(rpc_url):
    addr = os.environ.get("TEMPO_ESCROW_ADDRESS", "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70")
    with httpx.Client(timeout=10) as client:
        resp = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [addr, "latest"],
                "id": 1,
            },
        )
        code = resp.json().get("result", "0x")
        if code == "0x" or code == "0x0":
            return None
    return addr


@pytest.fixture
def charge_intent(rpc_url):
    return ChargeIntent(rpc_url=rpc_url)


def _tip20_balance(rpc_url: str, token: str, address: str) -> int:
    call_data = "0x70a08231" + "0" * 24 + address[2:].lower()
    with httpx.Client(timeout=10) as client:
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


def _fund_account(rpc_url: str, address: str) -> None:
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

    for _ in range(100):
        if _tip20_balance(rpc_url, PATH_USD, address) > 0:
            return
        time.sleep(0.2)
    raise RuntimeError(f"Account {address} not funded after 100 attempts")


@pytest.fixture(scope="session")
def funded_payer(rpc_url, is_local_node):
    if is_local_node:
        key = "0x" + os.urandom(32).hex()
        account = TempoAccount.from_key(key)
        _fund_account(rpc_url, account.address)
        return account
    return TempoAccount.from_env("TEMPO_TEST_PRIVATE_KEY")


@pytest.fixture(scope="session")
def funded_recipient(rpc_url, is_local_node):
    if is_local_node:
        key = "0x" + os.urandom(32).hex()
        account = TempoAccount.from_key(key)
        _fund_account(rpc_url, account.address)
        return account
    return TempoAccount.from_env("TEMPO_TEST_RECIPIENT_KEY")
