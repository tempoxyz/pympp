from __future__ import annotations

import os
import time

import httpx
import pytest

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.intents import ChargeIntent

# Standard dev key pre-funded on --dev nodes
DEV_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


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


def _fund_account_via_dev_key(rpc_url: str, address: str, currency: str, amount: int) -> None:
    """Fund an account by sending tokens from the pre-funded dev account."""
    from pytempo import Call, TempoTransaction

    dev_account = TempoAccount.from_key(DEV_PRIVATE_KEY)

    with httpx.Client(timeout=30) as client:
        chain_id_hex = client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
        ).json()["result"]
        nonce_hex = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [dev_account.address, "pending"],
                "id": 1,
            },
        ).json()["result"]
        gas_hex = client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_gasPrice", "params": [], "id": 1},
        ).json()["result"]

    cid = int(chain_id_hex, 16)
    nonce = int(nonce_hex, 16)
    gas_price = int(gas_hex, 16)

    selector = "a9059cbb"
    to_padded = address[2:].lower().zfill(64)
    amount_padded = hex(amount)[2:].zfill(64)
    data = f"0x{selector}{to_padded}{amount_padded}"

    tx = TempoTransaction.create(
        chain_id=cid,
        gas_limit=5_000_000,
        max_fee_per_gas=gas_price,
        max_priority_fee_per_gas=gas_price,
        nonce=nonce,
        nonce_key=0,
        fee_token=currency,
        calls=(Call.create(to=currency, value=0, data=data),),
    )
    signed = tx.sign(dev_account.private_key)
    raw_tx = "0x" + signed.encode().hex()

    with httpx.Client(timeout=30) as client:
        resp = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [raw_tx],
                "id": 1,
            },
        )
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"Fund transfer failed: {result['error']}")
        tx_hash = result["result"]

        for _ in range(120):
            resp = client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1,
                },
            )
            receipt = resp.json().get("result")
            if receipt is not None:
                if receipt.get("status") != "0x1":
                    raise RuntimeError(f"Fund transfer reverted: {tx_hash}")
                return
            time.sleep(0.5)
    raise RuntimeError(f"Fund transfer receipt not found: {tx_hash}")


def _fund_account(rpc_url: str, address: str, currency: str) -> None:
    """Fund an account using tempo_fundAddress if available, else dev key transfer."""
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
        if "error" not in result:
            for _ in range(100):
                if _tip20_balance(rpc_url, currency, address, client) > 0:
                    return
                time.sleep(0.2)
            raise RuntimeError(f"Account {address} not funded after tempo_fundAddress")

    # Fallback: transfer from dev account
    _fund_account_via_dev_key(rpc_url, address, currency, 100_000_000_000)

    with httpx.Client(timeout=30) as client:
        for _ in range(100):
            if _tip20_balance(rpc_url, currency, address, client) > 0:
                return
            time.sleep(0.2)
    raise RuntimeError(f"Account {address} not funded after 100 attempts")


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
