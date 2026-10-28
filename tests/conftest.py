from __future__ import annotations

import os
import time

import httpx
import pytest
from hypothesis import HealthCheck, settings

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.intents import ChargeIntent
from tests.network import TEMPO

# How long the first integration test waits for the node to answer, like
# mppx's test/setup.global.ts. A fresh localnet container takes a few seconds.
NODE_READY_TIMEOUT = 60.0


def _wait_for_node(rpc_url: str, timeout: float = NODE_READY_TIMEOUT) -> None:
    """Wait until the node answers `eth_blockNumber` with a produced block."""
    deadline = time.monotonic() + timeout
    error: object = None
    with httpx.Client(timeout=10) as client:
        while True:
            try:
                resp = client.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                )
                if int(resp.json()["result"], 16) > 0:
                    return
                error = "no block produced yet"
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                error = exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Tempo {TEMPO.network} node at {rpc_url} not ready after {timeout:.0f}s "
                    f"({error}). Start the localnet with `make node`."
                )
            time.sleep(0.5)


# Selected by [tool.mutmut]: mutmut reruns tests in one process (which trips
# differing_executors) and times mutants itself, so runs must be deterministic.
settings.register_profile(
    "mutmut",
    database=None,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.differing_executors],
)


@pytest.fixture(scope="session")
def rpc_url():
    if not TEMPO.enabled:
        pytest.skip("TEMPO_NETWORK not set (localnet or moderato)")
    _wait_for_node(TEMPO.rpc_url)
    return TEMPO.rpc_url


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
    """Fund an account with the node's `tempo_fundAddress` faucet (localnet or Moderato)."""
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


def _funded_account(rpc_url: str, currency: str, key_var: str) -> TempoAccount:
    """A pre-funded account from `key_var` when set, else a fresh one from the faucet.

    A fresh localnet holds no funds for configured (Moderato) keys, so it always uses the faucet.
    """
    if os.environ.get(key_var) and not TEMPO.is_localnet:
        return TempoAccount.from_env(key_var)
    account = TempoAccount.from_key("0x" + os.urandom(32).hex())
    _fund_account(rpc_url, account.address, currency)
    return account


@pytest.fixture(scope="session")
def funded_payer(rpc_url, currency):
    return _funded_account(rpc_url, currency, "TEMPO_TEST_PRIVATE_KEY")


@pytest.fixture(scope="session")
def funded_recipient(rpc_url, currency):
    return _funded_account(rpc_url, currency, "TEMPO_TEST_RECIPIENT_KEY")
