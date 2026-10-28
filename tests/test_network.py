"""TEMPO_NETWORK resolution for the test suite (tests/network.py)."""

import pytest

from mpp.methods.tempo._defaults import TESTNET_RPC_URL
from tests.network import LOCALNET_RPC_URL, resolve_tempo_network


@pytest.mark.parametrize(
    ("network", "rpc_url", "expected", "expected_url"),
    [
        (None, None, "none", ""),
        ("", "", "none", ""),
        ("none", "http://localhost:8545", "none", ""),
        ("localnet", None, "localnet", LOCALNET_RPC_URL),
        ("localnet", "http://127.0.0.1:44500", "localnet", "http://127.0.0.1:44500"),
        ("moderato", None, "moderato", TESTNET_RPC_URL),
        ("moderato", "https://rpc.example.com", "moderato", "https://rpc.example.com"),
        # TEMPO_RPC_URL alone keeps working and picks the network from its host.
        (None, "http://localhost:8545", "localnet", "http://localhost:8545"),
        (None, "http://127.0.0.1:9000", "localnet", "http://127.0.0.1:9000"),
        (None, TESTNET_RPC_URL, "moderato", TESTNET_RPC_URL),
    ],
)
def test_resolve_tempo_network(network, rpc_url, expected, expected_url):
    config = resolve_tempo_network(network, rpc_url)
    assert config.network == expected
    assert config.rpc_url == expected_url
    assert config.enabled == (expected != "none")
    assert config.is_localnet == (expected == "localnet")


def test_resolve_tempo_network_rejects_unknown_network():
    with pytest.raises(ValueError, match='Unsupported TEMPO_NETWORK "mainnet"'):
        resolve_tempo_network("mainnet", None)
