"""Tempo network the test suite runs against, chosen once per session.

Mirrors mppx's `test/config.ts`. `TEMPO_NETWORK` selects the network:

- `none` (default): pure tests only; `integration` tests are skipped.
- `localnet`: the Docker Tempo localnet from docker-compose.yml
  (`make node`), at http://localhost:8545 (port: `TEMPO_LOCALNET_PORT`) unless
  `TEMPO_RPC_URL` says otherwise.
- `moderato`: the public Moderato testnet.

`TEMPO_RPC_URL` overrides the network's RPC URL. Set alone, as before
`TEMPO_NETWORK` existed, it selects `localnet` for a localhost URL and
`moderato` otherwise.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from mpp.methods.tempo._defaults import TESTNET_RPC_URL

TempoNetwork = Literal["localnet", "moderato", "none"]

LOCALNET_RPC_URL = f"http://localhost:{os.environ.get('TEMPO_LOCALNET_PORT') or 8545}"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True, slots=True)
class TempoNetworkConfig:
    network: TempoNetwork
    rpc_url: str

    @property
    def enabled(self) -> bool:
        return self.network != "none"

    @property
    def is_localnet(self) -> bool:
        return self.network == "localnet"


def resolve_tempo_network(network: str | None, rpc_url: str | None) -> TempoNetworkConfig:
    """Resolve `TEMPO_NETWORK` and the `TEMPO_RPC_URL` override."""
    rpc_url = rpc_url or None
    if not network:
        if rpc_url is None:
            network = "none"
        else:
            network = "localnet" if urlparse(rpc_url).hostname in _LOCAL_HOSTS else "moderato"
    if network == "none":
        return TempoNetworkConfig("none", "")
    if network == "localnet":
        return TempoNetworkConfig("localnet", rpc_url or LOCALNET_RPC_URL)
    if network == "moderato":
        return TempoNetworkConfig("moderato", rpc_url or TESTNET_RPC_URL)
    raise ValueError(
        f'Unsupported TEMPO_NETWORK "{network}". Use "localnet", "moderato", or "none".'
    )


TEMPO = resolve_tempo_network(os.environ.get("TEMPO_NETWORK"), os.environ.get("TEMPO_RPC_URL"))
