"""ERC-8004 agents for :mod:`mpp.identity` (mppx `extensions/identity/erc8004`).

An agent is its token in an `ERC-8004 <https://eips.ethereum.org/EIPS/eip-8004>`_ Identity
Registry (by default the one on Tempo mainnet), and proves who it is with the wallet the registry
names (``getAgentWallet``). It signs each request with that wallet and pays from it.

- Headers: ``Agent-Id: eip155:<chainId>:<registry>:<agentId>`` and
  ``Agent-Signature: <created>.<nonce>.<signature>``, an EIP-191 signature over the method, URL,
  created time and nonce (:func:`message`).
- Server: :func:`server.create` returns a verifier, which reads the agent's wallet from the
  registry and checks the signature by EOA recovery or ERC-1271, and a payment check, which accepts
  a ``tempo`` charge (a transaction or a proof) whose source is the agent's wallet and otherwise
  falls back to the signature. A signature is valid for five minutes and, with a store, once::

      from mpp.extensions.identity import erc8004

      agents = erc8004.server.create(store=store)
      handler = mpp.charge(
          amount="0.01",
          identity=identity.Route(request=[agents.verifier], payment=agents.payment_check),
      )

- Client: :func:`client.prover` signs each request with the agent's wallet::

      prover = erc8004.client.prover(account=account, agent_id=42, scope=["https://api.example"])
      async with Mpp(methods=[...], identity=[prover]) as mpp: ...

The server and client modules need the ``evm`` extra: ``pip install "pympp[evm]"``.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING

import httpx

TYPE = "erc8004"
"""Identity type a payment check lists in the 402's ``Identity-Required`` header."""
CHAIN_ID = 4217
"""Chain the default registry is on: Tempo mainnet."""
IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
"""The ERC-8004 Identity Registry, at the same address on every chain that deploys it."""
RPC_URL = "https://rpc.tempo.xyz"
"""Default RPC for Tempo mainnet."""
ID_HEADER = "Agent-Id"
"""Carries the agent's ID: ``eip155:<chainId>:<registry>:<agentId>``."""
SIGNATURE_HEADER = "Agent-Signature"
"""Carries ``<created>.<nonce>.<signature>``: the agent wallet's signature of the request."""
MAX_AGE = 300
"""How long, in seconds, a request signature stays valid."""
CLOCK_TOLERANCE = 60
"""Allowed clock skew, in seconds."""

_ID_RE = re.compile(r"eip155:(\d{1,15}):(0x[0-9a-fA-F]{40}):(\d{1,78})")


@dataclass(frozen=True, slots=True)
class Agent:
    """An ERC-8004 agent whose wallet signed the request or paid.

    - ``id``: the agent's global ID, ``eip155:<chainId>:<registry>:<agentId>``.
    - ``agent_id``: the agent's token ID in the Identity Registry.
    - ``wallet``: the agent's wallet, from the registry's ``getAgentWallet``, checksummed.
    """

    id: str
    agent_id: int
    wallet: str


@dataclass(frozen=True, slots=True)
class AgentRef:
    """An agent's place in a registry: its chain, registry (checksummed) and token ID."""

    chain_id: int
    registry: str
    agent_id: int

    def format(self) -> str:
        """The agent's global ID: ``eip155:<chainId>:<registry>:<agentId>``."""
        return f"eip155:{self.chain_id}:{checksum(self.registry)}:{self.agent_id}"

    @classmethod
    def parse(cls, value: str) -> AgentRef | None:
        """Parse an agent's global ID, or return None when it is malformed."""
        match = _ID_RE.fullmatch(value)
        if match is None:
            return None
        agent_id = int(match.group(3))
        if agent_id >= 2**256:
            return None
        return cls(int(match.group(1)), checksum(match.group(2)), agent_id)


def message(*, id: str, method: str, url: str, created: int, nonce: str) -> str:
    """The message an agent's wallet signs (EIP-191) for one request attempt."""
    return "\n".join(("mppx:erc8004", id, f"{method} {target(url)}", str(created), nonce))


def target(url: str | httpx.URL) -> str:
    """``url``'s origin, path and query, as mppx reads ``origin + pathname + search``."""
    from mpp.identity import _origin  # pyright: ignore[reportPrivateUsage]

    parsed = httpx.URL(str(url))
    path, _, query = parsed.raw_path.decode("ascii").partition("?")
    return f"{_origin(str(parsed))}{path or '/'}{'?' + query if query else ''}"


def checksum(address: str) -> str:
    """EIP-55 checksum of a hex address."""
    from eth_hash.auto import keccak

    lower = address[2:].lower()
    digest = keccak(lower.encode()).hex()
    return "0x" + "".join(
        char.upper() if int(digest[index], 16) >= 8 else char for index, char in enumerate(lower)
    )


_SUBMODULES = ("client", "server")

if TYPE_CHECKING:
    from mpp.extensions.identity.erc8004 import client, server


def __getattr__(name: str) -> ModuleType:
    if name not in _SUBMODULES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        module = importlib.import_module(f"{__name__}.{name}")
    except ImportError as error:
        raise ImportError(
            f"Cannot import {__name__}.{name}: {error}. Install the evm extra: "
            'pip install "pympp[evm]"'
        ) from error
    globals()[name] = module
    return module


__all__ = [
    "CHAIN_ID",
    "CLOCK_TOLERANCE",
    "IDENTITY_REGISTRY",
    "ID_HEADER",
    "MAX_AGE",
    "RPC_URL",
    "SIGNATURE_HEADER",
    "TYPE",
    "Agent",
    "AgentRef",
    "checksum",
    "client",
    "message",
    "server",
    "target",
]
