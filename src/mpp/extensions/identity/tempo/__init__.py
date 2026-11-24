"""Tempo ID for :mod:`mpp.identity` (mppx `extensions/identity/tempo`).

Server: :func:`server.create` verifies Tempo ID access tokens offline against Tempo ID's keys,
with DPoP proofs, and returns a verifier and a payment check that also requires a ``tempo``
payment from an account the token grants to the app::

    from mpp.extensions.identity import tempo

    tempo_id = tempo.server.create(client_id="app_...", store=store)
    mpp = Mpp(methods=..., requires_auth=True)
    handler = mpp.charge(amount="0.01", identity=identity.Route(payment=tempo_id.payment_check))

Client: :func:`client.prover` sends the access token, a DPoP proof per request and the optional
ID token::

    prover = tempo.client.prover(access_token=session.access_token, scope=["https://api.example"])
    async with Mpp(methods=[...], identity=[prover]) as mpp: ...

The server and client modules need the ``tempo-id`` extra: ``pip install "pympp[tempo-id]"``.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Literal, TypeAlias

TYPE = "tempo-id"
"""Identity type a payment check lists in the 402's ``Identity-Required`` header."""
ISSUER = "https://id.tempo.xyz"
"""Tempo ID in production: the issuer of every access token."""
ID_TOKEN_HEADER = "Tempo-Id-Token"
"""Header that carries the user's ID token, for their email address."""
PROOF_MAX_AGE = 300
"""Seconds a DPoP proof is accepted after its ``iat``."""
CLOCK_TOLERANCE = 60
"""Seconds of clock skew allowed on token and proof times."""
DEFAULT_CHAIN_ID = 4217
"""Tempo mainnet: the chain payments settle on unless configured."""

ComplianceState: TypeAlias = Literal["clear", "exit_only", "blocked", "pending"]
"""The screening state of a Tempo Account: only ``clear`` may pay without limits."""


@dataclass(frozen=True, slots=True)
class Caller:
    """A Tempo ID user, as a verified access token (and, when sent, ID token) names them.

    - ``user_id``: stable across every app on Tempo ID.
    - ``client_id``: the app the user signed in to.
    - ``accounts``: the Tempo Accounts the token grants to the app on the configured chain,
      checksummed.
    - ``compliance``: each account's screening state in the app's realms, by checksummed
      address; empty for an unregistered app.
    - ``email`` (lowercased) and ``email_verified``: from the ID token, when sent with the
      ``email`` scope.
    """

    user_id: str
    client_id: str
    accounts: tuple[str, ...] = ()
    compliance: Mapping[str, ComplianceState] = field(default_factory=lambda: MappingProxyType({}))
    email: str | None = None
    email_verified: bool | None = None


@dataclass(frozen=True, slots=True)
class Payer(Caller):
    """A verified Tempo ID user and the Tempo Account that paid, checksummed."""

    account: str | None = None


_SUBMODULES = ("client", "server")

if TYPE_CHECKING:
    from mpp.extensions.identity.tempo import client, server


def __getattr__(name: str) -> ModuleType:
    if name not in _SUBMODULES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        module = importlib.import_module(f"{__name__}.{name}")
    except ImportError as error:
        raise ImportError(
            f"Cannot import {__name__}.{name}: {error}. Install the tempo-id extra: "
            'pip install "pympp[tempo-id]"'
        ) from error
    globals()[name] = module
    return module


__all__ = [
    "CLOCK_TOLERANCE",
    "DEFAULT_CHAIN_ID",
    "ID_TOKEN_HEADER",
    "ISSUER",
    "PROOF_MAX_AGE",
    "TYPE",
    "Caller",
    "ComplianceState",
    "Payer",
    "client",
    "server",
]
