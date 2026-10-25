"""Tempo payment methods for clients.

Usage::

    from mpp.client import Mpp
    from mpp.tempo import client as tempo

    mppx = Mpp(methods=[tempo.charge(account=account)])
"""

from mpp.tempo._internal.account import (
    TempoAccount,
    secp256k1_account,
)
from mpp.tempo.client._charge import ChargeContext, charge, transaction_hash
from mpp.tempo.client._methods import tempo
from mpp.tempo.client._resolve_account import (
    AuthorizePaymentChannel,
    ExecuteCalls,
    ResolveAccount,
    ResolveAccountInfo,
    ResolveAccountOperation,
    SignPaymentProof,
)

common = tempo
"""Alias of :func:`tempo`."""

__all__ = [
    "AuthorizePaymentChannel",
    "ChargeContext",
    "ExecuteCalls",
    "ResolveAccount",
    "ResolveAccountInfo",
    "ResolveAccountOperation",
    "SignPaymentProof",
    "TempoAccount",
    "charge",
    "common",
    "secp256k1_account",
    "tempo",
    "transaction_hash",
]
