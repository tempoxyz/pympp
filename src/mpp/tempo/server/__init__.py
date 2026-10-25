"""Tempo payment methods for servers.

Usage::

    from mpp.server import Mpp
    from mpp.tempo import server as tempo

    mppx = Mpp(methods=[tempo.charge(recipient="0x...")])

:func:`charge` returns ordered charge offers (one per accepted currency); :func:`tempo` is the
common Tempo offer group (currently the charge offers). Both are accepted directly in
``Mpp(methods=[...])``.
"""

from mpp.tempo._internal.account import TempoAccount, secp256k1_account
from mpp.tempo._internal.fee_payer import PolicyOverrides as FeePayerPolicy
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer
from mpp.tempo.server._charge import (
    ValidateSender,
    ValidateSenderParams,
    ValidationDetails,
)
from mpp.tempo.server._methods import charge, tempo
from mpp.tempo.server._relay import RelayErrorCode, RelayOptions

common = tempo
"""Alias of :func:`tempo`."""

__all__ = [
    "FeePayerPolicy",
    "RelayErrorCode",
    "RelayOptions",
    "RemoteFeePayer",
    "TempoAccount",
    "ValidateSender",
    "ValidateSenderParams",
    "ValidationDetails",
    "charge",
    "common",
    "secp256k1_account",
    "tempo",
]
