"""EVM client methods.

Example::

    from mpp.client import Mpp
    from mpp.evm import client as evm

    Mpp(methods=[evm.charge(account=account, currencies=[evm.assets.BASE_USDC])])
"""

from collections.abc import Sequence
from typing import Any

from mpp.evm import assets, chains, tokens
from mpp.evm._types import AuthorizationConfig
from mpp.evm.client._charge import ChargeContext, charge
from mpp.method import ClientMethod
from mpp.x402.assets import Currency


def evm(
    *,
    account: Any = None,
    authorization: AuthorizationConfig | None = None,
    decimals: int | None = None,
    max_amount: str | None = None,
    max_atomic_amount: str | None = None,
    networks: Sequence[int] | None = None,
    currencies: Sequence[Currency] | None = None,
) -> list[ClientMethod]:
    """Creates all EVM client methods from shared parameters (see :func:`charge`)."""
    return [
        charge(
            account=account,
            authorization=authorization,
            decimals=decimals,
            max_amount=max_amount,
            max_atomic_amount=max_atomic_amount,
            networks=networks,
            currencies=currencies,
        )
    ]


__all__ = ["ChargeContext", "assets", "chains", "charge", "evm", "tokens"]
