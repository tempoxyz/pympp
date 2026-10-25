"""Ordered Tempo offer groups: ``charge`` offers and the common ``tempo`` group.

Mainnet accepts OUSD first, then USDC.e; Moderato accepts OUSD first, then
pathUSD. ``currencies`` is an ordered list of addresses or chain-indexed USD
token definitions (filtered to USD tokens deployed on the chain, deduplicated
by address); explicit lists replace the defaults and an empty resolved list
raises. List order is presentation order, not a requirement on the client.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mpp import store as _store
from mpp.method import ServerMethod
from mpp.tempo._internal.currencies import Currency, ResolvedCurrency
from mpp.tempo._internal.currencies import resolve as resolve_currency_list
from mpp.tempo.server import _charge


def resolve_currencies(
    *,
    currency: str | None = None,
    currencies: Sequence[Currency] | None = None,
    chain_id: int | None = None,
    testnet: bool = False,
    decimals: int | None = None,
) -> list[ResolvedCurrency]:
    """Resolves the ordered offer currencies, honoring the deprecated single ``currency``."""
    if currency is not None and currencies is not None:
        raise ValueError("Specify either `currency` or `currencies`, not both.")
    return resolve_currency_list(
        chain_id=chain_id,
        testnet=testnet,
        currencies=[currency] if currency is not None else currencies,
        decimals=decimals,
    )


def charge(
    *,
    currency: str | None = None,
    currencies: Sequence[Currency] | None = None,
    chain_id: int | None = None,
    testnet: bool = False,
    decimals: int | None = None,
    store: _store.AtomicStore | None = None,
    **parameters: Any,
) -> list[ServerMethod]:
    """Creates ordered Tempo charge offers (OUSD first, then the network fallback).

    Accepts every :func:`mpp.tempo.server._charge.charge` keyword argument;
    ``currencies`` replaces the defaults (``currency`` is the deprecated
    single-currency form).
    """
    resolved = resolve_currencies(
        currency=currency,
        currencies=currencies,
        chain_id=chain_id,
        testnet=testnet,
        decimals=decimals,
    )
    return [
        _charge.charge(
            **parameters,
            currency=offer.currency,
            decimals=offer.decimals,
            chain_id=offer.chain_id,
            testnet=testnet,
            store=store,
        )
        for offer in resolved
    ]


def tempo(**parameters: Any) -> list[ServerMethod]:
    """Creates the common Tempo offers: the ordered :func:`charge` offers."""
    return charge(**parameters)
