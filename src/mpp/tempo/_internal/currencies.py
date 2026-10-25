"""Ordered USD currency offers for Tempo charges."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from mpp.tempo._internal.address import is_address
from mpp.tempo.assets import (
    DECIMALS,
    OUSD_ADDRESS,
    PATH_USD_ADDRESS,
    USDC_ADDRESS,
    Token,
    resolve_currency,
)
from mpp.tempo.chains import MAINNET_CHAIN_ID, TESTNET_CHAIN_ID, resolve_chain_id

type Currency = str | Token
"""An explicit token address or a chain-indexed token definition."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedCurrency:
    currency: str
    decimals: int
    chain_id: int


def resolve(
    *,
    chain_id: int | None = None,
    testnet: bool = False,
    currencies: Sequence[Currency] | None = None,
    decimals: int | None = None,
) -> list[ResolvedCurrency]:
    """Resolves ordered USD offers without expanding acceptance from a live registry.

    Token definitions that are not USD-denominated or lack an address on the
    chain are skipped; duplicate addresses keep their first occurrence.
    """
    chain_id = resolve_chain_id(chain_id=chain_id, testnet=testnet)
    if currencies is None:
        if chain_id == MAINNET_CHAIN_ID:
            currencies = [OUSD_ADDRESS, USDC_ADDRESS]
        elif chain_id == TESTNET_CHAIN_ID:
            currencies = [OUSD_ADDRESS, PATH_USD_ADDRESS]
        else:
            currencies = [resolve_currency(chain_id=chain_id)]

    seen: set[str] = set()
    resolved: list[ResolvedCurrency] = []
    for token in currencies:
        # A shared USD price cannot also price EUR, BTC, or unknown denominations.
        if isinstance(token, Token) and token.currency != "USD":
            continue
        currency = token if isinstance(token, str) else token.addresses.get(chain_id)
        if currency is None:
            continue
        if not is_address(currency, strict=False):
            raise ValueError(f"Invalid Tempo currency address: {currency}.")
        if isinstance(token, str):
            token_decimals: object = DECIMALS if decimals is None else decimals
        else:
            token_decimals = token.decimals
            if decimals is not None and decimals != token_decimals:
                raise ValueError("Configured `decimals` must match each token definition.")
        if (
            not isinstance(token_decimals, int)
            or isinstance(token_decimals, bool)
            or not 0 <= token_decimals <= 255
        ):
            raise ValueError("Token decimals must be an integer between 0 and 255.")
        key = currency.lower()
        if key in seen:
            continue
        seen.add(key)
        resolved.append(
            ResolvedCurrency(currency=currency, decimals=token_decimals, chain_id=chain_id)
        )
    if not resolved:
        raise ValueError(f"No accepted USD currencies for chain {chain_id}.")
    return resolved
