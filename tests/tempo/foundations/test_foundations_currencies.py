"""Port of mppx ``src/tempo/internal/currencies.test.ts``."""

from __future__ import annotations

from typing import Any

import pytest

from mpp.tempo._internal.currencies import ResolvedCurrency, resolve
from mpp.tempo.assets import OUSD, OUSD_ADDRESS, PATH_USD_ADDRESS, USDC_ADDRESS, Token


def _expected(currencies: list[str], chain_id: int) -> list[ResolvedCurrency]:
    return [ResolvedCurrency(currency=c, decimals=6, chain_id=chain_id) for c in currencies]


@pytest.mark.parametrize(
    ("parameters", "expected", "chain"),
    [
        ({}, [OUSD_ADDRESS, USDC_ADDRESS], 4217),
        ({"testnet": True}, [OUSD_ADDRESS, PATH_USD_ADDRESS], 42431),
        ({"chain_id": 42431}, [OUSD_ADDRESS, PATH_USD_ADDRESS], 42431),
        ({"chain_id": 4217, "testnet": True}, [OUSD_ADDRESS, USDC_ADDRESS], 4217),
        ({"chain_id": 31337}, [PATH_USD_ADDRESS], 31337),
        ({"currencies": [USDC_ADDRESS, OUSD_ADDRESS]}, [USDC_ADDRESS, OUSD_ADDRESS], 4217),
        ({"testnet": True, "currencies": [PATH_USD_ADDRESS]}, [PATH_USD_ADDRESS], 42431),
        ({"currencies": [OUSD]}, [OUSD_ADDRESS], 4217),
    ],
)
def test_resolves(parameters: dict[str, Any], expected: list[str], chain: int) -> None:
    assert resolve(**parameters) == _expected(expected, chain)


def test_deduplicates_preserving_first_occurrence() -> None:
    assert resolve(
        currencies=[USDC_ADDRESS, OUSD, OUSD_ADDRESS.lower(), USDC_ADDRESS.lower()]
    ) == resolve(currencies=[USDC_ADDRESS, OUSD_ADDRESS])


# "resolves maintained viem sets by chain and denomination" is not ported: it
# exercises viem's `tokenSets.tempo` registry, which has no Python counterpart.


def test_skips_unsupported_chains_and_non_usd_or_missing_denominations() -> None:
    assert resolve(
        currencies=[
            Token(addresses={1: USDC_ADDRESS}, currency="USD", decimals=6),
            Token(addresses={4217: USDC_ADDRESS}, currency="EUR", decimals=6),
            Token(addresses={4217: USDC_ADDRESS}, decimals=6),
            OUSD,
        ]
    ) == resolve(currencies=[OUSD])


def test_uses_token_metadata_decimals_and_explicit_address_decimals() -> None:
    assert resolve(currencies=[OUSD_ADDRESS], decimals=8)[0].decimals == 8
    assert (
        resolve(currencies=[Token(addresses={4217: OUSD_ADDRESS}, currency="USD", decimals=8)])[
            0
        ].decimals
        == 8
    )
    assert resolve(currencies=[OUSD], decimals=6)[0].decimals == 6


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        ({"currencies": []}, "No accepted USD currencies"),
        ({"currencies": [OUSD], "testnet": True}, "No accepted USD currencies for chain 42431"),
        ({"currencies": ["invalid"]}, "Invalid Tempo currency address"),
        ({"currencies": [OUSD], "decimals": 18}, "must match each token definition"),
        *(
            (
                {"currencies": [OUSD_ADDRESS], "decimals": decimals},
                "Token decimals must be an integer",
            )
            for decimals in (-1, 1.5, 256, float("nan"))
        ),
    ],
)
def test_rejects(parameters: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        resolve(**parameters)
