"""Port of mppx ``src/tempo/internal/defaults.test.ts`` (``mpp.tempo.chains`` + ``mpp.tempo.assets``)."""

from __future__ import annotations

from mpp.tempo.assets import (
    DECIMALS,
    DEFAULT_CURRENCIES,
    PATH_USD_ADDRESS,
    USDC_ADDRESS,
    resolve_currency,
)
from mpp.tempo.chains import (
    ESCROW_CONTRACTS,
    MAINNET_CHAIN_ID,
    RPC_URLS,
    TESTNET_CHAIN_ID,
)


class TestChainIds:
    def test_mainnet_is_4217(self) -> None:
        assert MAINNET_CHAIN_ID == 4217

    def test_testnet_is_42431(self) -> None:
        assert TESTNET_CHAIN_ID == 42431


class TestTokenAddresses:
    def test_usdc_address(self) -> None:
        assert USDC_ADDRESS == "0x20C000000000000000000000b9537d11c60E8b50"

    def test_path_usd_address(self) -> None:
        assert PATH_USD_ADDRESS == "0x20c0000000000000000000000000000000000000"

    def test_usdc_and_path_usd_differ(self) -> None:
        assert USDC_ADDRESS != PATH_USD_ADDRESS

    def test_decimals_is_6(self) -> None:
        assert DECIMALS == 6


class TestRpcUrls:
    def test_mainnet(self) -> None:
        assert RPC_URLS[MAINNET_CHAIN_ID] == "https://rpc.tempo.xyz"

    def test_testnet(self) -> None:
        assert RPC_URLS[TESTNET_CHAIN_ID] == "https://rpc.moderato.tempo.xyz"


class TestEscrowContracts:
    def test_mainnet(self) -> None:
        assert ESCROW_CONTRACTS[MAINNET_CHAIN_ID] == "0x33b901018174DDabE4841042ab76ba85D4e24f25"

    def test_testnet(self) -> None:
        assert ESCROW_CONTRACTS[TESTNET_CHAIN_ID] == "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"


class TestDefaultCurrencies:
    def test_mainnet_returns_usdc(self) -> None:
        assert DEFAULT_CURRENCIES[MAINNET_CHAIN_ID] == USDC_ADDRESS

    def test_testnet_returns_path_usd(self) -> None:
        assert DEFAULT_CURRENCIES[TESTNET_CHAIN_ID] == PATH_USD_ADDRESS

    def test_mainnet_and_testnet_differ(self) -> None:
        assert DEFAULT_CURRENCIES[MAINNET_CHAIN_ID] != DEFAULT_CURRENCIES[TESTNET_CHAIN_ID]


class TestResolveCurrency:
    def test_defaults_to_usdc(self) -> None:
        assert resolve_currency() == USDC_ADDRESS

    def test_testnet_returns_path_usd(self) -> None:
        assert resolve_currency(testnet=True) == PATH_USD_ADDRESS

    def test_testnet_false_returns_usdc(self) -> None:
        assert resolve_currency(testnet=False) == USDC_ADDRESS

    def test_chain_id_takes_precedence_over_testnet(self) -> None:
        assert resolve_currency(chain_id=TESTNET_CHAIN_ID, testnet=False) == PATH_USD_ADDRESS

    def test_unknown_chain_id_falls_back_to_path_usd(self) -> None:
        assert resolve_currency(chain_id=999999) == PATH_USD_ADDRESS
