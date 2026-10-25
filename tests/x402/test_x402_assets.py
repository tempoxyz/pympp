import pytest

from mpp.evm import tokens
from mpp.x402 import assets
from mpp.x402.assets import Eip3009Transfer, Permit2Transfer, ResolvedCurrency, Token


def test_defines_asset_metadata() -> None:
    asset = assets.define(
        address="0x1111111111111111111111111111111111111111",
        decimals=18,
        network="eip155:1",
        transfer=Eip3009Transfer(name="USD Coin", version="2"),
    )
    assert assets.is_asset(asset)
    assert asset.address == "0x1111111111111111111111111111111111111111"
    assert asset.decimals == 18
    assert asset.network == "eip155:1"
    assert asset.transfer == Eip3009Transfer(name="USD Coin", version="2")


def test_rejects_unbranded_values() -> None:
    assert not assets.is_asset(None)
    assert not assets.is_asset("0x1111111111111111111111111111111111111111")
    assert not assets.is_asset(
        {
            "address": "0x1111111111111111111111111111111111111111",
            "decimals": 18,
            "network": "eip155:1",
            "transfer": {"name": "USD Coin", "type": "eip3009", "version": "2"},
        }
    )


def test_defines_asset_metadata_from_tokens() -> None:
    asset = assets.from_token(tokens.USDC, chain_id=84532, version="2")
    assert assets.is_asset(asset)
    assert asset.address == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    assert asset.decimals == 6
    assert asset.network == "eip155:84532"
    assert asset.transfer == Eip3009Transfer(name="USD Coin", version="2")


def test_allows_token_transfer_metadata_overrides() -> None:
    eip3009 = assets.from_token(
        tokens.USDC, chain_id=84532, transfer=Eip3009Transfer(name="USDC", version="2")
    )
    permit2 = assets.from_token(tokens.USDC, chain_id=84532, transfer=Permit2Transfer())
    assert eip3009.transfer == Eip3009Transfer(name="USDC", version="2")
    assert eip3009.transfer.type == "eip3009"
    assert permit2.transfer == Permit2Transfer()
    assert permit2.transfer.type == "permit2"


def test_requires_token_names_for_eip3009_token_assets() -> None:
    unnamed = Token(addresses={1: "0x1111111111111111111111111111111111111111"}, decimals=6)
    with pytest.raises(ValueError, match=r"EIP-3009 token assets require a token name\."):
        assets.from_token(unnamed, chain_id=1, version="2")


def test_identifies_currency_kinds_and_converts_networks() -> None:
    assert assets.is_token(tokens.USDC)
    assert not assets.is_token(assets.BASE_SEPOLIA_USDC)
    assert assets.is_raw_address("0x1111111111111111111111111111111111111111")
    assert not assets.is_raw_address(assets.BASE_SEPOLIA_USDC)
    assert assets.to_network(84532) == "eip155:84532"
    assert assets.to_chain_id("eip155:84532") == 84532


def test_resolves_and_matches_currencies() -> None:
    raw = "0x1111111111111111111111111111111111111111"
    assert assets.resolve(raw, "eip155:84532") == ResolvedCurrency(address=raw)
    assert assets.resolve(assets.BASE_SEPOLIA_USDC, "eip155:84532") == ResolvedCurrency(
        address="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        decimals=6,
        transfer=Eip3009Transfer(name="USDC", version="2"),
    )
    assert assets.resolve(assets.BASE_SEPOLIA_USDC, "eip155:8453") is None
    assert assets.resolve(tokens.USDC, "eip155:84532") == ResolvedCurrency(
        address="0x036CbD53842c5426634e7929541eC2318f3dCF7e", decimals=6, name="USD Coin"
    )
    assert assets.resolve(tokens.USDC, "eip155:999999") is None
    usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    assert assets.matches(tokens.USDC, usdc, "eip155:84532")
    assert assets.matches(tokens.USDC, usdc.lower(), "eip155:84532")
    assert assets.matches(raw, raw, "eip155:84532")
    assert not assets.matches(
        assets.BASE_SEPOLIA_USDC, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532"
    )


def test_matches_rejects_malformed_addresses() -> None:
    with pytest.raises(ValueError, match="invalid"):
        assets.matches("0x1234", "0x1234", "eip155:1")


def test_throws_for_tokens_unavailable_on_a_chain() -> None:
    with pytest.raises(ValueError, match=r'Token has no address for chain id "999999"\.'):
        assets.from_token(tokens.USDC, chain_id=999_999, version="2")


@pytest.mark.parametrize(
    ("asset", "address", "network", "transfer"),
    [
        (
            assets.BASE_USDC,
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "eip155:8453",
            Eip3009Transfer(name="USD Coin", version="2"),
        ),
        (
            assets.BASE_SEPOLIA_USDC,
            "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "eip155:84532",
            Eip3009Transfer(name="USDC", version="2"),
        ),
        (
            assets.CELO_USDC,
            "0xcebA9300f2b948710d2653dD7B07f33A8B32118C",
            "eip155:42220",
            Eip3009Transfer(name="USDC", version="2"),
        ),
        (
            assets.CELO_USDT,
            "0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e",
            "eip155:42220",
            Eip3009Transfer(name="Tether USD", version="1"),
        ),
        (
            assets.CELO_SEPOLIA_USDC,
            "0x01C5C0122039549AD1493B8220cABEdD739BC44E",
            "eip155:11142220",
            Eip3009Transfer(name="USDC", version="2"),
        ),
    ],
)
def test_exports_known_asset_metadata(
    asset: assets.KnownAsset, address: str, network: str, transfer: Eip3009Transfer
) -> None:
    assert assets.is_asset(asset)
    assert (asset.address, asset.decimals, asset.network, asset.transfer) == (
        address,
        6,
        network,
        transfer,
    )
