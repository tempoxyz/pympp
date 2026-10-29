"""Settings shared by the example's scripts: accounts, chain and the token."""

import json
import os
from pathlib import Path
from typing import Any

from eth_account import Account
from web3 import Web3

from mpp.methods.evm import EvmAsset

HERE = Path(__file__).parent
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CHAIN_ID = int(os.environ.get("CHAIN_ID", "31337"))
NETWORK = f"eip155:{CHAIN_ID}"
# setup_chain.py writes the deployed token's address here for the other services.
TOKEN_FILE = Path(os.environ.get("TOKEN_FILE", HERE / "token.json"))
ARTIFACT = HERE / "TestUSDC.json"

# Anvil's default accounts ("test test ... junk"): payer 0, recipient 1, facilitator 2.
Account.enable_unaudited_hdwallet_features()
MNEMONIC = os.environ.get("MNEMONIC", "test test test test test test test test test test test junk")


def account(index: int) -> Any:
    return Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")


payer = account(0)
recipient = account(1)
facilitator_account = account(2)


def token_address() -> str:
    return json.loads(TOKEN_FILE.read_text())["address"]


def asset() -> EvmAsset:
    """The deployed EIP-3009 TestUSDC (domain name "USDC", version "2")."""
    return EvmAsset(
        address=token_address(), decimals=6, chain_id=CHAIN_ID, name="USDC", version="2"
    )


def token_contract(w3: Web3, address: str | None = None) -> Any:
    abi = json.loads(ARTIFACT.read_text())["abi"]
    return w3.eth.contract(address=Web3.to_checksum_address(address or token_address()), abi=abi)
