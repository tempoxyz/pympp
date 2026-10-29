"""Deploy the EIP-3009 TestUSDC to the chain and mint 1,000 USDC to the payer.

Does nothing when TOKEN_FILE already names a token deployed on the chain.
"""

import json
from typing import Any

from common import ARTIFACT, CHAIN_ID, RPC_URL, TOKEN_FILE, payer, token_contract
from web3 import Web3


def send(w3: Web3, tx: dict[str, Any]) -> Any:
    tx = {
        **tx,
        "from": payer.address,
        "nonce": w3.eth.get_transaction_count(payer.address),
        "chainId": CHAIN_ID,
        "gas": 3_000_000,
    }
    signed = payer.sign_transaction(tx)
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(signed.raw_transaction)
    )
    if receipt["status"] != 1:
        raise SystemExit(f"transaction failed: {receipt['transactionHash'].hex()}")
    return receipt


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if TOKEN_FILE.exists():
        address = json.loads(TOKEN_FILE.read_text())["address"]
        if w3.eth.get_code(Web3.to_checksum_address(address)):
            print(f"TestUSDC already deployed at {address}")
            return
    artifact = json.loads(ARTIFACT.read_text())
    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    address = send(w3, factory.constructor().build_transaction({"from": payer.address}))[
        "contractAddress"
    ]
    token = token_contract(w3, address)
    send(w3, token.functions.mint(payer.address, 1_000 * 10**6).build_transaction())
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps({"address": address}))
    print(f"TestUSDC deployed at {address}; minted 1000 USDC to {payer.address}")


if __name__ == "__main__":
    main()
