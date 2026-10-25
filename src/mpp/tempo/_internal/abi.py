"""Minimal ABI helpers for the Tempo contracts the payment methods call."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from eth_abi.abi import decode, encode
from eth_abi.exceptions import DecodingError

from mpp.tempo._internal.hexutil import keccak256, to_bytes, to_hex


@dataclass(frozen=True, slots=True)
class Function:
    """An ABI function, e.g. ``Function("transfer", ("address", "uint256"))``."""

    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...] = ()

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.inputs)})"

    @property
    def selector(self) -> str:
        return to_hex(keccak256(self.signature.encode())[:4])

    def encode(self, *args: Any) -> str:
        """ABI-encodes calldata for this function."""
        return self.selector + encode(list(self.inputs), list(args)).hex()

    def decode_input(self, data: str | bytes) -> tuple[Any, ...]:
        """Decodes calldata (selector included) for this function."""
        raw = to_bytes(data)
        if to_hex(raw[:4]) != self.selector:
            raise AbiDecodingError(f"Calldata does not match {self.signature}.")
        try:
            return tuple(decode(list(self.inputs), raw[4:]))
        except (DecodingError, ValueError) as error:
            raise AbiDecodingError(str(error)) from error

    def decode_output(self, data: str) -> tuple[Any, ...]:
        try:
            return tuple(decode(list(self.outputs), to_bytes(data)))
        except (DecodingError, ValueError) as error:
            raise AbiDecodingError(str(error)) from error


class AbiDecodingError(ValueError):
    pass


def event_topic(signature: str) -> str:
    return to_hex(keccak256(signature.encode()))


# TIP-20
TRANSFER: Final = Function("transfer", ("address", "uint256"), ("bool",))
TRANSFER_WITH_MEMO: Final = Function("transferWithMemo", ("address", "uint256", "bytes32"))
APPROVE: Final = Function("approve", ("address", "uint256"), ("bool",))
BALANCE_OF: Final = Function("balanceOf", ("address",), ("uint256",))

TRANSFER_EVENT_TOPIC: Final = event_topic("Transfer(address,address,uint256)")
TRANSFER_WITH_MEMO_EVENT_TOPIC: Final = event_topic(
    "TransferWithMemo(address,address,uint256,bytes32)"
)

# Stablecoin DEX
SWAP_EXACT_AMOUNT_OUT: Final = Function(
    "swapExactAmountOut", ("address", "address", "uint128", "uint128"), ("uint128",)
)
QUOTE_SWAP_EXACT_AMOUNT_OUT: Final = Function(
    "quoteSwapExactAmountOut", ("address", "address", "uint128"), ("uint128",)
)

# Fee manager
USER_TOKENS: Final = Function("userTokens", ("address",), ("address",))

# Account keychain
GET_KEY: Final = Function("getKey", ("address", "address"), ("(uint8,address,uint64,bool,bool)",))
