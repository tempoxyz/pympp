"""Typed-data signers used by EVM and x402 clients."""

import inspect
from collections.abc import Awaitable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TypedDataSigner(Protocol):
    """An account that signs EIP-712 typed data.

    ``typed_data`` is the full message: ``{"domain", "types", "primaryType", "message"}``
    (``types`` without ``EIP712Domain``). The result is a ``0x`` hex signature (65 bytes for
    secp256k1). ``eth_account`` ``LocalAccount`` objects are accepted as well.
    """

    @property
    def address(self) -> str: ...

    def sign_typed_data(self, typed_data: dict[str, Any], /) -> str | Awaitable[str]: ...


def has_signer(account: object) -> bool:
    """Returns whether ``account`` can sign typed data."""
    return account is not None and callable(getattr(account, "sign_typed_data", None))


async def sign_typed_data(account: Any, typed_data: dict[str, Any]) -> str:
    """Signs ``typed_data`` with a :class:`TypedDataSigner` or an ``eth_account`` account."""
    if _is_eth_account(account):
        signed = account.sign_typed_data(full_message=typed_data)
        return "0x" + bytes(signed.signature).hex()
    result = account.sign_typed_data(typed_data)
    if inspect.isawaitable(result):
        result = await result
    return str(result)


def _is_eth_account(account: object) -> bool:
    try:
        from eth_account.signers.local import LocalAccount
    except ImportError:  # pragma: no cover - eth-account is part of the `evm` extra
        return False
    return isinstance(account, LocalAccount)
