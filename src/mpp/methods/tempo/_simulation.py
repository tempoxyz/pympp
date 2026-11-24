"""Typed errors for a failed pre-signing simulation (mppx ``tempo/internal/simulation.ts``)."""

from __future__ import annotations

from mpp._typing import is_dict
from mpp.errors import InsufficientBalanceError, SpendingLimitExceededError

SPENDING_LIMIT_EXCEEDED_SELECTOR = bytes.fromhex("8a9e71ea")
"""``SpendingLimitExceeded()``, the account keychain's revert."""
INSUFFICIENT_BALANCE_SELECTOR = bytes.fromhex("832f98b5")
"""``InsufficientBalance(uint256,uint256,address)``, the TIP-20 revert."""


def revert_data(error: BaseException) -> bytes | None:
    """Return the revert data of a failed ``eth_estimateGas`` or ``eth_call``, if any.

    Reads the JSON-RPC error's ``data``, or that field's own ``data``, as mppx's
    ``getRevertData`` does.
    """
    from mpp.methods.tempo._rpc import RpcError

    if not isinstance(error, RpcError):
        return None
    detail = error.response.get("error")
    data: object = detail.get("data") if is_dict(detail) else None
    if is_dict(data):
        data = data.get("data")
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    try:
        raw = bytes.fromhex(data[2:])
    except ValueError:
        return None
    return raw if len(raw) >= 4 else None


def simulation_error(
    error: BaseException, *, account: str, access_key: str | None = None
) -> SpendingLimitExceededError | InsufficientBalanceError | None:
    """Map a failed pre-signing simulation to a typed client error.

    Tempo reverts with ``SpendingLimitExceeded()`` when the signing access key's remaining
    limit is below the payment, and with ``InsufficientBalance(available, required, token)``
    when the account holds too little of a token. Both would fail on chain, and a fee payer
    would pay for the failed transaction, so the client stops before it signs. Returns
    ``None`` for any other error. Raise the result ``from error``.
    """
    raw = revert_data(error)
    if raw is None:
        return None
    if raw[:4] == SPENDING_LIMIT_EXCEEDED_SELECTOR:
        return SpendingLimitExceededError(account, access_key)
    if raw[:4] == INSUFFICIENT_BALANCE_SELECTOR and len(raw) >= 4 + 96:
        available = int.from_bytes(raw[4:36], "big")
        required = int.from_bytes(raw[36:68], "big")
        token = "0x" + raw[80:100].hex()
        return InsufficientBalanceError(
            f"{account} holds {available} of token {token}, but the payment requires {required}"
        )
    return None
