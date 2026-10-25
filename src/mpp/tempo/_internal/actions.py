"""Read-only Tempo contract actions over :class:`RpcClient`.

Reads never carry a ``from``: a node refuses every call from an access key
whose authorization is not yet published.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from mpp.tempo._internal import abi
from mpp.tempo._internal.rpc import RpcClient, call_request
from mpp.tempo.chains import ACCOUNT_KEYCHAIN, FEE_MANAGER

_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_SIGNATURE_TYPES: dict[int, Literal["secp256k1", "p256", "webAuthn"]] = {
    0: "secp256k1",
    1: "p256",
    2: "webAuthn",
}


async def read(client: RpcClient, *, to: str, function: abi.Function, args: tuple[object, ...]):
    """Calls a view function and returns its decoded outputs."""
    result = await client.call(call_request(to=to, data=function.encode(*args)))
    return function.decode_output(result)


async def get_balance(client: RpcClient, *, token: str, account: str) -> int:
    """TIP-20 ``balanceOf``."""
    (balance,) = await read(client, to=token, function=abi.BALANCE_OF, args=(account,))
    return balance


async def get_user_fee_token(client: RpcClient, *, account: str) -> str | None:
    """The account's preferred fee token, or ``None`` when unset."""
    (token,) = await read(client, to=FEE_MANAGER, function=abi.USER_TOKENS, args=(account,))
    return None if token.lower() == _ZERO_ADDRESS else token


@dataclass(frozen=True, slots=True, kw_only=True)
class AccessKeyMetadata:
    address: str
    key_type: Literal["secp256k1", "p256", "webAuthn"]
    expiry: int
    enforce_limits: bool
    is_revoked: bool


async def get_access_key_metadata(
    client: RpcClient, *, account: str, access_key: str
) -> AccessKeyMetadata:
    """Account keychain ``getKey``."""
    ((signature_type, key_id, expiry, enforce_limits, is_revoked),) = await read(
        client, to=ACCOUNT_KEYCHAIN, function=abi.GET_KEY, args=(account, access_key)
    )
    return AccessKeyMetadata(
        address=key_id,
        key_type=_SIGNATURE_TYPES.get(signature_type, "secp256k1"),
        expiry=expiry,
        enforce_limits=enforce_limits,
        is_revoked=is_revoked,
    )


async def is_active_access_key(client: RpcClient, *, account: str, access_key: str) -> bool:
    """Whether ``access_key`` is authorized, unrevoked, and unexpired for ``account``."""
    try:
        metadata = await get_access_key_metadata(client, account=account, access_key=access_key)
    except Exception:
        return False
    return not metadata.is_revoked and metadata.expiry > int(time.time())
