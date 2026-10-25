"""Fee-token selection for Tempo transactions."""

from __future__ import annotations

from collections.abc import Sequence

from mpp.tempo._internal import actions
from mpp.tempo._internal.address import is_equal
from mpp.tempo._internal.rpc import RpcClient
from mpp.tempo.assets import DEFAULT_CURRENCIES, PATH_USD_ADDRESS


def _push_unique(
    tokens: list[str], token: str | None, allowed_tokens: Sequence[str] | None = None
) -> None:
    if not token:
        return
    if allowed_tokens is not None and not any(is_equal(a, token) for a in allowed_tokens):
        return
    if any(is_equal(t, token) for t in tokens):
        return
    tokens.append(token)


def default_fee_tokens(chain_id: int | None) -> list[str]:
    """Stablecoins mpp supports for Tempo transaction fees: pathUSD plus the chain currency."""
    tokens: list[str] = []
    _push_unique(tokens, PATH_USD_ADDRESS)
    _push_unique(tokens, DEFAULT_CURRENCIES.get(chain_id) if chain_id is not None else None)
    return tokens


async def _has_balance(client: RpcClient, account: str, token: str) -> bool:
    try:
        return await actions.get_balance(client, token=token, account=account) > 0
    except Exception:
        return False


async def resolve_fee_token(
    client: RpcClient,
    *,
    account: str,
    chain_id: int | None = None,
    chain_fee_token: str | None = None,
    allowed_tokens: Sequence[str] | None = None,
    candidate_tokens: Sequence[str] = (),
    prioritize_candidates: bool = False,
) -> str | None:
    """Resolves a funded fee token from account, chain, and caller preferences.

    Preference order: the account's fee-token setting, the chain fee token
    (``chain_fee_token`` or the chain's default currency), then candidates
    (first when ``prioritize_candidates``). ``allowed_tokens`` filters every
    preference. Returns the first funded token, else the first preference.
    """
    tokens: list[str] = []
    if prioritize_candidates:
        for token in candidate_tokens:
            _push_unique(tokens, token, allowed_tokens)
    try:
        user_token = await actions.get_user_fee_token(client, account=account)
    except Exception:
        user_token = None
    _push_unique(tokens, user_token, allowed_tokens)
    _push_unique(
        tokens,
        chain_fee_token or (DEFAULT_CURRENCIES.get(chain_id) if chain_id is not None else None),
        allowed_tokens,
    )
    if not prioritize_candidates:
        for token in candidate_tokens:
            _push_unique(tokens, token, allowed_tokens)
    for token in tokens:
        if await _has_balance(client, account, token):
            return token
    return tokens[0] if tokens else None
