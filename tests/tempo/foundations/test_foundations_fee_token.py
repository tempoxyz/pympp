"""Port of mppx ``src/tempo/internal/fee-token.test.ts``.

mppx runs these scenarios only against a localnet; here the node is faked
over ``httpx.MockTransport`` (balances + fee-manager ``userTokens``).
"""

from __future__ import annotations

from mpp.tempo._internal.address import is_equal
from mpp.tempo._internal.fee_token import default_fee_tokens, resolve_fee_token
from mpp.tempo.assets import PATH_USD_ADDRESS, USDC_ADDRESS
from mpp.tempo.chains import MAINNET_CHAIN_ID, TESTNET_CHAIN_ID

from ._fake_node import FakeNode, NodeError

ACCOUNT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ASSET = "0x20c0000000000000000000000000000000000001"
LOCALNET_CHAIN_ID = 1337
"""mppx's localnet chain has no default currency."""


def _node(*, funded: tuple[str, ...] = (), user_token: str | None = None) -> FakeNode:
    node = FakeNode()
    for token in funded:
        node.set_balance(token, ACCOUNT, 1_000_000)
    if user_token is not None:
        node.user_tokens[ACCOUNT.lower()] = user_token
    return node


def _assert_address(actual: str | None, expected: str) -> None:
    assert actual is not None
    assert actual.lower() == expected.lower()


async def test_uses_funded_account_fee_preference_first() -> None:
    async with _node(funded=(ASSET,), user_token=ASSET).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            candidate_tokens=[PATH_USD_ADDRESS],
        )
    _assert_address(fee_token, ASSET)


async def test_falls_through_to_first_funded_candidate() -> None:
    async with _node(funded=(ASSET,)).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            candidate_tokens=[PATH_USD_ADDRESS, ASSET],
        )
    _assert_address(fee_token, ASSET)


async def test_falls_through_from_unfunded_account_fee_preference() -> None:
    async with _node(funded=(ASSET,), user_token=PATH_USD_ADDRESS).client() as client:
        fee_token = await resolve_fee_token(
            client, account=ACCOUNT, chain_id=LOCALNET_CHAIN_ID, candidate_tokens=[ASSET]
        )
    _assert_address(fee_token, ASSET)


async def test_prioritizes_funded_allowed_candidates() -> None:
    node = _node(funded=(ASSET, PATH_USD_ADDRESS), user_token=ASSET)
    async with node.client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            allowed_tokens=[PATH_USD_ADDRESS, ASSET],
            candidate_tokens=[PATH_USD_ADDRESS, ASSET],
            prioritize_candidates=True,
        )
    _assert_address(fee_token, PATH_USD_ADDRESS)


async def test_falls_through_prioritized_candidates_when_path_usd_unfunded() -> None:
    async with _node(funded=(ASSET,)).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            allowed_tokens=[PATH_USD_ADDRESS, ASSET],
            candidate_tokens=[PATH_USD_ADDRESS, ASSET],
            prioritize_candidates=True,
        )
    _assert_address(fee_token, ASSET)


async def test_uses_funded_chain_fee_token_when_configured() -> None:
    async with _node(funded=(ASSET,)).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            chain_fee_token=ASSET,
            candidate_tokens=[PATH_USD_ADDRESS],
        )
    _assert_address(fee_token, ASSET)


async def test_falls_through_from_unfunded_chain_fee_token() -> None:
    async with _node(funded=(ASSET,)).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            chain_fee_token=PATH_USD_ADDRESS,
            candidate_tokens=[ASSET],
        )
    _assert_address(fee_token, ASSET)


async def test_falls_back_to_first_known_token_when_none_funded() -> None:
    async with _node().client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            candidate_tokens=[ASSET, PATH_USD_ADDRESS],
        )
    _assert_address(fee_token, ASSET)


# -- extra coverage of mppx fee-token.ts branches (no localnet needed) ------------------------


async def test_chain_default_currency_is_the_chain_fee_token() -> None:
    async with _node(funded=(USDC_ADDRESS,)).client() as client:
        fee_token = await resolve_fee_token(
            client, account=ACCOUNT, chain_id=MAINNET_CHAIN_ID, candidate_tokens=[ASSET]
        )
    _assert_address(fee_token, USDC_ADDRESS)


async def test_failed_reads_are_treated_as_unset_or_unfunded() -> None:
    node = _node()
    node.set_balance(ASSET, ACCOUNT, NodeError("boom"))
    node.set_balance(PATH_USD_ADDRESS, ACCOUNT, 5)
    async with node.client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            candidate_tokens=[ASSET, PATH_USD_ADDRESS],
        )
    _assert_address(fee_token, PATH_USD_ADDRESS)
    # Balance and fee-preference reads never carry a `from`.
    assert all("from" not in call for call in node.eth_calls)


async def test_allowed_tokens_filter_every_preference() -> None:
    async with _node(funded=(ASSET,), user_token=ASSET).client() as client:
        fee_token = await resolve_fee_token(
            client,
            account=ACCOUNT,
            chain_id=LOCALNET_CHAIN_ID,
            chain_fee_token=ASSET,
            allowed_tokens=[PATH_USD_ADDRESS],
            candidate_tokens=[ASSET, PATH_USD_ADDRESS],
        )
    _assert_address(fee_token, PATH_USD_ADDRESS)


async def test_returns_none_without_preferences() -> None:
    async with _node().client() as client:
        assert await resolve_fee_token(client, account=ACCOUNT) is None


def test_default_fee_tokens() -> None:
    assert default_fee_tokens(MAINNET_CHAIN_ID) == [PATH_USD_ADDRESS, USDC_ADDRESS]
    assert default_fee_tokens(TESTNET_CHAIN_ID) == [PATH_USD_ADDRESS]
    assert default_fee_tokens(None) == [PATH_USD_ADDRESS]
    assert is_equal(default_fee_tokens(LOCALNET_CHAIN_ID)[0], PATH_USD_ADDRESS)
