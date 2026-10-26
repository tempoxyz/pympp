"""Tempo charge auto-swap: buying a missing currency through the stablecoin DEX."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import rlp

from mpp import Challenge
from mpp.methods.tempo import CHAIN_ID, OUSD, PATH_USD, USDC, TempoAccount
from mpp.methods.tempo.client import AutoSwap, InsufficientFundsError, _tempo_method
from mpp.methods.tempo.intents import STABLECOIN_DEX, _validate_normalized_calls
from mpp.methods.tempo.schemas import ChargeRequest

ACCOUNT = TempoAccount.from_key("0x" + "01" * 32)
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
CURRENCY = "0x20c0000000000000000000000000000000000001"
AMOUNT = 1_000_000


def challenge() -> Challenge:
    return Challenge(
        id="auto-swap",
        method="tempo",
        intent="charge",
        request={"amount": str(AMOUNT), "currency": CURRENCY, "recipient": RECIPIENT},
    )


async def sign(
    auto_swap: bool | AutoSwap,
    balances: dict[str, int],
    quotes: dict[str, int | Exception],
) -> tuple[list[tuple[str, int, str]], str]:
    """Sign a charge and return its calls as (to, value, data) and its fee token."""
    method = _tempo_method(
        account=ACCOUNT, chain_id=CHAIN_ID, rpc_url="https://rpc.test", auto_swap=auto_swap
    )
    lowered = {token.lower(): value for token, value in balances.items()}
    quoted_amounts: list[int] = []

    async def fake_rpc_call(_url: str, name: str, params: list[Any], **_: Any) -> str:
        if name == "eth_call":
            assert params[0]["to"] == STABLECOIN_DEX
            data = params[0]["data"]
            assert data.startswith("0x1576fa0e")
            token_in = "0x" + data[10 + 24 : 10 + 64]
            quoted_amounts.append(int(data[10 + 128 :], 16))
            quote = {t.lower(): q for t, q in quotes.items()}[token_in]
            if isinstance(quote, Exception):
                raise quote
            return hex(quote)
        return {"eth_chainId": hex(CHAIN_ID), "eth_gasPrice": "0x1"}[name]

    async def fake_balance(_url: str, token: str, address: str) -> int:
        assert address == ACCOUNT.address
        return lowered.get(token.lower(), 0)

    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
        patch("mpp.methods.tempo.client._tip20_balance", side_effect=fake_balance),
        patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
    ):
        credential = await method.create_credential(challenge())
    # Every quote asks for the payer's shortfall in the charge currency.
    shortfall = AMOUNT - lowered.get(CURRENCY.lower(), 0)
    assert all(amount == shortfall for amount in quoted_amounts)
    fields = rlp.decode(bytes.fromhex(credential.payload["signature"][2:])[1:])
    calls = [
        ("0x" + to.hex(), int.from_bytes(value, "big"), "0x" + data.hex())
        for to, value, data in fields[4]
    ]
    return calls, "0x" + fields[10].hex()


def word(data: str, index: int) -> int:
    return int(data[10 + 64 * index : 10 + 64 * (index + 1)], 16)


@pytest.mark.asyncio
async def test_swaps_from_fallback_currency_with_slippage() -> None:
    calls, fee_token = await sign(True, {PATH_USD: 2_000_000}, {PATH_USD: 1_000_500})

    (approve_to, _, approve), (swap_to, _, swap), (transfer_to, _, _) = calls
    max_amount_in = 1_000_500 + 1_000_500 * 100 // 10_000
    assert approve_to == PATH_USD.lower()
    assert approve.startswith("0x095ea7b3")
    assert word(approve, 0) == int(STABLECOIN_DEX, 16) and word(approve, 1) == max_amount_in
    assert swap_to == STABLECOIN_DEX
    assert swap.startswith("0xf0122b75")
    assert [word(swap, i) for i in range(4)] == [
        int(PATH_USD, 16),
        int(CURRENCY, 16),
        AMOUNT,
        max_amount_in,
    ]
    assert transfer_to == CURRENCY
    # Fees are paid in a funded fee token, not the currency the payer lacks.
    assert fee_token == PATH_USD.lower()
    request = ChargeRequest(amount=str(AMOUNT), currency=CURRENCY, recipient=RECIPIENT)
    normalized = [(to, value, data.removeprefix("0x")) for to, value, data in calls]
    assert len(_validate_normalized_calls(normalized, request)) == 1


@pytest.mark.asyncio
async def test_no_swap_when_currency_is_funded() -> None:
    calls, fee_token = await sign(True, {CURRENCY: AMOUNT, PATH_USD: 2_000_000}, {})

    assert [to for to, _, _ in calls] == [CURRENCY]
    assert fee_token == CURRENCY


@pytest.mark.asyncio
async def test_options_try_explicit_currencies_first_then_defaults() -> None:
    options = AutoSwap(token_in=[OUSD], slippage=0.5)
    # OUSD's quote fails, pathUSD cannot cover its quote, so USDC.e funds the swap.
    calls, _ = await sign(
        options,
        {OUSD: 5_000_000, PATH_USD: 999_999, USDC: 2_000_000},
        {OUSD: RuntimeError("no route"), PATH_USD: 1_000_000, USDC: 1_000_000},
    )

    assert calls[0][0] == USDC.lower()
    assert word(calls[1][2], 3) == 1_000_000 + 1_000_000 * 50 // 10_000
    assert options.currencies() == (OUSD, PATH_USD, USDC)


@pytest.mark.asyncio
async def test_raises_when_no_currency_can_fund_the_swap() -> None:
    with pytest.raises(InsufficientFundsError, match=CURRENCY):
        await sign(True, {CURRENCY: AMOUNT - 1}, {})


@pytest.mark.asyncio
async def test_disabled_by_default() -> None:
    calls, _ = await sign(False, {}, {})

    assert [to for to, _, _ in calls] == [CURRENCY]


def test_explicit_currencies_are_deduplicated_against_defaults() -> None:
    assert AutoSwap(token_in=[USDC.upper().replace("0X", "0x")]).currencies() == (
        USDC.upper().replace("0X", "0x"),
        PATH_USD,
    )


@pytest.mark.parametrize("slippage", [-1, float("nan"), float("inf")])
def test_invalid_slippage_is_rejected(slippage: float) -> None:
    with pytest.raises(ValueError, match="slippage"):
        AutoSwap(slippage=slippage)


@pytest.mark.asyncio
async def test_swaps_only_the_missing_amount() -> None:
    calls, _ = await sign(True, {CURRENCY: AMOUNT - 1, PATH_USD: 2_000_000}, {PATH_USD: 1})

    (_, _, approve), (_, _, swap), (_, _, transfer) = calls
    assert word(swap, 2) == 1
    assert word(approve, 1) == word(swap, 3) == 1
    assert word(transfer, 1) == AMOUNT


@pytest.mark.asyncio
async def test_balance_must_cover_the_slippage_adjusted_input() -> None:
    # pathUSD covers the quote but not the 1% slippage maximum, so USDC.e funds the swap.
    calls, _ = await sign(
        True,
        {PATH_USD: 1_000_000, USDC: 1_010_000},
        {PATH_USD: 1_000_000, USDC: 1_000_000},
    )

    assert calls[0][0] == USDC.lower()
    assert word(calls[0][2], 1) == word(calls[1][2], 3) == 1_010_000
