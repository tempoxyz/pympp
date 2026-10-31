"""Session client auto-swap (mppx session/client autoSwap): buy the token before open/top-up."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.methods.tempo import PATH_USD, USDC, TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo.client import AutoSwap, InsufficientFundsError
from mpp.methods.tempo.intents import STABLECOIN_DEX
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS, ChannelDescriptor
from mpp.methods.tempo.session.client import (
    SessionContext,
    SessionManager,
    SessionMethod,
    session,
    session_manager,
)
from mpp.methods.tempo.session.client._state import resolve_auto_swap
from mpp.runtime import CredentialParams

PAYEE = "0x" + "11" * 20
TOKEN = "0x20c0000000000000000000000000000000000001"
CHAIN_ID = 4217
ACCOUNT = TempoAccount.from_key("0x" + "ab" * 32)
DEPOSIT = 1_000


def make_challenge(*, suggested_deposit: str = str(DEPOSIT)) -> Challenge:
    return Challenge(
        id=os.urandom(8).hex(),
        method="tempo",
        intent="session",
        request={
            "amount": "100",
            "currency": TOKEN,
            "recipient": PAYEE,
            "unitType": "request",
            "suggestedDeposit": suggested_deposit,
            "methodDetails": {
                "sessionProtocol": "v2",
                "chainId": CHAIN_ID,
                "escrowContract": ESCROW_ADDRESS,
            },
        },
        realm="api.test",
        expires=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )


def descriptor() -> ChannelDescriptor:
    return ChannelDescriptor(
        payer=ACCOUNT.address,
        payee=PAYEE,
        operator="0x" + "00" * 20,
        token=TOKEN,
        salt="0x" + "01" * 32,
        authorized_signer=ACCOUNT.address,
        expiring_nonce_hash="0x" + "02" * 32,
    )


class FakeChain:
    """Records the prefix calls open/top-up transactions are built with, and fakes the DEX."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.balances: dict[str, int] = {}
        self.quotes: dict[str, int] = {}
        self.opens: list[dict[str, Any]] = []
        self.top_ups: list[dict[str, Any]] = []
        self.rpc_clients: list[Any] = []
        monkeypatch.setattr(chain, "build_open_transaction", self.build_open_transaction)
        monkeypatch.setattr(chain, "build_top_up_transaction", self.build_top_up_transaction)
        monkeypatch.setattr(tempo_client, "_tip20_balance", self.balance)
        monkeypatch.setattr(tempo_client, "_rpc_call", self.rpc_call)

    async def build_open_transaction(self, account: TempoAccount, **kwargs: Any) -> Any:
        self.opens.append(kwargs)
        opened = ChannelDescriptor(
            payer=account.address,
            payee=kwargs["payee"],
            operator=kwargs["operator"],
            token=kwargs["token"],
            salt="0x" + os.urandom(32).hex(),
            authorized_signer=kwargs["authorized_signer"],
            expiring_nonce_hash="0x" + os.urandom(32).hex(),
        )
        channel_id = compute_channel_id(
            opened, chain_id=kwargs["chain_id"], escrow=kwargs["escrow"]
        )
        return "0x76" + "00" * 8, opened, channel_id

    async def build_top_up_transaction(
        self, account: TempoAccount, descriptor: ChannelDescriptor, additional: int, **kwargs: Any
    ) -> str:
        self.top_ups.append({"additional": additional, **kwargs})
        return "0x76" + "11" * 8

    async def balance(self, _url: str, token: str, address: str, **kwargs: Any) -> int:
        assert address == ACCOUNT.address
        self.rpc_clients.append(kwargs.get("client"))
        return {t.lower(): v for t, v in self.balances.items()}.get(token.lower(), 0)

    async def rpc_call(self, _url: str, name: str, params: list[Any], **kwargs: Any) -> str:
        assert name == "eth_call" and params[0]["to"] == STABLECOIN_DEX
        self.rpc_clients.append(kwargs.get("client"))
        token_in = "0x" + params[0]["data"][10 + 24 : 10 + 64]
        return hex(self.quotes[token_in])


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeChain:
    return FakeChain(monkeypatch)


def word(data: str, index: int) -> int:
    return int(data[10 + 64 * index : 10 + 64 * (index + 1)], 16)


async def pay(method: SessionMethod, context: SessionContext | None = None) -> dict[str, Any]:
    authorization = await method.create_credential(
        CredentialParams(challenge=make_challenge(), context=context)
    )
    return Credential.from_authorization(authorization).payload


def assert_swap(calls: Any, token_in: str, amount_out: int, max_amount_in: int) -> None:
    (approve_to, approve), (swap_to, swap) = calls
    assert approve_to == token_in
    assert approve.startswith("0x095ea7b3")
    assert word(approve, 0) == int(STABLECOIN_DEX, 16) and word(approve, 1) == max_amount_in
    assert swap_to == STABLECOIN_DEX
    assert swap.startswith("0xf0122b75")
    assert [word(swap, i) for i in range(4)] == [
        int(token_in, 16),
        int(TOKEN, 16),
        amount_out,
        max_amount_in,
    ]


def test_resolve_auto_swap() -> None:
    options = AutoSwap(slippage=2)
    assert resolve_auto_swap(None) is None
    assert resolve_auto_swap(False) is None
    assert resolve_auto_swap(True) == AutoSwap()
    assert resolve_auto_swap(options) is options


async def test_open_buys_the_deposit_shortfall(fake: FakeChain) -> None:
    fake.balances = {TOKEN: 200, PATH_USD: 10_000}
    fake.quotes = {PATH_USD.lower(): 800}
    http = httpx.AsyncClient()
    method = SessionMethod(account=ACCOUNT, auto_swap=True, http_client=http)

    payload = await pay(method)

    assert payload["action"] == "open"
    (open_call,) = fake.opens
    assert open_call["deposit"] == DEPOSIT
    assert_swap(open_call["prefix_calls"], PATH_USD, DEPOSIT - 200, 808)
    # Balance and quote reads go through the method's HTTP client.
    assert fake.rpc_clients and all(c is http for c in fake.rpc_clients)
    await http.aclose()


async def test_open_without_auto_swap_adds_no_calls(fake: FakeChain) -> None:
    await pay(SessionMethod(account=ACCOUNT))
    assert fake.opens[0]["prefix_calls"] == []
    assert fake.rpc_clients == []


async def test_funded_payer_needs_no_swap(fake: FakeChain) -> None:
    fake.balances = {TOKEN: DEPOSIT}
    await pay(SessionMethod(account=ACCOUNT, auto_swap=True))
    assert fake.opens[0]["prefix_calls"] == []


async def test_options_choose_currencies_and_slippage(fake: FakeChain) -> None:
    fake.balances = {USDC: 10_000, PATH_USD: 10_000}
    fake.quotes = {USDC.lower(): 1_000, PATH_USD.lower(): 1_000}
    await pay(SessionMethod(account=ACCOUNT, auto_swap=AutoSwap(token_in=[USDC], slippage=5)))
    assert_swap(fake.opens[0]["prefix_calls"], USDC, DEPOSIT, 1_050)


async def test_context_overrides_the_method_option(fake: FakeChain) -> None:
    fake.balances = {PATH_USD: 10_000}
    fake.quotes = {PATH_USD.lower(): 1_000}
    await pay(SessionMethod(account=ACCOUNT, auto_swap=True), SessionContext(auto_swap=False))
    await pay(SessionMethod(account=ACCOUNT), SessionContext(auto_swap=True))
    assert fake.opens[0]["prefix_calls"] == []
    assert_swap(fake.opens[1]["prefix_calls"], PATH_USD, DEPOSIT, 1_010)


async def test_no_route_fails_before_signing(fake: FakeChain) -> None:
    with pytest.raises(InsufficientFundsError):
        await pay(SessionMethod(account=ACCOUNT, auto_swap=True))
    assert fake.opens == []


async def test_top_up_buys_the_additional_deposit(fake: FakeChain) -> None:
    fake.balances = {PATH_USD: 10_000}
    fake.quotes = {PATH_USD.lower(): 500}
    method = SessionMethod(account=ACCOUNT, auto_swap=True)
    context = SessionContext(action="topUp", descriptor=descriptor(), additional_deposit_raw="500")

    payload = await pay(method, context)

    assert payload["action"] == "topUp"
    (top_up,) = fake.top_ups
    assert top_up["additional"] == 500
    assert_swap(top_up["prefix_calls"], PATH_USD, 500, 505)


async def test_signed_top_up_transaction_is_sent_as_is(fake: FakeChain) -> None:
    method = SessionMethod(account=ACCOUNT, auto_swap=True)
    context = SessionContext(
        action="topUp",
        descriptor=descriptor(),
        additional_deposit_raw="500",
        transaction="0x76" + "22" * 8,
    )
    assert (await pay(method, context))["transaction"] == context.transaction
    assert fake.top_ups == [] and fake.rpc_clients == []


def test_factories_accept_auto_swap() -> None:
    method: Any = session(account=ACCOUNT, auto_swap=True).create_credential
    assert method.__self__.auto_swap == AutoSwap()
    options = AutoSwap(slippage=3)
    manager = session_manager(account=ACCOUNT, auto_swap=options)
    assert isinstance(manager, SessionManager)
    assert manager._method.auto_swap is options  # pyright: ignore[reportPrivateUsage]
    assert session_manager(account=ACCOUNT)._method.auto_swap is None  # pyright: ignore[reportPrivateUsage]
