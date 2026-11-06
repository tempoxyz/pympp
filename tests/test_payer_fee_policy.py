"""Payer budgets reject hostile fee quotes before signing or broadcasting."""

from unittest.mock import AsyncMock, patch

import pytest
import rlp
from pytempo import TempoTransaction

from mpp.methods.tempo import CHAIN_ID, PATH_USD, TempoAccount
from mpp.methods.tempo.client import TempoMethod, TransactionError, charge
from mpp.methods.tempo.fee_payer_policy import get_policy
from mpp.methods.tempo.session import _chain as chain

ACCOUNT = TempoAccount.from_key("0x" + "11" * 32)
RECIPIENT = "0x" + "22" * 20


@pytest.mark.parametrize(
    "policy",
    [
        {"max_total_fee": -1},
        {"max_fee_per_gas": True},
        {"max_priority_fee_per_gas": 1.5},
        {"typo": 1},
    ],
)
def test_rejects_invalid_policy(policy):
    with pytest.raises(ValueError):
        charge(account=ACCOUNT, fee_policy=policy)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "quote,policy,error",
    [
        (10**20, None, "gas-price"),
        (-1, None, "gas-price"),
        (100, {"max_total_fee": 1}, "total-fee"),
        (100, {"max_fee_per_gas": 99}, "gas-price"),
    ],
)
async def test_charge_refuses_fees_before_signing(quote, policy, error):
    method = TempoMethod(account=ACCOUNT, chain_id=CHAIN_ID, payer_fee_policy=policy)

    async def rpc(_url, name, _params, **kwargs):
        return hex(CHAIN_ID) if name == "eth_chainId" else hex(quote)

    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=rpc),
        patch("mpp.methods.tempo.client._tip20_balance", new=AsyncMock(return_value=10**30)),
        patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        patch.object(TempoTransaction, "sign") as sign,
    ):
        with pytest.raises(TransactionError, match=error):
            await method._build_tempo_transfer("1", PATH_USD, RECIPIENT)
        sign.assert_not_called()


@pytest.mark.asyncio
async def test_charge_caps_priority_and_accepts_exact_total_budget():
    quote = get_policy(CHAIN_ID).max_fee_per_gas
    # Client retains its conservative static gas floor.
    gas = 1_000_000
    method = TempoMethod(
        account=ACCOUNT, chain_id=CHAIN_ID, payer_fee_policy={"max_total_fee": gas * quote}
    )

    async def rpc(_url, name, _params, **kwargs):
        return hex(CHAIN_ID) if name == "eth_chainId" else hex(quote)

    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=rpc),
        patch("mpp.methods.tempo.client._tip20_balance", new=AsyncMock(return_value=10**30)),
        patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
    ):
        raw, _ = await method._build_tempo_transfer("1", PATH_USD, RECIPIENT)
    fields = rlp.decode(bytes.fromhex(raw[2:])[1:])
    assert int.from_bytes(fields[1], "big") == get_policy(CHAIN_ID).max_priority_fee_per_gas
    assert int.from_bytes(fields[2], "big") == quote
    assert int.from_bytes(fields[3], "big") == gas


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "quote,gas,error", [(10**20, 100_000, "gas-price"), (100_000_000_000, 1_000_000, "total-fee")]
)
async def test_session_transactions_apply_default_payer_budget(quote, gas, error):
    async def rpc(_url, name, _params, _client):
        return hex(CHAIN_ID) if name == "eth_chainId" else hex(quote)

    with (
        patch.object(chain, "_rpc", side_effect=rpc),
        patch.object(chain, "_estimate_gas", new=AsyncMock(return_value=gas)),
        patch.object(TempoTransaction, "sign") as sign,
    ):
        with pytest.raises(ValueError, match=error):
            await chain._build_signed_transaction(
                ACCOUNT,
                [(PATH_USD, "0x")],
                rpc_url="http://localhost",
                chain_id=CHAIN_ID,
                fee_token=PATH_USD,
                awaiting_fee_payer=False,
                root_account=None,
                valid_before=None,
                valid_after=None,
                client=None,
            )
        sign.assert_not_called()
