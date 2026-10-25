"""Port of mppx ``src/tempo/internal/fee-payer.test.ts``."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import attrs
import httpx
import pytest
from pytempo import (
    AccessListItem,
    Call,
    KeyAuthorization,
    Signature,
    SignedKeyAuthorization,
    TempoTransaction,
)

from mpp.tempo._internal import abi
from mpp.tempo._internal.abi import Function
from mpp.tempo._internal.account import secp256k1_account
from mpp.tempo._internal.charge import ExpectedTransfer
from mpp.tempo._internal.envelope import (
    EXPIRING_NONCE_KEY,
    call_target,
    deserialize,
    fee_payer_sign_payload,
    fee_token,
    sender,
)
from mpp.tempo._internal.fee_payer import (
    CALL_SCOPES,
    FeePayerValidationError,
    PolicyOverrides,
    Sponsorship,
    assert_allowed_fee_token,
    assert_transaction_policy,
    default_allowed_fee_tokens,
    fill_hosted_fee_payer_transaction,
    preflight_sponsorship,
    prepare_sponsored_transaction,
    simulation_request,
    sponsored_simulation_request,
    validate_calls,
)
from mpp.tempo._internal.hexutil import to_hex
from mpp.tempo._internal.rpc import RpcClient, RpcError
from mpp.tempo._internal.selectors import (
    APPROVE_SELECTOR,
    SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    TRANSFER_SELECTOR,
    TRANSFER_WITH_MEMO_SELECTOR,
)
from mpp.tempo._internal.signature import secp256k1_signature, y_parity
from mpp.tempo.assets import MACH_ADDRESS, PATH_USD_ADDRESS, USDC_ADDRESS
from mpp.tempo.chains import (
    MAINNET_CHAIN_ID,
    STABLECOIN_DEX,
    TESTNET_CHAIN_ID,
)

DETAILS = {"amount": "1", "currency": "0x01", "recipient": "0x02"}
BOGUS = "0x0000000000000000000000000000000000000001"
RECIPIENT_2 = "0x0000000000000000000000000000000000000002"
SWAP_TOKEN_IN = "0x0000000000000000000000000000000000000003"
SWAP_TOKEN_OUT = "0x0000000000000000000000000000000000000004"
MEMO = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
SWAP_DATA = abi.SWAP_EXACT_AMOUNT_OUT.encode(SWAP_TOKEN_IN, SWAP_TOKEN_OUT, 100, 100)

SALT = bytes.fromhex("1" * 64)
EXPIRING_NONCE_HASH = bytes.fromhex("2" * 64)
_DESCRIPTOR_TYPE = "(address,address,address,address,bytes32,address,bytes32)"
SESSION_DESCRIPTOR = (BOGUS, BOGUS, BOGUS, BOGUS, SALT, BOGUS, EXPIRING_NONCE_HASH)

PRECOMPILE_OPEN = Function(
    "open", ("address", "address", "address", "uint96", "bytes32", "address")
)
PRECOMPILE_TOP_UP = Function("topUp", (_DESCRIPTOR_TYPE, "uint96"))
LEGACY_OPEN = Function("open", ("address", "address", "uint128", "bytes32", "address"))
LEGACY_TOP_UP = Function("topUp", ("bytes32", "uint256"))

SESSION_CALL_DATA = {
    "open": PRECOMPILE_OPEN.encode(BOGUS, BOGUS, BOGUS, 100, SALT, BOGUS),
    "topUp": PRECOMPILE_TOP_UP.encode(SESSION_DESCRIPTOR, 100),
    "legacy open": LEGACY_OPEN.encode(BOGUS, BOGUS, 100, SALT, BOGUS),
    "legacy topUp": LEGACY_TOP_UP.encode(EXPIRING_NONCE_HASH, 100),
}

FEE_PAYER_SIGNATURE = {
    "r": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "s": "0x0000000000000000000000000000000000000000000000000000000000000003",
    "yParity": 1,
}


def call(*, to: str = "", data: str = "0x", value: int = 0) -> Call:
    return Call(to=to, data=data, value=value)


def transfer(to: str, amount: int) -> str:
    return abi.TRANSFER.encode(to, amount)


def transfer_with_memo(to: str, amount: int, memo: str) -> str:
    return abi.TRANSFER_WITH_MEMO.encode(to, amount, bytes.fromhex(memo[2:]))


def approve(spender: str, amount: int) -> str:
    return abi.APPROVE.encode(spender, amount)


# -- callScopes --------------------------------------------------------------------------------


def test_call_scopes_has_4_allowed_patterns() -> None:
    assert len(CALL_SCOPES) == 4


def test_call_scopes_patterns_use_correct_selectors() -> None:
    assert [list(s) for s in CALL_SCOPES] == [
        [TRANSFER_SELECTOR],
        [TRANSFER_WITH_MEMO_SELECTOR],
        [APPROVE_SELECTOR, SWAP_EXACT_AMOUNT_OUT_SELECTOR, TRANSFER_SELECTOR],
        [APPROVE_SELECTOR, SWAP_EXACT_AMOUNT_OUT_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR],
    ]


# -- validateCalls -----------------------------------------------------------------------------


def test_validate_calls_accepts_single_transfer() -> None:
    validate_calls([call(data=transfer(BOGUS, 100))], DETAILS)


def test_validate_calls_accepts_approve_buy_transfer() -> None:
    validate_calls(
        [
            call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
            call(to=STABLECOIN_DEX, data=SWAP_DATA),
            call(data=transfer(BOGUS, 100)),
        ],
        DETAILS,
    )


def test_validate_calls_accepts_multiple_transfers_after_swap_prefix() -> None:
    validate_calls(
        [
            call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
            call(to=STABLECOIN_DEX, data=SWAP_DATA),
            call(data=transfer(BOGUS, 90)),
            call(data=transfer_with_memo(RECIPIENT_2, 10, MEMO)),
        ],
        DETAILS,
    )


def test_validate_calls_accepts_approve_buy_exact_expected_split_transfers() -> None:
    assert (
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
                call(to=SWAP_TOKEN_OUT, data=transfer(BOGUS, 90)),
                call(to=SWAP_TOKEN_OUT, data=transfer_with_memo(RECIPIENT_2, 10, MEMO)),
            ],
            DETAILS,
            currency=SWAP_TOKEN_OUT,
            expected_transfers=[
                ExpectedTransfer(amount="90", recipient=BOGUS),
                ExpectedTransfer(amount="10", memo=MEMO, recipient=RECIPIENT_2),
            ],
        )
        == SWAP_TOKEN_IN
    )


@pytest.mark.parametrize("amount_out", [1, 90, 100, 0, 101])
def test_validate_calls_bounds_sponsored_swap_output(amount_out: int) -> None:
    def validate() -> None:
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(
                    to=STABLECOIN_DEX,
                    data=abi.SWAP_EXACT_AMOUNT_OUT.encode(
                        SWAP_TOKEN_IN, SWAP_TOKEN_OUT, amount_out, 100
                    ),
                ),
                call(to=SWAP_TOKEN_OUT, data=transfer(BOGUS, 100)),
            ],
            DETAILS,
            currency=SWAP_TOKEN_OUT,
            expected_transfers=[ExpectedTransfer(amount="100", recipient=BOGUS)],
        )

    if 0 < amount_out <= 100:
        validate()
    else:
        with pytest.raises(FeePayerValidationError, match="swap output must be positive"):
            validate()


def test_validate_calls_error_rejects_extra_transfers_when_expected_payments_supplied() -> None:
    with pytest.raises(FeePayerValidationError, match="disallowed call pattern"):
        validate_calls(
            [
                call(to=SWAP_TOKEN_OUT, data=transfer(BOGUS, 100)),
                call(to=SWAP_TOKEN_OUT, data=transfer(RECIPIENT_2, 1)),
            ],
            DETAILS,
            currency=SWAP_TOKEN_OUT,
            expected_transfers=[ExpectedTransfer(amount="100", recipient=BOGUS)],
        )


def test_validate_calls_error_rejects_expected_transfers_to_wrong_token() -> None:
    with pytest.raises(FeePayerValidationError, match="payment transfer does not match challenge"):
        validate_calls(
            [call(to=SWAP_TOKEN_IN, data=transfer(BOGUS, 100))],
            DETAILS,
            currency=SWAP_TOKEN_OUT,
            expected_transfers=[ExpectedTransfer(amount="100", recipient=BOGUS)],
        )


def test_validate_calls_error_rejects_swaps_whose_output_does_not_fund_payment() -> None:
    with pytest.raises(
        FeePayerValidationError, match="swap tokenOut does not match payment currency"
    ):
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
                call(to=BOGUS, data=transfer(BOGUS, 100)),
            ],
            DETAILS,
            currency=BOGUS,
            expected_transfers=[ExpectedTransfer(amount="100", recipient=BOGUS)],
        )


def test_validate_calls_error_rejects_empty_calls() -> None:
    with pytest.raises(FeePayerValidationError):
        validate_calls([], DETAILS)


def test_validate_calls_error_rejects_unknown_selector() -> None:
    with pytest.raises(FeePayerValidationError, match="disallowed call pattern"):
        validate_calls([call(data="0xdeadbeef")], DETAILS)


def test_validate_calls_error_rejects_more_than_11_transfers() -> None:
    with pytest.raises(FeePayerValidationError, match="disallowed call pattern"):
        validate_calls(
            [call(data=transfer(f"0x{index + 1:040x}", 100)) for index in range(12)],
            DETAILS,
        )


def test_validate_calls_error_rejects_wrong_order() -> None:
    with pytest.raises(FeePayerValidationError, match="disallowed call pattern"):
        validate_calls(
            [
                call(data=transfer(BOGUS, 100)),
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
            ],
            DETAILS,
        )


def test_validate_calls_error_rejects_approve_with_non_dex_spender() -> None:
    with pytest.raises(FeePayerValidationError, match="approve spender is not the DEX"):
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(BOGUS, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
                call(data=transfer(BOGUS, 100)),
            ],
            DETAILS,
        )


def test_validate_calls_rejects_approve_targeting_non_token_contract() -> None:
    with pytest.raises(FeePayerValidationError):
        validate_calls(
            [
                call(to=BOGUS, data=approve(STABLECOIN_DEX, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
                call(data=transfer(BOGUS, 100)),
            ],
            DETAILS,
        )


def test_validate_calls_error_rejects_buy_targeting_non_dex_address() -> None:
    with pytest.raises(FeePayerValidationError, match="buy target is not the DEX"):
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(to=BOGUS, data=SWAP_DATA),
                call(data=transfer(BOGUS, 100)),
            ],
            DETAILS,
        )


def test_validate_calls_error_rejects_approve_buy_without_transfer() -> None:
    with pytest.raises(FeePayerValidationError, match="disallowed call pattern"):
        validate_calls(
            [
                call(to=SWAP_TOKEN_IN, data=approve(STABLECOIN_DEX, 100)),
                call(to=STABLECOIN_DEX, data=SWAP_DATA),
            ],
            DETAILS,
        )


# -- fee token allowlist -----------------------------------------------------------------------


def test_fee_token_allowlist_includes_path_usd_and_chain_default_currency() -> None:
    assert default_allowed_fee_tokens(MAINNET_CHAIN_ID) == [PATH_USD_ADDRESS, USDC_ADDRESS]


def test_fee_token_allowlist_dedupes_when_path_usd_is_chain_default() -> None:
    assert default_allowed_fee_tokens(TESTNET_CHAIN_ID) == [PATH_USD_ADDRESS]


def test_fee_token_allowlist_accepts_allowlisted_fee_tokens() -> None:
    assert_allowed_fee_token(USDC_ADDRESS, default_allowed_fee_tokens(MAINNET_CHAIN_ID))


def test_fee_token_allowlist_accepts_arbitrary_valid_addresses_only_without_allowlist() -> None:
    assert_allowed_fee_token(SWAP_TOKEN_IN)
    with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
        assert_allowed_fee_token(SWAP_TOKEN_IN, [])


# `null` is omitted: Python has no undefined/null distinction and `None` means "no fee token".
@pytest.mark.parametrize(
    "fee_token", ["", "pathUSD", "0x1234", f"0x{'g' * 40}", f"0x{'0' * 42}", 1]
)
def test_fee_token_allowlist_rejects_malformed_fee_tokens_without_allowlist(
    fee_token: object,
) -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is invalid"):
        assert_allowed_fee_token(fee_token)


def test_fee_token_allowlist_compares_valid_addresses_case_insensitively() -> None:
    assert_allowed_fee_token(USDC_ADDRESS.lower(), [USDC_ADDRESS])


def test_fee_token_allowlist_error_rejects_non_string_fee_tokens() -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is invalid"):
        assert_allowed_fee_token(1, default_allowed_fee_tokens(MAINNET_CHAIN_ID))


def test_fee_token_allowlist_error_rejects_fee_tokens_outside_allowlist() -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
        assert_allowed_fee_token(SWAP_TOKEN_IN, default_allowed_fee_tokens(MAINNET_CHAIN_ID))


def test_fee_token_allowlist_error_rejects_mach_as_fee_token() -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
        assert_allowed_fee_token(
            MACH_ADDRESS,
            default_allowed_fee_tokens(TESTNET_CHAIN_ID),
        )


# -- fillHostedFeePayerTransaction -------------------------------------------------------------

HOSTED_TRANSACTION = TempoTransaction(
    calls=(call(data=transfer(BOGUS, 100), to=BOGUS),),
    chain_id=MAINNET_CHAIN_ID,
    sender_address=BOGUS,
    gas_limit=150_000,
    max_fee_per_gas=1_000_000_000,
    max_priority_fee_per_gas=0,
    nonce=1,
    nonce_key=EXPIRING_NONCE_KEY,
    sender_signature=secp256k1_signature(r=1, s=1, y_parity=0),
    valid_before=math.floor(time.time()) + 300,
)
SPONSOR_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000042"

type Handler = Callable[[dict[str, Any]], Any]


class RecordingRpc:
    """An ``RpcClient`` backed by ``httpx.MockTransport``; records JSON-RPC request bodies."""

    def __init__(self, result: Handler) -> None:
        self.bodies: list[dict[str, Any]] = []

        def handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.bodies.append(body)
            reply = result(body)
            if isinstance(reply, RpcError):
                error = {"code": reply.code, "message": reply.message}
                return httpx.Response(
                    200, json={"jsonrpc": "2.0", "id": body["id"], "error": error}
                )
            if reply is _NO_RESULT:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"]})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": reply})

        self.client = RpcClient(
            "http://rpc.invalid", http=httpx.AsyncClient(transport=httpx.MockTransport(handle))
        )


_NO_RESULT = object()


def _constant(value: Any) -> Handler:
    return lambda _body: value


async def _fill(
    rpc: RecordingRpc,
    transaction: TempoTransaction = HOSTED_TRANSACTION,
    **kwargs: Any,
) -> Any:
    return await fill_hosted_fee_payer_transaction(
        transaction, client=rpc.client, chain_id=MAINNET_CHAIN_ID, details=DETAILS, **kwargs
    )


def _quantity(value: str | None) -> int | None:
    return None if value is None else int(value, 16)


@pytest.mark.parametrize(
    ("allowed_fee_tokens", "expected_fee_token"),
    [
        ([PATH_USD_ADDRESS], PATH_USD_ADDRESS),
        (None, SWAP_TOKEN_IN),
        ([SWAP_TOKEN_IN], SWAP_TOKEN_IN),
    ],
)
async def test_fill_hosted_preserves_sender_committed_fields_with_hosted_token_policy(
    allowed_fee_tokens: list[str] | None, expected_fee_token: str
) -> None:
    # Sign over the payload built from the actual RPC request body so this
    # verifies recovery parity with the real request shape.
    sponsor = secp256k1_account(SPONSOR_PRIVATE_KEY)
    signatures: list[Signature] = []

    def result(body: dict[str, Any]) -> Any:
        rpc = body["params"][0]
        rebuilt = TempoTransaction(
            access_list=tuple(
                AccessListItem(address=i["address"], storage_keys=tuple(i["storageKeys"]))
                for i in rpc.get("accessList", [])
            ),
            calls=tuple(
                call(
                    to=c.get("to") or "",
                    data=c.get("data", "0x"),
                    value=int(c["value"], 16) if c.get("value") not in (None, "0x") else 0,
                )
                for c in rpc["calls"]
            ),
            chain_id=HOSTED_TRANSACTION.chain_id,
            fee_token=expected_fee_token,
            sender_address=rpc["from"],
            gas_limit=_quantity(rpc.get("gas")) or 0,
            max_fee_per_gas=_quantity(rpc.get("maxFeePerGas")) or 0,
            max_priority_fee_per_gas=_quantity(rpc.get("maxPriorityFeePerGas")) or 0,
            nonce=_quantity(rpc.get("nonce")) or 0,
            nonce_key=_quantity(rpc.get("nonceKey")) or 0,
            valid_after=_quantity(rpc.get("validAfter")),
            valid_before=_quantity(rpc.get("validBefore")),
        )
        signature = sponsor.sign_raw(fee_payer_sign_payload(rebuilt, sender=rpc["from"]))
        assert isinstance(signature, Signature)
        signatures.append(signature)
        return {
            "tx": {
                "feePayerSignature": {
                    "r": hex(signature.r),
                    "s": hex(signature.s),
                    "yParity": y_parity(signature),
                },
                "feeToken": expected_fee_token,
                "gas": "0x1",
                "maxFeePerGas": "0x2",
                "calls": [{"to": SWAP_TOKEN_OUT, "data": "0x"}],
                "chainId": "0x1",
                "nonce": "0x99",
            }
        }

    rpc = RecordingRpc(result)
    filled = await _fill(rpc, allowed_fee_tokens=allowed_fee_tokens)

    assert filled.fee_token == expected_fee_token
    assert filled.fee_payer.lower() == sponsor.address.lower()

    assert len(rpc.bodies) == 1
    body = rpc.bodies[0]
    assert body["method"] == "eth_fillTransaction"
    params = body["params"][0]
    expected = {
        "calls": [
            {"data": to_hex(c.data), "to": call_target(c), "value": "0x"}
            for c in HOSTED_TRANSACTION.calls
        ],
        "feePayer": True,
        "from": sender(HOSTED_TRANSACTION),
        "gas": hex(150_000),
        "maxFeePerGas": hex(1_000_000_000),
        # Like ox, a zero priority fee is unset and omitted.
        "maxPriorityFeePerGas": None,
        "nonce": "0x1",
        "nonceKey": hex(EXPIRING_NONCE_KEY),
        "type": "0x76",
        "validBefore": hex(HOSTED_TRANSACTION.valid_before or 0),
    }
    assert {k: params.get(k) for k in expected} == expected

    transaction = deserialize(filled.serialized_transaction)
    assert transaction.gas_limit == HOSTED_TRANSACTION.gas_limit
    assert transaction.max_fee_per_gas == HOSTED_TRANSACTION.max_fee_per_gas
    assert transaction.calls == HOSTED_TRANSACTION.calls
    assert (fee_token(transaction) or "").lower() == expected_fee_token.lower()
    assert transaction.chain_id == HOSTED_TRANSACTION.chain_id
    assert transaction.nonce == HOSTED_TRANSACTION.nonce
    assert transaction.valid_before == HOSTED_TRANSACTION.valid_before
    assert transaction.fee_payer_signature is not None
    assert transaction.fee_payer_signature.r == signatures[0].r
    assert transaction.fee_payer_signature.s == signatures[0].s


async def test_fill_hosted_error_requires_fee_token() -> None:
    rpc = RecordingRpc(_constant({"tx": {"feePayerSignature": FEE_PAYER_SIGNATURE}}))
    with pytest.raises(FeePayerValidationError, match="did not return a feeToken"):
        await _fill(rpc)


@pytest.mark.parametrize("fee_token", ["not-an-address", "0x1234", f"0x{'g' * 40}"])
async def test_fill_hosted_error_rejects_malformed_fee_token_without_allowlist(
    fee_token: str,
) -> None:
    rpc = RecordingRpc(
        _constant({"tx": {"feePayerSignature": FEE_PAYER_SIGNATURE, "feeToken": fee_token}})
    )
    with pytest.raises(FeePayerValidationError, match="feeToken is invalid"):
        await _fill(rpc)


@pytest.mark.parametrize(
    "result",
    [_NO_RESULT, None, {"tx": {}}, {"tx": {"feeToken": SWAP_TOKEN_IN}}],
    ids=["undefined", "null", "empty-tx", "fee-token-only"],
)
async def test_fill_hosted_error_requires_sponsor_signature_without_allowlist(
    result: Any,
) -> None:
    rpc = RecordingRpc(_constant(result))
    with pytest.raises(FeePayerValidationError, match="failed to sponsor transaction"):
        await _fill(rpc)


async def test_fill_hosted_error_rejects_invalid_signature_without_allowlist() -> None:
    rpc = RecordingRpc(
        _constant(
            {
                "tx": {
                    "feePayerSignature": {"r": "0x0", "s": "0x0", "yParity": 0},
                    "feeToken": SWAP_TOKEN_IN,
                }
            }
        )
    )
    with pytest.raises(FeePayerValidationError, match="invalid feePayerSignature"):
        await _fill(rpc)


async def test_fill_hosted_error_rejects_fee_token_outside_allowlist() -> None:
    rpc = RecordingRpc(
        _constant({"tx": {"feePayerSignature": FEE_PAYER_SIGNATURE, "feeToken": SWAP_TOKEN_IN}})
    )
    with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
        await _fill(rpc, allowed_fee_tokens=default_allowed_fee_tokens(MAINNET_CHAIN_ID))


async def test_fill_hosted_error_surfaces_hosted_fee_payer_errors() -> None:
    rpc = RecordingRpc(_constant(RpcError(-32000, "Invalid or revoked API key")))
    with pytest.raises(RpcError, match="Invalid or revoked API key"):
        await _fill(rpc)


async def test_fill_hosted_error_enforces_policy_before_requesting_fill() -> None:
    rpc = RecordingRpc(_constant(None))
    with pytest.raises(FeePayerValidationError, match="gas exceeds sponsor policy"):
        await _fill(rpc, policy=PolicyOverrides(max_gas=150_000 - 1))
    assert rpc.bodies == []


async def test_fill_hosted_error_rejects_non_empty_access_lists_before_fill() -> None:
    rpc = RecordingRpc(_constant(None))
    with pytest.raises(FeePayerValidationError, match="accessList is not allowed"):
        await _fill(
            rpc,
            attrs.evolve(HOSTED_TRANSACTION, access_list=(AccessListItem(address=BOGUS),)),
        )
    assert rpc.bodies == []


async def test_fill_hosted_error_rejects_padded_calldata_before_fill() -> None:
    rpc = RecordingRpc(_constant(None))
    call = HOSTED_TRANSACTION.calls[0]
    with pytest.raises(FeePayerValidationError, match="calldata is not canonical"):
        await _fill(
            rpc,
            attrs.evolve(
                HOSTED_TRANSACTION, calls=(attrs.evolve(call, data=f"{to_hex(call.data)}01"),)
            ),
        )
    assert rpc.bodies == []


async def test_fill_hosted_error_rejects_unknown_calldata_before_fill() -> None:
    rpc = RecordingRpc(_constant(None))
    call = HOSTED_TRANSACTION.calls[0]
    with pytest.raises(FeePayerValidationError, match="call calldata is invalid"):
        await _fill(
            rpc, attrs.evolve(HOSTED_TRANSACTION, calls=(attrs.evolve(call, data="0xdeadbeef"),))
        )
    assert rpc.bodies == []


# -- simulationTransaction ---------------------------------------------------------------------
# The Python helpers return RPC-formatted call requests rather than viem transaction objects,
# so the assertions check the equivalent wire shape (and that no signature is ever included).

_SIGNED_FEE_PAYER = secp256k1_signature(r=2, s=3, y_parity=1)


def test_simulation_strips_signed_fee_payer_fields_for_sponsored_preflight() -> None:
    transaction = TempoTransaction(
        chain_id=TESTNET_CHAIN_ID,
        calls=(call(to=BOGUS),),
        fee_payer_signature=_SIGNED_FEE_PAYER,
        sender_address=BOGUS,
    )
    assert simulation_request(transaction, fee_payer=True) == {
        "calls": [{"to": BOGUS, "value": "0x", "data": "0x"}],
        "type": "0x76",
        "from": BOGUS,
    }


def test_simulation_preserves_non_sponsored_fields_except_fee_payer_signature() -> None:
    transaction = TempoTransaction(
        chain_id=TESTNET_CHAIN_ID,
        calls=(call(to=BOGUS),),
        fee_payer_signature=_SIGNED_FEE_PAYER,
        sender_address=BOGUS,
        gas_limit=1,
    )
    assert simulation_request(transaction, fee_payer=False) == {
        "chainId": hex(TESTNET_CHAIN_ID),
        "gas": "0x1",
        "nonce": "0x0",
        "nonceKey": "0x0",
        "calls": [{"to": BOGUS, "value": "0x", "data": "0x"}],
        "type": "0x76",
        "from": BOGUS,
    }


def test_simulation_builds_final_sponsored_envelope_without_either_signature() -> None:
    transaction = TempoTransaction(
        chain_id=TESTNET_CHAIN_ID,
        calls=(call(to=BOGUS),),
        fee_payer_signature=_SIGNED_FEE_PAYER,
        fee_token=SWAP_TOKEN_IN,
        gas_limit=0,
        sender_address=BOGUS,
        sender_signature=secp256k1_signature(r=1, s=2, y_parity=0),
    )
    assert sponsored_simulation_request(transaction, fee_payer=SWAP_TOKEN_OUT, fee_token=BOGUS) == {
        "chainId": hex(TESTNET_CHAIN_ID),
        "nonce": "0x0",
        "nonceKey": "0x0",
        "calls": [{"to": BOGUS, "value": "0x", "data": "0x"}],
        "feeToken": BOGUS,
        "type": "0x76",
        "from": BOGUS,
        "feePayer": SWAP_TOKEN_OUT,
    }


# -- preflightSponsorship ----------------------------------------------------------------------

PREFLIGHT_TRANSACTION = TempoTransaction(
    chain_id=TESTNET_CHAIN_ID,
    calls=(call(to=BOGUS),),
    gas_limit=0,
    fee_token=SWAP_TOKEN_IN,
    sender_address=BOGUS,
)


async def test_preflight_simulates_sender_before_completion_and_envelope_after() -> None:
    simulations: list[dict[str, Any]] = []
    completions = 0

    async def simulate(request: dict[str, Any]) -> None:
        simulations.append(request)

    async def complete() -> Sponsorship:
        nonlocal completions
        completions += 1
        return Sponsorship(fee_payer=SWAP_TOKEN_OUT, transaction=PREFLIGHT_TRANSACTION)

    result = await preflight_sponsorship(
        PREFLIGHT_TRANSACTION, complete=complete, simulate=simulate
    )

    assert completions == 1
    assert result.fee_payer == SWAP_TOKEN_OUT
    calls = [{"to": BOGUS, "value": "0x", "data": "0x"}]
    assert simulations == [
        {"calls": calls, "type": "0x76", "from": BOGUS},
        {
            "chainId": hex(TESTNET_CHAIN_ID),
            "nonce": "0x0",
            "nonceKey": "0x0",
            "calls": calls,
            "feeToken": SWAP_TOKEN_IN,
            "type": "0x76",
            "from": BOGUS,
            "feePayer": SWAP_TOKEN_OUT,
        },
    ]


@pytest.mark.parametrize(
    ("complete_calls", "failing_simulation", "simulation_calls"),
    [(0, 1, 1), (1, 2, 2)],
)
async def test_preflight_stops_at_simulation(
    complete_calls: int, failing_simulation: int, simulation_calls: int
) -> None:
    completions = 0
    simulations = 0

    async def simulate(_request: dict[str, Any]) -> None:
        nonlocal simulations
        simulations += 1
        if simulations == failing_simulation:
            raise RuntimeError("simulation failed")

    async def complete() -> Sponsorship:
        nonlocal completions
        completions += 1
        return Sponsorship(fee_payer=SWAP_TOKEN_OUT, transaction=PREFLIGHT_TRANSACTION)

    with pytest.raises(RuntimeError, match="simulation failed"):
        await preflight_sponsorship(PREFLIGHT_TRANSACTION, complete=complete, simulate=simulate)

    assert completions == complete_calls
    assert simulations == simulation_calls


# -- prepareSponsoredTransaction ---------------------------------------------------------------

BASE_TRANSACTION = TempoTransaction(
    calls=(call(data=transfer(BOGUS, 100), to=BOGUS),),
    chain_id=TESTNET_CHAIN_ID,
    fee_token=BOGUS,
    sender_address=BOGUS,
    gas_limit=150_000,
    max_fee_per_gas=1_000_000_000,
    max_priority_fee_per_gas=1_000_000_000,
    nonce=1,
    nonce_key=EXPIRING_NONCE_KEY,
    sender_signature=secp256k1_signature(r=1, s=1, y_parity=0),
    valid_before=math.floor(time.time()) + 300,
)
KEY_AUTHORIZATION = SignedKeyAuthorization(
    authorization=KeyAuthorization(key_id=BOGUS, chain_id=TESTNET_CHAIN_ID),
    signature=secp256k1_signature(r=1, s=2, y_parity=0),
)


def prepare(transaction: TempoTransaction = BASE_TRANSACTION, **kwargs: Any) -> TempoTransaction:
    kwargs.setdefault("chain_id", TESTNET_CHAIN_ID)
    kwargs.setdefault("allowed_fee_tokens", [BOGUS])
    return prepare_sponsored_transaction(transaction, details=DETAILS, **kwargs)


def _at(milliseconds: int) -> datetime:
    return datetime.fromtimestamp(2_000_000_000, UTC) + timedelta(milliseconds=milliseconds)


@pytest.mark.parametrize(
    ("milliseconds", "remaining", "accepted"),
    [(0, 14, False), (0, 15, True), (1, 15, False), (1, 16, True), (999, 16, True)],
)
def test_minimum_validity_at_offset_and_remaining(
    milliseconds: int, remaining: int, accepted: bool
) -> None:
    def validate() -> None:
        assert_transaction_policy(
            attrs.evolve(BASE_TRANSACTION, valid_before=2_000_000_000 + remaining),
            chain_id=TESTNET_CHAIN_ID,
            details=DETAILS,
            now=_at(milliseconds),
        )

    if accepted:
        validate()
    else:
        with pytest.raises(FeePayerValidationError, match="at least 15 seconds"):
            validate()


@pytest.mark.parametrize("offset", [0, 1, 999])
def test_accepts_15_second_maximum_at_millisecond_offset(offset: int) -> None:
    now = _at(offset)
    assert_transaction_policy(
        attrs.evolve(BASE_TRANSACTION, valid_before=math.ceil(now.timestamp()) + 15),
        chain_id=TESTNET_CHAIN_ID,
        details=DETAILS,
        now=now,
        policy=PolicyOverrides(max_validity_window_seconds=15),
    )


@pytest.mark.parametrize("maximum", [0, 14, 14.5, math.nan, math.inf])
def test_rejects_incompatible_maximum_window(maximum: Any) -> None:
    with pytest.raises(
        FeePayerValidationError,
        match="maxValidityWindowSeconds must be an integer of at least 15 seconds",
    ):
        assert_transaction_policy(
            BASE_TRANSACTION,
            chain_id=TESTNET_CHAIN_ID,
            details=DETAILS,
            policy=PolicyOverrides(max_validity_window_seconds=maximum),
        )


def test_prepare_accepts_bounded_sponsored_transaction_fields() -> None:
    prepared = prepare()
    assert prepared.awaiting_fee_payer is True
    assert prepared.gas_limit == BASE_TRANSACTION.gas_limit
    assert prepared.max_fee_per_gas == BASE_TRANSACTION.max_fee_per_gas
    assert prepared.valid_before == BASE_TRANSACTION.valid_before
    assert fee_token(prepared) == BOGUS
    assert sender(prepared) == BOGUS
    assert prepared.sender_signature == BASE_TRANSACTION.sender_signature


# viem accepts both `'expiring'` and `maxUint256`; Python only has the integer form.
def test_prepare_accepts_serialized_expiring_nonce_key() -> None:
    prepare(attrs.evolve(BASE_TRANSACTION, nonce_key=2**256 - 1))


def test_prepare_error_rejects_non_expiring_nonce_keys() -> None:
    with pytest.raises(FeePayerValidationError, match="must use an expiring nonce"):
        prepare(attrs.evolve(BASE_TRANSACTION, nonce_key=1))


def test_prepare_accepts_higher_moderato_priority_fees_by_default() -> None:
    prepare(
        attrs.evolve(
            BASE_TRANSACTION,
            gas_limit=626_497,
            max_fee_per_gas=24_000_000_000,
            max_priority_fee_per_gas=24_000_000_000,
        )
    )


_MAINNET_HIGH_PRIORITY = attrs.evolve(
    BASE_TRANSACTION,
    chain_id=MAINNET_CHAIN_ID,
    gas_limit=626_497,
    max_fee_per_gas=24_000_000_000,
    max_priority_fee_per_gas=24_000_000_000,
)


def test_prepare_accepts_fee_payer_policy_overrides() -> None:
    prepare(
        _MAINNET_HIGH_PRIORITY,
        chain_id=MAINNET_CHAIN_ID,
        policy=PolicyOverrides(max_priority_fee_per_gas=50_000_000_000),
    )


def test_prepare_error_rejects_excessive_priority_fee_under_custom_override() -> None:
    with pytest.raises(
        FeePayerValidationError, match="maxPriorityFeePerGas exceeds sponsor policy"
    ):
        prepare(
            _MAINNET_HIGH_PRIORITY,
            chain_id=MAINNET_CHAIN_ID,
            policy=PolicyOverrides(max_priority_fee_per_gas=20_000_000_000),
        )


def test_prepare_ignores_undefined_policy_override_values() -> None:
    with pytest.raises(
        FeePayerValidationError, match="maxPriorityFeePerGas exceeds sponsor policy"
    ):
        prepare(
            _MAINNET_HIGH_PRIORITY,
            chain_id=MAINNET_CHAIN_ID,
            policy=PolicyOverrides(max_priority_fee_per_gas=None),
        )


def test_prepare_rejects_key_authorization_by_default() -> None:
    with pytest.raises(FeePayerValidationError, match="keyAuthorization is not allowed"):
        prepare(attrs.evolve(BASE_TRANSACTION, key_authorization=KEY_AUTHORIZATION))


def test_prepare_preserves_key_authorization_when_explicitly_allowed() -> None:
    sponsored = prepare(
        attrs.evolve(BASE_TRANSACTION, key_authorization=KEY_AUTHORIZATION),
        policy=PolicyOverrides(allow_key_authorization=True),
    )
    assert sponsored.key_authorization == KEY_AUTHORIZATION


# Arbitrary unknown keys cannot exist on pytempo's `TempoTransaction`; the closest Python
# equivalent of an unsupported field is a non-empty `tempo_authorization_list`.
def test_prepare_error_rejects_unsupported_fields() -> None:
    with pytest.raises(FeePayerValidationError, match="contains unsupported fields"):
        prepare(
            attrs.evolve(
                BASE_TRANSACTION,
                tempo_authorization_list=(b"\x01",),
            )
        )


def test_prepare_error_rejects_fee_payer_signature_on_client_submitted_transactions() -> None:
    with pytest.raises(FeePayerValidationError, match="contains rejected fields"):
        prepare(attrs.evolve(BASE_TRANSACTION, fee_payer_signature=_SIGNED_FEE_PAYER))


def test_prepare_error_rejects_excessive_max_fee_per_gas() -> None:
    with pytest.raises(FeePayerValidationError, match="maxFeePerGas exceeds sponsor policy"):
        prepare(attrs.evolve(BASE_TRANSACTION, max_fee_per_gas=200_000_000_000))


def test_prepare_error_rejects_combined_gas_and_fee_budget_outside_policy() -> None:
    with pytest.raises(FeePayerValidationError, match="total fee budget exceeds sponsor policy"):
        prepare(attrs.evolve(BASE_TRANSACTION, gas_limit=1_500_000, max_fee_per_gas=50_000_000_000))


def test_prepare_error_rejects_mismatched_fee_token() -> None:
    with pytest.raises(FeePayerValidationError, match="feeToken is not allowed"):
        prepare(allowed_fee_tokens=[RECIPIENT_2])


def test_prepare_error_rejects_long_lived_sponsored_transactions() -> None:
    with pytest.raises(FeePayerValidationError, match="validity window exceeds sponsor policy"):
        prepare(attrs.evolve(BASE_TRANSACTION, valid_before=math.floor(time.time()) + 3_600))


def test_prepare_error_rejects_non_empty_access_lists() -> None:
    with pytest.raises(FeePayerValidationError, match="accessList is not allowed"):
        prepare(attrs.evolve(BASE_TRANSACTION, access_list=(AccessListItem(address=BOGUS),)))


def _with_data(data: str) -> TempoTransaction:
    return attrs.evolve(
        BASE_TRANSACTION, calls=(attrs.evolve(BASE_TRANSACTION.calls[0], data=data),)
    )


@pytest.mark.parametrize("data", SESSION_CALL_DATA.values(), ids=SESSION_CALL_DATA.keys())
def test_prepare_accepts_canonical_session_calldata(data: str) -> None:
    prepare(_with_data(data))


@pytest.mark.parametrize("data", SESSION_CALL_DATA.values(), ids=SESSION_CALL_DATA.keys())
def test_prepare_error_rejects_padded_session_calldata(data: str) -> None:
    with pytest.raises(FeePayerValidationError, match="calldata is not canonical"):
        prepare(_with_data(f"{data}00"))


def test_prepare_error_rejects_unknown_call_calldata() -> None:
    with pytest.raises(FeePayerValidationError, match="call calldata is invalid"):
        prepare(_with_data("0xdeadbeef"))


def test_prepare_error_rejects_known_but_unsupported_call_calldata() -> None:
    with pytest.raises(FeePayerValidationError, match="call calldata is invalid"):
        prepare(_with_data(abi.BALANCE_OF.encode(BOGUS)))


def test_prepare_error_rejects_padded_calldata() -> None:
    with pytest.raises(FeePayerValidationError, match="calldata is not canonical"):
        prepare(_with_data(f"{to_hex(BASE_TRANSACTION.calls[0].data)}01"))


def test_prepare_error_rejects_missing_calls() -> None:
    with pytest.raises(FeePayerValidationError, match="must declare calls"):
        prepare(attrs.evolve(BASE_TRANSACTION, calls=()))


def test_prepare_error_rejects_nonzero_call_value() -> None:
    with pytest.raises(FeePayerValidationError, match="call value is not allowed"):
        prepare(
            attrs.evolve(
                BASE_TRANSACTION, calls=(attrs.evolve(BASE_TRANSACTION.calls[0], value=1),)
            )
        )


def test_error_rejects_dirty_address_padding_as_non_canonical() -> None:
    # viem decodes the low 20 bytes of the address word, so the re-encoding differs.
    dirty = abi.TRANSFER.selector + "ff" * 12 + BOGUS[2:] + (100).to_bytes(32, "big").hex()
    with pytest.raises(FeePayerValidationError, match="calldata is not canonical"):
        prepare(attrs.evolve(BASE_TRANSACTION, calls=(call(data=dirty, to=BOGUS),)))
