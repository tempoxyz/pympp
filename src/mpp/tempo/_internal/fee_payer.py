"""Fee sponsorship: sponsor policy, call-pattern validation, and co-signing.

A sponsor co-signs a sender-signed Tempo transaction only when it pays for
an allowed payment pattern within its fee policy.
"""

from __future__ import annotations

import math
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Final

import attrs
from eth_abi.exceptions import NonEmptyPaddingBytes
from pytempo import Call, Signature, TempoTransaction

from mpp.tempo._internal import abi
from mpp.tempo._internal.abi import AbiDecodingError, Function
from mpp.tempo._internal.account import TempoAccount
from mpp.tempo._internal.address import is_address, is_equal, is_tempo_address
from mpp.tempo._internal.charge import ExpectedTransfer
from mpp.tempo._internal.envelope import (
    EXPIRING_NONCE_KEY,
    call_target,
    fee_payer_sign_payload,
    key_authorization_to_rpc,
    serialize,
)
from mpp.tempo._internal.envelope import fee_token as transaction_fee_token
from mpp.tempo._internal.envelope import sender as transaction_sender
from mpp.tempo._internal.fee_token import default_fee_tokens
from mpp.tempo._internal.hexutil import int_to_hex, to_hex
from mpp.tempo._internal.rpc import RpcClient, access_list_to_rpc, call_request
from mpp.tempo._internal.selectors import (
    APPROVE_SELECTOR,
    SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    TRANSFER_SELECTOR,
    TRANSFER_WITH_MEMO_SELECTOR,
)
from mpp.tempo._internal.signature import recover_address, secp256k1_signature
from mpp.tempo.chains import MAINNET_CHAIN_ID, STABLECOIN_DEX, TESTNET_CHAIN_ID

CALL_SCOPES: Final = (
    (TRANSFER_SELECTOR,),
    (TRANSFER_WITH_MEMO_SELECTOR,),
    (APPROVE_SELECTOR, SWAP_EXACT_AMOUNT_OUT_SELECTOR, TRANSFER_SELECTOR),
    (APPROVE_SELECTOR, SWAP_EXACT_AMOUNT_OUT_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR),
)
"""Allowed call patterns (ordered selectors) for sponsored transactions."""


class FeePayerValidationError(Exception):
    """A transaction violates the sponsor's call or fee policy."""

    def __init__(self, reason: str, details: Mapping[str, str] | None = None) -> None:
        details = dict(details or {})
        super().__init__(
            "\n".join(
                [f"Invalid transaction: {reason}", *(f"  - {k}: {v}" for k, v in details.items())]
            )
        )
        self.reason = reason
        self.details = details


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """Sponsor fee policy."""

    allow_key_authorization: bool = False
    """Allows a sponsored transaction to install a new access key."""
    max_gas: int = 2_000_000
    max_fee_per_gas: int = 100_000_000_000
    max_priority_fee_per_gas: int = 10_000_000_000
    max_total_fee: int = 50_000_000_000_000_000
    """Covers ``transferWithMemo`` and swap transactions at peak gas prices."""
    max_validity_window_seconds: int = 15 * 60


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyOverrides:
    """Partial :class:`Policy`; unset fields use the chain's default policy."""

    allow_key_authorization: bool | None = None
    max_gas: int | None = None
    max_fee_per_gas: int | None = None
    max_priority_fee_per_gas: int | None = None
    max_total_fee: int | None = None
    max_validity_window_seconds: int | None = None


DEFAULT_POLICY: Final = Policy()

POLICY_BY_CHAIN_ID: Final[Mapping[int, Policy]] = {
    MAINNET_CHAIN_ID: DEFAULT_POLICY,
    # Moderato regularly needs a higher priority fee than mainnet.
    TESTNET_CHAIN_ID: replace(DEFAULT_POLICY, max_priority_fee_per_gas=50_000_000_000),
}


def get_policy(chain_id: int, overrides: PolicyOverrides | None = None) -> Policy:
    base = POLICY_BY_CHAIN_ID.get(chain_id, DEFAULT_POLICY)
    if overrides is None:
        return base
    changes = {
        name: value
        for name in Policy.__dataclass_fields__
        if (value := getattr(overrides, name)) is not None
    }
    return replace(base, **changes)


def default_allowed_fee_tokens(chain_id: int | None) -> list[str]:
    """Fee tokens mpp lets sponsored transactions charge by default."""
    return default_fee_tokens(chain_id)


def assert_allowed_fee_token(
    fee_token: object, allowed_fee_tokens: Sequence[str] | None = None
) -> None:
    """Validates a fee-token address and, when given, the server's allowlist."""
    if fee_token is None:
        return
    if not isinstance(fee_token, str) or not (
        is_address(fee_token, strict=False) or is_tempo_address(fee_token)
    ):
        raise FeePayerValidationError("fee-sponsored transaction feeToken is invalid")
    if allowed_fee_tokens is not None and not any(
        is_equal(a, fee_token) for a in allowed_fee_tokens
    ):
        raise FeePayerValidationError(
            "fee-sponsored transaction feeToken is not allowed", {"feeToken": fee_token}
        )


# -- canonical calldata ------------------------------------------------------------------------

_DESCRIPTOR: Final = "(address,address,address,address,bytes32,address,bytes32)"

_SPONSORED_FUNCTIONS: Final[Mapping[str, Function]] = {
    function.selector: function
    for function in (
        abi.APPROVE,
        abi.TRANSFER,
        abi.TRANSFER_WITH_MEMO,
        abi.SWAP_EXACT_AMOUNT_OUT,
        # Legacy (contract) session escrow, nonpayable functions.
        Function("close", ("bytes32", "uint128", "bytes")),
        Function("open", ("address", "address", "uint128", "bytes32", "address")),
        Function("requestClose", ("bytes32",)),
        Function("settle", ("bytes32", "uint128", "bytes")),
        Function("topUp", ("bytes32", "uint256")),
        Function("withdraw", ("bytes32",)),
        # TIP-1034 precompile session escrow, nonpayable functions.
        Function("open", ("address", "address", "address", "uint96", "bytes32", "address")),
        Function("settle", (_DESCRIPTOR, "uint96", "bytes")),
        Function("topUp", (_DESCRIPTOR, "uint96")),
        Function("close", (_DESCRIPTOR, "uint96", "uint96", "bytes")),
        Function("requestClose", (_DESCRIPTOR,)),
        Function("withdraw", (_DESCRIPTOR,)),
    )
}


def _canonical_call_data(data: str) -> str | None:
    """Re-encodes decoded calldata; ``None`` when it is not a sponsored call.

    Words with dirty padding are reported as non-canonical (viem decodes such an
    address word and its re-encoding differs).
    """
    function = _SPONSORED_FUNCTIONS.get(data[:10].lower())
    if function is None:
        return None
    try:
        return function.encode(*function.decode_input(data))
    except AbiDecodingError as error:
        return "0x" if isinstance(error.__cause__, NonEmptyPaddingBytes) else None
    except (ValueError, TypeError, OverflowError):
        return None


def _assert_canonical(transaction: TempoTransaction, details: Mapping[str, str]) -> None:
    """Rejects fields that add intrinsic gas without changing the decoded payment intent."""
    if transaction.access_list:
        raise FeePayerValidationError(
            "fee-sponsored transaction accessList is not allowed",
            {**details, "accessListEntries": str(len(transaction.access_list))},
        )
    if not transaction.calls:
        raise FeePayerValidationError("fee-sponsored transaction must declare calls", details)
    for index, call in enumerate(transaction.calls):
        if call.value:
            raise FeePayerValidationError(
                "fee-sponsored transaction call value is not allowed",
                {**details, "call": str(index), "value": str(call.value)},
            )
        if not call.data:
            raise FeePayerValidationError(
                "fee-sponsored transaction call is missing calldata",
                {**details, "call": str(index)},
            )
        data = to_hex(call.data)
        canonical = _canonical_call_data(data)
        if canonical is None:
            raise FeePayerValidationError(
                "fee-sponsored transaction call calldata is invalid",
                {**details, "call": str(index)},
            )
        if data != canonical.lower():
            raise FeePayerValidationError(
                "fee-sponsored transaction call calldata is not canonical",
                {**details, "call": str(index)},
            )


# -- call patterns -----------------------------------------------------------------------------


def validate_calls(
    calls: Sequence[Call],
    details: Mapping[str, str],
    *,
    currency: str | None = None,
    expected_transfers: Sequence[ExpectedTransfer] | None = None,
) -> str | None:
    """Validates an allowed sponsored call pattern.

    Returns the funding currency (the swap input token, or the payment currency)
    when the calls are bound to ``expected_transfers``.
    """
    details = dict(details)

    def disallowed() -> FeePayerValidationError:
        return FeePayerValidationError("disallowed call pattern in fee-payer transaction", details)

    if not calls:
        raise disallowed()
    selectors = [to_hex(call.data[:4]) if call.data else None for call in calls]
    has_swap_prefix = selectors[0] == APPROVE_SELECTOR
    if has_swap_prefix:
        if len(selectors) < 2 or selectors[1] != SWAP_EXACT_AMOUNT_OUT_SELECTOR:
            raise disallowed()
    elif selectors[0] == SWAP_EXACT_AMOUNT_OUT_SELECTOR:
        raise disallowed()

    transfer_selectors = selectors[2 if has_swap_prefix else 0 :]
    if not transfer_selectors:
        raise disallowed()
    limit = len(expected_transfers) if expected_transfers is not None else 11
    if (
        len(transfer_selectors) > limit
        or any(
            s not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR) for s in transfer_selectors
        )
        or (expected_transfers is not None and len(transfer_selectors) != len(expected_transfers))
    ):
        raise disallowed()

    # Bind the swap approval to the token the DEX call will actually spend.
    buy_call = next(
        (c for c, s in zip(calls, selectors, strict=True) if s == SWAP_EXACT_AMOUNT_OUT_SELECTOR),
        None,
    )
    buy_args = abi.SWAP_EXACT_AMOUNT_OUT.decode_input(buy_call.data) if buy_call else None
    approve_call = next(
        (c for c, s in zip(calls, selectors, strict=True) if s == APPROVE_SELECTOR), None
    )
    if approve_call is not None:
        spender, amount = abi.APPROVE.decode_input(approve_call.data)
        approve_target = call_target(approve_call)
        if not approve_target or (buy_args and not is_equal(approve_target, buy_args[0])):
            raise FeePayerValidationError("approve target does not match swap tokenIn", details)
        if not is_equal(spender, STABLECOIN_DEX):
            raise FeePayerValidationError("approve spender is not the DEX", details)
        if buy_args and amount != buy_args[3]:
            raise FeePayerValidationError("approve amount does not match swap max input", details)
    buy_target = call_target(buy_call) if buy_call is not None else None
    if buy_call is not None and (not buy_target or not is_equal(buy_target, STABLECOIN_DEX)):
        raise FeePayerValidationError("buy target is not the DEX", details)

    if expected_transfers is None:
        return None

    currency = currency or details.get("currency")
    if not currency:
        raise FeePayerValidationError("missing payment currency", details)

    if buy_args:
        _, token_out, amount_out, _ = buy_args
        expected_amount_out = sum(int(t.amount) for t in expected_transfers)
        if not is_equal(token_out, currency):
            raise FeePayerValidationError("swap tokenOut does not match payment currency", details)
        if amount_out <= 0 or amount_out > expected_amount_out:
            raise FeePayerValidationError(
                "swap output must be positive and no greater than payment amount", details
            )

    transfer_calls = list(calls[2 if has_swap_prefix else 0 :])
    used: set[int] = set()
    for expected in sorted(expected_transfers, key=lambda t: 0 if t.memo else 1):
        index = next(
            (
                i
                for i, call in enumerate(transfer_calls)
                if i not in used and _transfer_matches(call, currency, expected)
            ),
            None,
        )
        if index is None:
            raise FeePayerValidationError("payment transfer does not match challenge", details)
        used.add(index)
    return call_target(approve_call) if approve_call is not None else currency


def _transfer_matches(call: Call, currency: str, expected: ExpectedTransfer) -> bool:
    target = call_target(call)
    if not target or not is_equal(target, currency) or not call.data:
        return False
    selector = to_hex(call.data[:4])
    try:
        if selector == TRANSFER_SELECTOR:
            recipient, amount = abi.TRANSFER.decode_input(call.data)
            return (
                is_equal(recipient, expected.recipient)
                and str(amount) == expected.amount
                and expected.memo is None
            )
        if selector == TRANSFER_WITH_MEMO_SELECTOR:
            recipient, amount, memo = abi.TRANSFER_WITH_MEMO.decode_input(call.data)
            if not is_equal(recipient, expected.recipient) or str(amount) != expected.amount:
                return False
            if expected.memo:
                return to_hex(memo) == expected.memo.lower()
            return expected.allow_any_memo
    except AbiDecodingError:
        return False
    return False


# -- fee policy --------------------------------------------------------------------------------


def _now_seconds(now: datetime | None) -> float:
    return now.timestamp() if now is not None else time.time()


def assert_remaining_validity(
    transaction: TempoTransaction,
    *,
    details: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> None:
    """Rejects transactions that can expire before sponsorship and submission finish."""
    valid_before = transaction.valid_before
    failure_details = {**(details or {}), "validBefore": str(valid_before)}
    if valid_before is None:
        raise FeePayerValidationError(
            "fee-sponsored transaction must declare validBefore for the expiring nonce",
            {**(details or {}), "validBefore": "undefined"},
        )
    current = _now_seconds(now)
    if valid_before <= math.floor(current):
        raise FeePayerValidationError(
            "fee-sponsored transaction has already expired", failure_details
        )
    if valid_before < math.ceil(current) + 15:
        raise FeePayerValidationError(
            "fee-sponsored transaction needs at least 15 seconds of remaining validity",
            failure_details,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyCheck:
    gas_limit: int
    max_fee_per_gas: int
    total_fee: int
    valid_before: int


def assert_transaction_policy(
    transaction: TempoTransaction,
    *,
    chain_id: int,
    details: Mapping[str, str],
    challenge_expires: str | None = None,
    now: datetime | None = None,
    policy: PolicyOverrides | None = None,
) -> PolicyCheck:
    """Validates sponsor fee policy limits for a fee-payer transaction."""
    resolved = get_policy(chain_id, policy)

    def fail(reason: str, extra: Mapping[str, str] | None = None) -> FeePayerValidationError:
        return FeePayerValidationError(reason, {**details, **(extra or {})})

    if transaction.chain_id != chain_id:
        raise fail(
            "fee-sponsored transaction chainId does not match challenge",
            {"chainId": str(transaction.chain_id)},
        )
    _assert_canonical(transaction, details)

    if transaction.key_authorization is not None and not resolved.allow_key_authorization:
        raise fail("fee-sponsored transaction keyAuthorization is not allowed")

    gas = transaction.gas_limit
    if gas <= 0:
        raise fail("fee-sponsored transaction must declare gas")
    if gas > resolved.max_gas:
        raise fail("fee-sponsored transaction gas exceeds sponsor policy", {"gas": str(gas)})

    max_fee = transaction.max_fee_per_gas
    if max_fee <= 0:
        raise fail("fee-sponsored transaction must declare maxFeePerGas")
    if max_fee > resolved.max_fee_per_gas:
        raise fail(
            "fee-sponsored transaction maxFeePerGas exceeds sponsor policy",
            {"maxFeePerGas": str(max_fee)},
        )

    total_fee = gas * max_fee
    if total_fee > resolved.max_total_fee:
        raise fail(
            "fee-sponsored transaction total fee budget exceeds sponsor policy",
            {"gas": str(gas), "maxFeePerGas": str(max_fee), "totalFee": str(total_fee)},
        )
    max_priority = transaction.max_priority_fee_per_gas
    if max_priority > max_fee:
        raise fail(
            "fee-sponsored transaction maxPriorityFeePerGas exceeds maxFeePerGas",
            {"maxFeePerGas": str(max_fee), "maxPriorityFeePerGas": str(max_priority)},
        )
    if max_priority > resolved.max_priority_fee_per_gas:
        raise fail(
            "fee-sponsored transaction maxPriorityFeePerGas exceeds sponsor policy",
            {"maxPriorityFeePerGas": str(max_priority)},
        )

    if transaction.nonce_key != EXPIRING_NONCE_KEY:
        raise fail("fee-sponsored transaction must use an expiring nonce")
    valid_before = transaction.valid_before
    if valid_before is None:
        raise fail("fee-sponsored transaction must declare validBefore for the expiring nonce")

    window = resolved.max_validity_window_seconds
    if isinstance(window, bool) or not isinstance(window, int) or window < 15:
        raise fail("sponsor maxValidityWindowSeconds must be an integer of at least 15 seconds")
    assert_remaining_validity(transaction, details=details, now=now)

    max_valid_before = math.ceil(_now_seconds(now)) + window
    if challenge_expires:
        expires_at = datetime.fromisoformat(challenge_expires.replace("Z", "+00:00"))
        max_valid_before = min(max_valid_before, math.floor(expires_at.timestamp()) + 60)
    if valid_before > max_valid_before:
        raise fail(
            "fee-sponsored transaction validity window exceeds sponsor policy",
            {"validBefore": str(valid_before)},
        )
    return PolicyCheck(
        gas_limit=gas, max_fee_per_gas=max_fee, total_fee=total_fee, valid_before=valid_before
    )


def prepare_sponsored_transaction(
    transaction: TempoTransaction,
    *,
    chain_id: int,
    details: Mapping[str, str],
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
    now: datetime | None = None,
    policy: PolicyOverrides | None = None,
) -> TempoTransaction:
    """Validates a sender-signed transaction and returns it ready for the sponsor to sign.

    The returned transaction keeps every sender-committed field; only the
    (sponsor-selected) ``fee_token`` may differ from what the sender signed.
    """
    if transaction.tempo_authorization_list:
        raise FeePayerValidationError(
            "fee-sponsored transaction contains unsupported fields",
            {**details, "unsupportedFields": "authorizationList"},
        )
    if transaction.fee_payer_signature is not None:
        raise FeePayerValidationError(
            "fee-sponsored transaction contains rejected fields",
            {**details, "rejectedFields": "feePayerSignature"},
        )
    check = assert_transaction_policy(
        transaction,
        chain_id=chain_id,
        details=details,
        challenge_expires=challenge_expires,
        now=now,
        policy=policy,
    )
    fee_token = transaction_fee_token(transaction)
    if (
        fee_token is not None
        and allowed_fee_tokens is not None
        and not any(is_equal(fee_token, allowed) for allowed in allowed_fee_tokens)
    ):
        raise FeePayerValidationError(
            "fee-sponsored transaction feeToken is not allowed", {**details, "feeToken": fee_token}
        )
    return attrs.evolve(
        transaction,
        awaiting_fee_payer=True,
        gas_limit=check.gas_limit,
        max_fee_per_gas=check.max_fee_per_gas,
        valid_before=check.valid_before,
    )


def sign_as_fee_payer(transaction: TempoTransaction, fee_payer: TempoAccount) -> str:
    """Co-signs a sender-signed sponsored transaction and serializes it as ``0x76``."""
    sender = transaction_sender(transaction)
    if sender is None:
        raise FeePayerValidationError("fee-sponsored transaction has no sender")
    signature = fee_payer.sign(fee_payer_sign_payload(transaction, sender=sender), raw=True)
    if not isinstance(signature, Signature):
        raise TypeError("Fee payers must sign with a secp256k1 root key.")
    return serialize(attrs.evolve(transaction, fee_payer_signature=signature))


# -- hosted fee payers -------------------------------------------------------------------------


def hosted_fee_payer_request(transaction: TempoTransaction) -> dict[str, Any]:
    """The ``eth_fillTransaction`` request asking a hosted sponsor to co-sign."""
    request: dict[str, Any] = {}
    if transaction.access_list:
        request["accessList"] = access_list_to_rpc(transaction)
    request["calls"] = [
        {
            **({"to": target} if (target := call_target(call)) else {}),
            **({"data": to_hex(call.data)} if call.data else {}),
            "value": int_to_hex(call.value) if call.value else "0x",
        }
        for call in transaction.calls
    ]
    request["feePayer"] = True
    request["from"] = transaction_sender(transaction)
    if transaction.gas_limit:
        request["gas"] = int_to_hex(transaction.gas_limit)
    if transaction.key_authorization is not None:
        request["keyAuthorization"] = key_authorization_to_rpc(transaction.key_authorization)
    if transaction.max_fee_per_gas:
        request["maxFeePerGas"] = int_to_hex(transaction.max_fee_per_gas)
    if transaction.max_priority_fee_per_gas:
        request["maxPriorityFeePerGas"] = int_to_hex(transaction.max_priority_fee_per_gas)
    request["nonce"] = int_to_hex(transaction.nonce)
    request["nonceKey"] = int_to_hex(transaction.nonce_key)
    request["type"] = "0x76"
    if transaction.valid_after is not None:
        request["validAfter"] = int_to_hex(transaction.valid_after)
    if transaction.valid_before is not None:
        request["validBefore"] = int_to_hex(transaction.valid_before)
    return request


@dataclass(frozen=True, slots=True, kw_only=True)
class HostedSponsorship:
    fee_payer: str
    """The sponsor address recovered from its signature."""
    fee_token: str
    serialized_transaction: str


def _parse_quantity(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return int(value)


async def fill_hosted_fee_payer_transaction(
    transaction: TempoTransaction,
    *,
    client: RpcClient,
    chain_id: int,
    details: Mapping[str, str],
    allowed_fee_tokens: Sequence[str] | None = None,
    challenge_expires: str | None = None,
    policy: PolicyOverrides | None = None,
) -> HostedSponsorship:
    """Co-signs through a hosted fee payer without letting it mutate sender-committed fields."""
    assert_transaction_policy(
        transaction,
        chain_id=chain_id,
        details=details,
        challenge_expires=challenge_expires,
        policy=policy,
    )
    result = await client.fill_transaction(hosted_fee_payer_request(transaction))
    filled = result.get("tx") if isinstance(result, dict) else None
    if not isinstance(filled, dict) or not filled.get("feePayerSignature"):
        raise FeePayerValidationError("hosted fee payer failed to sponsor transaction")
    fee_token = filled.get("feeToken")
    if not isinstance(fee_token, str):
        raise FeePayerValidationError("hosted fee payer did not return a feeToken")
    assert_allowed_fee_token(fee_token, allowed_fee_tokens)

    raw_signature = filled["feePayerSignature"]
    try:
        signature = secp256k1_signature(
            r=_parse_quantity(raw_signature["r"]),
            s=_parse_quantity(raw_signature["s"]),
            y_parity=_parse_quantity(raw_signature.get("yParity")),
        )
        # Recover the concrete sponsor so callers can simulate with a concrete
        # `feePayer` (nodes reject `eth_call` with `feePayer: true`).
        sender = transaction_sender(transaction)
        assert sender is not None
        fee_payer = recover_address(
            fee_payer_sign_payload(attrs.evolve(transaction, fee_token=fee_token), sender=sender),
            signature,
        )
    except Exception as error:
        raise FeePayerValidationError(
            "hosted fee payer returned an invalid feePayerSignature"
        ) from error
    return HostedSponsorship(
        fee_payer=fee_payer,
        fee_token=fee_token,
        serialized_transaction=serialize(
            attrs.evolve(transaction, fee_payer_signature=signature, fee_token=fee_token)
        ),
    )


# -- simulation --------------------------------------------------------------------------------


def simulation_request(transaction: TempoTransaction, *, fee_payer: bool) -> dict[str, Any]:
    """Pre-broadcast simulation request.

    Sponsored transactions are simulated as plain calls from the sender (fee
    fields omitted), so the sender's fee-token balance is irrelevant.
    """
    if fee_payer:
        return call_request(sender=transaction_sender(transaction), calls=transaction.calls)
    return call_request(transaction=transaction)


def sponsored_simulation_request(
    transaction: TempoTransaction, *, fee_payer: str, fee_token: str | None = None
) -> dict[str, Any]:
    """Simulation request for the final co-signed transaction (signatures are never sent)."""
    return call_request(transaction=transaction, fee_payer=fee_payer, fee_token=fee_token)


@dataclass(frozen=True, slots=True, kw_only=True)
class Sponsorship:
    fee_payer: str
    transaction: TempoTransaction
    fee_token: str | None = None
    serialized_transaction: str | None = None


async def preflight_sponsorship[S: Sponsorship](
    transaction: TempoTransaction,
    *,
    complete: Callable[[], Awaitable[S]],
    simulate: Callable[[dict[str, Any]], Awaitable[object]],
) -> S:
    """Simulates the sender's calls, completes sponsorship, then simulates the final envelope.

    ``complete`` runs only after sender-context execution succeeds, so a
    reverting transaction never reaches a signer or hosted fee payer.
    """
    await simulate(simulation_request(transaction, fee_payer=True))
    completed = await complete()
    await simulate(
        sponsored_simulation_request(
            completed.transaction, fee_payer=completed.fee_payer, fee_token=completed.fee_token
        )
    )
    return completed
