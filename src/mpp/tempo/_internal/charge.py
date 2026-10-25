"""Charge transfer expansion and on-chain payment verification helpers.

``get_transfers`` mirrors mppx ``internal/charge.ts``. The verification
helpers mirror the transfer/memo checks of mppx's Tempo charge server so the
charge server (and conformance harness) can verify hash credentials and
signed transactions against a challenge.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from pytempo import Call

from mpp.errors import CredentialReplayedError, PaymentError
from mpp.tempo import attribution
from mpp.tempo._internal import abi
from mpp.tempo._internal.address import is_equal
from mpp.tempo._internal.envelope import call_target
from mpp.tempo._internal.hexutil import to_hex
from mpp.tempo._internal.proof import PkhSource
from mpp.tempo._internal.rpc import Log, RpcClient, TransactionReceipt
from mpp.tempo._internal.selectors import (
    APPROVE_SELECTOR,
    SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    TRANSFER_SELECTOR,
    TRANSFER_WITH_MEMO_SELECTOR,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class Split:
    amount: str
    recipient: str
    memo: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Transfer:
    amount: str
    recipient: str
    memo: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectedTransfer:
    amount: str
    recipient: str
    memo: str | None = None
    allow_any_memo: bool = False


def get_transfers(
    *, amount: str, recipient: str, memo: str | None = None, splits: Sequence[Split] = ()
) -> list[Transfer]:
    """Expands a charge into the primary transfer followed by its splits."""
    total = int(amount)
    split_total = sum(int(split.amount) for split in splits)
    if split_total >= total:
        raise ValueError("Invalid charge request: split total must be less than total amount.")
    primary = total - split_total
    if primary <= 0:
        raise ValueError("Invalid charge request: primary transfer amount must be positive.")
    return [
        Transfer(amount=str(primary), memo=memo, recipient=recipient),
        *(Transfer(amount=s.amount, memo=s.memo, recipient=s.recipient) for s in splits),
    ]


def splits_from_method_details(method_details: dict[str, object] | None) -> list[Split]:
    """Reads wire ``methodDetails.splits`` into :class:`Split` values."""
    raw = (method_details or {}).get("splits") or []
    if not isinstance(raw, list):
        return []
    return [
        Split(amount=str(s["amount"]), recipient=str(s["recipient"]), memo=s.get("memo"))
        for s in raw
        if isinstance(s, dict)
    ]


def get_expected_transfers(
    *, amount: str, recipient: str, splits: Sequence[Split] = ()
) -> list[ExpectedTransfer]:
    """Expected transfers for verification; memo-less entries accept any memo."""
    return [
        ExpectedTransfer(
            amount=t.amount, recipient=t.recipient, memo=t.memo, allow_any_memo=not t.memo
        )
        for t in get_transfers(amount=amount, recipient=recipient, splits=splits)
    ]


class MismatchError(PaymentError):
    """A credential does not match the challenge (``verification-failed``, 402)."""

    type = "https://paymentauth.org/problems/verification-failed"
    title = "Verification Failed"

    def __init__(self, reason: str, details: dict[str, str] | None = None) -> None:
        details = details or {}
        message = (
            reason
            if reason.startswith("Payment verification failed")
            else f"Payment verification failed: {reason}"
        )
        super().__init__(
            "\n".join([message, *(f"  - {k}: {v}" for k, v in details.items())]),
            details=details,
        )


class TransactionRevertedError(Exception):
    def __init__(self, transaction_hash: str) -> None:
        super().__init__(f"Transaction reverted: {transaction_hash}")
        self.transaction_hash = transaction_hash


# -- calls -------------------------------------------------------------------------------------


def _selector(call: Call) -> str | None:
    return to_hex(call.data[:4]) if call.data else None


def get_transfer_calls(calls: Sequence[Call]) -> list[Call]:
    """Returns the transfer calls, skipping an ``approve`` + ``swapExactAmountOut`` prefix."""
    selectors = [_selector(call) for call in calls]
    offset = 2 if selectors[:2] == [APPROVE_SELECTOR, SWAP_EXACT_AMOUNT_OUT_SELECTOR] else 0
    transfer_calls = list(calls[offset:])
    if not transfer_calls or any(
        s not in (TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR) for s in selectors[offset:]
    ):
        raise MismatchError("Invalid transaction: no matching payment call found")
    return transfer_calls


def decode_transfer_call(call: Call, currency: str) -> Transfer | None:
    """Decodes a ``transfer``/``transferWithMemo`` call to ``currency``."""
    target = call_target(call)
    if not target or not is_equal(target, currency) or not _selector(call):
        return None
    try:
        match _selector(call):
            case s if s == TRANSFER_SELECTOR:
                recipient, amount = abi.TRANSFER.decode_input(call.data)
                return Transfer(amount=str(amount), recipient=recipient)
            case s if s == TRANSFER_WITH_MEMO_SELECTOR:
                recipient, amount, memo = abi.TRANSFER_WITH_MEMO.decode_input(call.data)
                return Transfer(amount=str(amount), recipient=recipient, memo=to_hex(memo))
    except abi.AbiDecodingError:
        return None
    return None


def _memo_first(transfers: Sequence[ExpectedTransfer]) -> list[ExpectedTransfer]:
    # Match memo-specific transfers before wildcards so `allow_any_memo` entries
    # do not greedily consume memo-bearing calls/logs.
    return sorted(transfers, key=lambda t: 0 if t.memo else 1)


def assert_transfer_calls(
    calls: Sequence[Call],
    *,
    currency: str,
    transfers: Sequence[ExpectedTransfer],
    exact_count: bool = False,
    challenge_id: str | None = None,
    realm: str | None = None,
) -> list[Transfer]:
    """Matches each expected transfer to a distinct transfer call.

    With ``challenge_id`` and ``realm``, calls bound to this challenge are matched before
    interchangeable ones, and calls attributed to another challenge last.
    """
    transfer_calls = get_transfer_calls(calls)
    if exact_count and len(transfer_calls) != len(transfers):
        raise MismatchError(
            "Invalid transaction: no matching payment call found",
            {"expectedCalls": str(len(transfers)), "actualCalls": str(len(transfer_calls))},
        )
    order = _binding_order(
        [_call_memo(call, currency) for call in transfer_calls],
        challenge_id=challenge_id,
        realm=realm,
    )
    used: set[int] = set()
    matched: list[Transfer] = []
    for expected in _memo_first(transfers):
        index = next(
            (
                i
                for i in order
                if i not in used and _call_matches(transfer_calls[i], currency, expected)
            ),
            None,
        )
        if index is None:
            raise MismatchError(
                "Invalid transaction: no matching payment call found",
                {"amount": expected.amount, "currency": currency, "recipient": expected.recipient},
            )
        used.add(index)
        decoded = decode_transfer_call(transfer_calls[index], currency)
        assert decoded is not None
        matched.append(decoded)
    return matched


def _call_memo(call: Call, currency: str) -> str | None:
    decoded = decode_transfer_call(call, currency)
    return decoded.memo if decoded is not None else None


def _call_matches(call: Call, currency: str, expected: ExpectedTransfer) -> bool:
    decoded = decode_transfer_call(call, currency)
    if decoded is None:
        return False
    if not is_equal(decoded.recipient, expected.recipient) or decoded.amount != expected.amount:
        return False
    if expected.memo:
        return decoded.memo is not None and decoded.memo.lower() == expected.memo.lower()
    if expected.allow_any_memo:
        return True
    return decoded.memo is None


# -- logs --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class TransferLog:
    kind: Literal["transfer", "memo"]
    address: str
    sender: str
    recipient: str
    amount: int
    memo: str | None = None
    log_index: int | None = None


def _topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


def _parse_transfer_log(log: Log) -> TransferLog | None:
    if not log.topics:
        return None
    topic0 = log.topics[0].lower()
    try:
        amount = int(log.data, 16)
    except ValueError:
        return None
    log_index = log.log_index
    if topic0 == abi.TRANSFER_EVENT_TOPIC and len(log.topics) == 3:
        return TransferLog(
            kind="transfer",
            address=log.address,
            sender=_topic_address(log.topics[1]),
            recipient=_topic_address(log.topics[2]),
            amount=amount,
            log_index=log_index,
        )
    if topic0 == abi.TRANSFER_WITH_MEMO_EVENT_TOPIC and len(log.topics) == 4:
        return TransferLog(
            kind="memo",
            address=log.address,
            sender=_topic_address(log.topics[1]),
            recipient=_topic_address(log.topics[2]),
            amount=amount,
            memo=log.topics[3].lower(),
            log_index=log_index,
        )
    return None


def get_transfer_log_effects(receipt: TransactionReceipt) -> list[TransferLog]:
    """Parses TIP-20 transfer logs, collapsing a ``Transfer`` + ``TransferWithMemo`` pair."""
    parsed = [log for raw in receipt.logs if (log := _parse_transfer_log(raw)) is not None]
    # Like viem: all Transfer logs, then all TransferWithMemo logs, stably sorted by log index.
    logs = sorted(
        [log for log in parsed if log.kind == "transfer"]
        + [log for log in parsed if log.kind == "memo"],
        key=lambda log: float("inf") if log.log_index is None else log.log_index,
    )
    effects: list[TransferLog] = []
    index = 0
    while index < len(logs):
        log = logs[index]
        following = logs[index + 1] if index + 1 < len(logs) else None
        if following and log.kind != following.kind and _is_same_transfer(log, following):
            effects.append(log if log.kind == "memo" else following)
            index += 2
            continue
        effects.append(log)
        index += 1
    return effects


def _is_same_transfer(a: TransferLog, b: TransferLog) -> bool:
    return (
        is_equal(a.address, b.address)
        and is_equal(a.sender, b.sender)
        and is_equal(a.recipient, b.recipient)
        and a.amount == b.amount
        and a.log_index is not None
        and b.log_index is not None
        and abs(a.log_index - b.log_index) == 1
    )


type ValidateSender = Callable[[str, str, PkhSource | None], Awaitable[bool]]
"""``(expected_sender, sender, source) -> allowed``: authorizes third-party transfer senders."""


async def is_valid_transfer_sender(
    *,
    expected_sender: str,
    sender: str,
    source: PkhSource | None = None,
    validate_sender: ValidateSender | None = None,
) -> bool:
    if is_equal(sender, expected_sender):
        return True
    if validate_sender is None:
        return False
    return await validate_sender(expected_sender, sender, source)


async def assert_transfer_logs(
    receipt: TransactionReceipt,
    *,
    currency: str,
    sender: str,
    transfers: Sequence[ExpectedTransfer],
    source: PkhSource | None = None,
    validate_sender: ValidateSender | None = None,
    challenge_id: str | None = None,
    realm: str | None = None,
) -> list[TransferLog]:
    """Matches each expected transfer to a distinct transfer log in a successful receipt.

    With ``challenge_id`` and ``realm``, logs bound to this challenge are matched before
    interchangeable ones (e.g. an equal transfer for another challenge in a batched
    transaction), and logs attributed to another challenge last.
    """
    if receipt.status != "success":
        raise TransactionRevertedError(receipt.transaction_hash)
    logs = get_transfer_log_effects(receipt)
    order = _binding_order([log.memo for log in logs], challenge_id=challenge_id, realm=realm)
    used: set[int] = set()
    matched: list[TransferLog] = []
    for transfer in _memo_first(transfers):
        match_index: int | None = None
        for index in order:
            log = logs[index]
            if index in used or not _log_matches(log, currency, transfer):
                continue
            if not await is_valid_transfer_sender(
                expected_sender=sender,
                sender=log.sender,
                source=source,
                validate_sender=validate_sender,
            ):
                continue
            match_index = index
            break
        if match_index is None:
            raise MismatchError(
                "Payment verification failed: no matching transfer found.",
                {"amount": transfer.amount, "currency": currency, "recipient": transfer.recipient},
            )
        used.add(match_index)
        matched.append(logs[match_index])
    return matched


def _log_matches(log: TransferLog, currency: str, transfer: ExpectedTransfer) -> bool:
    if not is_equal(log.address, currency) or not is_equal(log.recipient, transfer.recipient):
        return False
    if str(log.amount) != transfer.amount:
        return False
    if transfer.memo:
        return log.kind == "memo" and log.memo is not None and log.memo == transfer.memo.lower()
    if transfer.allow_any_memo:
        return True
    return log.kind == "transfer"


# -- challenge binding ---------------------------------------------------------------------------


def _is_bound(memo: str | None, *, challenge_id: str, realm: str) -> bool:
    return (
        memo is not None
        and attribution.is_mpp_memo(memo)
        and attribution.verify_server(memo, realm)
        and attribution.verify_challenge_binding(memo, challenge_id)
    )


def _is_foreign(memo: str | None, *, challenge_id: str, realm: str) -> bool:
    """Whether ``memo`` attributes a transfer to another challenge or server."""
    return (
        memo is not None
        and attribution.is_mpp_memo(memo)
        and not _is_bound(memo, challenge_id=challenge_id, realm=realm)
    )


def _binding_order(
    memos: Sequence[str | None], *, challenge_id: str | None, realm: str | None
) -> list[int]:
    """Indices ordered bound-to-this-challenge first, then neutral, then foreign."""
    if challenge_id is None or realm is None:
        return list(range(len(memos)))

    def rank(index: int) -> int:
        memo = memos[index]
        if _is_bound(memo, challenge_id=challenge_id, realm=realm):
            return 0
        return 2 if _is_foreign(memo, challenge_id=challenge_id, realm=realm) else 1

    return sorted(range(len(memos)), key=rank)


def _shares_neutral_leg(
    matched: Sequence[str | None], others: Sequence[str | None], *, challenge_id: str, realm: str
) -> bool:
    """Whether a neutral (plain or fixed-memo) leg may belong to another challenge.

    In a batch that also pays another challenge, a leg not bound to this challenge cannot be
    assigned to it, so two charges could share one plain or fixed-memo transfer.
    """
    return not all(
        _is_bound(memo, challenge_id=challenge_id, realm=realm) for memo in matched
    ) and any(_is_foreign(memo, challenge_id=challenge_id, realm=realm) for memo in others)


def is_challenge_bound(memos: Sequence[str | None], *, challenge_id: str, realm: str) -> bool:
    """Whether matched transfers carry a challenge-bound attribution memo and no conflicting one.

    Plain transfers and non-MPP memos are allowed but cannot establish the
    binding; any MPP memo for another server or challenge fails it.
    """
    bound = False
    for memo in memos:
        if not memo or not attribution.is_mpp_memo(memo):
            continue
        if not attribution.verify_server(memo, realm) or not attribution.verify_challenge_binding(
            memo, challenge_id
        ):
            return False
        bound = True
    return bound


def assert_challenge_bound_memo(
    matched_logs: Sequence[TransferLog],
    *,
    challenge_id: str,
    realm: str,
    receipt: TransactionReceipt | None = None,
    currency: str | None = None,
) -> None:
    """Settled transfers must be bound to the challenge (a replayed payment is a 403).

    With ``receipt`` and ``currency``, a neutral leg in a receipt that also pays another
    challenge is rejected too.
    """
    memos = [log.memo for log in matched_logs]
    if not is_challenge_bound(memos, challenge_id=challenge_id, realm=realm):
        raise CredentialReplayedError(reason="memo is not bound to this challenge")
    if receipt is not None and currency is not None:
        others = [
            log.memo for log in get_transfer_log_effects(receipt) if is_equal(log.address, currency)
        ]
        if _shares_neutral_leg(memos, others, challenge_id=challenge_id, realm=realm):
            raise CredentialReplayedError(reason="Unbound split leg in a multi-challenge receipt")


def assert_challenge_bound_call_memo(
    matched_calls: Sequence[Transfer],
    *,
    challenge_id: str,
    realm: str,
    calls: Sequence[Call] = (),
    currency: str | None = None,
) -> None:
    """Matched calls must be bound to the challenge; with ``calls`` and ``currency``, a
    neutral leg in a transaction that also pays another challenge is rejected too."""
    memos = [call.memo for call in matched_calls]
    if not is_challenge_bound(memos, challenge_id=challenge_id, realm=realm):
        raise MismatchError("Payment verification failed: memo is not bound to this challenge.")
    if currency is not None:
        others = [_call_memo(call, currency) for call in calls]
        if _shares_neutral_leg(memos, others, challenge_id=challenge_id, realm=realm):
            raise MismatchError(
                "Payment verification failed: unbound split leg in a multi-challenge transaction."
            )


# -- hash credentials --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class HashVerification:
    receipt: TransactionReceipt
    sender: str
    """The expected payer (``source`` address or the receipt sender)."""
    payer: str | None
    """The single account the matched transfers debited, if unambiguous."""
    transfers: list[ExpectedTransfer]
    matched_logs: list[TransferLog]


async def verify_hash_receipt(
    receipt: TransactionReceipt,
    *,
    challenge_id: str,
    realm: str,
    amount: str,
    currency: str,
    recipient: str,
    splits: Sequence[Split] = (),
    source: PkhSource | None = None,
    validate_sender: ValidateSender | None = None,
) -> HashVerification:
    """Verifies a pushed payment's receipt against a challenge (mppx hash credential checks)."""
    transfers = get_expected_transfers(amount=amount, recipient=recipient, splits=splits)
    sender = source.address if source else receipt.sender
    if sender is None:
        raise MismatchError("Payment verification failed: receipt has no sender.")
    matched = await assert_transfer_logs(
        receipt,
        currency=currency,
        sender=sender,
        transfers=transfers,
        source=source,
        validate_sender=validate_sender,
        challenge_id=challenge_id,
        realm=realm,
    )
    assert_challenge_bound_memo(
        matched, challenge_id=challenge_id, realm=realm, receipt=receipt, currency=currency
    )
    # The payer is the debited account.
    payers = {log.sender.lower() for log in matched}
    return HashVerification(
        receipt=receipt,
        sender=sender,
        payer=next(iter(payers)) if len(payers) == 1 else None,
        transfers=transfers,
        matched_logs=matched,
    )


async def verify_hash_credential(
    client: RpcClient,
    *,
    transaction_hash: str,
    challenge_id: str,
    realm: str,
    amount: str,
    currency: str,
    recipient: str,
    splits: Sequence[Split] = (),
    source: PkhSource | None = None,
    validate_sender: ValidateSender | None = None,
) -> HashVerification:
    """Fetches the receipt for ``transaction_hash`` and runs :func:`verify_hash_receipt`."""
    receipt = await client.get_transaction_receipt(transaction_hash)
    return await verify_hash_receipt(
        receipt,
        challenge_id=challenge_id,
        realm=realm,
        amount=amount,
        currency=currency,
        recipient=recipient,
        splits=splits,
        source=source,
        validate_sender=validate_sender,
    )
