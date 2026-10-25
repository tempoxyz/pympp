"""Charge verification helpers (transfer calls, transfer logs, challenge-bound memos)."""

from __future__ import annotations

import pytest
from pytempo import Call

from mpp.errors import CredentialReplayedError
from mpp.tempo import attribution
from mpp.tempo._internal import abi
from mpp.tempo._internal.charge import (
    ExpectedTransfer,
    MismatchError,
    Split,
    TransactionRevertedError,
    assert_challenge_bound_call_memo,
    assert_challenge_bound_memo,
    assert_transfer_calls,
    assert_transfer_logs,
    get_expected_transfers,
    get_transfer_log_effects,
    is_challenge_bound,
    verify_hash_receipt,
)
from mpp.tempo._internal.proof import PkhSource
from mpp.tempo._internal.rpc import Log, TransactionReceipt

CURRENCY = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x2222222222222222222222222222222222222222"
SPLIT_RECIPIENT = "0x3333333333333333333333333333333333333333"
PAYER = "0x1111111111111111111111111111111111111111"
SETTLER = "0x4444444444444444444444444444444444444444"
REALM = "api.example.com"
CHALLENGE = "challenge-123"
MEMO = attribution.encode(challenge_id=CHALLENGE, server_id=REALM)
OTHER_MEMO = "0x" + "ab" * 32


def transfer_call(to: str, amount: int, memo: str | None = None, token: str = CURRENCY) -> Call:
    if memo is None:
        return Call(to=token, data=abi.TRANSFER.encode(to, amount))
    return Call(to=token, data=abi.TRANSFER_WITH_MEMO.encode(to, amount, bytes.fromhex(memo[2:])))


def topic(address: str) -> str:
    return "0x" + "00" * 12 + address[2:].lower()


def transfer_log(
    to: str, amount: int, *, sender: str = PAYER, memo: str | None = None, index: int | None = None
) -> Log:
    if memo is None:
        topics = (abi.TRANSFER_EVENT_TOPIC, topic(sender), topic(to))
    else:
        topics = (abi.TRANSFER_WITH_MEMO_EVENT_TOPIC, topic(sender), topic(to), memo)
    return Log(
        address=CURRENCY,
        topics=topics,
        data="0x" + amount.to_bytes(32, "big").hex(),
        log_index=index,
    )


def receipt(*logs: Log, status: str = "success", sender: str = PAYER) -> TransactionReceipt:
    return TransactionReceipt(
        transaction_hash="0x" + "11" * 32,
        status=status,  # type: ignore[arg-type]
        sender=sender,
        logs=logs,
    )


SPLIT_TRANSFERS = get_expected_transfers(
    amount="100",
    recipient=RECIPIENT,
    splits=[Split(amount="30", recipient=SPLIT_RECIPIENT, memo=OTHER_MEMO)],
)


def test_expected_transfers_allow_any_memo_only_without_memo() -> None:
    assert [
        ExpectedTransfer(amount="70", recipient=RECIPIENT, allow_any_memo=True),
        ExpectedTransfer(amount="30", recipient=SPLIT_RECIPIENT, memo=OTHER_MEMO),
    ] == SPLIT_TRANSFERS


def test_transfer_calls_match_memo_specific_transfers_first() -> None:
    calls = [transfer_call(SPLIT_RECIPIENT, 30, OTHER_MEMO), transfer_call(RECIPIENT, 70, MEMO)]
    matched = assert_transfer_calls(calls, currency=CURRENCY, transfers=SPLIT_TRANSFERS)
    assert [m.recipient.lower() for m in matched] == [SPLIT_RECIPIENT, RECIPIENT]
    assert matched[1].memo == MEMO


def test_transfer_calls_skip_swap_prefix() -> None:
    calls = [
        Call(to=CURRENCY, data=abi.APPROVE.encode(SETTLER, 1)),
        Call(to=SETTLER, data=abi.SWAP_EXACT_AMOUNT_OUT.encode(CURRENCY, CURRENCY, 1, 1)),
        transfer_call(RECIPIENT, 100, MEMO),
    ]
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    assert len(assert_transfer_calls(calls, currency=CURRENCY, transfers=transfers)) == 1


@pytest.mark.parametrize(
    "calls",
    [
        [transfer_call(RECIPIENT, 99, MEMO)],
        [transfer_call(PAYER, 100, MEMO)],
        [transfer_call(RECIPIENT, 100, MEMO, token=SETTLER)],
        [Call(to=CURRENCY, data=abi.APPROVE.encode(RECIPIENT, 100))],
        [],
    ],
)
def test_transfer_calls_reject_mismatches(calls: list[Call]) -> None:
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    with pytest.raises(MismatchError, match="no matching payment call found"):
        assert_transfer_calls(calls, currency=CURRENCY, transfers=transfers)


def test_transfer_calls_exact_count() -> None:
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    calls = [transfer_call(RECIPIENT, 100, MEMO), transfer_call(RECIPIENT, 100)]
    assert_transfer_calls(calls, currency=CURRENCY, transfers=transfers)
    with pytest.raises(MismatchError) as info:
        assert_transfer_calls(calls, currency=CURRENCY, transfers=transfers, exact_count=True)
    assert info.value.details == {"expectedCalls": "1", "actualCalls": "2"}
    assert info.value.to_problem_details()["type"].endswith("/verification-failed")


def test_challenge_binding_rules() -> None:
    other_challenge = attribution.encode(challenge_id="other", server_id=REALM)
    other_realm = attribution.encode(challenge_id=CHALLENGE, server_id="other.example.com")
    bound = {"challenge_id": CHALLENGE, "realm": REALM}
    assert is_challenge_bound([MEMO], **bound)
    assert is_challenge_bound([MEMO, None, OTHER_MEMO], **bound)
    assert not is_challenge_bound([None, OTHER_MEMO], **bound)
    assert not is_challenge_bound([MEMO, other_challenge], **bound)
    assert not is_challenge_bound([other_realm], **bound)


def test_log_effects_collapse_transfer_and_memo_pairs() -> None:
    effects = get_transfer_log_effects(
        receipt(
            transfer_log(RECIPIENT, 100, index=0),
            transfer_log(RECIPIENT, 100, memo=MEMO, index=1),
            transfer_log(SPLIT_RECIPIENT, 5, index=3),
        )
    )
    assert [(e.kind, e.amount) for e in effects] == [("memo", 100), ("transfer", 5)]


async def test_transfer_logs_match_and_bind() -> None:
    matched = await assert_transfer_logs(
        receipt(transfer_log(RECIPIENT, 100, memo=MEMO, index=0)),
        currency=CURRENCY,
        sender=PAYER,
        transfers=get_expected_transfers(amount="100", recipient=RECIPIENT),
    )
    assert_challenge_bound_memo(matched, challenge_id=CHALLENGE, realm=REALM)
    with pytest.raises(
        CredentialReplayedError, match="memo is not bound to this challenge"
    ) as info:
        assert_challenge_bound_memo(matched, challenge_id="other", realm=REALM)
    assert info.value.status == 403


async def test_transfer_logs_reject_reverted_and_unmatched() -> None:
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    with pytest.raises(TransactionRevertedError):
        await assert_transfer_logs(
            receipt(status="reverted"), currency=CURRENCY, sender=PAYER, transfers=transfers
        )
    with pytest.raises(MismatchError, match="no matching transfer found"):
        await assert_transfer_logs(
            receipt(transfer_log(RECIPIENT, 100, sender=SETTLER, memo=MEMO)),
            currency=CURRENCY,
            sender=PAYER,
            transfers=transfers,
        )


async def test_transfer_logs_accept_validated_sender() -> None:
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    settled = receipt(transfer_log(RECIPIENT, 100, sender=SETTLER, memo=MEMO))
    seen: list[tuple[str, str, PkhSource | None]] = []

    async def validate_sender(expected: str, sender: str, source: PkhSource | None) -> bool:
        seen.append((expected, sender, source))
        return True

    source = PkhSource(address=PAYER, chain_id=4217)
    await assert_transfer_logs(
        settled,
        currency=CURRENCY,
        sender=PAYER,
        transfers=transfers,
        source=source,
        validate_sender=validate_sender,
    )
    assert seen == [(PAYER, SETTLER, source)]


async def test_verify_hash_receipt() -> None:
    verified = await verify_hash_receipt(
        receipt(transfer_log(RECIPIENT, 100, memo=MEMO)),
        challenge_id=CHALLENGE,
        realm=REALM,
        amount="100",
        currency=CURRENCY,
        recipient=RECIPIENT,
    )
    assert verified.payer == PAYER
    assert verified.sender == PAYER


def test_call_memo_binding() -> None:
    transfers = get_expected_transfers(amount="100", recipient=RECIPIENT)
    matched = assert_transfer_calls(
        [transfer_call(RECIPIENT, 100)], currency=CURRENCY, transfers=transfers
    )
    with pytest.raises(MismatchError, match="memo is not bound to this challenge"):
        assert_challenge_bound_call_memo(matched, challenge_id=CHALLENGE, realm=REALM)


# -- pympp#313: split attribution memos ------------------------------------------------------

MEMO_A = attribution.encode(challenge_id="challenge-a", server_id=REALM)
MEMO_B = attribution.encode(challenge_id="challenge-b", server_id=REALM)


async def test_single_transfer_prefers_leg_bound_to_this_challenge() -> None:
    # An equal transfer for another challenge in the same receipt is not this payment.
    for logs in (
        [
            transfer_log(RECIPIENT, 100, memo=MEMO_A, index=0),
            transfer_log(RECIPIENT, 100, memo=MEMO_B, index=1),
        ],
        [
            transfer_log(RECIPIENT, 100, memo=MEMO_B, index=0),
            transfer_log(RECIPIENT, 100, memo=MEMO_A, index=1),
        ],
    ):
        verified = await verify_hash_receipt(
            receipt(*logs),
            challenge_id="challenge-b",
            realm=REALM,
            amount="100",
            currency=CURRENCY,
            recipient=RECIPIENT,
        )
        assert [log.memo for log in verified.matched_logs] == [MEMO_B]


async def test_split_prefers_legs_bound_to_this_challenge() -> None:
    logs = [
        transfer_log(SPLIT_RECIPIENT, 30, memo=MEMO_A, index=0),
        transfer_log(RECIPIENT, 70, memo=MEMO_A, index=1),
        transfer_log(RECIPIENT, 70, memo=MEMO_B, index=2),
        transfer_log(SPLIT_RECIPIENT, 30, memo=MEMO_B, index=3),
    ]
    verified = await verify_hash_receipt(
        receipt(*logs),
        challenge_id="challenge-b",
        realm=REALM,
        amount="100",
        currency=CURRENCY,
        recipient=RECIPIENT,
        splits=[Split(amount="30", recipient=SPLIT_RECIPIENT)],
    )
    assert [log.memo for log in verified.matched_logs] == [MEMO_B, MEMO_B]


@pytest.mark.parametrize("kind", ["plain", "fixed"])
@pytest.mark.parametrize("challenge_id", ["challenge-a", "challenge-b"])
async def test_split_cannot_share_neutral_leg_between_challenges(
    kind: str, challenge_id: str
) -> None:
    shared = transfer_log(
        SPLIT_RECIPIENT, 30, memo=None if kind == "plain" else OTHER_MEMO, index=0
    )
    logs = [
        shared,
        transfer_log(RECIPIENT, 70, memo=MEMO_A, index=1),
        transfer_log(RECIPIENT, 70, memo=MEMO_B, index=2),
    ]
    with pytest.raises(CredentialReplayedError, match="Unbound split leg"):
        await verify_hash_receipt(
            receipt(*logs),
            challenge_id=challenge_id,
            realm=REALM,
            amount="100",
            currency=CURRENCY,
            recipient=RECIPIENT,
            splits=[
                Split(
                    amount="30",
                    recipient=SPLIT_RECIPIENT,
                    memo=None if kind == "plain" else OTHER_MEMO,
                )
            ],
        )


async def test_split_allows_plain_and_non_mpp_memo_legs_alone() -> None:
    for split_memo in (None, OTHER_MEMO):
        verified = await verify_hash_receipt(
            receipt(
                transfer_log(RECIPIENT, 70, memo=MEMO, index=0),
                transfer_log(SPLIT_RECIPIENT, 30, memo=split_memo, index=1),
            ),
            challenge_id=CHALLENGE,
            realm=REALM,
            amount="100",
            currency=CURRENCY,
            recipient=RECIPIENT,
            splits=[Split(amount="30", recipient=SPLIT_RECIPIENT, memo=split_memo)],
        )
        assert len(verified.matched_logs) == 2


def test_calls_prefer_bound_legs_and_reject_shared_neutral_leg() -> None:
    transfers = get_expected_transfers(
        amount="100", recipient=RECIPIENT, splits=[Split(amount="30", recipient=SPLIT_RECIPIENT)]
    )
    calls = [
        transfer_call(SPLIT_RECIPIENT, 30, MEMO_A),
        transfer_call(RECIPIENT, 70, MEMO_A),
        transfer_call(RECIPIENT, 70, MEMO_B),
        transfer_call(SPLIT_RECIPIENT, 30, MEMO_B),
    ]
    bound = {"challenge_id": "challenge-b", "realm": REALM}
    matched = assert_transfer_calls(calls, currency=CURRENCY, transfers=transfers, **bound)
    assert [call.memo for call in matched] == [MEMO_B, MEMO_B]
    assert_challenge_bound_call_memo(matched, calls=calls, currency=CURRENCY, **bound)

    shared = [transfer_call(SPLIT_RECIPIENT, 30), *calls[1:3]]
    matched = assert_transfer_calls(shared, currency=CURRENCY, transfers=transfers, **bound)
    with pytest.raises(MismatchError, match="unbound split leg"):
        assert_challenge_bound_call_memo(matched, calls=shared, currency=CURRENCY, **bound)
