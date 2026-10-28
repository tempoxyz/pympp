"""Adversarial tests for Tempo charge verification.

Modelled on mppx's `src/tempo/server/Charge.test.ts` and
`src/tempo/internal/fee-payer.test.ts`: receipts that pay the wrong party,
replays (concurrent, case-variant, cross-mode and re-encoded), the sponsored
call-pattern policy, and fail-closed arms for malformed transactions, receipts
and broadcast-marker stores. The Tempo RPC is an in-process fake.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import rlp
from pytempo import Call, TempoTransaction

from mpp import Credential, Receipt
from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationError
from mpp.methods.tempo import PATH_USD, TESTNET_CHAIN_ID, TempoAccount
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope
from mpp.methods.tempo.intents import (
    APPROVE_SELECTOR,
    STABLECOIN_DEX,
    SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    TRANSFER_SELECTOR,
    TRANSFER_TOPIC,
    TRANSFER_WITH_MEMO_SELECTOR,
    TRANSFER_WITH_MEMO_TOPIC,
    ChargeIntent,
    _canonical_raw_transaction,
    _raw_transaction_hash,
)
from mpp.store import MemoryStore
from tests import TEST_REALM, internal_cause, make_credential

CHAIN_ID = TESTNET_CHAIN_ID
CURRENCY = PATH_USD
OTHER_TOKEN = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x742d35cc6634c0532925a3b844bc9e7595f8fe00"
OTHER_RECIPIENT = "0x9999999999999999999999999999999999999999"
PAYER = "0x1234567890123456789012345678901234567890"
NOT_DEX = "0x00000000000000000000000000000000000000de"
AMOUNT = 1_000_000
PAYER_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
FEE_PAYER_KEY = "0x" + "ab" * 32
CHALLENGE_ID = "adversarial-challenge"
TX_HASH = "0x" + "ab" * 32


def _word(value: int | str) -> str:
    if isinstance(value, str):
        return value.removeprefix("0x").lower().zfill(64)
    return hex(value)[2:].zfill(64)


def _topic(address: str) -> str:
    return "0x" + _word(address)


def _memo(challenge_id: str = CHALLENGE_ID) -> str:
    return encode_attribution(challenge_id=challenge_id, server_id=TEST_REALM)


def _expires(seconds: float = 3600) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _request(*, fee_payer: bool = False, splits: list[dict] | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {"chainId": CHAIN_ID}
    if fee_payer:
        details["feePayer"] = True
    if splits:
        details["splits"] = splits
    return {
        "amount": str(AMOUNT),
        "currency": CURRENCY,
        "recipient": RECIPIENT,
        "methodDetails": details,
    }


def _credential(payload: dict[str, Any], challenge_id: str = CHALLENGE_ID) -> Credential:
    return make_credential(payload=payload, challenge_id=challenge_id, expires=_expires())


def _hash_credential(tx_hash: str = TX_HASH, challenge_id: str = CHALLENGE_ID) -> Credential:
    return _credential({"type": "hash", "hash": tx_hash}, challenge_id)


def _tx_credential(raw_tx: str, challenge_id: str = CHALLENGE_ID) -> Credential:
    return _credential({"type": "transaction", "signature": raw_tx}, challenge_id)


# ── calldata ─────────────────────────────────────────────────────────


def transfer_data(recipient: str = RECIPIENT, amount: int = AMOUNT, memo: str | None = None) -> str:
    if memo is None:
        return f"0x{TRANSFER_SELECTOR}{_word(recipient)}{_word(amount)}"
    return f"0x{TRANSFER_WITH_MEMO_SELECTOR}{_word(recipient)}{_word(amount)}{_word(memo)}"


def approve_data(spender: str = STABLECOIN_DEX, amount: int = 2 * AMOUNT) -> str:
    return f"0x{APPROVE_SELECTOR}{_word(spender)}{_word(amount)}"


def swap_data(
    token_in: str = OTHER_TOKEN,
    token_out: str = CURRENCY,
    amount_out: int = AMOUNT,
    max_in: int = 2 * AMOUNT,
) -> str:
    return (
        f"0x{SWAP_EXACT_AMOUNT_OUT_SELECTOR}"
        f"{_word(token_in)}{_word(token_out)}{_word(amount_out)}{_word(max_in)}"
    )


def pay_call(recipient: str = RECIPIENT, amount: int = AMOUNT, value: int = 0) -> Call:
    """The bound payment leg: a transferWithMemo attributed to this challenge."""
    return Call.create(to=CURRENCY, value=value, data=transfer_data(recipient, amount, _memo()))


def approve_call(to: str = OTHER_TOKEN, spender: str = STABLECOIN_DEX, value: int = 0) -> Call:
    return Call.create(to=to, value=value, data=approve_data(spender))


def swap_call(to: str = STABLECOIN_DEX, value: int = 0, **kwargs: Any) -> Call:
    return Call.create(to=to, value=value, data=swap_data(**kwargs))


# ── transactions ─────────────────────────────────────────────────────


def signed_tx(calls: tuple[Call, ...], *, fee_payer: bool = False, nonce: int = 0) -> str:
    """A client-signed Tempo transaction: 0x76, or a 0x78 envelope awaiting a sponsor."""
    tx = TempoTransaction.create(
        chain_id=CHAIN_ID,
        gas_limit=100_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        nonce=nonce,
        nonce_key=(1 << 256) - 1,
        fee_token=None,
        awaiting_fee_payer=fee_payer,
        valid_before=int(time.time()) + 300,
        calls=calls,
    )
    signed = tx.sign(PAYER_KEY)
    if fee_payer:
        return "0x" + encode_fee_payer_envelope(signed).hex()
    return "0x" + signed.encode().hex()


def raw_rlp_tx(fields: Any, type_byte: bytes = b"\x76") -> str:
    return "0x" + (type_byte + rlp.encode(fields)).hex()


def tx_hash_of(raw_tx: str) -> str:
    """The hash a node reports for a submitted 0x76 transaction."""
    return _raw_transaction_hash(_canonical_raw_transaction(raw_tx))


# ── receipts ─────────────────────────────────────────────────────────


def memo_log(
    *,
    currency: str = CURRENCY,
    recipient: str = RECIPIENT,
    amount: int = AMOUNT,
    memo: str | None = None,
) -> dict[str, Any]:
    return {
        "address": currency,
        "topics": [
            TRANSFER_WITH_MEMO_TOPIC,
            _topic(PAYER),
            _topic(recipient),
            memo or _memo(),
        ],
        "data": "0x" + _word(amount),
    }


def plain_log(*, recipient: str = RECIPIENT, amount: int = AMOUNT) -> dict[str, Any]:
    return {
        "address": CURRENCY,
        "topics": [TRANSFER_TOPIC, _topic(PAYER), _topic(recipient)],
        "data": "0x" + _word(amount),
    }


def receipt(tx_hash: str, logs: list[dict[str, Any]] | None = None, **extra: Any) -> dict:
    return {"status": "0x1", "transactionHash": tx_hash, "logs": logs or [memo_log()], **extra}


class FakeRpc:
    """An in-process Tempo JSON-RPC node.

    Receipts are looked up by lowercase hash. ``send`` decides the
    ``eth_sendRawTransactionSync`` answer; by default it mines the canonical
    transaction with a log paying this challenge.
    """

    def __init__(self) -> None:
        self.receipts: dict[str, dict[str, Any]] = {}
        self.methods: list[str] = []
        self.sent: list[str] = []
        self.send = lambda raw_tx: {"result": receipt(tx_hash_of(raw_tx))}
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def count(self, method: str) -> int:
        return self.methods.count(method)

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body["params"]
        self.methods.append(method)
        # Yield so concurrent verifications interleave at every RPC.
        await asyncio.sleep(0)
        answer: dict[str, Any]
        if method == "eth_chainId":
            answer = {"result": hex(CHAIN_ID)}
        elif method == "eth_getTransactionReceipt":
            answer = {"result": self.receipts.get(params[0].lower())}
        elif method == "eth_getTransactionByHash":
            answer = {"result": None}
        elif method == "tempo_simulateV1":
            answer = {"result": {"blocks": [{"calls": [{"status": "0x1"}]}]}}
        elif method == "eth_sendRawTransactionSync":
            self.sent.append(params[0])
            answer = self.send(params[0])
        else:
            answer = {"error": {"code": -32601, "message": f"unexpected {method}"}}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **answer})


def make_intent(
    rpc: FakeRpc, *, fee_payer: bool = False, store: MemoryStore | None = None
) -> ChargeIntent:
    return ChargeIntent(
        rpc_url="https://rpc.test",
        http_client=rpc.client,
        store=store if store is not None else MemoryStore(),
        fee_payer=TempoAccount.from_key(FEE_PAYER_KEY) if fee_payer else None,
        fee_token=PATH_USD if fee_payer else None,
    )


def stored_keys(intent: ChargeIntent) -> list[str]:
    store = intent._store
    assert isinstance(store, MemoryStore)
    return list(store._data)


# ──────────────────────────────────────────────────────────────────────
# 1. Push-mode receipts must pay the requested recipient, token and amount
# ──────────────────────────────────────────────────────────────────────


async def test_push_receipt_paying_request_settles() -> None:
    rpc = FakeRpc()
    rpc.receipts[TX_HASH] = receipt(TX_HASH)
    intent = make_intent(rpc)

    result = await intent.verify(_hash_credential(), _request())

    assert result.reference == TX_HASH


@pytest.mark.parametrize(
    "logs",
    [
        # A challenge-bound memo cannot redirect the payment elsewhere.
        [memo_log(recipient=OTHER_RECIPIENT)],
        [memo_log(recipient=OTHER_RECIPIENT), plain_log(recipient=OTHER_RECIPIENT)],
        [memo_log(currency=OTHER_TOKEN)],
        [memo_log(amount=AMOUNT - 1)],
        [memo_log(amount=AMOUNT + 1)],
        [{**memo_log(), "data": "0x" + _word(AMOUNT)[:-2]}],
        [{**memo_log(), "topics": memo_log()["topics"][:3]}],
    ],
    ids=[
        "memo-log-other-recipient",
        "memo-and-plain-log-other-recipient",
        "memo-log-other-token",
        "memo-log-underpays",
        "memo-log-overpays",
        "memo-log-truncated-amount",
        "memo-log-without-memo-topic",
    ],
)
async def test_push_receipt_not_paying_request_is_rejected(logs: list[dict]) -> None:
    rpc = FakeRpc()
    rpc.receipts[TX_HASH] = receipt(TX_HASH, logs)
    intent = make_intent(rpc)

    with pytest.raises(VerificationError, match="Transfer log matching request"):
        await intent.verify(_hash_credential(), _request())

    # A rejected hash stays usable for a payment that does match.
    assert stored_keys(intent) == []


def test_single_transfer_log_memo_must_equal_expected_memo() -> None:
    """The single-transfer log matcher binds an expected memo exactly.

    Charge requests carry no primary memo (see
    ``test_primary_memo_is_not_a_method_detail``), so this arm is only
    reachable through the matcher itself.
    """
    intent = ChargeIntent(rpc_url="https://rpc.test")
    expected = bytes.fromhex(_word(0xABC))
    tx_receipt = receipt(TX_HASH, [memo_log(memo="0x" + _word(0xABD)), plain_log()])

    def matches(logs: list[dict], memo: bytes | None) -> list:
        return intent._verify_single_transfer_log({"logs": logs}, CURRENCY, RECIPIENT, AMOUNT, memo)

    assert matches(tx_receipt["logs"], expected) == []
    upper = memo_log(memo="0x" + _word(0xABC).upper())
    assert [m.kind for m in matches([upper], expected)] == ["memo"]
    assert len(matches(tx_receipt["logs"], None)) == 2


# ──────────────────────────────────────────────────────────────────────
# 2. Replays
# ──────────────────────────────────────────────────────────────────────


async def test_concurrent_hash_replay_settles_once() -> None:
    rpc = FakeRpc()
    rpc.receipts[TX_HASH] = receipt(TX_HASH)
    intent = make_intent(rpc)
    credential = _hash_credential()

    results = await asyncio.gather(
        *(intent.verify(credential, _request()) for _ in range(5)), return_exceptions=True
    )

    assert sum(isinstance(r, Receipt) for r in results) == 1
    assert sum(isinstance(r, CredentialReplayedError) for r in results) == 4
    assert rpc.count("eth_getTransactionReceipt") == 1


async def test_concurrent_transaction_replay_broadcasts_once() -> None:
    rpc = FakeRpc()
    intent = make_intent(rpc)
    credential = _tx_credential(signed_tx((pay_call(),)))

    results = await asyncio.gather(
        *(intent.verify(credential, _request()) for _ in range(5)), return_exceptions=True
    )

    assert sum(isinstance(r, Receipt) for r in results) == 1
    assert sum(isinstance(r, CredentialReplayedError) for r in results) == 4
    assert len(rpc.sent) == 1


@pytest.mark.parametrize(
    ("first", "replay"),
    [
        ("0x" + "AB" * 32, "0x" + "ab" * 32),
        ("0x" + "ab" * 32, "0x" + "AB" * 32),
        ("0x" + "AB" * 32, "0x" + "aB" * 32),
    ],
    ids=["upper-then-lower", "lower-then-upper", "upper-then-mixed"],
)
async def test_hash_replay_with_case_variant_is_rejected(first: str, replay: str) -> None:
    rpc = FakeRpc()
    rpc.receipts[TX_HASH.lower()] = receipt(TX_HASH)
    intent = make_intent(rpc)

    accepted = await intent.verify(_hash_credential(first), _request())
    assert accepted.reference == first

    with pytest.raises(CredentialReplayedError):
        await intent.verify(_hash_credential(replay), _request())
    assert rpc.count("eth_getTransactionReceipt") == 1


@pytest.mark.parametrize("order", ["pull-then-push", "push-then-pull"])
async def test_hash_replay_across_modes_is_rejected(order: str) -> None:
    rpc = FakeRpc()
    intent = make_intent(rpc)
    raw_tx = signed_tx((pay_call(),))
    tx_hash = tx_hash_of(raw_tx)
    rpc.receipts[tx_hash] = receipt(tx_hash)
    pull, push = _tx_credential(raw_tx), _hash_credential(tx_hash)
    first, second = (pull, push) if order == "pull-then-push" else (push, pull)

    assert (await intent.verify(first, _request())).reference == tx_hash
    with pytest.raises(CredentialReplayedError):
        await intent.verify(second, _request())

    assert len(rpc.sent) == (1 if order == "pull-then-push" else 0)
    assert rpc.count("eth_getTransactionReceipt") == (0 if order == "pull-then-push" else 1)


def _reencode_sender_signature(envelope: str) -> str:
    """Flip the envelope's sender recovery ID between 0/1 and 27/28 encodings."""
    fields = rlp.decode(bytes.fromhex(envelope[4:]))
    signature = fields[-1]
    v = signature[64]
    flipped = signature[:64] + bytes([v - 27 if v >= 27 else v + 27])
    return raw_rlp_tx([*fields[:-1], flipped], b"\x78")


async def test_sponsored_envelope_variants_are_replays() -> None:
    """A re-encoded envelope co-signs to the same transaction, so it is a replay."""
    rpc = FakeRpc()
    intent = make_intent(rpc, fee_payer=True)
    envelope = signed_tx((pay_call(),), fee_payer=True)
    variant = _reencode_sender_signature(envelope)
    assert variant != envelope

    await intent.verify(_tx_credential(envelope), _request(fee_payer=True))
    for replay in (envelope, variant):
        with pytest.raises(CredentialReplayedError):
            await intent.verify(_tx_credential(replay), _request(fee_payer=True))

    assert len(rpc.sent) == 1
    assert rpc.count("tempo_simulateV1") == 1


# ──────────────────────────────────────────────────────────────────────
# 3. Sponsored call-pattern policy
# ──────────────────────────────────────────────────────────────────────

TEN_SPLITS = [{"amount": "1", "recipient": "0x" + f"{i + 1:040x}"} for i in range(10)]
SPLIT_CALLS = tuple(
    Call.create(to=CURRENCY, value=0, data=transfer_data(split["recipient"], 1))
    for split in TEN_SPLITS
)


async def _validate(calls: tuple[Call, ...], splits: list[dict] | None = None) -> None:
    intent = ChargeIntent(rpc_url="https://rpc.test")
    raw_tx = signed_tx(calls, fee_payer=True)
    await intent.validate(_tx_credential(raw_tx), _request(fee_payer=True, splits=splits))


@pytest.mark.parametrize(
    ("calls", "splits"),
    [
        ((pay_call(),), None),
        ((approve_call(), swap_call(), pay_call()), None),
        ((approve_call(), swap_call(amount_out=AMOUNT), pay_call()), None),
        ((pay_call(amount=AMOUNT - 10), *SPLIT_CALLS), TEN_SPLITS),
        ((approve_call(), swap_call(), pay_call(amount=AMOUNT - 10), *SPLIT_CALLS), TEN_SPLITS),
    ],
    ids=[
        "transfer",
        "approve-swap-transfer",
        "swap-output-equals-payment",
        "11-transfers",
        "approve-swap-11-transfers",
    ],
)
async def test_sponsored_call_pattern_accepted(
    calls: tuple[Call, ...], splits: list[dict] | None
) -> None:
    await _validate(calls, splits)


@pytest.mark.parametrize(
    ("calls", "splits", "error"),
    [
        (
            (
                pay_call(amount=AMOUNT - 10),
                *SPLIT_CALLS,
                Call.create(to=CURRENCY, value=0, data=transfer_data(RECIPIENT, 1)),
            ),
            TEN_SPLITS,
            "disallowed call pattern",
        ),
        ((pay_call(), approve_call(), swap_call()), None, "disallowed call pattern"),
        ((approve_call(), swap_call()), None, "disallowed call pattern"),
        ((approve_call(), pay_call()), None, "disallowed call pattern"),
        ((swap_call(), pay_call()), None, "disallowed call pattern"),
        ((approve_call(), approve_call(), pay_call()), None, "disallowed call pattern"),
        (
            (approve_call(spender=NOT_DEX), swap_call(), pay_call()),
            None,
            "approve spender is not the stablecoin DEX",
        ),
        (
            (approve_call(to=NOT_DEX), swap_call(), pay_call()),
            None,
            "approve target does not match swap token",
        ),
        (
            (approve_call(), swap_call(to=NOT_DEX), pay_call()),
            None,
            "swap target is not the stablecoin DEX",
        ),
        (
            (approve_call(to=CURRENCY), swap_call(token_in=CURRENCY), pay_call()),
            None,
            "swap input and output tokens must differ",
        ),
        (
            (
                Call.create(to=OTHER_TOKEN, value=0, data=approve_data()[:-2]),
                swap_call(),
                pay_call(),
            ),
            None,
            "malformed approve call data",
        ),
        (
            (
                approve_call(),
                Call.create(to=STABLECOIN_DEX, value=0, data=swap_data()[:-2]),
                pay_call(),
            ),
            None,
            "malformed swap call data",
        ),
        ((pay_call(value=1),), None, "no matching payment call found"),
    ],
    ids=[
        "12-transfers",
        "transfer-before-approve-swap",
        "approve-swap-without-transfer",
        "approve-without-swap",
        "swap-without-approve",
        "approve-twice",
        "approve-spender-not-dex",
        "approve-target-not-swap-token",
        "swap-target-not-dex",
        "swap-same-token",
        "short-approve",
        "short-swap",
        "transfer-with-value",
    ],
)
async def test_sponsored_call_pattern_rejected(
    calls: tuple[Call, ...], splits: list[dict] | None, error: str
) -> None:
    with pytest.raises(VerificationError, match=error):
        await _validate(calls, splits)


@pytest.mark.parametrize(
    "calls",
    [
        (approve_call(value=1), swap_call(), pay_call()),
        (approve_call(), swap_call(value=1), pay_call()),
    ],
    ids=["approve-with-value", "swap-with-value"],
)
async def test_sponsored_swap_prefix_with_value_rejected(calls: tuple[Call, ...]) -> None:
    with pytest.raises(VerificationError):
        await _validate(calls)


def test_cosign_rejects_envelope_without_calls() -> None:
    envelope = signed_tx((pay_call(),), fee_payer=True)
    fields = rlp.decode(bytes.fromhex(envelope[4:]))
    fields[4] = []
    intent = make_intent(FakeRpc(), fee_payer=True)
    request = intent._prepare_credential(_tx_credential(envelope), _request(fee_payer=True))[0]

    with pytest.raises(VerificationError, match="Transaction contains no calls"):
        intent._cosign_as_fee_payer(raw_rlp_tx(fields, b"\x78"), PATH_USD, request=request)


async def test_sponsored_envelope_with_unknown_fields_is_not_cosigned() -> None:
    """An envelope with extra top-level fields is refused before any RPC."""
    rpc = FakeRpc()
    intent = make_intent(rpc, fee_payer=True)

    with pytest.raises(Exception, match="Malformed fee payer envelope"):
        await intent.verify(_tx_credential(_extended_envelope()), _request(fee_payer=True))

    assert rpc.methods == []
    assert stored_keys(intent) == []


def _extended_envelope() -> str:
    envelope = signed_tx((pay_call(),), fee_payer=True)
    fields = rlp.decode(bytes.fromhex(envelope[4:]))
    return raw_rlp_tx([*fields[:-1], b"\x01", b"\x02", fields[-1]], b"\x78")


@pytest.mark.parametrize(
    "raw_tx",
    [_extended_envelope(), signed_tx((pay_call(),))],
    ids=["unknown-envelope-fields", "unsponsored-0x76"],
)
async def test_malformed_sponsored_transaction_is_a_verification_error(raw_tx: str) -> None:
    intent = make_intent(FakeRpc(), fee_payer=True)

    with pytest.raises(VerificationError):
        await intent.verify(_tx_credential(raw_tx), _request(fee_payer=True))


# ──────────────────────────────────────────────────────────────────────
# 4. Fail-closed arms
# ──────────────────────────────────────────────────────────────────────

VALID_CALL = [bytes.fromhex(CURRENCY[2:]), b"", bytes.fromhex(transfer_data(memo=_memo())[2:])]


@pytest.mark.parametrize(
    ("raw_tx", "error"),
    [
        ("0x76abc", "Invalid serialized transaction"),
        ("0x76c0", "Invalid serialized transaction"),
        (raw_rlp_tx(b"not a list"), "Invalid serialized transaction"),
        (raw_rlp_tx([CHAIN_ID, 0, 0, 0]), "Invalid serialized transaction"),
        (raw_rlp_tx([[CHAIN_ID], 0, 0, 0, [VALID_CALL]]), "Invalid transaction chain ID"),
        (raw_rlp_tx([CHAIN_ID + 1, 0, 0, 0, [VALID_CALL]]), "does not match charge chain ID"),
        (raw_rlp_tx([CHAIN_ID, 0, 0, 0, []]), "Transaction contains no calls"),
        (raw_rlp_tx([CHAIN_ID, 0, 0, 0, [b"call"]]), "malformed call data"),
        (raw_rlp_tx([CHAIN_ID, 0, 0, 0, [VALID_CALL[:2]]]), "malformed call data"),
        (
            raw_rlp_tx([CHAIN_ID, 0, 0, 0, [[[b"to"], b"", VALID_CALL[2]]]]),
            "malformed call data",
        ),
        (
            raw_rlp_tx([CHAIN_ID, 0, 0, 0, [[VALID_CALL[0], b"", [b"data"]]]]),
            "malformed call data",
        ),
        (
            raw_rlp_tx([CHAIN_ID, 0, 0, 0, [[VALID_CALL[0], [b"value"], VALID_CALL[2]]]]),
            "malformed call data",
        ),
    ],
    ids=[
        "odd-hex",
        "empty-list",
        "not-a-list",
        "too-few-fields",
        "chain-id-not-bytes",
        "chain-id-mismatch",
        "no-calls",
        "call-not-a-list",
        "call-too-short",
        "call-to-not-bytes",
        "call-data-not-bytes",
        "call-value-not-scalar",
    ],
)
async def test_validate_rejects_malformed_transaction(raw_tx: str, error: str) -> None:
    intent = ChargeIntent(rpc_url="https://rpc.test")

    with pytest.raises(VerificationError, match=error):
        await intent.validate(_tx_credential(raw_tx), _request())


@pytest.mark.parametrize(
    ("returned", "error"),
    [
        ({}, "No transaction hash returned"),
        ({"transactionHash": 1}, "Invalid transaction hash returned"),
        ({"transactionHash": TX_HASH}, "does not match submitted transaction"),
    ],
    ids=["missing", "not-a-string", "other-transaction"],
)
async def test_broadcast_receipt_hash_must_be_submitted_transaction(
    returned: dict[str, Any], error: str
) -> None:
    rpc = FakeRpc()
    tx_receipt = {key: value for key, value in receipt(TX_HASH).items() if key != "transactionHash"}
    rpc.send = lambda raw_tx: {"result": {**tx_receipt, **returned}}
    intent = make_intent(rpc)

    with pytest.raises(InternalPaymentError) as raised:
        await intent.verify(_tx_credential(signed_tx((pay_call(),))), _request())

    cause = internal_cause(raised.value)
    assert isinstance(cause, VerificationError)
    assert error in str(cause)
    assert len(rpc.sent) == 1
    # The payment was not confirmed, so its replay reservation is released.
    assert stored_keys(intent) == []


async def _seed_unknown_submission(intent: ChargeIntent, envelope: str) -> str:
    """Record an earlier sponsored submission of ``envelope`` with an unknown outcome."""
    cosigned, _ = intent._cosign_as_fee_payer(envelope, PATH_USD)
    store = intent._store
    assert store is not None
    await store.put(f"mpp:charge-broadcast:{_raw_transaction_hash(envelope).lower()}", cosigned)
    return cosigned


async def test_reconciled_receipt_for_other_transaction_is_rejected() -> None:
    rpc = FakeRpc()
    intent = make_intent(rpc, fee_payer=True)
    envelope = signed_tx((pay_call(),), fee_payer=True)
    cosigned = await _seed_unknown_submission(intent, envelope)
    rpc.receipts[_raw_transaction_hash(cosigned)] = receipt(TX_HASH)

    with pytest.raises(VerificationError, match="does not match submitted transaction"):
        await intent.verify(_tx_credential(envelope), _request(fee_payer=True))

    assert rpc.sent == []


async def test_reconciliation_after_challenge_expiry_is_unknown_outcome() -> None:
    rpc = FakeRpc()
    intent = make_intent(rpc, fee_payer=True)
    envelope = signed_tx((pay_call(),), fee_payer=True)
    await _seed_unknown_submission(intent, envelope)

    # Fresh when the credential is prepared, expired at the send.
    with (
        patch("mpp.methods.tempo.intents._challenge_expired", side_effect=[False, True]),
        pytest.raises(InternalPaymentError) as raised,
    ):
        await intent.verify(_tx_credential(envelope), _request(fee_payer=True))

    assert "unknown outcome" in str(internal_cause(raised.value))
    assert rpc.sent == []


class MarkerStore(MemoryStore):
    """A store whose broadcast-marker writes fail or lose a race."""

    def __init__(self, outcome: str) -> None:
        super().__init__()
        self.outcome = outcome

    async def _marker(self, key: str) -> bool | None:
        if not key.startswith("mpp:charge-broadcast:"):
            return None
        if self.outcome == "raise":
            raise ConnectionError("store unavailable")
        return False

    async def put_if_absent(self, key: str, value: Any) -> bool:
        marker = await self._marker(key)
        return await super().put_if_absent(key, value) if marker is None else marker

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        marker = await self._marker(key)
        if marker is None:
            return await super().put_if_absent_until(key, value, expires_at)
        return marker


@pytest.mark.parametrize(
    ("outcome", "cause"),
    [("raise", "store unavailable"), ("taken", "owns this credential's recovery record")],
)
async def test_sponsored_broadcast_requires_its_own_marker(outcome: str, cause: str) -> None:
    rpc = FakeRpc()
    intent = make_intent(rpc, fee_payer=True, store=MarkerStore(outcome))

    with pytest.raises(InternalPaymentError) as raised:
        await intent.verify(
            _tx_credential(signed_tx((pay_call(),), fee_payer=True)), _request(fee_payer=True)
        )

    assert cause in str(internal_cause(raised.value))
    assert rpc.sent == []
    assert stored_keys(intent) == []
