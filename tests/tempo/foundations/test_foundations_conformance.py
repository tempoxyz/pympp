"""Conformance vectors: tempo-proof, tempo-fee-payer-cosign, tempo-receipt-verification.

The vectors are loaded unchanged from ``vendor/mpp-tools/conformance/vectors``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import attrs
import httpx
import pytest
from pytempo import AccessListItem, Call, TempoTransaction

from mpp.errors import PaymentError, VerificationFailedError
from mpp.tempo._internal import charge, fee_payer, proof
from mpp.tempo._internal import envelope as transaction
from mpp.tempo._internal.account import secp256k1_account
from mpp.tempo._internal.rpc import RpcClient

VECTORS = Path(__file__).parents[3] / "vendor/mpp-tools/conformance/vectors"


def load(name: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / f"{name}.json").read_text())["scenarios"]


# -- tempo-proof -------------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", load("tempo-proof"), ids=lambda s: s["name"])
def test_tempo_proof_typed_data(scenario: dict[str, Any]) -> None:
    # mpp-tools keeps the historical v2 proof vector: the pre-binding MPP v2
    # shape (no `account`). Current mppx (and `mpp.tempo.proof`) uses the
    # wallet-bound v3 contract; the v2 shape is kept as `legacy_v2_typed_data`.
    data = scenario["input"]
    result = proof.legacy_v2_typed_data(
        chain_id=data["chainId"], challenge_id=data["challengeId"], realm=data["realm"]
    )
    assert scenario["expected"]["ok"] is True
    assert result == scenario["expected"]["value"]


# -- tempo-fee-payer-cosign --------------------------------------------------------------------

# The vector messages come from another SDK; mppx words the same rejections differently
# (and checks challenge-bound memos before sponsor policy). Each scenario maps to the
# mppx rejection it exercises; the full mppx-ordered flow must reject with a
# verification error, and the targeted mppx check must fail for the intended reason.
COSIGN_REASONS: dict[str, tuple[str, str]] = {
    # name: (stage, mppx reason substring)
    "plain_transfer_without_challenge_memo_rejected": (
        "calls",
        "memo is not bound to this challenge",
    ),
    "wrong_challenge_memo_rejected": ("calls", "memo is not bound to this challenge"),
    "extra_call_rejected": ("calls", "no matching payment call found"),
    "gas_limit_above_policy_rejected": (
        "policy",
        "fee-sponsored transaction gas exceeds sponsor policy",
    ),
    "attacker_fee_token_rejected": (
        "fee_token",
        "fee-sponsored transaction feeToken is not allowed",
    ),
    "wrong_nonce_key_rejected": ("policy", "fee-sponsored transaction must use an expiring nonce"),
    "validity_window_above_policy_rejected": (
        "policy",
        "fee-sponsored transaction validity window exceeds sponsor policy",
    ),
    "access_list_rejected": ("policy", "fee-sponsored transaction accessList is not allowed"),
}


def _uint(value: Any, now: int) -> int:
    if isinstance(value, str) and value.startswith("now+"):
        return now + int(value[4:])
    if value == "max":
        return transaction.MAX_UINT256
    return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)


def _client_envelope(data: dict[str, Any], now: int) -> str:
    """The payer's sponsored (0x78) envelope built from the vector transaction."""
    tx = data["transaction"]
    payer = secp256k1_account(data["payerPrivateKey"])
    unsigned = TempoTransaction(
        chain_id=_uint(tx["chainId"], now),
        max_priority_fee_per_gas=_uint(tx["maxPriorityFeePerGas"], now),
        max_fee_per_gas=_uint(tx["maxFeePerGas"], now),
        gas_limit=_uint(tx["gasLimit"], now),
        calls=tuple(
            Call(to=c["to"], value=_uint(c["value"], now), data=c["data"]) for c in tx["calls"]
        ),
        access_list=tuple(
            AccessListItem(address=address, storage_keys=tuple(keys))
            for address, keys in tx["accessList"]
        ),
        nonce_key=_uint(tx["nonceKey"], now),
        nonce=_uint(tx["nonce"], now),
        valid_before=_uint(tx["validBefore"], now),
        awaiting_fee_payer=True,
    )
    return transaction.serialize_for_fee_payer(payer.sign_transaction(unsigned))


def _cosign(data: dict[str, Any], tx: TempoTransaction) -> str:
    """mppx charge-server order: calls + challenge memo, fee token, then sponsor policy."""
    request, challenge = data["request"], data.get("challenge")
    chain_id = request["methodDetails"]["chainId"]
    details = {
        "amount": request["amount"],
        "currency": request["currency"],
        "recipient": request["recipient"],
    }
    transfers = charge.get_expected_transfers(
        amount=request["amount"], recipient=request["recipient"]
    )
    matched = charge.assert_transfer_calls(
        tx.calls, currency=request["currency"], transfers=transfers, exact_count=True
    )
    if challenge is not None:  # Older scenarios carry no challenge to bind a memo to.
        charge.assert_challenge_bound_call_memo(
            matched, challenge_id=challenge["id"], realm=challenge["realm"]
        )
    fee_payer.validate_calls(
        tx.calls, details, currency=request["currency"], expected_transfers=transfers
    )
    allowed = fee_payer.default_allowed_fee_tokens(chain_id)
    fee_payer.assert_allowed_fee_token(transaction.fee_token(tx), allowed)
    sponsored = fee_payer.prepare_sponsored_transaction(
        attrs.evolve(tx, fee_token=data["feeToken"]),
        chain_id=chain_id,
        details=details,
        allowed_fee_tokens=allowed,
    )
    return fee_payer.sign_as_fee_payer(sponsored, secp256k1_account(data["feePayerPrivateKey"]))


def _server_transaction(scenario: dict[str, Any], now: int) -> TempoTransaction:
    data = scenario["input"]
    tx = transaction.deserialize(_client_envelope(data, now))
    if data["transaction"]["feeToken"] is not None:
        # An attacker-chosen fee token carried in the client envelope.
        tx = attrs.evolve(tx, fee_token=data["transaction"]["feeToken"])
    return tx


@pytest.mark.parametrize("scenario", load("tempo-fee-payer-cosign"), ids=lambda s: s["name"])
def test_tempo_fee_payer_cosign(scenario: dict[str, Any]) -> None:
    now = int(time.time())
    data, expected = scenario["input"], scenario["expected"]
    tx = _server_transaction(scenario, now)

    if expected["ok"]:
        cosigned = transaction.deserialize(_cosign(data, tx))
        summary = {
            "type": "0x76",
            "feeToken": transaction.fee_token(cosigned),
            "feePayerSignaturePresent": cosigned.fee_payer_signature is not None,
            "accessListLength": len(cosigned.access_list),
            "callCount": len(cosigned.calls),
        }
        assert summary == expected["value"]
        assert transaction.sender(cosigned) == secp256k1_account(data["payerPrivateKey"]).address
        assert transaction.recover_fee_payer(cosigned) == (
            secp256k1_account(data["feePayerPrivateKey"]).address
        )
        return

    assert expected["error"]["type"] == "verification_error"
    with pytest.raises((PaymentError, fee_payer.FeePayerValidationError)):
        _cosign(data, tx)

    stage, reason = COSIGN_REASONS[scenario["name"]]
    request = data["request"]
    chain_id = request["methodDetails"]["chainId"]
    details = {k: request[k] for k in ("amount", "currency", "recipient")}

    def targeted_check() -> None:
        match stage:
            case "calls":
                _cosign(data, tx)
            case "fee_token":
                fee_payer.assert_allowed_fee_token(
                    transaction.fee_token(tx), fee_payer.default_allowed_fee_tokens(chain_id)
                )
            case "policy":
                fee_payer.prepare_sponsored_transaction(
                    attrs.evolve(tx, fee_token=data["feeToken"]),
                    chain_id=chain_id,
                    details=details,
                )

    with pytest.raises((PaymentError, fee_payer.FeePayerValidationError), match=reason):
        targeted_check()


# -- tempo-receipt-verification ----------------------------------------------------------------


def _rpc_returning(receipt: dict[str, Any]) -> RpcClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "eth_getTransactionReceipt"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": receipt})

    return RpcClient(
        "http://tempo.invalid", http=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )


@pytest.mark.parametrize("scenario", load("tempo-receipt-verification"), ids=lambda s: s["name"])
async def test_tempo_receipt_verification(scenario: dict[str, Any]) -> None:
    credential = scenario["input"]["credential"]
    challenge, payload = credential["challenge"], credential["payload"]
    request = challenge["request"]
    receipt = dict(scenario["input"]["receipt"])
    # Node receipts always carry `from`; the fixture omits it. The payer is the
    # transfer source of the first log.
    receipt.setdefault("from", "0x" + receipt["logs"][0]["topics"][1][-40:])

    async def verify() -> dict[str, str]:
        async with _rpc_returning(receipt) as client:
            verified = await charge.verify_hash_credential(
                client,
                transaction_hash=payload["hash"],
                challenge_id=challenge["id"],
                realm=challenge["realm"],
                amount=request["amount"],
                currency=request["currency"],
                recipient=request["recipient"],
                splits=charge.splits_from_method_details(request.get("methodDetails")),
            )
        return {"status": "success", "reference": verified.receipt.transaction_hash}

    expected = scenario["expected"]
    if expected["ok"]:
        assert await verify() == expected["value"]
    else:
        assert expected["error"]["type"] == "verification_error"
        with pytest.raises((VerificationFailedError, charge.MismatchError)):
            await verify()
