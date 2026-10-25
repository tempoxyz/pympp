"""Ported from mppx src/Errors.test.ts."""

import json

import pytest

from mpp import Challenge
from mpp import errors as E

P = "https://paymentauth.org/problems"

CASES = [
    (
        E.MalformedCredentialError(),
        "MalformedCredentialError",
        "Credential is malformed.",
        402,
        f"{P}/malformed-credential",
    ),
    (
        E.MalformedCredentialError(reason="invalid base64url"),
        "MalformedCredentialError",
        "Credential is malformed: invalid base64url.",
        402,
        f"{P}/malformed-credential",
    ),
    (
        E.InvalidChallengeError(),
        "InvalidChallengeError",
        "Challenge is invalid.",
        402,
        f"{P}/invalid-challenge",
    ),
    (
        E.InvalidChallengeError(id="abc123"),
        "InvalidChallengeError",
        'Challenge "abc123" is invalid.',
        402,
        f"{P}/invalid-challenge",
    ),
    (
        E.InvalidChallengeError(reason="expired"),
        "InvalidChallengeError",
        "Challenge is invalid: expired.",
        402,
        f"{P}/invalid-challenge",
    ),
    (
        E.InvalidChallengeError(id="abc123", reason="already used"),
        "InvalidChallengeError",
        'Challenge "abc123" is invalid: already used.',
        402,
        f"{P}/invalid-challenge",
    ),
    (
        E.VerificationFailedError(),
        "VerificationFailedError",
        "Payment verification failed.",
        402,
        f"{P}/verification-failed",
    ),
    (
        E.VerificationFailedError(reason="invalid signature"),
        "VerificationFailedError",
        "Payment verification failed: invalid signature.",
        402,
        f"{P}/verification-failed",
    ),
    (
        E.CredentialReplayedError(),
        "CredentialReplayedError",
        "Payment verification failed: Credential has already been used.",
        403,
        f"{P}/verification-failed",
    ),
    (
        E.InternalPaymentError(),
        "InternalPaymentError",
        "An internal payment error occurred.",
        500,
        f"{P}/internal-payment-error",
    ),
    (
        E.PaymentExpiredError(),
        "PaymentExpiredError",
        "Payment has expired.",
        402,
        f"{P}/payment-expired",
    ),
    (
        E.PaymentExpiredError(expires="2025-01-26T12:00:00Z"),
        "PaymentExpiredError",
        "Payment expired at 2025-01-26T12:00:00Z.",
        402,
        f"{P}/payment-expired",
    ),
    (
        E.PaymentRequiredError(),
        "PaymentRequiredError",
        "Payment is required.",
        402,
        f"{P}/payment-required",
    ),
    (
        E.PaymentRequiredError(description="API access fee"),
        "PaymentRequiredError",
        "Payment is required (API access fee).",
        402,
        f"{P}/payment-required",
    ),
    (
        E.InvalidPayloadError(),
        "InvalidPayloadError",
        "Credential payload is invalid.",
        402,
        f"{P}/invalid-payload",
    ),
    (
        E.InvalidPayloadError(reason="missing signature field"),
        "InvalidPayloadError",
        "Credential payload is invalid: missing signature field.",
        402,
        f"{P}/invalid-payload",
    ),
    (E.BadRequestError(), "BadRequestError", "Bad request.", 400, f"{P}/bad-request"),
    (
        E.BadRequestError(reason="missing field"),
        "BadRequestError",
        "Bad request: missing field.",
        400,
        f"{P}/bad-request",
    ),
    (
        E.PaymentInsufficientError(),
        "PaymentInsufficientError",
        "Payment amount is insufficient.",
        402,
        f"{P}/payment-insufficient",
    ),
    (
        E.PaymentInsufficientError(reason="expected 1000, received 500"),
        "PaymentInsufficientError",
        "Payment insufficient: expected 1000, received 500.",
        402,
        f"{P}/payment-insufficient",
    ),
    (
        E.PaymentMethodUnsupportedError(),
        "PaymentMethodUnsupportedError",
        "Payment method is not supported.",
        400,
        f"{P}/method-unsupported",
    ),
    (
        E.PaymentMethodUnsupportedError(method="bitcoin"),
        "PaymentMethodUnsupportedError",
        'Payment method "bitcoin" is not supported.',
        400,
        f"{P}/method-unsupported",
    ),
    (
        E.InsufficientBalanceError(),
        "InsufficientBalanceError",
        "Insufficient balance.",
        402,
        f"{P}/session/insufficient-balance",
    ),
    (
        E.InsufficientBalanceError(reason="x"),
        "InsufficientBalanceError",
        "Insufficient balance: x.",
        402,
        f"{P}/session/insufficient-balance",
    ),
    (
        E.InvalidSignatureError(),
        "InvalidSignatureError",
        "Invalid signature.",
        402,
        f"{P}/session/invalid-signature",
    ),
    (
        E.InvalidSignatureError(reason="x"),
        "InvalidSignatureError",
        "Invalid signature: x.",
        402,
        f"{P}/session/invalid-signature",
    ),
    (
        E.SignerMismatchError(),
        "SignerMismatchError",
        "Signer is not authorized for this channel.",
        402,
        f"{P}/session/signer-mismatch",
    ),
    (
        E.AmountExceedsDepositError(),
        "AmountExceedsDepositError",
        "Voucher amount exceeds channel deposit.",
        402,
        f"{P}/session/amount-exceeds-deposit",
    ),
    (
        E.DeltaTooSmallError(),
        "DeltaTooSmallError",
        "Amount increase below minimum voucher delta.",
        402,
        f"{P}/session/delta-too-small",
    ),
    (
        E.ChannelNotFoundError(),
        "ChannelNotFoundError",
        "No channel with this ID exists.",
        410,
        f"{P}/session/channel-not-found",
    ),
    (
        E.ChannelClosedError(),
        "ChannelClosedError",
        "Channel is closed.",
        410,
        f"{P}/session/channel-finalized",
    ),
    (
        E.ChannelClosedError(reason="channel is finalized on-chain"),
        "ChannelClosedError",
        "Channel closed: channel is finalized on-chain.",
        410,
        f"{P}/session/channel-finalized",
    ),
    (
        E.PaymentActionRequiredError(),
        "PaymentActionRequiredError",
        "Payment requires action.",
        402,
        f"{P}/payment-action-required",
    ),
    (
        E.PaymentActionRequiredError(reason="requires_action"),
        "PaymentActionRequiredError",
        "Payment requires action: requires_action.",
        402,
        f"{P}/payment-action-required",
    ),
]


@pytest.mark.parametrize(("error", "name", "message", "status", "type_"), CASES)
def test_error_snapshot(
    error: E.PaymentError, name: str, message: str, status: int, type_: str
) -> None:
    assert (error.name, error.message, error.status, error.type) == (name, message, status, type_)
    assert str(error) == message


def test_relay_metadata() -> None:
    error = E.VerificationFailedError(
        details={"party": "originator"}, reason="Originator matched a sanctions list"
    )
    assert error.details == {"party": "originator"}
    assert error.to_problem_details("challenge-id") == {
        "challengeId": "challenge-id",
        "detail": "Payment verification failed: Originator matched a sanctions list.",
        "details": {"party": "originator"},
        "status": 402,
        "title": "Verification Failed",
        "type": f"{P}/verification-failed",
    }


def test_omits_empty_details() -> None:
    assert "details" not in E.VerificationFailedError(details={}).to_problem_details()


@pytest.mark.parametrize(
    "reason",
    [
        "Transaction hash has already been used",
        "Proof credential has already been used",
        "memo is not bound to this challenge",
    ],
)
def test_replayed_differs_only_in_status(reason: str) -> None:
    error = E.CredentialReplayedError(reason=reason)
    assert isinstance(error, E.VerificationFailedError)
    assert error.to_problem_details("challenge-id") == {
        **E.VerificationFailedError(reason=reason).to_problem_details("challenge-id"),
        "status": 403,
    }


def test_internal_error_keeps_cause_private() -> None:
    assert E.InternalPaymentError().__cause__ is None
    cause = RuntimeError("request to https://rpc.example.com/?key=secret-key failed")
    error = E.InternalPaymentError(cause=cause)
    assert error.__cause__ is cause
    assert error.to_problem_details("challenge-id") == E.InternalPaymentError().to_problem_details(
        "challenge-id"
    )
    assert "secret-key" not in json.dumps(error.to_problem_details("challenge-id"))


def test_outcome_unknown() -> None:
    challenge = Challenge.create(
        id="abc", intent="charge", method="tempo", realm="api.example.com", request={"amount": "1"}
    )
    cause = TypeError("fetch failed")
    error = E.PaymentOutcomeUnknownError(
        cause=cause, challenge=challenge, credential="Payment abc", transaction_hash="0x01"
    )
    assert (
        error.message
        == 'Payment outcome is unknown after sending a credential for challenge "abc". Do not blindly retry.'
    )
    assert error.type == f"{P}/payment-outcome-unknown"
    assert (error.__cause__, error.challenge, error.credential, error.transaction_hash) == (
        cause,
        challenge,
        "Payment abc",
        "0x01",
    )


def test_problem_details_hints() -> None:
    assert E.PaymentRequiredError(description="API access fee").to_problem_details("ch_abc") == {
        "challengeId": "ch_abc",
        "detail": "Payment is required (API access fee).",
        "hint": E.HINT_PAYMENT_REQUIRED,
        "status": 402,
        "title": "Payment Required",
        "type": f"{P}/payment-required",
    }
    assert (
        E.PaymentMethodUnsupportedError(method="x").to_problem_details()["hint"]
        == E.HINT_METHOD_UNSUPPORTED
    )
    assert E.MalformedCredentialError(reason="invalid JSON").to_problem_details() == {
        "detail": "Credential is malformed: invalid JSON.",
        "hint": E.HINT_MALFORMED_CREDENTIAL,
        "status": 402,
        "title": "Malformed Credential",
        "type": f"{P}/malformed-credential",
    }
    assert E.InvalidChallengeError(id="abc123", reason="expired").to_problem_details("abc123") == {
        "challengeId": "abc123",
        "detail": 'Challenge "abc123" is invalid: expired.',
        "status": 402,
        "title": "Invalid Challenge",
        "type": f"{P}/invalid-challenge",
    }
    assert E.PaymentActionRequiredError(
        reason="Stripe PaymentIntent requires action"
    ).to_problem_details("ch_123") == {
        "challengeId": "ch_123",
        "detail": "Payment requires action: Stripe PaymentIntent requires action.",
        "status": 402,
        "title": "Payment Action Required",
        "type": f"{P}/payment-action-required",
    }
