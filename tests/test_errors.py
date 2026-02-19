"""Tests for payment error types and RFC 9457 Problem Details."""

import pytest

from mpp.errors import (
    BadRequestError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentActionRequiredError,
    PaymentError,
    PaymentExpiredError,
    PaymentInsufficientError,
    PaymentMethodUnsupportedError,
    PaymentRequiredError,
    VerificationFailedError,
)


class TestToProblemDetails:
    def test_base_error_includes_required_fields(self) -> None:
        """to_problem_details() should include type, title, status, detail."""
        err = PaymentError("something went wrong")
        details = err.to_problem_details()
        assert details["type"] == "https://paymentauth.org/problems/payment-error"
        assert details["title"] == "Payment Error"
        assert details["status"] == 402
        assert isinstance(details["status"], int)
        assert details["detail"] == "something went wrong"

    def test_includes_challenge_id_when_provided(self) -> None:
        """to_problem_details(challenge_id=...) should include challengeId."""
        err = PaymentError("test")
        details = err.to_problem_details(challenge_id="ch-123")
        assert details["challengeId"] == "ch-123"

    def test_excludes_challenge_id_when_none(self) -> None:
        """to_problem_details() without challenge_id should not have challengeId key."""
        err = PaymentError("test")
        details = err.to_problem_details()
        assert "challengeId" not in details

    def test_problem_details_keys_are_exact(self) -> None:
        """Problem Details keys should be exactly the expected set."""
        err = PaymentError("test")

        without = err.to_problem_details()
        assert set(without.keys()) == {"type", "title", "status", "detail"}

        with_cid = err.to_problem_details(challenge_id="ch-1")
        assert set(with_cid.keys()) == {"type", "title", "status", "detail", "challengeId"}


class TestAutoSlug:
    @pytest.mark.parametrize(
        "cls, expected_suffix",
        [
            (InvalidPayloadError, "/invalid-payload"),
            (MalformedCredentialError, "/malformed-credential"),
            (InvalidChallengeError, "/invalid-challenge"),
            (VerificationFailedError, "/verification-failed"),
            (PaymentExpiredError, "/payment-expired"),
            (PaymentInsufficientError, "/payment-insufficient"),
            (PaymentActionRequiredError, "/payment-action-required"),
            (PaymentRequiredError, "/payment-required"),
        ],
        ids=lambda cls: cls.__name__ if isinstance(cls, type) else cls,
    )
    def test_auto_slug(self, cls: type, expected_suffix: str) -> None:
        assert cls.type.endswith(expected_suffix)


class TestAutoTitle:
    @pytest.mark.parametrize(
        "cls, expected_title",
        [
            (InvalidPayloadError, "Invalid Payload"),
            (MalformedCredentialError, "Malformed Credential"),
            (InvalidChallengeError, "Invalid Challenge"),
            (VerificationFailedError, "Verification Failed"),
            (PaymentExpiredError, "Payment Expired"),
            (PaymentInsufficientError, "Payment Insufficient"),
            (PaymentMethodUnsupportedError, "Method Unsupported"),
            (PaymentActionRequiredError, "Payment Action Required"),
            (PaymentRequiredError, "Payment Required"),
            (BadRequestError, "Bad Request"),
        ],
        ids=lambda cls: cls.__name__ if isinstance(cls, type) else cls,
    )
    def test_auto_title(self, cls: type, expected_title: str) -> None:
        assert cls.title == expected_title


class TestSubclassInstantiation:
    def test_payment_required_with_args(self) -> None:
        err = PaymentRequiredError(realm="api.example.com", description="Monthly quota")
        assert "api.example.com" in str(err)
        assert "Monthly quota" in str(err)

    def test_payment_required_no_args(self) -> None:
        err = PaymentRequiredError()
        assert "Payment is required" in str(err)

    def test_malformed_credential_with_reason(self) -> None:
        err = MalformedCredentialError(reason="bad base64")
        assert "bad base64" in str(err)

    def test_malformed_credential_no_reason(self) -> None:
        err = MalformedCredentialError()
        assert "malformed" in str(err).lower()

    def test_invalid_challenge_with_id_and_reason(self) -> None:
        err = InvalidChallengeError(challenge_id="ch-99", reason="expired")
        assert "ch-99" in str(err)
        assert "expired" in str(err)

    def test_invalid_challenge_no_args(self) -> None:
        err = InvalidChallengeError()
        assert "invalid" in str(err).lower()

    def test_verification_failed_with_reason(self) -> None:
        err = VerificationFailedError(reason="wrong amount")
        assert "wrong amount" in str(err)

    def test_verification_failed_no_reason(self) -> None:
        err = VerificationFailedError()
        assert "verification failed" in str(err).lower()

    def test_payment_expired_with_timestamp(self) -> None:
        err = PaymentExpiredError(expires="2024-01-01T00:00:00Z")
        assert "2024-01-01" in str(err)

    def test_payment_expired_no_args(self) -> None:
        err = PaymentExpiredError()
        assert "expired" in str(err).lower()

    def test_invalid_payload_with_reason(self) -> None:
        err = InvalidPayloadError(reason="missing hash")
        assert "missing hash" in str(err)

    def test_invalid_payload_no_reason(self) -> None:
        err = InvalidPayloadError()
        assert "invalid" in str(err).lower()

    def test_bad_request_with_reason(self) -> None:
        err = BadRequestError(reason="missing field")
        assert err.status == 400
        assert "missing field" in str(err)

    def test_bad_request_no_reason(self) -> None:
        err = BadRequestError()
        assert "Bad request" in str(err)

    def test_payment_insufficient_with_reason(self) -> None:
        err = PaymentInsufficientError(reason="need 100, got 50")
        assert "need 100" in str(err)

    def test_payment_insufficient_no_reason(self) -> None:
        err = PaymentInsufficientError()
        assert "insufficient" in str(err).lower()

    def test_method_unsupported_with_method(self) -> None:
        err = PaymentMethodUnsupportedError(method="stripe")
        assert err.status == 400
        assert "stripe" in str(err)
        assert err.type.endswith("/method-unsupported")
        assert err.title == "Method Unsupported"

    def test_method_unsupported_no_args(self) -> None:
        err = PaymentMethodUnsupportedError()
        assert "not supported" in str(err)

    def test_payment_action_required_with_reason(self) -> None:
        err = PaymentActionRequiredError(reason="3DS needed")
        assert "3DS needed" in str(err)

    def test_payment_action_required_no_reason(self) -> None:
        err = PaymentActionRequiredError()
        assert "requires action" in str(err)


class TestSubclassProblemDetails:
    def test_subclass_problem_details_has_correct_type(self) -> None:
        """Subclass to_problem_details() should use auto-generated type URI."""
        err = InvalidPayloadError(reason="bad")
        details = err.to_problem_details(challenge_id="ch-1")
        assert details["type"].endswith("/invalid-payload")
        assert details["status"] == 402
        assert isinstance(details["status"], int)
        assert details["challengeId"] == "ch-1"
        assert "bad" in details["detail"]

    def test_bad_request_status_in_problem_details(self) -> None:
        """BadRequestError should have status 400 in problem details."""
        err = BadRequestError(reason="invalid")
        details = err.to_problem_details()
        assert details["status"] == 400
        assert isinstance(details["status"], int)
