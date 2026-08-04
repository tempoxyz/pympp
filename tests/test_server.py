"""Tests for server-side verification."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from mpp import BodyDigest, Challenge, Credential, Receipt
from mpp.errors import (
    InvalidChallengeError,
    MalformedCredentialError,
    PaymentExpiredError,
    PaymentMethodUnsupportedError,
    VerificationFailedError,
)
from mpp.events import EventDispatcher
from mpp.server import (
    Intent,
    Mpp,
    Validation,
    broadcast_credential,
    intent,
    pay,
    validate_credential,
    verify_credential,
    verify_or_challenge,
)
from mpp.server.intent import VerificationError
from tests import make_bound_credential, make_credential

try:
    from starlette.responses import Response as StarletteResponse

    HAS_STARLETTE = True
except ImportError:
    HAS_STARLETTE = False
    StarletteResponse = None  # type: ignore[misc, assignment]


class TestVerifyOrChallenge:
    @pytest.mark.asyncio
    async def test_returns_challenge_when_no_authorization(self) -> None:
        """Should return a challenge when no Authorization header."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        result = await verify_or_challenge(
            authorization=None,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)
        assert result.method == "tempo"
        assert result.intent == "charge"
        assert result.request["amount"] == "1000"
        assert result.expires is not None  # default expires is a challenge-level auth-param

    @pytest.mark.asyncio
    async def test_emits_challenge_created(self) -> None:
        """Should emit challenge.created before returning a 402 challenge."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on(
            "challenge.created",
            lambda payload: events.append(
                f"challenge:{payload['challenge'].id}:{payload['request']['amount']}"
            ),
        )
        dispatcher.on("*", lambda event: events.append(f"*:{event.name}"))

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        result = await verify_or_challenge(
            authorization=None,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            events=dispatcher,
        )

        assert isinstance(result, Challenge)
        assert events == [f"challenge:{result.id}:1000", "*:challenge.created"]

    @pytest.mark.asyncio
    async def test_returns_challenge_when_invalid_scheme(self) -> None:
        """Should return a challenge for non-Payment authorization."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        result = await verify_or_challenge(
            authorization="Bearer token123",
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_verifies_valid_credential(self) -> None:
        """Should verify a valid credential and return receipt."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert credential.payload == {"hash": "0xabc"}
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.status == "success"

    @pytest.mark.asyncio
    async def test_issues_challenge_with_body_digest(self) -> None:
        """Should bind a supplied server request body into the issued challenge."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        body = b'{"query":"paid"}'
        result = await verify_or_challenge(
            authorization=None,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            body=body,
        )

        assert isinstance(result, Challenge)
        assert result.digest == BodyDigest.compute(body)

    @pytest.mark.asyncio
    async def test_verifies_matching_body_digest(self) -> None:
        """Should accept a digest-bound credential only for the matching body."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        body = b'{"query":"paid"}'
        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=BodyDigest.compute(body),
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            body=body,
        )

        assert isinstance(result, tuple)
        _credential, receipt = result
        assert receipt.status == "success"
        assert receipt.reference == "0x123"

    @pytest.mark.asyncio
    async def test_rejects_mismatched_body_digest(self) -> None:
        """Should reject a credential when the actual server body differs."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=BodyDigest.compute(b'{"query":"paid"}'),
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            body=b'{"query":"tampered"}',
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_rejects_digest_bound_credential_without_body(self) -> None:
        """Should reject a digest-bound credential when no body is supplied."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=BodyDigest.compute(b'{"query":"paid"}'),
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)
        assert result.digest is None

    @pytest.mark.asyncio
    async def test_emits_payment_success(self) -> None:
        """Should emit payment.success after intent verification."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on(
            "payment.success",
            lambda payload: events.append(
                f"success:{payload['challenge'].id}:{payload['receipt'].reference}"
            ),
        )

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            events=dispatcher,
        )

        assert isinstance(result, tuple)
        assert events == [f"success:{credential.challenge.id}:0x123"]


class TestFunctionalIntent:
    @pytest.mark.asyncio
    async def test_decorator_creates_intent(self) -> None:
        """@intent decorator should create a functional intent."""

        @intent(name="subscribe")
        async def my_subscribe(credential: Credential, request: dict) -> Receipt:
            return Receipt.success(f"sub-{credential.challenge.id}")

        assert my_subscribe.name == "subscribe"

        receipt = await my_subscribe.verify(
            make_credential(payload={}, challenge_id="test"),
            {"plan": "premium"},
        )
        assert receipt.reference == "sub-test"


class TestClassBasedIntent:
    @pytest.mark.asyncio
    async def test_class_intent(self) -> None:
        """Class-based intent should work with verify_or_challenge."""

        class MyIntent:
            name = "custom"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success("custom-ref")

        credential = make_bound_credential(
            payload={},
            request={},
            realm="test",
            secret_key="test-secret",
            method="custompay",
            intent="custom",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=MyIntent(),
            request={},
            realm="test",
            secret_key="test-secret",
            method="custompay",
        )

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.reference == "custom-ref"


class TestSplitIntentLifecycle:
    class SplitCharge:
        name = "charge"

        def __init__(self) -> None:
            self.calls: list[str] = []

        async def validate(self, credential: Credential, request: dict) -> Validation:
            self.calls.append("validate")
            return Validation(
                challenge=credential.challenge,
                credential=credential,
                details={"mode": "pull"},
                intent=self.name,
                method=credential.challenge.method,
                request=request,
                source=credential.source,
            )

        async def broadcast(self, credential: Credential, request: dict) -> Receipt:
            self.calls.append("broadcast")
            return Receipt.success("split-ref")

        async def verify(self, credential: Credential, request: dict) -> Receipt:
            self.calls.append("legacy-verify")
            return Receipt.success("legacy-ref")

    @staticmethod
    def server(split: Intent) -> Mpp:
        class TestMethod:
            name = "tempo"
            intents: dict[str, Intent] = {"charge": split}

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        return Mpp.create(
            method=TestMethod(),
            realm="api.example.com",
            secret_key="test-secret",
        )

    @pytest.mark.asyncio
    async def test_validate_does_not_broadcast(self) -> None:
        split = self.SplitCharge()
        credential = make_credential(payload={})

        result = await validate_credential(intent=split, credential=credential, request={})

        assert result.details == {"mode": "pull"}
        assert split.calls == ["validate"]

    @pytest.mark.asyncio
    async def test_broadcast_revalidates_before_terminal_operation(self) -> None:
        split = self.SplitCharge()
        credential = make_credential(payload={})

        receipt = await broadcast_credential(intent=split, credential=credential, request={})

        assert receipt.reference == "split-ref"
        assert split.calls == ["validate", "broadcast"]

    @pytest.mark.asyncio
    async def test_mpp_broadcast_calls_validate_hook_first(self) -> None:
        split = self.SplitCharge()
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
        )

        receipt = await self.server(split).broadcast_credential(credential)

        assert receipt.reference == "split-ref"
        assert split.calls == ["validate", "broadcast"]

    @pytest.mark.asyncio
    async def test_mpp_broadcast_stops_when_validate_hook_fails(self) -> None:
        class RejectingSplit(self.SplitCharge):
            async def validate(self, credential: Credential, request: dict) -> Validation:
                self.calls.append("validate")
                raise VerificationFailedError("rejected")

        split = RejectingSplit()
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
        )

        with pytest.raises(VerificationFailedError, match="rejected"):
            await self.server(split).broadcast_credential(credential)

        assert split.calls == ["validate"]

    @pytest.mark.asyncio
    async def test_route_uses_split_lifecycle(self) -> None:
        split = self.SplitCharge()
        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=split,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, tuple)
        assert result[1].reference == "split-ref"
        assert split.calls == ["validate", "broadcast"]

    @pytest.mark.asyncio
    async def test_validation_failure_prevents_broadcast(self) -> None:
        class FailingSplit(self.SplitCharge):
            async def validate(self, credential: Credential, request: dict) -> Validation:
                self.calls.append("validate")
                raise VerificationFailedError("invalid")

        split = FailingSplit()

        with pytest.raises(VerificationFailedError, match="invalid"):
            await broadcast_credential(
                intent=split,
                credential=make_credential(payload={}),
                request={},
            )

        assert split.calls == ["validate"]

    @pytest.mark.asyncio
    async def test_legacy_intent_only_supports_terminal_lifecycle(self) -> None:
        calls: list[str] = []

        class LegacyCharge:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                calls.append("verify")
                return Receipt.success("legacy-ref")

        legacy = LegacyCharge()
        credential = make_credential(payload={})

        with pytest.raises(VerificationFailedError, match="does not support non-mutating"):
            await validate_credential(intent=legacy, credential=credential, request={})

        receipt = await broadcast_credential(intent=legacy, credential=credential, request={})
        assert receipt.reference == "legacy-ref"
        assert calls == ["verify"]

    @pytest.mark.asyncio
    async def test_broadcast_hook_requires_non_mutating_validation(self) -> None:
        class UnsafeBroadcast:
            name = "charge"

            async def broadcast(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success("unsafe-ref")

        with pytest.raises(VerificationFailedError, match="does not support non-mutating"):
            await broadcast_credential(
                intent=UnsafeBroadcast(),  # type: ignore[arg-type]
                credential=make_credential(payload={}),
                request={},
            )

    @pytest.mark.asyncio
    async def test_rejects_invalid_validation_result(self) -> None:
        class InvalidSplit(self.SplitCharge):
            async def validate(  # type: ignore[override]
                self, credential: Credential, request: dict
            ) -> dict:
                return {}

        with pytest.raises(VerificationFailedError, match="invalid validation result"):
            await validate_credential(
                intent=InvalidSplit(),
                credential=make_credential(payload={}),
                request={},
            )

    @pytest.mark.asyncio
    async def test_mpp_exposes_bound_standalone_lifecycle(self) -> None:
        split = self.SplitCharge()
        server = self.server(split)
        request = {"amount": "1000"}
        credential = make_bound_credential(
            payload={},
            request=request,
            realm="api.example.com",
            secret_key="test-secret",
        )

        validation = await server.validate_credential(
            credential.to_authorization(), request=request
        )
        receipt = await server.broadcast_credential(credential, intent="charge", request=request)
        bare_credential = credential.to_authorization().removeprefix("Payment ")
        legacy_receipt = await server.verify_credential(bare_credential)

        assert validation.request == request
        assert receipt.reference == "split-ref"
        assert legacy_receipt.reference == "split-ref"
        assert split.calls == [
            "validate",
            "validate",
            "broadcast",
            "validate",
            "broadcast",
        ]

        with pytest.raises(InvalidChallengeError, match="credential request does not match"):
            await server.validate_credential(credential, request={"amount": "2000"})

    @pytest.mark.asyncio
    async def test_low_level_verify_alias_uses_split_lifecycle(self) -> None:
        split = self.SplitCharge()

        receipt = await verify_credential(
            intent=split,
            credential=make_credential(payload={}),
            request={},
        )

        assert receipt.reference == "split-ref"
        assert split.calls == ["validate", "broadcast"]

    @pytest.mark.asyncio
    async def test_rejects_intent_without_terminal_hook(self) -> None:
        class ValidationOnly:
            name = "charge"

            async def validate(self, credential: Credential, request: dict) -> Validation:
                return Validation(
                    challenge=credential.challenge,
                    credential=credential,
                    details={},
                    intent=self.name,
                    method=credential.challenge.method,
                    request=request,
                )

        with pytest.raises(VerificationFailedError, match="does not support credential broadcast"):
            await broadcast_credential(
                intent=ValidationOnly(),  # type: ignore[arg-type]
                credential=make_credential(payload={}),
                request={},
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("field", "value", "error"),
        [
            ("realm", "other.example.com", InvalidChallengeError),
            ("method", "stripe", PaymentMethodUnsupportedError),
            ("id", "tampered", InvalidChallengeError),
        ],
    )
    async def test_standalone_rejects_mismatched_challenge_fields(
        self,
        field: str,
        value: str,
        error: type[Exception],
    ) -> None:
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
        )
        credential = replace(
            credential,
            challenge=replace(credential.challenge, **{field: value}),
        )

        with pytest.raises(error):
            await self.server(self.SplitCharge()).validate_credential(credential)

    @pytest.mark.asyncio
    async def test_standalone_rejects_requested_intent_mismatch(self) -> None:
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
        )

        with pytest.raises(InvalidChallengeError):
            await self.server(self.SplitCharge()).validate_credential(
                credential,
                intent="refund",
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["not-a-credential", "Payment not-base64"])
    async def test_standalone_rejects_malformed_serialized_credential(self, value: str) -> None:
        with pytest.raises(MalformedCredentialError):
            await self.server(self.SplitCharge()).validate_credential(value)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("field", ["request", "opaque"])
    async def test_standalone_rejects_malformed_bound_fields(self, field: str) -> None:
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
        )
        credential = replace(
            credential,
            challenge=replace(credential.challenge, **{field: "not-base64"}),
        )

        with pytest.raises(MalformedCredentialError):
            await self.server(self.SplitCharge()).validate_credential(credential)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "expires",
        [
            None,
            "not-a-date",
            (datetime.now() + timedelta(hours=1)).isoformat(),
            (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        ],
    )
    async def test_standalone_rejects_missing_or_invalid_expiry(
        self,
        expires: str | None,
    ) -> None:
        challenge = Challenge.create(
            secret_key="test-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={},
            expires=expires,
        )
        credential = Credential(challenge=challenge.to_echo(), payload={})

        with pytest.raises(PaymentExpiredError):
            await self.server(self.SplitCharge()).validate_credential(credential)

    @pytest.mark.asyncio
    async def test_standalone_rejects_unregistered_intent(self) -> None:
        credential = make_bound_credential(
            payload={},
            request={},
            realm="api.example.com",
            secret_key="test-secret",
            intent="refund",
        )

        with pytest.raises(PaymentMethodUnsupportedError):
            await self.server(self.SplitCharge()).validate_credential(credential)


class TestVerificationError:
    @pytest.mark.asyncio
    async def test_returns_challenge_on_parse_error(self) -> None:
        """Should return challenge when credential parsing fails."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        result = await verify_or_challenge(
            authorization="Payment not-valid-base64!!",
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_emits_payment_failed_on_parse_error(self) -> None:
        """Should emit payment.failed for rejected Payment credentials."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on(
            "payment.failed",
            lambda payload: events.append(
                f"failed:{payload['challenge'].id}:{type(payload['error']).__name__}"
            ),
        )

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        result = await verify_or_challenge(
            authorization="Payment not-valid-base64!!",
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            events=dispatcher,
        )

        assert isinstance(result, Challenge)
        assert events == [f"failed:{result.id}:MalformedCredentialError"]

    @pytest.mark.asyncio
    async def test_emits_payment_failed_on_invalid_hmac(self) -> None:
        """Should emit payment.failed when the challenge ID is not server-issued."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on(
            "payment.failed",
            lambda payload: events.append(type(payload["error"]).__name__),
        )

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="wrong-secret",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            events=dispatcher,
        )

        assert isinstance(result, Challenge)
        assert events == ["InvalidChallengeError"]

    @pytest.mark.asyncio
    async def test_intent_can_raise_verification_error(self) -> None:
        """VerificationError should propagate from intent."""

        @intent(name="charge")
        async def failing_intent(credential: Credential, request: dict) -> Receipt:
            raise VerificationError("Payment verification failed")

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        auth_header = credential.to_authorization()

        with pytest.raises(VerificationError, match="Payment verification failed"):
            await verify_or_challenge(
                authorization=auth_header,
                intent=failing_intent,
                request={"amount": "1000"},
                realm="api.example.com",
                secret_key="test-secret",
            )

    @pytest.mark.asyncio
    async def test_emits_payment_failed_when_intent_raises(self) -> None:
        """Should emit payment.failed when method verification raises."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on(
            "payment.failed",
            lambda payload: events.append(
                f"failed:{payload['challenge'].id}:{type(payload['error']).__name__}"
            ),
        )

        @intent(name="charge")
        async def failing_intent(credential: Credential, request: dict) -> Receipt:
            raise VerificationError("Payment verification failed")

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        with pytest.raises(VerificationError, match="Payment verification failed"):
            await verify_or_challenge(
                authorization=credential.to_authorization(),
                intent=failing_intent,
                request={"amount": "1000"},
                realm="api.example.com",
                secret_key="test-secret",
                events=dispatcher,
            )

        assert events == [f"failed:{credential.challenge.id}:VerificationError"]

    @pytest.mark.asyncio
    async def test_returns_receipt_for_success(self) -> None:
        """Successful receipts should be returned normally."""

        @intent(name="charge")
        async def success_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-success-456")

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=success_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.status == "success"
        assert receipt.reference == "tx-success-456"


class TestChallengeExpiryEnforcement:
    @pytest.mark.asyncio
    async def test_rejects_expired_credential(self) -> None:
        """Should return a new challenge when echoed expires is in the past."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            expires="2020-01-01T00:00:00Z",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_accepts_unexpired_credential(self) -> None:
        """Should accept credential when echoed expires is in the future."""
        from datetime import UTC, datetime, timedelta

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            expires=future,
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.status == "success"

    @pytest.mark.asyncio
    async def test_rejects_missing_expires(self) -> None:
        """Should reject credentials that lack an expires field (fail closed)."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        # Construct a credential with no expires but a valid HMAC
        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            expires="",  # empty string to force falsy expires
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_rejects_malformed_expires(self) -> None:
        """Should reject credentials with unparseable expires (fail closed)."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            expires="not-a-date",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)


class TestCrossEndpointReplay:
    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_intent(self) -> None:
        """Should reject a credential whose echoed intent doesn't match the endpoint."""

        @intent(name="charge")
        async def charge_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @intent(name="session")
        async def session_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0xsession")

        # Create a credential for the "session" intent
        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "100"},
            realm="api.example.com",
            secret_key="test-secret",
            intent="session",
        )
        auth_header = credential.to_authorization()

        # Present it to the "charge" endpoint — should be rejected
        result = await verify_or_challenge(
            authorization=auth_header,
            intent=charge_intent,
            request={"amount": "100"},
            realm="api.example.com",
            secret_key="test-secret",
        )

        assert isinstance(result, Challenge)
        assert result.intent == "charge"


class MockRequest:
    """Mock request object for testing."""

    def __init__(
        self,
        authorization: str | None = None,
        body: bytes | None = None,
        path: str | None = None,
        route: str | None = None,
        query_string: str | None = None,
    ) -> None:
        self.headers = {"authorization": authorization} if authorization else {}
        self.body = body
        if path is not None:
            self.path = path
        if route is not None:
            self.route = route
        if query_string is not None:
            self.query_string = query_string


class DjangoStyleRequest:
    """Mock Django-style request object for testing."""

    def __init__(self, authorization: str | None = None) -> None:
        self.META = {"HTTP_AUTHORIZATION": authorization} if authorization else {}


def challenge_from_402(result) -> Challenge:
    headers = result.headers if HAS_STARLETTE else result["headers"]
    return Challenge.from_www_authenticate(headers["WWW-Authenticate"])


class TestWrapPaymentHandler:
    @pytest.mark.asyncio
    async def test_raises_type_error_when_request_is_none(self) -> None:
        """wrap_payment_handler should raise TypeError when request arg is missing."""
        from mpp.server.decorator import wrap_payment_handler

        async def verify_fn(auth, req):
            return Challenge.create(
                secret_key="s", realm="r", method="tempo", intent="charge", request={}
            )

        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {}

        wrapped = wrap_payment_handler(handler, verify_fn, lambda: "r")

        with pytest.raises(TypeError, match="Missing request argument 'req'"):
            await wrapped()


class TestPay:
    def test_framework_scope_handles_non_utf8_query_string(self) -> None:
        """framework_scope must not crash on non-UTF-8 query bytes from the wire."""
        from mpp.server.decorator import framework_scope

        class AsgiRequest:
            def __init__(self, query_string: bytes) -> None:
                self.scope = {
                    "type": "http",
                    "path": "/paid",
                    "query_string": query_string,
                }

        scope = framework_scope(AsgiRequest(b"\xff\xfe"))

        assert scope["resource"] == "/paid"
        assert scope["query"] == b"\xff\xfe".decode("latin-1")

    @pytest.mark.asyncio
    async def test_returns_402_when_no_authorization(self) -> None:
        """Should return 402 dict when no Authorization header."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid content"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            assert "WWW-Authenticate" in result.headers
            assert "Payment" in result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            assert result["status"] == 402
            assert "WWW-Authenticate" in result["headers"]
            assert "Payment" in result["headers"]["WWW-Authenticate"]

    @pytest.mark.asyncio
    async def test_forwards_events_to_verify(self) -> None:
        """Standalone pay() should forward configured event handlers."""
        events: list[str] = []
        dispatcher = EventDispatcher()
        dispatcher.on("challenge.created", lambda payload: events.append(payload["intent"]))

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            events=dispatcher,
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid content"}

        await handler(MockRequest())

        assert events == ["charge"]

    @pytest.mark.asyncio
    async def test_calls_handler_with_valid_credential(self) -> None:
        """Should call handler with credential and receipt when authorized."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {
                "data": "paid content",
                "receipt_ref": receipt.reference,
            }

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid content"
        assert result["receipt_ref"] == "tx-ref-123"

    def test_starlette_route_scope_binds_real_framework_abi(self) -> None:
        """Standalone pay() should bind Starlette route/resource/query scope."""
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(request, credential: Credential, receipt: Receipt):
            return JSONResponse({"data": "paid", "receipt_ref": receipt.reference})

        app = Starlette(routes=[Route("/paid/{id}", handler)])

        with TestClient(app) as client:
            challenge_response = client.get("/paid/one?view=full")
            assert challenge_response.status_code == 402

            challenge = Challenge.from_www_authenticate(
                challenge_response.headers["WWW-Authenticate"]
            )
            assert challenge.request["_mppx_scope"] == {
                "route": "/paid/{id}",
                "resource": "/paid/one",
                "query": "view=full",
            }

            credential = Credential(
                challenge=challenge.to_echo(),
                payload={"hash": "0xabc"},
            )
            replay_response = client.get(
                "/paid/two?view=full",
                headers={"Authorization": credential.to_authorization()},
            )

            assert replay_response.status_code == 402

    @pytest.mark.asyncio
    async def test_rejects_paid_retry_with_different_auto_route_scope(self) -> None:
        """Standalone pay() should bind credentials to framework route scope."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        challenge_result = await handler(
            MockRequest(path="/paid/one", route="/paid/{id}", query_string="view=full")
        )
        challenge = challenge_from_402(challenge_result)
        assert challenge.request["_mppx_scope"] == {
            "route": "/paid/{id}",
            "resource": "/paid/one",
            "query": "view=full",
        }
        credential = Credential(
            challenge=challenge.to_echo(),
            payload={"hash": "0xabc"},
        )

        result = await handler(
            MockRequest(
                authorization=credential.to_authorization(),
                path="/paid/two",
                route="/paid/{id}",
                query_string="view=full",
            )
        )

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert isinstance(result, dict)
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_supports_dynamic_request_params(self) -> None:
        """Should support callable request params."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert request["amount"] == "2000"
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request=lambda req: {"amount": req.query_amount},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        class RequestWithQuery(MockRequest):
            query_amount = "2000"

        credential = make_bound_credential(
            payload={},
            request={"amount": "2000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = RequestWithQuery(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid"

    @pytest.mark.asyncio
    async def test_body_callback_binds_and_verifies_actual_request_body(self) -> None:
        """Standalone pay() should use the configured body callback for digest verification."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            body=lambda req: req.body,
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        original_body = b'{"query":"paid"}'
        challenge_result = await handler(MockRequest(body=original_body))
        headers = (
            challenge_result["headers"]
            if isinstance(challenge_result, dict)
            else challenge_result.headers
        )
        challenge = Challenge.from_www_authenticate(headers["WWW-Authenticate"])
        assert challenge.digest == BodyDigest.compute(original_body)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=challenge.digest,
        )

        result = await handler(
            MockRequest(
                authorization=credential.to_authorization(),
                body=b'{"query":"tampered"}',
            )
        )

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert isinstance(result, dict)
            assert result["status"] == 402
        replacement = challenge_from_402(result)
        assert replacement.digest == BodyDigest.compute(b'{"query":"tampered"}')

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body_value",
        [
            '{"query":"paid"}',
            {"query": "paid"},
        ],
    )
    async def test_body_callback_supports_str_and_dict_values(self, body_value) -> None:
        """Standalone pay() should accept non-bytes body callback values."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            body=lambda _req: body_value,
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"receipt_ref": receipt.reference}

        challenge_result = await handler(MockRequest())
        challenge = challenge_from_402(challenge_result)
        assert challenge.digest == BodyDigest.compute(body_value)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=challenge.digest,
        )

        result = await handler(MockRequest(authorization=credential.to_authorization()))

        assert result == {"receipt_ref": "tx-ref-123"}

    @pytest.mark.asyncio
    async def test_supports_django_style_requests(self) -> None:
        """Should extract authorization from Django META."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(
            req: DjangoStyleRequest, credential: Credential, receipt: Receipt
        ) -> dict:
            return {"paid": True}

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = DjangoStyleRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["paid"] is True

    @pytest.mark.asyncio
    async def test_returns_402_for_invalid_scheme(self) -> None:
        """Should return 402 for non-Payment authorization."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        request = MockRequest(authorization="Bearer some-token")
        result = await handler(request)

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_preserves_function_metadata(self) -> None:
        """Decorator should preserve function name and docstring."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        async def my_handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            """My handler docstring."""
            return {"data": "paid"}

        assert my_handler.__name__ == "my_handler"
        assert my_handler.__doc__ == "My handler docstring."
        wrapped = getattr(my_handler, "__wrapped__", None)
        assert wrapped is not None
        assert wrapped.__name__ == "my_handler"

    @pytest.mark.asyncio
    async def test_custom_method_name(self) -> None:
        """Should pass custom method name to verify_or_challenge."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        @pay(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key="test-secret",
            method="custompay",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            www_auth = result["headers"]["WWW-Authenticate"]
        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.method == "custompay"


def _make_server(test_intent):
    """Create an Mpp instance with a mock method for testing."""

    class MockMethod:
        name = "tempo"
        currency = "0xUSD"
        recipient = "0xRecipient"
        decimals = 6
        intents = {"charge": test_intent}

        async def create_credential(self, challenge):
            return make_credential(payload={}, challenge_id="test")

    return Mpp(
        method=MockMethod(),
        realm="api.example.com",
        secret_key="test-secret",
    )


class TestMppPay:
    @pytest.mark.asyncio
    async def test_returns_402_when_no_authorization(self) -> None:
        """server.pay() should return 402 when no Authorization header."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid content"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            assert "WWW-Authenticate" in result.headers
            assert "Payment" in result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_exposes_server_event_helpers(self) -> None:
        """Mpp should expose mppx-compatible server event helper methods."""
        events: list[str] = []

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)
        server.on_challenge_created(
            lambda payload: events.append(f"challenge:{payload['request']['amount']}")
        )
        server.on_payment_success(
            lambda payload: events.append(f"success:{payload['receipt'].reference}")
        )
        assert callable(server.on_payment_failed(lambda payload: events.append("failed")))
        server.on("*", lambda event: events.append(f"*:{event.name}"))

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"receipt_ref": receipt.reference}

        challenge_result = await handler(MockRequest())
        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(challenge_result, StarletteResponse)
        else:
            assert isinstance(challenge_result, dict)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        success_result = await handler(MockRequest(authorization=credential.to_authorization()))

        assert success_result == {"receipt_ref": "tx-ref-456"}
        assert events == [
            "challenge:500000",
            "*:challenge.created",
            "success:tx-ref-456",
            "*:payment.success",
        ]

    @pytest.mark.asyncio
    async def test_calls_handler_with_valid_credential(self) -> None:
        """server.pay() should call handler with credential and receipt."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {
                "data": "paid content",
                "credential_id": credential.challenge.id,
                "receipt_ref": receipt.reference,
            }

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid content"
        assert result["receipt_ref"] == "tx-ref-456"

    @pytest.mark.asyncio
    async def test_rejects_paid_retry_with_different_auto_route_scope(self) -> None:
        """server.pay() should bind credentials to framework route scope."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"receipt_ref": receipt.reference}

        challenge_result = await handler(
            MockRequest(path="/paid/one", route="/paid/{id}", query_string="view=full")
        )
        challenge = challenge_from_402(challenge_result)
        assert challenge.request["_mppx_scope"] == {
            "route": "/paid/{id}",
            "resource": "/paid/one",
            "query": "view=full",
        }
        credential = Credential(
            challenge=challenge.to_echo(),
            payload={"hash": "0xabc"},
        )

        result = await handler(
            MockRequest(
                authorization=credential.to_authorization(),
                path="/paid/two",
                route="/paid/{id}",
                query_string="view=full",
            )
        )

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert isinstance(result, dict)
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_body_callback_binds_and_verifies_actual_request_body(self) -> None:
        """server.pay() should use the configured body callback for digest verification."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)

        @server.pay(amount="0.50", body=lambda req: req.body)
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"receipt_ref": receipt.reference}

        original_body = b'{"query":"paid"}'
        challenge_result = await handler(MockRequest(body=original_body))
        headers = (
            challenge_result["headers"]
            if isinstance(challenge_result, dict)
            else challenge_result.headers
        )
        challenge = Challenge.from_www_authenticate(headers["WWW-Authenticate"])
        assert challenge.digest == BodyDigest.compute(original_body)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=challenge.digest,
        )

        result = await handler(
            MockRequest(
                authorization=credential.to_authorization(),
                body=original_body,
            )
        )

        assert result == {"receipt_ref": "tx-ref-456"}

    @pytest.mark.asyncio
    async def test_charge_binds_and_verifies_body_digest(self) -> None:
        """Mpp.charge(body=...) should bind and verify the actual request body."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)
        body = b'{"query":"paid"}'

        challenge = await server.charge(authorization=None, amount="0.50", body=body)
        assert isinstance(challenge, Challenge)
        assert challenge.digest == BodyDigest.compute(body)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=challenge.digest,
        )

        result = await server.charge(
            authorization=credential.to_authorization(),
            amount="0.50",
            body=body,
        )

        assert isinstance(result, tuple)
        _credential, receipt = result
        assert receipt.status == "success"
        assert receipt.reference == "tx-ref-456"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body_value",
        [
            '{"query":"paid"}',
            {"query": "paid"},
        ],
    )
    async def test_body_callback_supports_str_and_dict_values(self, body_value) -> None:
        """server.pay() should accept non-bytes body callback values."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-456")

        server = _make_server(test_intent)

        @server.pay(amount="0.50", body=lambda _req: body_value)
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"receipt_ref": receipt.reference}

        challenge_result = await handler(MockRequest())
        challenge = challenge_from_402(challenge_result)
        assert challenge.digest == BodyDigest.compute(body_value)

        credential = make_bound_credential(
            payload={"hash": "0xabc"},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
            digest=challenge.digest,
        )

        result = await handler(MockRequest(authorization=credential.to_authorization()))

        assert result == {"receipt_ref": "tx-ref-456"}

    @pytest.mark.asyncio
    async def test_converts_human_amount_to_base_units(self) -> None:
        """server.pay() should convert human-readable amount via charge()."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert request["amount"] == "500000"  # 0.50 * 10^6
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        credential = make_bound_credential(
            payload={},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid"

    @pytest.mark.asyncio
    async def test_preserves_function_metadata(self) -> None:
        """server.pay() should preserve function name and docstring."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def my_handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            """My handler docstring."""
            return {"data": "paid"}

        assert my_handler.__name__ == "my_handler"
        assert my_handler.__doc__ == "My handler docstring."

    @pytest.mark.asyncio
    async def test_supports_currency_override(self) -> None:
        """server.pay() should allow overriding currency per-endpoint."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert request["currency"] == "0xOverride"
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="1.00", currency="0xOverride")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000000", "currency": "0xOverride", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid"

    @pytest.mark.asyncio
    async def test_supports_django_style_requests(self) -> None:
        """server.pay() should extract authorization from Django META."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(
            req: DjangoStyleRequest, credential: Credential, receipt: Receipt
        ) -> dict:
            return {"paid": True}

        credential = make_bound_credential(
            payload={},
            request={"amount": "500000", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = DjangoStyleRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["paid"] is True

    @pytest.mark.asyncio
    async def test_supports_recipient_override(self) -> None:
        """server.pay() should allow overriding recipient per-endpoint."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert request["recipient"] == "0xOverrideRecipient"
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="1.00", recipient="0xOverrideRecipient")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        credential = make_bound_credential(
            payload={},
            request={"amount": "1000000", "currency": "0xUSD", "recipient": "0xOverrideRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid"

    @pytest.mark.asyncio
    async def test_returns_402_for_invalid_scheme(self) -> None:
        """server.pay() should return 402 for non-Payment authorization."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        request = MockRequest(authorization="Bearer some-token")
        result = await handler(request)

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_passes_description(self) -> None:
        """server.pay() should pass description through to charge()."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50", description="Premium access")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            www_auth = result["headers"]["WWW-Authenticate"]
        assert 'description="Premium access"' in www_auth

    @pytest.mark.asyncio
    async def test_supports_custom_intent(self) -> None:
        """server.pay() should support intents other than charge."""

        @intent(name="session")
        async def session_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("session-ref")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": session_intent, "session": session_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.000075", intent="session")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "session", "receipt_ref": receipt.reference}

        credential = make_bound_credential(
            payload={},
            request={"amount": "75", "currency": "0xUSD", "recipient": "0xRecipient"},
            realm="api.example.com",
            secret_key="test-secret",
            intent="session",
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "session"
        assert result["receipt_ref"] == "session-ref"

    @pytest.mark.asyncio
    async def test_raises_for_unknown_intent(self) -> None:
        """server.pay() should raise ValueError for unsupported intent."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        with pytest.raises(ValueError, match="does not support nonexistent intent"):
            server.pay(amount="0.50", intent="nonexistent")

    @pytest.mark.asyncio
    async def test_raises_when_method_has_no_currency(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = None
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        with pytest.raises(
            ValueError, match=r"currency must be set on the method or passed to pay\(\)"
        ):
            await handler(MockRequest())

    @pytest.mark.asyncio
    async def test_raises_when_method_has_no_recipient(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = None
            decimals = 6
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        with pytest.raises(
            ValueError, match=r"recipient must be set on the method or passed to pay\(\)"
        ):
            await handler(MockRequest())

    @pytest.mark.asyncio
    async def test_passes_expires_and_extra_into_challenge(self) -> None:
        from datetime import UTC, datetime, timedelta

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50", extra={"plan": "pro"}, expires_in=timedelta(minutes=1))
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        before = datetime.now(UTC)
        result = await handler(MockRequest())
        after = datetime.now(UTC)

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            www_auth = result["headers"]["WWW-Authenticate"]

        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.request["extra"] == {"plan": "pro"}
        assert challenge.expires is not None
        expires = datetime.fromisoformat(challenge.expires)
        assert before + timedelta(seconds=59) < expires < after + timedelta(seconds=61)

    @pytest.mark.asyncio
    async def test_rejects_non_string_extra_values(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        @server.pay(amount="0.50", extra={"plan": "pro", "attempts": 1})  # type: ignore[dict-item]
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        with pytest.raises(ValueError, match=r"extra must be a dict\[str, str\]"):
            await handler(MockRequest())


class TestMppChainIdAutoEmit:
    """Tests for Mpp auto-emitting chainId from the method's chain_id."""

    @pytest.mark.asyncio
    async def test_charge_emits_chain_id_from_method(self) -> None:
        """Mpp.charge() should include chainId in methodDetails from method.chain_id."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            chain_id = 42431
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await server.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert result.request["methodDetails"]["chainId"] == 42431

    @pytest.mark.asyncio
    async def test_charge_explicit_chain_id_overrides_method(self) -> None:
        """Explicit chain_id= on charge() should override method.chain_id."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            chain_id = 42431
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await server.charge(authorization=None, amount="0.50", chain_id=4217)
        assert isinstance(result, Challenge)
        assert result.request["methodDetails"]["chainId"] == 4217

    @pytest.mark.asyncio
    async def test_charge_no_chain_id_no_method_details(self) -> None:
        """No chainId when method has no chain_id and none passed."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        server = _make_server(test_intent)

        result = await server.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert "methodDetails" not in result.request

    @pytest.mark.asyncio
    async def test_pay_decorator_emits_chain_id_from_method(self) -> None:
        """server.pay() should include chainId from method.chain_id."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            chain_id = 42431
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            www_auth = result["headers"]["WWW-Authenticate"]
        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.request["methodDetails"]["chainId"] == 42431

    @pytest.mark.asyncio
    async def test_pay_decorator_explicit_chain_id_overrides(self) -> None:
        """server.pay(chain_id=4217) should override method.chain_id."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            chain_id = 42431
            intents = {"charge": test_intent}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50", chain_id=4217)
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            www_auth = result["headers"]["WWW-Authenticate"]
        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.request["methodDetails"]["chainId"] == 4217


class TestMppRequestTransformHook:
    """Tests for method.transform_request integration in Mpp helpers."""

    @pytest.mark.asyncio
    async def test_charge_applies_method_transform_request(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": test_intent}

            def transform_request(self, request: dict, credential: Credential | None) -> dict:
                assert credential is None
                return {**request, "extra": {"hook": "charge"}}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await server.charge(authorization=None, amount="0.50")
        assert isinstance(result, Challenge)
        assert result.request["extra"]["hook"] == "charge"

    @pytest.mark.asyncio
    async def test_pay_applies_method_transform_request(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": test_intent}

            def transform_request(self, request: dict, credential: Credential | None) -> dict:
                assert credential is None
                return {**request, "extra": {"hook": "pay"}}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())
        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(result, StarletteResponse)
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            www_auth = result["headers"]["WWW-Authenticate"]

        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.request["extra"]["hook"] == "pay"

    @pytest.mark.asyncio
    async def test_charge_transform_request_is_deterministic_across_retries(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        seen: list[bool] = []

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": test_intent}

            def transform_request(self, request: dict, credential: Credential | None) -> dict:
                seen.append(credential is not None)
                marker = "credential" if credential is not None else "none"
                return {**request, "extra": {"hook": marker}}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        first = await server.charge(authorization=None, amount="0.50")
        assert isinstance(first, Challenge)
        assert first.request["extra"]["hook"] == "none"

        credential = make_bound_credential(
            payload={},
            request=first.request,
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await server.charge(authorization=credential.to_authorization(), amount="0.50")
        assert isinstance(result, tuple)
        assert seen == [False, False]

    @pytest.mark.asyncio
    async def test_pay_transform_request_is_deterministic_across_retries(self) -> None:
        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123")

        seen: list[bool] = []

        class MockMethod:
            name = "tempo"
            currency = "0xUSD"
            recipient = "0xRecipient"
            decimals = 6
            intents = {"charge": test_intent}

            def transform_request(self, request: dict, credential: Credential | None) -> dict:
                seen.append(credential is not None)
                marker = "credential" if credential is not None else "none"
                return {**request, "extra": {"hook": marker}}

        server = Mpp(
            method=MockMethod(),  # type: ignore[arg-type]
            realm="api.example.com",
            secret_key="test-secret",
        )

        @server.pay(amount="0.50")
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        challenge_result = await handler(MockRequest())
        if HAS_STARLETTE:
            assert StarletteResponse is not None
            assert isinstance(challenge_result, StarletteResponse)
            challenge = Challenge.from_www_authenticate(
                challenge_result.headers["WWW-Authenticate"]
            )
        else:
            assert isinstance(challenge_result, dict)
            challenge = Challenge.from_www_authenticate(
                challenge_result["headers"]["WWW-Authenticate"]
            )

        credential = make_bound_credential(
            payload={},
            request=challenge.request,
            realm="api.example.com",
            secret_key="test-secret",
        )

        result = await handler(MockRequest(authorization=credential.to_authorization()))
        assert result["data"] == "paid"
        assert seen == [False, False]


class TestMalformedEchoedFields:
    """Malformed base64 in echoed request/opaque should re-issue challenge, not crash."""

    @pytest.mark.asyncio
    async def test_returns_challenge_for_invalid_base64_request(self) -> None:
        """Invalid base64 in echoed request should return challenge, not 500."""
        from mpp import ChallengeEcho, Credential

        echo = ChallengeEcho(
            id="fake-id",
            realm="r",
            method="tempo",
            intent="charge",
            request="not!valid!base64!!!",
        )
        credential = Credential(challenge=echo, payload={"sig": "0x"})

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request={"amount": "1000"},
            realm="r",
            secret_key="test-secret",
        )
        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_returns_challenge_for_invalid_base64_opaque(self) -> None:
        """Invalid base64 in echoed opaque should return challenge, not 500."""
        from mpp import ChallengeEcho, Credential

        echo = ChallengeEcho(
            id="fake-id",
            realm="r",
            method="tempo",
            intent="charge",
            request="e30",  # valid base64 for {}
            opaque="not!valid!base64!!!",
        )
        credential = Credential(challenge=echo, payload={"sig": "0x"})

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request={"amount": "1000"},
            realm="r",
            secret_key="test-secret",
        )
        assert isinstance(result, Challenge)


class TestExpiresEnforcement:
    """Transport-layer expires enforcement as defense-in-depth."""

    @pytest.mark.asyncio
    async def test_rejects_expired_credential(self) -> None:
        """Credential with expired challenge should be rejected at transport layer."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            secret_key="test-secret",
            expires="2020-01-01T00:00:00.000Z",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="r",
            secret_key="test-secret",
        )
        assert isinstance(result, Challenge), "Should reject expired credential"

    @pytest.mark.asyncio
    async def test_accepts_non_expired_credential(self) -> None:
        """Credential with future expires should be accepted."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0xOK")

        request = {"amount": "1000"}
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            secret_key="test-secret",
            expires="2099-01-01T00:00:00.000Z",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="r",
            secret_key="test-secret",
        )
        assert isinstance(result, tuple), "Should accept non-expired credential"


class TestRequestSubstitutionPrevention:
    """Credential for one request should be rejected at a different request endpoint."""

    @pytest.mark.asyncio
    async def test_rejects_credential_for_different_amount(self) -> None:
        """Cheap-route credential should not work at expensive route."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        cheap_request = {"amount": "100", "currency": "0xUSD", "recipient": "0xR"}
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=cheap_request,
            realm="r",
            secret_key="test-secret",
        )

        expensive_request = {"amount": "999999", "currency": "0xUSD", "recipient": "0xR"}
        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=expensive_request,
            realm="r",
            secret_key="test-secret",
        )
        assert isinstance(result, Challenge), "Should reject credential for different amount"

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_opaque(self) -> None:
        """Credential with mismatched opaque/meta should be rejected."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            secret_key="test-secret",
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="r",
            secret_key="test-secret",
            meta={"tier": "premium"},
        )
        assert isinstance(result, Challenge), "Should reject credential with wrong opaque"


class TestCrossRealmPrevention:
    """After HMAC verification, assert echoed realm/method/intent match."""

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_realm(self) -> None:
        """Credential issued for realm-A should be rejected at realm-B."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        shared_secret = "shared-key"
        request = {"amount": "1000"}

        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="realm-A",
            secret_key=shared_secret,
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="realm-B",
            secret_key=shared_secret,
        )
        assert isinstance(result, Challenge), "Should reject cross-realm credential"

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_method(self) -> None:
        """Credential for method-A should be rejected when server expects method-B."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        secret = "test-secret"
        request = {"amount": "1000"}

        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            method="tempo",
            secret_key=secret,
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="r",
            method="stripe",
            secret_key=secret,
        )
        assert isinstance(result, Challenge), "Should reject wrong method"

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_intent(self) -> None:
        """Credential for intent 'charge' should be rejected when server expects 'session'."""

        class SessionIntent:
            name = "session"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        secret = "test-secret"
        request = {"amount": "1000"}

        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            intent="charge",
            secret_key=secret,
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=SessionIntent(),
            request=request,
            realm="r",
            secret_key=secret,
        )
        assert isinstance(result, Challenge), "Should reject wrong intent"

    @pytest.mark.asyncio
    async def test_accepts_matching_realm_method_intent(self) -> None:
        """Credential should be accepted when realm/method/intent all match."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0xOK")

        secret = "test-secret"
        request = {"amount": "1000"}

        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            method="tempo",
            intent="charge",
            secret_key=secret,
        )

        result = await verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),
            request=request,
            realm="r",
            method="tempo",
            secret_key=secret,
        )
        assert isinstance(result, tuple), "Should accept matching credential"
        _, receipt = result
        assert receipt.reference == "0xOK"
