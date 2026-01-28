"""Tests for server-side verification."""

import pytest

from mpay import Challenge, ChallengeEcho, Credential, Receipt
from mpay.server import intent, requires_payment, verify_or_challenge
from mpay.server.intent import VerificationError
from mpay.server.verify import _compute_challenge_id, verify_challenge_id

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
            return Receipt.success("0x123", method="tempo")

        result = await verify_or_challenge(
            authorization=None,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )

        assert isinstance(result, Challenge)
        assert result.method == "tempo"
        assert result.intent == "charge"
        assert result.request == {"amount": "1000"}

    @pytest.mark.asyncio
    async def test_returns_challenge_when_invalid_scheme(self) -> None:
        """Should return a challenge for non-Payment authorization."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        result = await verify_or_challenge(
            authorization="Bearer token123",
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_verifies_valid_credential(self) -> None:
        """Should verify a valid credential and return receipt."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert credential.challenge.id == "test-id"
            assert credential.payload == {"hash": "0xabc"}
            return Receipt.success("0x123", method="tempo")

        credential = Credential(
            challenge=ChallengeEcho(
                id="test-id",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={"hash": "0xabc"},
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )

        assert isinstance(result, tuple)
        cred, receipt = result
        assert cred.challenge.id == "test-id"
        assert receipt.status == "success"


class TestHMACBoundChallengeIds:
    def test_compute_challenge_id_deterministic(self) -> None:
        """HMAC challenge ID should be deterministic."""
        id1 = _compute_challenge_id(
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=None,
            digest=None,
            secret_key="test-secret",
        )
        id2 = _compute_challenge_id(
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=None,
            digest=None,
            secret_key="test-secret",
        )
        assert id1 == id2

    def test_compute_challenge_id_different_inputs(self) -> None:
        """Different inputs should produce different HMAC IDs."""
        id1 = _compute_challenge_id(
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=None,
            digest=None,
            secret_key="test-secret",
        )
        id2 = _compute_challenge_id(
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "2000"},  # Different amount
            expires=None,
            digest=None,
            secret_key="test-secret",
        )
        assert id1 != id2

    def test_verify_challenge_id_valid(self) -> None:
        """Should verify valid HMAC-bound challenge ID."""
        secret_key = "test-secret"
        realm = "api.example.com"
        request = {"amount": "1000"}

        # Compute the expected ID
        challenge_id = _compute_challenge_id(
            realm=realm,
            method="tempo",
            intent="charge",
            request=request,
            expires=None,
            digest=None,
            secret_key=secret_key,
        )

        # Create credential with the computed ID
        credential = Credential(
            challenge=ChallengeEcho(
                id=challenge_id,
                realm=realm,
                method="tempo",
                intent="charge",
                request=request,
            ),
            payload={"hash": "0xabc"},
        )

        assert verify_challenge_id(credential, realm, secret_key) is True

    def test_verify_challenge_id_invalid(self) -> None:
        """Should reject invalid HMAC-bound challenge ID."""
        credential = Credential(
            challenge=ChallengeEcho(
                id="tampered-id",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={"hash": "0xabc"},
        )

        assert verify_challenge_id(credential, "api.example.com", "test-secret") is False

    @pytest.mark.asyncio
    async def test_verify_or_challenge_with_secret_key(self) -> None:
        """Should use HMAC-bound IDs when secret_key is provided."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        secret_key = "test-secret"
        realm = "api.example.com"
        request = {"amount": "1000"}

        # Get challenge with HMAC-bound ID
        result = await verify_or_challenge(
            authorization=None,
            intent=test_intent,
            request=request,
            realm=realm,
            secret_key=secret_key,
        )

        assert isinstance(result, Challenge)
        # HMAC mode uses expires=None for deterministic IDs (stateless verification)
        assert result.expires is None

        # Verify the challenge ID is HMAC-bound
        expected_id = _compute_challenge_id(
            realm=realm,
            method="tempo",
            intent="charge",
            request=request,
            expires=None,
            digest=None,
            secret_key=secret_key,
        )
        assert result.id == expected_id

    @pytest.mark.asyncio
    async def test_verify_or_challenge_rejects_invalid_hmac(self) -> None:
        """Should reject credentials with invalid HMAC IDs."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        secret_key = "test-secret"
        realm = "api.example.com"
        request = {"amount": "1000"}

        # Create credential with invalid ID
        credential = Credential(
            challenge=ChallengeEcho(
                id="invalid-id",
                realm=realm,
                method="tempo",
                intent="charge",
                request=request,
            ),
            payload={"hash": "0xabc"},
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=test_intent,
            request=request,
            realm=realm,
            secret_key=secret_key,
        )

        # Should return a new challenge instead of accepting invalid credential
        assert isinstance(result, Challenge)


class TestFunctionalIntent:
    @pytest.mark.asyncio
    async def test_decorator_creates_intent(self) -> None:
        """@intent decorator should create a functional intent."""

        @intent(name="subscribe")
        async def my_subscribe(credential: Credential, request: dict) -> Receipt:
            return Receipt.success(f"sub-{credential.challenge.id}", method="tempo")

        assert my_subscribe.name == "subscribe"

        receipt = await my_subscribe.verify(
            Credential(
                challenge=ChallengeEcho(
                    id="test",
                    realm="test.com",
                    method="tempo",
                    intent="subscribe",
                    request={"plan": "premium"},
                ),
                payload={},
            ),
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
                return Receipt.success("custom-ref", method="custom-method")

        credential = Credential(
            challenge=ChallengeEcho(
                id="test",
                realm="test.com",
                method="custom-method",
                intent="custom",
                request={},
            ),
            payload={},
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=MyIntent(),
            request={},
            realm="test",
            method="custom-method",
        )

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.reference == "custom-ref"


class TestVerificationError:
    @pytest.mark.asyncio
    async def test_returns_challenge_on_parse_error(self) -> None:
        """Should return challenge when credential parsing fails."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        result = await verify_or_challenge(
            authorization="Payment not-valid-base64!!",
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )

        assert isinstance(result, Challenge)

    @pytest.mark.asyncio
    async def test_intent_can_raise_verification_error(self) -> None:
        """VerificationError from intent should propagate to caller."""

        @intent(name="charge")
        async def failing_intent(credential: Credential, request: dict) -> Receipt:
            raise VerificationError("Payment verification failed")

        credential = Credential(
            challenge=ChallengeEcho(
                id="test",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={},
        )
        auth_header = credential.to_authorization()

        with pytest.raises(VerificationError, match="Payment verification failed"):
            await verify_or_challenge(
                authorization=auth_header,
                intent=failing_intent,
                request={"amount": "1000"},
                realm="api.example.com",
            )


class MockRequest:
    """Mock request object for testing."""

    def __init__(self, authorization: str | None = None) -> None:
        self.headers = {"authorization": authorization} if authorization else {}


class DjangoStyleRequest:
    """Mock Django-style request object for testing."""

    def __init__(self, authorization: str | None = None) -> None:
        self.META = {"HTTP_AUTHORIZATION": authorization} if authorization else {}


class TestRequiresPayment:
    @pytest.mark.asyncio
    async def test_returns_402_when_no_authorization(self) -> None:
        """Should return 402 dict when no Authorization header."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid content"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            assert "WWW-Authenticate" in result.headers
            assert "Payment" in result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            assert result["_mpay_challenge"] is True
            assert result["status"] == 402
            assert "WWW-Authenticate" in result["headers"]
            assert "Payment" in result["headers"]["WWW-Authenticate"]

    @pytest.mark.asyncio
    async def test_calls_handler_with_valid_credential(self) -> None:
        """Should call handler with credential and receipt when authorized."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("tx-ref-123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {
                "data": "paid content",
                "credential_id": credential.challenge.id,
                "receipt_ref": receipt.reference,
            }

        credential = Credential(
            challenge=ChallengeEcho(
                id="test-cred-id",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={"hash": "0xabc"},
        )
        request = MockRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid content"
        assert result["credential_id"] == "test-cred-id"
        assert result["receipt_ref"] == "tx-ref-123"

    @pytest.mark.asyncio
    async def test_supports_dynamic_request_params(self) -> None:
        """Should support callable request params."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            assert request["amount"] == "2000"
            return Receipt.success("0x123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request=lambda req: {"amount": req.query_amount},
            realm="api.example.com",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        class RequestWithQuery(MockRequest):
            query_amount = "2000"

        credential = Credential(
            challenge=ChallengeEcho(
                id="test",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "2000"},
            ),
            payload={},
        )
        request = RequestWithQuery(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["data"] == "paid"

    @pytest.mark.asyncio
    async def test_supports_django_style_requests(self) -> None:
        """Should extract authorization from Django META."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def handler(
            req: DjangoStyleRequest, credential: Credential, receipt: Receipt
        ) -> dict:
            return {"credential_id": credential.challenge.id}

        credential = Credential(
            challenge=ChallengeEcho(
                id="django-cred",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000"},
            ),
            payload={},
        )
        request = DjangoStyleRequest(authorization=credential.to_authorization())
        result = await handler(request)

        assert result["credential_id"] == "django-cred"

    @pytest.mark.asyncio
    async def test_returns_402_for_invalid_scheme(self) -> None:
        """Should return 402 for non-Payment authorization."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        request = MockRequest(authorization="Bearer some-token")
        result = await handler(request)

        if HAS_STARLETTE:
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
            assert result["_mpay_challenge"] is True
            assert result["status"] == 402

    @pytest.mark.asyncio
    async def test_preserves_function_metadata(self) -> None:
        """Decorator should preserve function name and docstring."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="tempo")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def my_handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            """My handler docstring."""
            return {"data": "paid"}

        assert my_handler.__name__ == "my_handler"
        assert my_handler.__doc__ == "My handler docstring."

    @pytest.mark.asyncio
    async def test_custom_method_name(self) -> None:
        """Should pass custom method name to verify_or_challenge."""

        @intent(name="charge")
        async def test_intent(credential: Credential, request: dict) -> Receipt:
            return Receipt.success("0x123", method="custom-method")

        @requires_payment(
            intent=test_intent,
            request={"amount": "1000"},
            realm="api.example.com",
            method="custom-method",
        )
        async def handler(req: MockRequest, credential: Credential, receipt: Receipt) -> dict:
            return {"data": "paid"}

        result = await handler(MockRequest())

        if HAS_STARLETTE:
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            www_auth = result.headers["WWW-Authenticate"]
        else:
            assert result["_mpay_challenge"] is True
            www_auth = result["headers"]["WWW-Authenticate"]
        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.method == "custom-method"
