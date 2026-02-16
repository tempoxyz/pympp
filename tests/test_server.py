"""Tests for server-side verification."""

import pytest

from mpp import Challenge, Credential, Receipt
from mpp.server import Mpp, intent, pay, verify_or_challenge
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
        assert "expires" in result.request  # default expires is added

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
            method="custom-method",
            intent="custom",
        )
        auth_header = credential.to_authorization()

        result = await verify_or_challenge(
            authorization=auth_header,
            intent=MyIntent(),
            request={},
            realm="test",
            secret_key="test-secret",
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


class MockRequest:
    """Mock request object for testing."""

    def __init__(self, authorization: str | None = None) -> None:
        self.headers = {"authorization": authorization} if authorization else {}


class DjangoStyleRequest:
    """Mock Django-style request object for testing."""

    def __init__(self, authorization: str | None = None) -> None:
        self.META = {"HTTP_AUTHORIZATION": authorization} if authorization else {}


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
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
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
            assert result["_mpp_challenge"] is True
            www_auth = result["headers"]["WWW-Authenticate"]
        challenge = Challenge.from_www_authenticate(www_auth)
        assert challenge.method == "custom-method"


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
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            assert "WWW-Authenticate" in result.headers
            assert "Payment" in result.headers["WWW-Authenticate"]
        else:
            assert isinstance(result, dict)
            assert result["_mpp_challenge"] is True
            assert result["status"] == 402

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
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
        else:
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
            assert isinstance(result, StarletteResponse)
            assert result.status_code == 402
            www_auth = result.headers["WWW-Authenticate"]
        else:
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
            method=MockMethod(),
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
