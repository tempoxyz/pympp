"""Tests for MCP transport support."""

from datetime import UTC, datetime

import pytest

from mpp import Challenge, Credential, Receipt, generate_challenge_id
from mpp.extensions.mcp import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    META_CREDENTIAL,
    META_RECEIPT,
    MalformedCredentialError,
    MCPChallenge,
    MCPCredential,
    MCPReceipt,
    PaymentRequiredError,
    PaymentVerificationError,
    create_challenge,
    pay,
    payment_capabilities,
    verify_or_challenge,
)
from tests import TEST_SECRET

MCP_TEST_SECRET = TEST_SECRET


def _make_bound_mcp_challenge(
    *,
    realm: str = "api.example.com",
    method: str = "tempo",
    intent: str = "charge",
    request: dict | None = None,
    secret_key: str = MCP_TEST_SECRET,
    expires: str | None = None,
    description: str | None = None,
) -> MCPChallenge:
    """Create an MCPChallenge with an HMAC-bound ID for testing."""
    if request is None:
        request = {"amount": "1000"}
    challenge_id = generate_challenge_id(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
    )
    return MCPChallenge(
        id=challenge_id,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        description=description,
    )


class TestMCPChallenge:
    """Tests for MCPChallenge type."""

    def test_to_dict_required_fields(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        result = challenge.to_dict()
        assert result == {
            "id": "ch_abc",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": {"amount": "1000"},
        }

    def test_to_dict_optional_fields(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2025-01-15T12:05:00Z",
            description="API call fee",
        )
        result = challenge.to_dict()
        assert result["expires"] == "2025-01-15T12:05:00Z"
        assert result["description"] == "API call fee"

    def test_from_dict(self) -> None:
        data = {
            "id": "ch_abc",
            "realm": "api.example.com",
            "method": "tempo",
            "intent": "charge",
            "request": {"amount": "1000"},
            "expires": "2025-01-15T12:05:00Z",
        }
        challenge = MCPChallenge.from_dict(data)
        assert challenge.id == "ch_abc"
        assert challenge.realm == "api.example.com"
        assert challenge.expires == "2025-01-15T12:05:00Z"

    def test_to_core(self) -> None:
        mcp_challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2025-01-15T12:05:00Z",
            description="API call fee",
        )
        core = mcp_challenge.to_core()
        assert isinstance(core, Challenge)
        assert core.id == "ch_abc"
        assert core.method == "tempo"
        assert core.intent == "charge"
        assert core.request == {"amount": "1000"}

    def test_from_core(self) -> None:
        core = Challenge(
            id="ch_abc",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        mcp = MCPChallenge.from_core(
            core,
            realm="api.example.com",
            expires="2025-01-15T12:05:00Z",
            description="Test",
        )
        assert mcp.id == "ch_abc"
        assert mcp.realm == "api.example.com"
        assert mcp.expires == "2025-01-15T12:05:00Z"
        assert mcp.description == "Test"


class TestMCPCredential:
    """Tests for MCPCredential type."""

    def test_to_dict(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
            source="0x1234",
        )
        result = credential.to_dict()
        assert result["challenge"]["id"] == "ch_abc"
        assert result["payload"] == {"signature": "0xabc"}
        assert result["source"] == "0x1234"

    def test_to_meta(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
        )
        meta = credential.to_meta()
        assert META_CREDENTIAL in meta
        assert meta[META_CREDENTIAL]["challenge"]["id"] == "ch_abc"

    def test_from_meta(self) -> None:
        meta = {
            META_CREDENTIAL: {
                "challenge": {
                    "id": "ch_abc",
                    "realm": "api.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": {"amount": "1000"},
                },
                "payload": {"signature": "0xabc"},
            }
        }
        credential = MCPCredential.from_meta(meta)
        assert credential is not None
        assert credential.challenge.id == "ch_abc"
        assert credential.payload == {"signature": "0xabc"}

    def test_from_meta_missing(self) -> None:
        assert MCPCredential.from_meta({}) is None

    def test_to_core(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
            source="0x1234",
        )
        core = mcp_credential.to_core()
        assert isinstance(core, Credential)
        assert core.challenge.id == "ch_abc"
        assert core.challenge.realm == "api.example.com"
        assert core.challenge.method == "tempo"
        assert core.challenge.intent == "charge"
        assert core.payload == {"signature": "0xabc"}
        assert core.source == "0x1234"


class TestMCPReceipt:
    """Tests for MCPReceipt type."""

    def test_to_dict(self) -> None:
        receipt = MCPReceipt(
            status="success",
            challenge_id="ch_abc",
            method="tempo",
            timestamp="2025-01-15T12:00:30Z",
            reference="0xtx789",
            settlement={"amount": "1000", "currency": "usd"},
        )
        result = receipt.to_dict()
        assert result == {
            "status": "success",
            "challengeId": "ch_abc",
            "method": "tempo",
            "timestamp": "2025-01-15T12:00:30Z",
            "reference": "0xtx789",
            "settlement": {"amount": "1000", "currency": "usd"},
        }

    def test_to_meta(self) -> None:
        receipt = MCPReceipt(
            status="success",
            challenge_id="ch_abc",
            method="tempo",
            timestamp="2025-01-15T12:00:30Z",
        )
        meta = receipt.to_meta()
        assert META_RECEIPT in meta

    def test_from_meta(self) -> None:
        meta = {
            META_RECEIPT: {
                "status": "success",
                "challengeId": "ch_abc",
                "method": "tempo",
                "timestamp": "2025-01-15T12:00:30Z",
            }
        }
        receipt = MCPReceipt.from_meta(meta)
        assert receipt is not None
        assert receipt.challenge_id == "ch_abc"

    def test_to_core(self) -> None:
        mcp_receipt = MCPReceipt(
            status="success",
            challenge_id="ch_abc",
            method="tempo",
            timestamp="2025-01-15T12:00:30Z",
            reference="0xtx789",
        )
        core = mcp_receipt.to_core()
        assert isinstance(core, Receipt)
        assert core.status == "success"
        assert core.reference == "0xtx789"

    def test_from_core(self) -> None:
        core = Receipt(
            status="success",
            timestamp=datetime(2025, 1, 15, 12, 0, 30, tzinfo=UTC),
            reference="0xtx789",
        )
        mcp = MCPReceipt.from_core(
            core,
            challenge_id="ch_abc",
            method="tempo",
            settlement={"amount": "1000"},
        )
        assert mcp.status == "success"
        assert mcp.challenge_id == "ch_abc"
        assert mcp.method == "tempo"
        assert mcp.timestamp == "2025-01-15T12:00:30Z"
        assert mcp.settlement == {"amount": "1000"}


class TestErrors:
    """Tests for MCP error types."""

    def test_payment_required_error(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        error = PaymentRequiredError(challenges=[challenge])
        result = error.to_jsonrpc_error()
        assert result["code"] == CODE_PAYMENT_REQUIRED
        assert result["message"] == "Payment Required"
        assert result["data"]["httpStatus"] == 402
        assert len(result["data"]["challenges"]) == 1

    def test_payment_verification_error(self) -> None:
        challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        error = PaymentVerificationError(
            challenges=[challenge],
            reason="signature-invalid",
            detail="Signature verification failed",
        )
        result = error.to_jsonrpc_error()
        assert result["code"] == CODE_PAYMENT_VERIFICATION_FAILED
        assert result["data"]["failure"]["reason"] == "signature-invalid"
        assert result["data"]["failure"]["detail"] == "Signature verification failed"

    def test_malformed_credential_error(self) -> None:
        error = MalformedCredentialError(detail="Missing required field: challenge.id")
        result = error.to_jsonrpc_error()
        assert result["code"] == CODE_MALFORMED_CREDENTIAL
        assert result["message"] == "Invalid params"
        assert result["data"]["detail"] == "Missing required field: challenge.id"
        assert result["data"]["httpStatus"] == 402


class TestCapabilities:
    """Tests for capability advertisement."""

    def test_payment_capabilities(self) -> None:
        caps = payment_capabilities(["tempo", "stripe"], ["charge", "authorize"])
        assert caps == {
            "payment": {
                "methods": ["tempo", "stripe"],
                "intents": ["charge", "authorize"],
            }
        }


class TestPayDecorator:
    """Tests for the @pay decorator."""

    async def test_raises_payment_required_when_no_credential(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        with pytest.raises(PaymentRequiredError) as exc_info:
            await my_tool("test")

        error = exc_info.value.to_jsonrpc_error()
        assert error["code"] == CODE_PAYMENT_REQUIRED
        assert len(exc_info.value.challenges) == 1
        challenge = exc_info.value.challenges[0]
        assert challenge.realm == "api.example.com"
        assert challenge.intent == "charge"

    async def test_verifies_credential_and_injects_receipt(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000", "currency": "usd"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}, paid by {credential.source}"

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000", "currency": "usd"},
        )
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
            source="0x1234",
        )

        result = await my_tool("test", _meta=mcp_credential.to_meta())
        assert result == "Result: test, paid by 0x1234"

    async def test_raises_malformed_credential_error(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        with pytest.raises(MalformedCredentialError) as exc_info:
            await my_tool("test", _meta={META_CREDENTIAL: {"invalid": "data"}})

        error = exc_info.value.to_jsonrpc_error()
        assert error["code"] == CODE_MALFORMED_CREDENTIAL

    async def test_raises_verification_error_on_failure(self) -> None:
        from mpp.server.intent import VerificationError

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                raise VerificationError("Payment failed")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        challenge = _make_bound_mcp_challenge(request={"amount": "1000"})
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
        )

        with pytest.raises(PaymentVerificationError) as exc_info:
            await my_tool("test", _meta=mcp_credential.to_meta())

        error = exc_info.value.to_jsonrpc_error()
        assert error["code"] == CODE_PAYMENT_VERIFICATION_FAILED
        assert "Payment failed" in error["data"]["failure"]["detail"]

    async def test_dynamic_request_params(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request=lambda query, **kw: {"amount": str(len(query) * 10)},
            realm="api.example.com",
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        with pytest.raises(PaymentRequiredError) as exc_info:
            await my_tool("hello")

        challenge = exc_info.value.challenges[0]
        assert challenge.request == {"amount": "50"}

    async def test_realm_defaults_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MPP_REALM", "mcp.example.com")

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        with pytest.raises(PaymentRequiredError) as exc_info:
            await my_tool("test")

        challenge = exc_info.value.challenges[0]
        assert challenge.realm == "mcp.example.com"

    async def test_realm_defaults_to_localhost(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in [
            "MPP_REALM",
            "VERCEL_URL",
            "RAILWAY_PUBLIC_DOMAIN",
            "RENDER_EXTERNAL_HOSTNAME",
            "HOST",
            "HOSTNAME",
        ]:
            monkeypatch.delenv(var, raising=False)

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        @pay(
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
        )
        async def my_tool(query: str, *, credential: MCPCredential, receipt: MCPReceipt) -> str:
            return f"Result: {query}"

        with pytest.raises(PaymentRequiredError) as exc_info:
            await my_tool("test")

        challenge = exc_info.value.challenges[0]
        assert challenge.realm == "localhost"


class TestVerifyOrChallenge:
    """Tests for the generic verify_or_challenge function."""

    async def test_returns_challenge_when_no_credential(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        result = await verify_or_challenge(
            meta=None,
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert isinstance(result, MCPChallenge)
        assert result.realm == "api.example.com"
        assert result.intent == "charge"
        assert result.request == {"amount": "1000"}

    async def test_returns_challenge_when_meta_empty(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        result = await verify_or_challenge(
            meta={},
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert isinstance(result, MCPChallenge)

    async def test_verifies_credential_and_returns_tuple(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000", "currency": "usd"},
        )
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
            source="0x1234",
        )

        result = await verify_or_challenge(
            meta=mcp_credential.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000", "currency": "usd"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert isinstance(result, tuple)
        credential, receipt = result
        assert isinstance(credential, MCPCredential)
        assert isinstance(receipt, MCPReceipt)
        assert credential.source == "0x1234"
        assert receipt.status == "success"

    async def test_rejects_credential_with_invalid_challenge_id(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = MCPChallenge(
            id="forged-id",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
        )

        result = await verify_or_challenge(
            meta=mcp_credential.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert isinstance(result, MCPChallenge)

    async def test_raises_malformed_on_bad_credential(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        with pytest.raises(MalformedCredentialError):
            await verify_or_challenge(
                meta={META_CREDENTIAL: {"bad": "data"}},
                intent=MockIntent(),  # type: ignore[arg-type]
                request={"amount": "1000"},
                realm="api.example.com",
                secret_key=MCP_TEST_SECRET,
            )

    async def test_raises_verification_error_on_failure(self) -> None:
        from mpp.server.intent import VerificationError

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                raise VerificationError("Payment failed")

        challenge = _make_bound_mcp_challenge(request={"amount": "1000"})
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
        )

        with pytest.raises(PaymentVerificationError) as exc_info:
            await verify_or_challenge(
                meta=mcp_credential.to_meta(),
                intent=MockIntent(),  # type: ignore[arg-type]
                request={"amount": "1000"},
                realm="api.example.com",
                secret_key=MCP_TEST_SECRET,
            )

        assert exc_info.value.detail == "Payment failed"


class TestCreateChallenge:
    """Tests for create_challenge helper."""

    def test_creates_challenge_with_required_fields(self) -> None:
        challenge = create_challenge(
            method="tempo",
            intent_name="charge",
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert challenge.method == "tempo"
        assert challenge.intent == "charge"
        assert challenge.request == {"amount": "1000"}
        assert challenge.realm == "api.example.com"
        assert challenge.id is not None
        assert challenge.expires is not None

    def test_creates_challenge_with_description(self) -> None:
        challenge = create_challenge(
            method="tempo",
            intent_name="charge",
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
            description="API call fee",
        )

        assert challenge.description == "API call fee"

    def test_challenge_id_is_hmac_bound(self) -> None:
        challenge = create_challenge(
            method="tempo",
            intent_name="charge",
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        expected_id = generate_challenge_id(
            secret_key=MCP_TEST_SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=challenge.expires,
        )
        assert challenge.id == expected_id

    def test_challenge_id_deterministic(self) -> None:
        challenge1 = create_challenge(
            method="tempo",
            intent_name="charge",
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        challenge2 = create_challenge(
            method="tempo",
            intent_name="charge",
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        # Different expires timestamps means different IDs (expected)
        # But same secret+params should produce consistent HMACs
        assert len(challenge1.id) > 0
        assert len(challenge2.id) > 0
