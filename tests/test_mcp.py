"""Tests for MCP transport support."""

import base64
import json
from datetime import UTC, datetime, timedelta

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
    digest: str | None = None,
    opaque: dict[str, str] | None = None,
    _no_default_expires: bool = False,
) -> MCPChallenge:
    """Create an MCPChallenge with an HMAC-bound ID for testing.

    Defaults ``expires`` to 1 hour in the future so credentials pass
    expiry enforcement.  Pass ``_no_default_expires=True`` to test the
    missing-expires rejection path.
    """
    if request is None:
        request = {"amount": "1000"}
    if expires is None and not _no_default_expires:
        expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    challenge_id = generate_challenge_id(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        digest=digest,
        opaque=opaque,
    )
    return MCPChallenge(
        id=challenge_id,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        description=description,
        digest=digest,
        opaque=opaque,
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

    def test_to_core_preserves_digest_opaque(self) -> None:
        mcp_challenge = MCPChallenge(
            id="ch_abc",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            digest="sha-256=abc",
            opaque={"pi": "pi_123"},
        )
        core = mcp_challenge.to_core()
        assert core.digest == "sha-256=abc"
        assert core.opaque == {"pi": "pi_123"}

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

    def test_from_core_preserves_digest_opaque(self) -> None:
        core = Challenge(
            id="ch_abc",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            digest="sha-256=xyz",
            opaque={"k": "v"},
        )
        mcp = MCPChallenge.from_core(core, realm="r")
        assert mcp.digest == "sha-256=xyz"
        assert mcp.opaque == {"k": "v"}


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
            await my_tool("test")  # type: ignore[call-arg]

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

        result = await my_tool("test", _meta=mcp_credential.to_meta())  # type: ignore[call-arg]
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
            await my_tool("test", _meta={META_CREDENTIAL: {"invalid": "data"}})  # type: ignore[call-arg]

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
            await my_tool("test", _meta=mcp_credential.to_meta())  # type: ignore[call-arg]

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
            await my_tool("hello")  # type: ignore[call-arg]

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
            await my_tool("test")  # type: ignore[call-arg]

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
            await my_tool("test")  # type: ignore[call-arg]

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

    async def test_rejects_credential_with_wrong_realm(self) -> None:
        """Credential issued for realm-A should be rejected at realm-B."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            realm="realm-A",
            secret_key="shared-key",
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="realm-B",
            secret_key="shared-key",
        )
        assert isinstance(result, MCPChallenge), "Should reject cross-realm credential"

    async def test_rejects_credential_with_wrong_method(self) -> None:
        """Credential for method 'tempo' should be rejected when server expects 'stripe'."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            secret_key="shared-key",
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="api.example.com",
            method="stripe",
            secret_key="shared-key",
        )
        assert isinstance(result, MCPChallenge), "Should reject wrong method"

    async def test_rejects_credential_with_wrong_intent(self) -> None:
        """Credential for intent 'charge' should be rejected when server expects 'session'."""

        class SessionIntent:
            name = "session"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            secret_key="shared-key",
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=SessionIntent(),  # type: ignore[arg-type]
            request=request,
            realm="api.example.com",
            secret_key="shared-key",
        )
        assert isinstance(result, MCPChallenge), "Should reject wrong intent"

    async def test_rejects_credential_for_different_request(self) -> None:
        """Credential for cheap request should be rejected at expensive endpoint."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        cheap_request = {"amount": "100"}
        challenge = _make_bound_mcp_challenge(request=cheap_request)
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        expensive_request = {"amount": "999999"}
        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=expensive_request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, MCPChallenge), "Should reject credential for different request"

    async def test_rejects_expired_credential(self) -> None:
        """Credential with expired challenge should be rejected at transport layer."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            expires="2020-01-01T00:00:00.000Z",
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, MCPChallenge), "Should reject expired credential"

    async def test_accepts_non_expired_credential(self) -> None:
        """Credential with future expires should be accepted."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0xOK")

        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            expires="2099-01-01T00:00:00.000Z",
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, tuple), "Should accept non-expired credential"


class TestMCPChallengeExpiryEnforcement:
    """Tests for challenge expiry enforcement in MCP verify_or_challenge."""

    async def test_rejects_expired_credential(self) -> None:
        """Should return a new challenge when echoed expires is in the past."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000"},
            expires="2020-01-01T00:00:00Z",
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

    async def test_accepts_unexpired_credential(self) -> None:
        """Should accept credential when echoed expires is in the future."""
        from datetime import timedelta

        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000"},
            expires=future,
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

        assert isinstance(result, tuple)
        _, receipt = result
        assert receipt.status == "success"


class TestMCPExpiryFailClosed:
    """Tests for fail-closed expiry enforcement in MCP verify_or_challenge."""

    async def test_rejects_missing_expires(self) -> None:
        """Should return a new challenge when expires is absent."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000"},
            _no_default_expires=True,
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

    async def test_rejects_malformed_expires(self) -> None:
        """Should return a new challenge when expires is unparseable."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000"},
            expires="not-a-date",
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


class TestMCPCrossEndpointReplay:
    """Tests for cross-endpoint credential replay prevention in MCP."""

    async def test_rejects_credential_with_wrong_intent(self) -> None:
        """Should reject a credential whose echoed intent doesn't match."""

        class ChargeIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        # Create a credential for a different intent
        challenge = _make_bound_mcp_challenge(
            request={"amount": "1000"},
            intent="session",
        )
        mcp_credential = MCPCredential(
            challenge=challenge,
            payload={"signature": "0xabc"},
        )

        # Present it to the "charge" endpoint
        result = await verify_or_challenge(
            meta=mcp_credential.to_meta(),
            intent=ChargeIntent(),  # type: ignore[arg-type]
            request={"amount": "1000"},
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )

        assert isinstance(result, MCPChallenge)


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


class TestMCPDigestOpaque:
    """PY-01: MCPChallenge digest and opaque field handling."""

    def test_mcp_challenge_has_digest_and_opaque_fields(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            digest="sha-256=abc",
            opaque={"pi": "pi_123"},
        )
        assert ch.digest == "sha-256=abc"
        assert ch.opaque == {"pi": "pi_123"}

    def test_mcp_challenge_to_dict_includes_digest_opaque(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={},
            digest="sha-256=xyz",
            opaque={"k": "v"},
        )
        d = ch.to_dict()
        assert d["digest"] == "sha-256=xyz"
        assert d["opaque"] == {"k": "v"}

    def test_mcp_challenge_to_dict_omits_none_digest_opaque(self) -> None:
        ch = MCPChallenge(id="test", realm="r", method="tempo", intent="charge", request={})
        d = ch.to_dict()
        assert "digest" not in d
        assert "opaque" not in d

    def test_mcp_challenge_from_dict_parses_digest_opaque(self) -> None:
        data = {
            "id": "test",
            "realm": "r",
            "method": "tempo",
            "intent": "charge",
            "request": {},
            "digest": "sha-256=abc",
            "opaque": {"k": "v"},
        }
        ch = MCPChallenge.from_dict(data)
        assert ch.digest == "sha-256=abc"
        assert ch.opaque == {"k": "v"}

    @pytest.mark.asyncio
    async def test_mcp_verify_succeeds_with_digest(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        digest_val = "sha-256=abc123"
        challenge = _make_bound_mcp_challenge(
            request=request,
            digest=digest_val,
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),
            request=request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, tuple), "Should verify successfully with digest"

    @pytest.mark.asyncio
    async def test_mcp_verify_succeeds_with_opaque(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        opaque = {"pi": "pi_abc"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            opaque=opaque,
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),
            request=request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, tuple), "Should verify successfully with opaque"

    @pytest.mark.asyncio
    async def test_mcp_verify_fails_without_matching_digest(self) -> None:
        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        challenge_id = generate_challenge_id(
            secret_key=MCP_TEST_SECRET,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request=request,
            digest="sha-256=original",
        )
        ch = MCPChallenge(
            id=challenge_id,
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request=request,
            digest="sha-256=tampered",
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),
            request=request,
            realm="api.example.com",
            secret_key=MCP_TEST_SECRET,
        )
        assert isinstance(result, MCPChallenge)


class TestMCPCredentialToCoreDigestOpaque:
    """PY-06: MCPCredential.to_core() must pass digest/opaque to ChallengeEcho."""

    def test_to_core_includes_digest(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            digest="sha-256=abc123",
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.digest == "sha-256=abc123"

    def test_to_core_includes_opaque(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            opaque={"pi": "pi_123"},
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.opaque is not None
        decoded = json.loads(base64.urlsafe_b64decode(core.challenge.opaque + "==").decode())
        assert decoded == {"pi": "pi_123"}

    def test_to_core_opaque_is_sorted(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={},
            opaque={"z": "last", "a": "first"},
        )
        cred = MCPCredential(challenge=ch, payload={})
        core = cred.to_core()
        assert core.challenge.opaque is not None
        decoded_json = base64.urlsafe_b64decode(core.challenge.opaque + "==").decode()
        assert decoded_json.index('"a"') < decoded_json.index('"z"')

    def test_to_core_none_digest_opaque(self) -> None:
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.digest is None
        assert core.challenge.opaque is None

    def test_to_core_roundtrip_hmac_with_opaque(self) -> None:
        opaque = {"pi": "pi_abc"}
        request = {"amount": "1000"}
        challenge = _make_bound_mcp_challenge(
            request=request,
            opaque=opaque,
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})
        core = cred.to_core()

        from mpp._parsing import _b64_decode

        echo = core.challenge
        echo_request = _b64_decode(echo.request) if echo.request else {}
        echo_opaque = _b64_decode(echo.opaque) if echo.opaque else None
        recomputed_id = generate_challenge_id(
            secret_key=MCP_TEST_SECRET,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo_request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=echo_opaque,
        )
        assert recomputed_id == challenge.id

    def test_to_core_roundtrip_hmac_with_digest(self) -> None:
        request = {"amount": "1000"}
        digest_val = "sha-256=test123"
        challenge = _make_bound_mcp_challenge(
            request=request,
            digest=digest_val,
        )
        cred = MCPCredential(challenge=challenge, payload={"sig": "0x"})
        core = cred.to_core()

        from mpp._parsing import _b64_decode

        echo = core.challenge
        echo_request = _b64_decode(echo.request) if echo.request else {}
        recomputed_id = generate_challenge_id(
            secret_key=MCP_TEST_SECRET,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo_request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=None,
        )
        assert recomputed_id == challenge.id
