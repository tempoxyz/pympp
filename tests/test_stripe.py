"""Tests for the Stripe payment method."""

from __future__ import annotations

import base64
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from mpp import Challenge, Credential, ChallengeEcho, Receipt
from mpp.errors import (
    PaymentActionRequiredError,
    PaymentExpiredError,
    VerificationFailedError,
)
from mpp.methods.stripe import ChargeIntent, StripeMethod, stripe
from mpp.methods.stripe.client import OnChallengeParameters
from mpp.methods.stripe.intents import _resolve_payment_intents
from mpp.methods.stripe.schemas import ChargeRequest, StripeCredentialPayload, StripeMethodDetails


# ──────────────────────────────────────────────────────────────────
# Schema tests
# ──────────────────────────────────────────────────────────────────


class TestStripeCredentialPayload:
    def test_valid_payload(self):
        payload = StripeCredentialPayload.model_validate({"spt": "spt_test_123"})
        assert payload.spt == "spt_test_123"
        assert payload.externalId is None

    def test_with_external_id(self):
        payload = StripeCredentialPayload.model_validate(
            {"spt": "spt_test_123", "externalId": "order-42"}
        )
        assert payload.spt == "spt_test_123"
        assert payload.externalId == "order-42"

    def test_missing_spt(self):
        with pytest.raises(Exception):
            StripeCredentialPayload.model_validate({"externalId": "order-42"})


class TestChargeRequest:
    def test_valid_request(self):
        req = ChargeRequest.model_validate({
            "amount": "150",
            "currency": "usd",
            "methodDetails": {
                "networkId": "bn_test",
                "paymentMethodTypes": ["card"],
            },
        })
        assert req.amount == "150"
        assert req.currency == "usd"
        assert req.methodDetails.networkId == "bn_test"
        assert req.methodDetails.paymentMethodTypes == ["card"]

    def test_missing_method_details(self):
        with pytest.raises(Exception):
            ChargeRequest.model_validate({
                "amount": "150",
                "currency": "usd",
            })

    def test_empty_payment_method_types(self):
        with pytest.raises(Exception):
            ChargeRequest.model_validate({
                "amount": "150",
                "currency": "usd",
                "methodDetails": {
                    "networkId": "bn_test",
                    "paymentMethodTypes": [],
                },
            })


# ──────────────────────────────────────────────────────────────────
# Client tests
# ──────────────────────────────────────────────────────────────────


def _make_challenge(**overrides: Any) -> Challenge:
    defaults = {
        "id": "test-challenge-id",
        "method": "stripe",
        "intent": "charge",
        "request": {
            "amount": "150",
            "currency": "usd",
            "methodDetails": {
                "networkId": "bn_test",
                "paymentMethodTypes": ["card"],
            },
        },
        "realm": "api.example.com",
        "request_b64": "eyJ0ZXN0IjoidHJ1ZSJ9",
        "expires": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    defaults.update(overrides)
    return Challenge(**defaults)


class TestStripeMethod:
    @pytest.mark.asyncio
    async def test_create_credential(self):
        async def fake_create_token(params: OnChallengeParameters) -> str:
            assert params.amount == "150"
            assert params.currency == "usd"
            assert params.network_id == "bn_test"
            assert params.payment_method == "pm_card_visa"
            return "spt_test_abc"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge()
        cred = await method.create_credential(challenge)

        assert cred.payload["spt"] == "spt_test_abc"
        assert cred.challenge.method == "stripe"
        assert cred.challenge.intent == "charge"

    @pytest.mark.asyncio
    async def test_create_credential_with_external_id(self):
        async def fake_create_token(params: OnChallengeParameters) -> str:
            return "spt_test_abc"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            external_id="order-42",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge()
        cred = await method.create_credential(challenge)

        assert cred.payload["spt"] == "spt_test_abc"
        assert cred.payload["externalId"] == "order-42"

    @pytest.mark.asyncio
    async def test_create_credential_no_create_token_raises(self):
        method = stripe(
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge()
        with pytest.raises(ValueError, match="create_token"):
            await method.create_credential(challenge)

    @pytest.mark.asyncio
    async def test_create_credential_no_payment_method_raises(self):
        async def fake_create_token(params: OnChallengeParameters) -> str:
            return "spt_test_abc"

        method = stripe(
            create_token=fake_create_token,
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge()
        with pytest.raises(ValueError, match="payment_method"):
            await method.create_credential(challenge)

    @pytest.mark.asyncio
    async def test_create_credential_missing_network_id_raises(self):
        """networkId is required in challenge.methodDetails (mppx parity)."""
        async def fake_create_token(params: OnChallengeParameters) -> str:
            return "spt_test_abc"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge(request={
            "amount": "150",
            "currency": "usd",
            "methodDetails": {
                "paymentMethodTypes": ["card"],
            },
        })
        with pytest.raises(ValueError, match="networkId is required"):
            await method.create_credential(challenge)

    @pytest.mark.asyncio
    async def test_create_credential_rejects_metadata_external_id(self):
        """metadata.externalId is reserved (mppx parity)."""
        async def fake_create_token(params: OnChallengeParameters) -> str:
            return "spt_test_abc"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge(request={
            "amount": "150",
            "currency": "usd",
            "methodDetails": {
                "networkId": "bn_test",
                "paymentMethodTypes": ["card"],
                "metadata": {"externalId": "should-fail"},
            },
        })
        with pytest.raises(ValueError, match="externalId is reserved"):
            await method.create_credential(challenge)

    def test_transform_request(self):
        method = stripe(
            network_id="bn_test",
            payment_method_types=["card"],
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        request = {"amount": "150", "currency": "usd"}
        result = method.transform_request(request, None)

        assert result["methodDetails"]["networkId"] == "bn_test"
        assert result["methodDetails"]["paymentMethodTypes"] == ["card"]

    def test_transform_request_does_not_overwrite(self):
        method = stripe(
            network_id="bn_default",
            payment_method_types=["card"],
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        request = {
            "amount": "150",
            "currency": "usd",
            "methodDetails": {"networkId": "bn_override"},
        }
        result = method.transform_request(request, None)

        assert result["methodDetails"]["networkId"] == "bn_override"
        assert result["methodDetails"]["paymentMethodTypes"] == ["card"]

    def test_method_name(self):
        method = stripe(
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )
        assert method.name == "stripe"

    def test_intents(self):
        intent = ChargeIntent(secret_key="sk_test_123")
        method = stripe(intents={"charge": intent})
        assert method.intents["charge"] is intent

    @pytest.mark.asyncio
    async def test_expires_at_from_challenge(self):
        """Verify expires_at is computed from the challenge's expires field."""
        recorded_params: list[OnChallengeParameters] = []

        async def fake_create_token(params: OnChallengeParameters) -> str:
            recorded_params.append(params)
            return "spt_test"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        challenge = _make_challenge(expires=expires)
        await method.create_credential(challenge)

        expected = math.floor(
            datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        )
        assert recorded_params[0].expires_at == expected

    @pytest.mark.asyncio
    async def test_expires_at_fallback_when_no_expires(self):
        """When challenge has no expires, default to now + 1 hour."""
        recorded_params: list[OnChallengeParameters] = []

        async def fake_create_token(params: OnChallengeParameters) -> str:
            recorded_params.append(params)
            return "spt_test"

        method = stripe(
            create_token=fake_create_token,
            payment_method="pm_card_visa",
            intents={"charge": ChargeIntent(secret_key="sk_test_123")},
        )

        challenge = _make_challenge(expires=None)
        before = math.floor(time.time()) + 3600
        await method.create_credential(challenge)
        after = math.floor(time.time()) + 3600

        assert before <= recorded_params[0].expires_at <= after


# ──────────────────────────────────────────────────────────────────
# Server intent tests
# ──────────────────────────────────────────────────────────────────


def _make_credential(
    spt: str = "spt_test_abc",
    external_id: str | None = None,
    expires: str | None = None,
) -> Credential:
    payload: dict[str, Any] = {"spt": spt}
    if external_id:
        payload["externalId"] = external_id
    if expires is None:
        expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return Credential(
        challenge=ChallengeEcho(
            id="test-challenge-id",
            realm="api.example.com",
            method="stripe",
            intent="charge",
            request="eyJ0ZXN0IjoidHJ1ZSJ9",
            expires=expires,
        ),
        payload=payload,
        source="stripe:test",
    )


SAMPLE_REQUEST: dict[str, Any] = {
    "amount": "150",
    "currency": "usd",
    "methodDetails": {
        "networkId": "bn_test",
        "paymentMethodTypes": ["card"],
    },
}


@dataclass
class FakePaymentIntent:
    id: str = "pi_test_123"
    status: str = "succeeded"


class FakePaymentIntents:
    def __init__(self, result: FakePaymentIntent | None = None):
        self._result = result or FakePaymentIntent()

    def create(self, *args: Any, **kwargs: Any) -> FakePaymentIntent:
        return self._result


class FakeStripeClient:
    """Legacy-style client with client.payment_intents."""

    def __init__(self, result: FakePaymentIntent | None = None):
        self.payment_intents = FakePaymentIntents(result)


class FakeV1:
    def __init__(self, result: FakePaymentIntent | None = None):
        self.payment_intents = FakePaymentIntents(result)


class FakeModernStripeClient:
    """Modern-style client with client.v1.payment_intents (stripe-python v8+)."""

    def __init__(self, result: FakePaymentIntent | None = None):
        self.v1 = FakeV1(result)


class TestResolvePaymentIntents:
    def test_modern_client_v1(self):
        client = FakeModernStripeClient()
        pi = _resolve_payment_intents(client)
        assert pi is client.v1.payment_intents

    def test_legacy_client(self):
        client = FakeStripeClient()
        pi = _resolve_payment_intents(client)
        assert pi is client.payment_intents

    def test_unsupported_client_raises(self):
        with pytest.raises(TypeError, match="Unsupported Stripe client"):
            _resolve_payment_intents(object())


class TestChargeIntent:
    @pytest.mark.asyncio
    async def test_verify_with_client_success(self):
        intent = ChargeIntent(client=FakeStripeClient())
        credential = _make_credential()
        receipt = await intent.verify(credential, SAMPLE_REQUEST)

        assert receipt.status == "success"
        assert receipt.reference == "pi_test_123"
        assert receipt.method == "stripe"

    @pytest.mark.asyncio
    async def test_verify_with_modern_client_success(self):
        """Verify works with client.v1.payment_intents (stripe-python v8+)."""
        intent = ChargeIntent(client=FakeModernStripeClient())
        credential = _make_credential()
        receipt = await intent.verify(credential, SAMPLE_REQUEST)

        assert receipt.status == "success"
        assert receipt.reference == "pi_test_123"
        assert receipt.method == "stripe"

    @pytest.mark.asyncio
    async def test_verify_with_external_id(self):
        intent = ChargeIntent(client=FakeStripeClient())
        credential = _make_credential(external_id="order-42")
        receipt = await intent.verify(credential, SAMPLE_REQUEST)

        assert receipt.external_id == "order-42"

    @pytest.mark.asyncio
    async def test_verify_expired_challenge(self):
        intent = ChargeIntent(client=FakeStripeClient())
        expired = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        credential = _make_credential(expires=expired)

        with pytest.raises(PaymentExpiredError):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_requires_action(self):
        pi = FakePaymentIntent(status="requires_action")
        intent = ChargeIntent(client=FakeStripeClient(result=pi))
        credential = _make_credential()

        with pytest.raises(PaymentActionRequiredError):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_failed_status(self):
        pi = FakePaymentIntent(status="requires_payment_method")
        intent = ChargeIntent(client=FakeStripeClient(result=pi))
        credential = _make_credential()

        with pytest.raises(VerificationFailedError, match="requires_payment_method"):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_missing_spt(self):
        intent = ChargeIntent(client=FakeStripeClient())
        credential = Credential(
            challenge=ChallengeEcho(
                id="test-challenge-id",
                realm="api.example.com",
                method="stripe",
                intent="charge",
                request="eyJ0ZXN0IjoidHJ1ZSJ9",
                expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            ),
            payload={"not_spt": "bad"},
        )

        with pytest.raises(VerificationFailedError, match="spt"):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_client_exception(self):
        class FailingIntents:
            def create(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("Stripe API error")

        class FailingClient:
            payment_intents = FailingIntents()

        intent = ChargeIntent(client=FailingClient())
        credential = _make_credential()

        with pytest.raises(VerificationFailedError, match="PaymentIntent failed"):
            await intent.verify(credential, SAMPLE_REQUEST)

    def test_no_client_or_secret_key_raises(self):
        with pytest.raises(ValueError, match="Either client or secret_key"):
            ChargeIntent()

    @pytest.mark.asyncio
    async def test_analytics_metadata(self):
        """Verify analytics metadata is passed to PaymentIntent creation."""
        captured: list[tuple[tuple, dict]] = []

        class CapturingIntents:
            def create(self, *args: Any, **kwargs: Any) -> FakePaymentIntent:
                captured.append((args, kwargs))
                return FakePaymentIntent()

        class CapturingClient:
            payment_intents = CapturingIntents()

        intent = ChargeIntent(client=CapturingClient())
        credential = _make_credential()
        await intent.verify(credential, SAMPLE_REQUEST)

        params = captured[0][0][0]
        metadata = params["metadata"]
        assert metadata["mpp_version"] == "1"
        assert metadata["mpp_is_mpp"] == "true"
        assert metadata["mpp_intent"] == "charge"
        assert metadata["mpp_challenge_id"] == "test-challenge-id"
        assert metadata["mpp_server_id"] == "api.example.com"
        assert metadata["mpp_client_id"] == "stripe:test"

    @pytest.mark.asyncio
    async def test_idempotency_key(self):
        """Verify idempotency key format matches mppx."""
        captured: list[tuple[tuple, dict]] = []

        class CapturingIntents:
            def create(self, *args: Any, **kwargs: Any) -> FakePaymentIntent:
                captured.append((args, kwargs))
                return FakePaymentIntent()

        class CapturingClient:
            payment_intents = CapturingIntents()

        intent = ChargeIntent(client=CapturingClient())
        credential = _make_credential(spt="spt_test_xyz")
        await intent.verify(credential, SAMPLE_REQUEST)

        options = captured[0][1]["options"]
        assert options["idempotency_key"] == "mppx_test-challenge-id_spt_test_xyz"

    @pytest.mark.asyncio
    async def test_client_request_body_is_first_positional_arg(self):
        """Verify request body is passed as first positional arg (Stripe SDK convention)."""
        captured: list[tuple[tuple, dict]] = []

        class CapturingIntents:
            def create(self, *args: Any, **kwargs: Any) -> FakePaymentIntent:
                captured.append((args, kwargs))
                return FakePaymentIntent()

        class CapturingClient:
            payment_intents = CapturingIntents()

        intent = ChargeIntent(client=CapturingClient())
        credential = _make_credential()
        await intent.verify(credential, SAMPLE_REQUEST)

        assert len(captured[0][0]) == 1
        body = captured[0][0][0]
        assert body["amount"] == 150
        assert body["currency"] == "usd"
        assert body["confirm"] is True
        assert body["shared_payment_granted_token"] == "spt_test_abc"
        assert "options" in captured[0][1]

    @pytest.mark.asyncio
    async def test_user_metadata_overrides_analytics(self):
        """User-supplied metadata should override analytics keys."""
        captured: list[tuple[tuple, dict]] = []

        class CapturingIntents:
            def create(self, *args: Any, **kwargs: Any) -> FakePaymentIntent:
                captured.append((args, kwargs))
                return FakePaymentIntent()

        class CapturingClient:
            payment_intents = CapturingIntents()

        intent = ChargeIntent(client=CapturingClient())
        credential = _make_credential()
        request_with_metadata = {
            **SAMPLE_REQUEST,
            "methodDetails": {
                **SAMPLE_REQUEST["methodDetails"],
                "metadata": {"mpp_version": "custom", "user_key": "user_val"},
            },
        }
        await intent.verify(credential, request_with_metadata)

        metadata = captured[0][0][0]["metadata"]
        assert metadata["mpp_version"] == "custom"
        assert metadata["user_key"] == "user_val"


# ──────────────────────────────────────────────────────────────────
# Raw HTTP path tests (_create_with_secret_key)
# ──────────────────────────────────────────────────────────────────


class TestChargeIntentRawHttp:
    @pytest.mark.asyncio
    async def test_verify_with_secret_key_success(self):
        """Verify the raw HTTP path creates a PaymentIntent successfully."""
        mock_response = httpx.Response(
            200,
            json={"id": "pi_http_123", "status": "succeeded"},
            request=httpx.Request("POST", "https://api.stripe.com/v1/payment_intents"),
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = mock_response

        intent = ChargeIntent(secret_key="sk_test_raw", http_client=mock_client)
        credential = _make_credential()
        receipt = await intent.verify(credential, SAMPLE_REQUEST)

        assert receipt.status == "success"
        assert receipt.reference == "pi_http_123"
        assert receipt.method == "stripe"

        call_kwargs = mock_client.post.call_args
        assert "api.stripe.com/v1/payment_intents" in call_kwargs.args[0]

        headers = call_kwargs.kwargs["headers"]
        expected_auth = base64.b64encode(b"sk_test_raw:").decode()
        assert headers["Authorization"] == f"Basic {expected_auth}"
        assert headers["Idempotency-Key"] == "mppx_test-challenge-id_spt_test_abc"

        data = call_kwargs.kwargs["data"]
        assert data["amount"] == "150"
        assert data["currency"] == "usd"
        assert data["shared_payment_granted_token"] == "spt_test_abc"

    @pytest.mark.asyncio
    async def test_verify_with_secret_key_stripe_error(self):
        """Verify Stripe error details are surfaced in the exception."""
        mock_response = httpx.Response(
            400,
            json={"error": {"message": "Invalid card number", "code": "card_declined"}},
            request=httpx.Request("POST", "https://api.stripe.com/v1/payment_intents"),
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = mock_response

        intent = ChargeIntent(secret_key="sk_test_raw", http_client=mock_client)
        credential = _make_credential()

        with pytest.raises(VerificationFailedError, match="Invalid card number"):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_with_secret_key_non_json_error(self):
        """Verify non-JSON error responses are handled gracefully."""
        mock_response = httpx.Response(
            500,
            text="Internal Server Error",
            request=httpx.Request("POST", "https://api.stripe.com/v1/payment_intents"),
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = mock_response

        intent = ChargeIntent(secret_key="sk_test_raw", http_client=mock_client)
        credential = _make_credential()

        with pytest.raises(VerificationFailedError, match="Internal Server Error"):
            await intent.verify(credential, SAMPLE_REQUEST)

    @pytest.mark.asyncio
    async def test_verify_with_secret_key_metadata_in_form(self):
        """Verify metadata is encoded as form fields."""
        mock_response = httpx.Response(
            200,
            json={"id": "pi_meta", "status": "succeeded"},
            request=httpx.Request("POST", "https://api.stripe.com/v1/payment_intents"),
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = mock_response

        intent = ChargeIntent(secret_key="sk_test_raw", http_client=mock_client)
        credential = _make_credential()
        await intent.verify(credential, SAMPLE_REQUEST)

        data = mock_client.post.call_args.kwargs["data"]
        assert data["metadata[mpp_is_mpp]"] == "true"
        assert data["metadata[mpp_version]"] == "1"


# ──────────────────────────────────────────────────────────────────
# Async context manager tests
# ──────────────────────────────────────────────────────────────────


class TestChargeIntentLifecycle:
    @pytest.mark.asyncio
    async def test_aclose_closes_owned_client(self):
        """Owned HTTP client is closed on aclose()."""
        intent = ChargeIntent(secret_key="sk_test")
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        intent._http_client = mock_client
        intent._owns_client = True

        await intent.aclose()

        mock_client.aclose.assert_awaited_once()
        assert intent._http_client is None

    @pytest.mark.asyncio
    async def test_aclose_does_not_close_injected_client(self):
        """Injected HTTP client is NOT closed on aclose()."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        intent = ChargeIntent(secret_key="sk_test", http_client=mock_client)

        await intent.aclose()

        mock_client.aclose.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_context_manager_closes_owned_client(self):
        """__aexit__ closes the owned HTTP client."""
        intent = ChargeIntent(secret_key="sk_test")
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        intent._http_client = mock_client
        intent._owns_client = True

        async with intent:
            pass

        mock_client.aclose.assert_awaited_once()


# ──────────────────────────────────────────────────────────────────
# Integration: stripe() factory
# ──────────────────────────────────────────────────────────────────


class TestStripeFactory:
    def test_defaults(self):
        method = stripe(
            intents={"charge": ChargeIntent(secret_key="sk_test")},
        )
        assert method.name == "stripe"
        assert method.decimals == 2
        assert method.payment_method_types == ["card"]
        assert method.currency is None

    def test_custom_params(self):
        method = stripe(
            intents={"charge": ChargeIntent(secret_key="sk_test")},
            currency="eur",
            decimals=0,
            network_id="bn_custom",
            payment_method_types=["card", "sepa_debit"],
            recipient="acct_123",
        )
        assert method.currency == "eur"
        assert method.decimals == 0
        assert method.network_id == "bn_custom"
        assert method.payment_method_types == ["card", "sepa_debit"]
        assert method.recipient == "acct_123"

    def test_no_secret_key_param(self):
        """Factory no longer accepts secret_key (removed per review)."""
        with pytest.raises(TypeError):
            stripe(
                intents={"charge": ChargeIntent(secret_key="sk_test")},
                secret_key="sk_test",  # type: ignore[call-arg]
            )
