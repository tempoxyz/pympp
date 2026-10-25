"""Ports of mppx ``stripe/server/internal/*.test.ts`` and ``spt.test.ts`` plus API client tests."""

import logging
from typing import Any

import httpx
import pytest

from mpp import Challenge
from mpp.stripe import (
    STRIPE_PREVIEW_VERSION,
    PaymentIntent,
    PaymentIntentOptions,
    StripeError,
    StripeHttpClient,
)
from mpp.stripe import server as stripe
from mpp.stripe._internal.api import encode_form

# -- analytics ---------------------------------------------------------------------------------


def _challenge(id: str = "challenge_123", intent: str = "charge") -> Challenge:
    return Challenge(id=id, realm="r", method="stripe", intent=intent, request={})


def test_build_analytics() -> None:
    assert stripe.build_analytics(challenge=_challenge()) == {
        "machine_payment": "true",
        "mpp_challenge_id": "challenge_123",
        "mpp_intent": "charge",
        "mpp_sdk": stripe.sdk_identifier(),
    }


def test_build_analytics_without_challenge() -> None:
    assert stripe.build_analytics() == {
        "machine_payment": "true",
        "mpp_sdk": stripe.sdk_identifier(),
    }


def test_build_analytics_intent_override() -> None:
    assert stripe.build_analytics(challenge=_challenge(), intent="session")["mpp_intent"] == (
        "session"
    )


def test_build_analytics_limits_values() -> None:
    metadata = stripe.build_analytics(challenge=_challenge(id="i" * 501, intent="😀" * 501))
    assert len(metadata["mpp_challenge_id"]) == 500
    assert len(metadata["mpp_intent"]) == 500


def test_sdk_identifier() -> None:
    assert stripe.sdk_identifier().startswith("pympp/")


# -- spt module --------------------------------------------------------------------------------


def test_spt_alias() -> None:
    assert stripe.spt is stripe.charge


def test_server_import_does_not_load_rails() -> None:
    import subprocess
    import sys

    code = (
        "import sys, mpp.stripe.server; "
        "assert not any(m.startswith(('mpp.tempo', 'mpp.evm', 'eth_')) for m in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


# -- record payment ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "cents"), [("14999", 1), ("15000", 1), ("19999", 1), ("20000", 2)]
)
async def test_record_converts_raw_units_to_cents(
    make_stripe: Any, amount: str, cents: int
) -> None:
    client = make_stripe(status="processing")
    await stripe.record_crypto_payment(
        client, amount=amount, network="tempo", analytics_metadata={}, reference="0xtx123"
    )
    assert len(client.calls) == 1
    assert client.calls[0].params["amount"] == cents


async def test_record_skips_below_one_cent(
    make_stripe: Any, caplog: pytest.LogCaptureFixture
) -> None:
    client = make_stripe()
    with caplog.at_level(logging.WARNING, logger="mpp.stripe"):
        await stripe.record_crypto_payment(
            client, amount="9999", network="tempo", analytics_metadata={}, reference="0x1"
        )
    assert client.calls == []
    assert "skipping PI recording" in caplog.text


async def test_record_params(make_stripe: Any) -> None:
    client = make_stripe()
    await stripe.record_crypto_payment(
        client,
        amount="500000",
        network="base",
        analytics_metadata={"machine_payment": "true"},
        reference="0xtx123",
    )
    call = client.calls[0]
    assert call.params == {
        "amount": 50,
        "currency": "usd",
        "confirm": True,
        "payment_method_data": {"type": "crypto"},
        "payment_method_types": ["crypto"],
        "payment_method_options": {
            "crypto": {
                "mode": "transaction_verification",
                "transaction_verification_options": {
                    "network": "base",
                    "transaction_hash": "0xtx123",
                },
            }
        },
        "metadata": {"machine_payment": "true"},
    }
    assert call.idempotency_key == "0xtx123"
    assert call.api_version == STRIPE_PREVIEW_VERSION


class FlakyStripe:
    def __init__(self, first: Exception) -> None:
        self.first: Exception | None = first
        self.calls: list[tuple[dict[str, Any], str | None]] = []

    async def create_payment_intent(
        self,
        params: Any,
        *,
        api_version: str,
        idempotency_key: Any = None,
        stripe_account: Any = None,
    ) -> PaymentIntent:
        self.calls.append((dict(params), idempotency_key))
        if self.first is not None:
            error, self.first = self.first, None
            raise error
        return PaymentIntent(id="pi_123", status="succeeded")


async def test_record_retries_without_optional_fields(caplog: pytest.LogCaptureFixture) -> None:
    invalid = StripeError("Invalid customer", type="invalid_request_error")
    client = FlakyStripe(invalid)
    analytics = {
        "machine_payment": "true",
        "mpp_challenge_id": "challenge_123",
        "mpp_intent": "charge",
        "mpp_sdk": stripe.sdk_identifier(),
    }
    with caplog.at_level(logging.WARNING, logger="mpp.stripe"):
        await stripe.record_crypto_payment(
            client,
            amount="500000",
            network="tempo",
            analytics_metadata=analytics,
            payment_intent_options=PaymentIntentOptions.model_validate(
                {
                    "amount": 999,
                    "confirm": False,
                    "customer": "cus_123",
                    "currency": "eur",
                    "hooks": {"inputs": {"tax": {"calculation": "taxcalc_123"}}},
                    "metadata": {"machine_payment": "custom", "request_id": "req_123"},
                    "receipt_email": "customer@example.com",
                }
            ),
            reference="0xtx123",
        )
    assert len(client.calls) == 2
    first, first_key = client.calls[0]
    assert first["amount"] == 50
    assert first["confirm"] is True
    assert first["currency"] == "usd"
    assert first["customer"] == "cus_123"
    assert first["hooks"] == {"inputs": {"tax": {"calculation": "taxcalc_123"}}}
    assert first["receipt_email"] == "customer@example.com"
    assert first["metadata"] == {**analytics, "machine_payment": "custom", "request_id": "req_123"}
    second, second_key = client.calls[1]
    assert "customer" not in second
    assert "hooks" not in second
    assert "receipt_email" not in second
    assert second["metadata"] == analytics
    assert first_key == "0xtx123"
    assert second_key == "0xtx123_fallback"
    assert "retrying without them" in caplog.text


async def test_record_does_not_retry_ambiguous_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = FlakyStripe(ConnectionResetError("Connection reset"))
    with caplog.at_level(logging.ERROR, logger="mpp.stripe"):
        await stripe.record_crypto_payment(
            client,
            amount="500000",
            network="tempo",
            analytics_metadata={},
            payment_intent_options=PaymentIntentOptions(customer="cus_123"),
            reference="0xtx123",
        )
    assert len(client.calls) == 1
    assert "[stripe] failed to record crypto payment:" in caplog.text


async def test_record_does_not_retry_without_optional_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = FlakyStripe(StripeError("bad", type="invalid_request_error"))
    with caplog.at_level(logging.ERROR, logger="mpp.stripe"):
        await stripe.record_crypto_payment(
            client, amount="500000", network="tempo", analytics_metadata={}, reference="0x1"
        )
    assert len(client.calls) == 1
    assert "failed to record crypto payment" in caplog.text


# -- deposit addresses -------------------------------------------------------------------------


async def test_deposit_address_lists_then_caches(make_stripe: Any) -> None:
    client = make_stripe()
    assert await stripe.find_or_create_deposit_address(client, "tempo") == "0xabc"
    assert await stripe.find_or_create_deposit_address(client, "tempo") == "0xabc"
    assert client.raw_calls == [
        ("GET", "/v1/crypto/deposit_addresses?network=tempo&limit=1", None, None)
    ]


async def test_deposit_address_creates_when_missing(make_stripe: Any) -> None:
    client = make_stripe(addresses={"list": None, "created": "0xnew"})
    assert await stripe.find_or_create_deposit_address(client, "base") == "0xnew"
    assert client.raw_calls[1] == (
        "POST",
        "/v1/crypto/deposit_addresses",
        {"network": "base"},
        None,
    )
    assert await stripe.find_or_create_deposit_address(client, "base") == "0xnew"
    assert len(client.raw_calls) == 2


# -- HTTP client -------------------------------------------------------------------------------


def test_encode_form() -> None:
    assert encode_form(
        {
            "a": 1,
            "b": True,
            "c": None,
            "d": {"e": {"f": "g"}},
            "h": ["x", {"y": "z"}],
        }
    ) == [("a", "1"), ("b", "true"), ("d[e][f]", "g"), ("h[0]", "x"), ("h[1][y]", "z")]


async def test_http_client_create_payment_intent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"id": "pi_1", "status": "succeeded"},
            headers={"Idempotent-Replayed": "true"},
        )

    client = StripeHttpClient(
        "sk_test_123", http=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    intent = await client.create_payment_intent(
        {"amount": 100, "metadata": {"k": "v"}},
        api_version=STRIPE_PREVIEW_VERSION,
        idempotency_key="key_1",
    )
    assert intent == PaymentIntent(id="pi_1", status="succeeded", replayed=True)
    request = seen[0]
    assert request.headers["Authorization"] == "Basic c2tfdGVzdF8xMjM6"
    assert request.headers["Idempotency-Key"] == "key_1"
    assert "Stripe-Account" not in request.headers
    assert dict(httpx.QueryParams(request.content.decode())) == {
        "amount": "100",
        "metadata[k]": "v",
    }


async def test_http_client_raw_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": []})

    client = StripeHttpClient(
        "sk_test_123", http=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    path = "/v1/crypto/deposit_addresses?network=tempo&limit=1"
    assert await client.raw_request("GET", path, api_version="v", stripe_account="acct_1") == {
        "data": []
    }
    assert str(seen[0].url) == f"https://api.stripe.com{path}"
    assert seen[0].headers["Stripe-Account"] == "acct_1"
    await client.raw_request(
        "POST", "/v1/crypto/deposit_addresses", {"network": "base"}, api_version="v"
    )
    assert seen[1].method == "POST"
    assert seen[1].content == b"network=base"


async def test_http_client_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": {"message": "No such customer", "type": "invalid_request_error"}},
        )

    client = StripeHttpClient(
        "sk_test_123", http=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(StripeError) as info:
        await client.create_payment_intent({}, api_version="v")
    assert info.value.message == "No such customer"
    assert info.value.type == "invalid_request_error"
    assert info.value.status_code == 400


async def test_http_client_non_json_error() -> None:
    client = StripeHttpClient(
        "sk",
        http=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(500, text="oops"))
        ),
    )
    with pytest.raises(StripeError, match="oops"):
        await client.create_payment_intent({}, api_version="v")
