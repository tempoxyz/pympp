"""Stripe API helpers shared by the machine-payments rails."""

from collections.abc import Mapping
from typing import Any

from mpp.stripe._internal.api import HttpMethod, PaymentIntent, StripeClient, StripeRawClient
from mpp.stripe._internal.constants import STRIPE_PREVIEW_VERSION


async def create_payment_intent(
    client: StripeClient,
    params: Mapping[str, Any],
    *,
    idempotency_key: str | None = None,
) -> PaymentIntent:
    """Creates a PaymentIntent with the preview API version."""
    return await client.create_payment_intent(
        params, api_version=STRIPE_PREVIEW_VERSION, idempotency_key=idempotency_key
    )


async def stripe_request(
    client: StripeRawClient,
    method: HttpMethod,
    path: str,
    params: Mapping[str, Any] | None = None,
) -> Any:
    """Makes a raw Stripe API request (GET requests carry no body params)."""
    return await client.raw_request(
        method,
        path,
        None if method == "GET" else params,
        api_version=STRIPE_PREVIEW_VERSION,
    )
