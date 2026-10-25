"""Records settled crypto payments as Stripe PaymentIntents (``transaction_verification``)."""

import logging
from collections.abc import Mapping
from typing import Any, Final, Literal

from mpp.stripe._internal.api import StripeClient
from mpp.stripe._internal.payment_intent import PaymentIntentOptions
from mpp.stripe.server._request import create_payment_intent

logger = logging.getLogger("mpp.stripe")

type Network = Literal["tempo", "base", "solana"]

_TOKEN_DECIMALS: Final[Mapping[str, int]] = {"tempo": 6, "base": 6, "solana": 6}
"""Stablecoin decimals per Stripe-managed rail (the Stripe network name equals the key)."""


async def record_crypto_payment(
    client: StripeClient,
    *,
    network: Network,
    reference: str,
    amount: str,
    analytics_metadata: Mapping[str, str],
    payment_intent_options: PaymentIntentOptions | None = None,
) -> None:
    """Records a crypto payment as a Stripe PaymentIntent using ``transaction_verification``.

    If Stripe definitively rejects caller-provided optional fields, retries once without them
    (idempotency key ``<reference>_fallback``). Errors are logged, never raised.
    """
    decimals = _TOKEN_DECIMALS[network]
    amount_cents = int(amount) // 10 ** (decimals - 2)
    if amount_cents < 1:
        logger.warning(
            "[stripe] skipping PI recording: %s raw units on %s floors to %s cents "
            "(below Stripe minimum)",
            amount,
            network,
            amount_cents,
        )
        return

    required: dict[str, Any] = {
        "amount": amount_cents,
        "currency": "usd",
        "confirm": True,
        "payment_method_data": {"type": "crypto"},
        "payment_method_types": ["crypto"],
        "payment_method_options": {
            "crypto": {
                "mode": "transaction_verification",
                "transaction_verification_options": {
                    "network": network,
                    "transaction_hash": reference,
                },
            }
        },
        "metadata": dict(analytics_metadata),
    }
    options = payment_intent_options.to_params() if payment_intent_options else {}
    try:
        try:
            await create_payment_intent(
                client,
                {
                    **required,
                    **options,
                    "metadata": {**analytics_metadata, **options.get("metadata", {})},
                },
                idempotency_key=reference,
            )
        except Exception as error:
            if payment_intent_options is None or not _is_definitive_invalid_request(error):
                raise
            logger.warning(
                "[stripe] optional PI recording fields were rejected; retrying without them: %s",
                error,
            )
            await create_payment_intent(client, required, idempotency_key=f"{reference}_fallback")
    except Exception as error:
        logger.error("[stripe] failed to record crypto payment: %s", error, exc_info=error)


def _is_definitive_invalid_request(error: BaseException) -> bool:
    """Whether Stripe definitively rejected request parameters before creating a PaymentIntent."""
    error_type = getattr(error, "type", None)
    return (
        error_type in ("invalid_request_error", "StripeInvalidRequestError")
        or type(error).__name__ == "InvalidRequestError"  # stripe-python SDK
    )
