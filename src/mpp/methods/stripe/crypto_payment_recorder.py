"""Best-effort Stripe recording for completed on-chain payments."""

from __future__ import annotations

import logging
from typing import Any

from mpp import Credential, Receipt
from mpp.methods.stripe import _defaults
from mpp.methods.stripe.analytics import build_analytics
from mpp.methods.stripe.connect import ConnectSettlement
from mpp.methods.stripe.intents import _create_payment_intent

logger = logging.getLogger(__name__)

_NETWORK_DECIMALS = {"tempo": 6, "base": 6, "solana": 6}


def recorded_cents(network: str, request: dict[str, Any]) -> int:
    """USD cents of the PaymentIntent that records ``request``'s on-chain amount."""
    return int(request["amount"]) // 10 ** (_NETWORK_DECIMALS[network] - 2)


async def record_crypto_payment(
    *,
    client: Any,
    network: str,
    metadata: dict[str, str] | None,
    credential: Credential | None,
    request: dict[str, Any],
    receipt: Receipt,
    payment_intent_options: dict[str, Any] | None = None,
    resolved_metadata: dict[str, str] | None = None,
    connect: ConnectSettlement | None = None,
) -> None:
    """Record a settled crypto transfer; failure cannot undo settlement."""
    reference = receipt.reference
    options = payment_intent_options or {}
    try:
        cents = recorded_cents(network, request)
        if cents < 1:
            return
        analytics = build_analytics(credential) if credential else {"machine_payment": "true"}
        required = {
            "amount": cents,
            "currency": "usd",
            "confirm": True,
            "metadata": analytics,
            "payment_method_data": {"type": "crypto"},
            "payment_method_types": ["crypto"],
            "payment_method_options": {
                "crypto": {
                    "mode": "transaction_verification",
                    "transaction_verification_options": {
                        "network": network,
                        "transaction_hash": reference,
                    },
                },
            },
        }
        resolved_metadata = resolved_metadata or {
            **analytics,
            **(metadata or {}),
            "machine_payment": "true",
            **options.get("metadata", {}),
        }
        params = {**required, **options, "metadata": resolved_metadata}
        try:
            await _create(client, params, reference, connect)
        except Exception as error:
            if not (metadata or options) or not _optional_rejection(error):
                raise
            logger.warning(
                "[stripe] optional PaymentIntent fields rejected for %r; retrying without them",
                reference,
            )
            await _create(client, required, f"{reference}_fallback", connect)
    except Exception as error:
        logger.warning(
            "[stripe] failed to record crypto payment network=%r transaction_hash=%r: %s",
            network,
            reference,
            error,
        )


async def _create(
    client: Any, params: dict[str, Any], idempotency_key: str, connect: ConnectSettlement | None
) -> None:
    options: dict[str, Any] = {
        "headers": {"X-Request-Source": _defaults.STRIPE_REQUEST_SOURCE},
        "idempotency_key": idempotency_key,
        "stripe_version": _defaults.MACHINE_PAYMENTS_API_VERSION,
        "max_network_retries": 0,
    }
    if connect and connect.stripe_account is not None:
        options["stripe_account"] = connect.stripe_account
    await _create_payment_intent(
        client, {**params, **(connect.params() if connect else {})}, options
    )


def _optional_rejection(error: Exception) -> bool:
    import stripe

    if not isinstance(error, stripe.InvalidRequestError):
        return False
    # stripe leaves InvalidRequestError.param unannotated.
    param: object = error.param  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return isinstance(param, str) and any(
        param == name or param.startswith((name + "[", name + "."))
        for name in ("customer", "receipt_email", "metadata", "hooks")
    )
