"""Stripe charge for servers: verifies SPT credentials by confirming a Stripe PaymentIntent."""

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final

from pydantic import ValidationError

from mpp import expires
from mpp.errors import InvalidChallengeError, PaymentActionRequiredError, VerificationFailedError
from mpp.method import (
    CanOfferContext,
    MaybeAwaitable,
    PaymentSuccessHookContext,
    ServerMethod,
    VerifyContext,
    resolve,
)
from mpp.receipt import Receipt
from mpp.stripe import ChargePayload
from mpp.stripe import charge as charge_method
from mpp.stripe._internal.api import PaymentIntent, StripeClient, StripeHttpClient
from mpp.stripe._internal.constants import STRIPE_PREVIEW_VERSION
from mpp.stripe._internal.payment_intent import (
    ResolveContext,
    resolve_options,
    split_request,
)
from mpp.stripe.server._analytics import build_analytics

MINIMUM_CHARGE_AMOUNTS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "aed": 200,
        "ars": 50,
        "aud": 50,
        "bgn": 100,
        "brl": 50,
        "cad": 50,
        "chf": 50,
        "cop": 50,
        "czk": 1_500,
        "dkk": 250,
        "eur": 50,
        "gbp": 30,
        "hkd": 400,
        "huf": 17_500,
        "idr": 50,
        "ils": 50,
        "inr": 50,
        "jpy": 50,
        "krw": 50,
        "mxn": 1_000,
        "myr": 200,
        "nok": 300,
        "nzd": 50,
        "php": 50,
        "pln": 200,
        "ron": 200,
        "rub": 50,
        "sek": 300,
        "sgd": 50,
        "thb": 1_000,
        "usd": 50,
        "zar": 50,
    }
)
"""Stripe's general minimum charge amounts in each currency's smallest unit.

Payment methods with lower provider-specific exceptions remain conservatively subject to the
general minimum. See https://docs.stripe.com/currencies#minimum-and-maximum-charge-amounts
"""


def charge(
    *,
    client: StripeClient | None = None,
    secret_key: str | None = None,
    network_id: str | None = None,
    payment_method_types: list[str] | None = None,
    amount: str | None = None,
    currency: str | None = None,
    decimals: int | None = None,
    description: str | None = None,
    external_id: str | None = None,
    metadata: Mapping[str, str] | None = None,
    can_offer: Callable[[CanOfferContext], MaybeAwaitable[bool]] | None = None,
    on_payment_success: Callable[[PaymentSuccessHookContext], MaybeAwaitable[None]] | None = None,
) -> ServerMethod:
    """Creates a Stripe charge method for servers.

    Verifies payment by creating (and confirming) a Stripe PaymentIntent with the credential's
    Shared Payment Token. Pass either ``client`` (any :class:`~mpp.stripe.StripeClient`) or a
    raw ``secret_key`` (requests are then sent with :class:`~mpp.stripe.StripeHttpClient`).

    Request fields (``amount``, ``currency``, ``decimals``, ``network_id``,
    ``payment_method_types``, …) given here become route defaults. PaymentIntent options are
    request-scoped only: pass ``payment_intent_options`` per route (as mppx does).

    Args:
        client: Stripe client used to create PaymentIntents.
        secret_key: Stripe secret API key (alternative to ``client``).
        metadata: Metadata included in the challenge (``methodDetails.metadata``) and on the
            PaymentIntent.
        can_offer: Additional offer policy, consulted after the currency minimum check.
        on_payment_success: Side-effect hook run after a successful payment.

    Example::

        from mpp.stripe import server as stripe

        method = stripe.charge(secret_key="sk_...", network_id="internal",
                               payment_method_types=["card"])
    """
    if (client is None) == (secret_key is None):
        raise TypeError("stripe.charge() requires exactly one of `client` or `secret_key`.")
    stripe_client: StripeClient = (
        client if client is not None else StripeHttpClient(secret_key or "")
    )

    defaults = {
        key: value
        for key, value in {
            "amount": amount,
            "currency": currency,
            "decimals": decimals,
            "description": description,
            "external_id": external_id,
            "metadata": dict(metadata) if metadata is not None else None,
            "network_id": network_id,
            "payment_method_types": payment_method_types,
        }.items()
        if value is not None
    }

    async def offer(context: CanOfferContext) -> bool:
        request = context.request
        minimum = MINIMUM_CHARGE_AMOUNTS.get(str(request["currency"]).lower())
        if minimum is not None and int(request["amount"]) < minimum:
            return False
        return True if can_offer is None else await resolve(can_offer(context))

    async def verify(context: VerifyContext[Any]) -> Receipt:
        credential = context.credential
        challenge = credential.challenge
        options_input, method_request = split_request(context.request)
        try:
            request = charge_method.normalize_request(method_request)
        except ValidationError:
            # Standalone verification passes the HMAC-bound challenge request, which is already
            # in canonical (wire) form and must not be transformed again.
            request = method_request

        expires.ensure(challenge.expires, challenge.id)

        try:
            payload = ChargePayload.model_validate(
                credential.payload.model_dump(by_alias=True)
                if isinstance(credential.payload, ChargePayload)
                else credential.payload
            )
        except ValidationError as error:
            raise ValueError("Invalid credential payload: missing or malformed spt") from error

        request_external_id = request.get("externalId")
        if request_external_id is not None and payload.external_id != request_external_id:
            raise InvalidChallengeError(
                id=challenge.id, reason="credential externalId does not match this route request"
            )

        resolve_context = ResolveContext(
            challenge=challenge, credential=credential, envelope=context.envelope, request=request
        )
        options = await resolve_options(options_input, resolve_context)
        option_params = options.to_params() if options else {}
        user_metadata = (request.get("methodDetails") or {}).get("metadata") or {}
        params: dict[str, Any] = {
            "amount": int(request["amount"]),
            "automatic_payment_methods": {"allow_redirects": "never", "enabled": True},
            "confirm": True,
            "currency": request["currency"],
            **option_params,
            "metadata": {
                **build_analytics(challenge=challenge),
                **user_metadata,
                **option_params.get("metadata", {}),
            },
            # Not yet in Stripe SDK types (SPTs are in private preview).
            "shared_payment_granted_token": payload.spt,
        }

        intent = await _create_payment_intent(
            stripe_client,
            params,
            idempotency_key=f"mpp_{challenge.id}_{payload.spt}",
        )
        if intent.replayed:
            raise VerificationFailedError(reason="Payment has already been processed.")
        if intent.status == "requires_action":
            raise PaymentActionRequiredError(reason="Stripe PaymentIntent requires action")
        if intent.status != "succeeded":
            raise RuntimeError(f"Stripe PaymentIntent status: {intent.status}")

        return Receipt(
            method="stripe",
            reference=intent.id,
            timestamp=expires.to_iso(expires.now()),
            external_id=request_external_id,
        )

    return ServerMethod(
        method=charge_method,
        verify=verify,
        can_offer=offer,
        on_payment_success=on_payment_success,
        defaults=defaults,
    )


async def _create_payment_intent(
    client: StripeClient,
    params: Mapping[str, Any],
    *,
    idempotency_key: str,
) -> PaymentIntent:
    try:
        return await client.create_payment_intent(
            params, api_version=STRIPE_PREVIEW_VERSION, idempotency_key=idempotency_key
        )
    except Exception as error:
        raise VerificationFailedError(reason=f"Stripe PaymentIntent failed: {error}") from error


__all__ = ["MINIMUM_CHARGE_AMOUNTS", "charge"]
