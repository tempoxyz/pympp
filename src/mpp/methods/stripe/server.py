"""Stripe charge for servers.

Usage::

    from mpp.methods.stripe import server as stripe
    from mpp.server import Mpp

    mpp = Mpp(methods=stripe.charge(secret_key="sk_...", network_id="bn_...", currency="usd"))
    result = await mpp.charge(amount="0.50")(request)
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from mpp._defaults import DEFAULT_TIMEOUT
from mpp.methods.stripe.connect import ConnectInput
from mpp.methods.stripe.intents import ChargeIntent
from mpp.methods.stripe.schemas import charge as definition
from mpp.server.method import RequestContext, ServerMethod, VerifyContext

if TYPE_CHECKING:
    from mpp import Receipt
    from mpp.methods import CanOfferFn, PaymentSuccessHandler

__all__ = ["charge"]


def charge(
    *,
    network_id: str,
    client: Any | None = None,
    secret_key: str | None = None,
    payment_method_types: list[str] | None = None,
    currency: str | None = None,
    decimals: int = 2,
    recipient: str | None = None,
    external_id: str | None = None,
    metadata: dict[str, str] | None = None,
    connect: ConnectInput = None,
    http_client: Any | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> ServerMethod:
    """Create the Stripe charge server method, verified with Shared Payment Tokens.

    Each credential's SPT confirms a Stripe PaymentIntent. Routes take ``amount``
    (decimal string), and optionally ``currency``, ``decimals``, ``recipient``,
    ``external_id`` and ``payment_intent_options`` (private PaymentIntent input:
    a mapping, or a sync or async callable receiving a
    :class:`~mpp.methods.stripe.PaymentIntentContext`).

    Args:
        network_id: Stripe Business Network profile ID, sent as
            ``methodDetails.networkId``.
        client: Pre-configured Stripe SDK client (recommended).
        secret_key: Stripe secret API key, used when ``client`` is not given.
        payment_method_types: Stripe payment method types (default: ``["card"]``).
        currency: Default ISO currency code (e.g. ``"usd"``).
        decimals: Decimal places of the currency (default: 2).
        recipient: Optional default recipient.
        external_id: Default authenticated external reference, sent as
            ``externalId``; clients echo it in their credential.
        metadata: Stripe metadata sent in the challenge and on the PaymentIntent.
        connect: Stripe Connect settlement for the PaymentIntent, or a sync or
            async callable receiving a
            :class:`~mpp.methods.stripe.PaymentIntentContext` that returns it.
            Server-only: never included in the challenge.
        http_client: httpx client for ``secret_key`` requests, owned by the caller.
        timeout: Stripe request timeout in seconds.
        can_offer: Decides whether to advertise an offer for a wire request.
        on_payment_success: Called with each successful Stripe charge event.
    """
    intent = ChargeIntent(
        client=client, secret_key=secret_key, http_client=http_client, timeout=timeout
    )
    fixed: dict[str, Any] = {
        "network_id": network_id,
        "payment_method_types": list(payment_method_types or ["card"]),
        "metadata": metadata,
    }
    defaults = {
        "decimals": decimals,
        "recipient": recipient,
        "external_id": external_id,
    }

    def resolve_request(context: RequestContext) -> dict[str, Any]:
        input = {key: value for key, value in context.request.items() if value is not None}
        for key, value in fixed.items():
            if key in input and input[key] != value:
                raise ValueError(f"{key} does not match the configured value")
            input[key] = value
        for key, value in defaults.items():
            if value is not None:
                input.setdefault(key, value)
        return input

    async def verify(context: VerifyContext) -> Receipt:
        payload: Any = context.credential.payload
        credential = replace(context.credential, payload=payload.model_dump(exclude_none=True))
        options = context.request.get("payment_intent_options")
        return await intent.verify(credential, context.challenge.request, options, connect)

    return ServerMethod(
        method=definition,
        verify=verify,
        resolve_request=resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        defaults={"currency": currency} if currency is not None else None,
        credential_options=("payment_intent_options",),
    )
