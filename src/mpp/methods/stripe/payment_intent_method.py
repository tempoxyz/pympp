"""Decorate a crypto rail with private, request-scoped Stripe input."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, Field, create_model

from mpp import Credential, Receipt
from mpp.methods.stripe.analytics import merge_metadata
from mpp.methods.stripe.payment_intent_options import prepare_options, resolve_options
from mpp.server.method import ServerMethod, VerifyContext

RecordPayment = Callable[
    [Credential, dict[str, Any], Receipt, dict[str, Any], dict[str, str]], Awaitable[None]
]


def with_payment_intent_input(
    method: ServerMethod,
    record_payment: RecordPayment,
    configured_metadata: Mapping[str, str] | None = None,
) -> ServerMethod:
    """Accept ``payment_intent_options`` route input on ``method`` and record its payments.

    The options never enter the challenge. They are resolved immediately before
    the terminal payment operation (after ``validate`` when the method has one),
    so a resolver error prevents settlement, and passed to ``record_payment``
    with the receipt.
    """
    definition = method.method
    request_model = create_model(
        f"{definition.request_model.__name__}WithPaymentIntentOptions",
        __base__=definition.request_model,
        payment_intent_options=(
            Annotated[Any, AfterValidator(prepare_options)],
            Field(default=None, exclude=True),
        ),
    )

    async def settle(context: VerifyContext, terminal: Any) -> Receipt:
        credential = _native(context.credential)
        request = context.challenge.request
        options = await resolve_options(
            context.request.get("payment_intent_options"), credential, request
        )
        metadata = merge_metadata(credential, configured_metadata, options)
        receipt = await terminal(context)
        await record_payment(credential, request, receipt, options, metadata)
        return receipt

    async def verify(context: VerifyContext) -> Receipt:
        return await settle(context, method.verify)

    async def broadcast(context: VerifyContext) -> Receipt:
        return await settle(context, method.broadcast)

    return replace(
        method,
        method=replace(definition, request_model=request_model),
        verify=verify if method.verify is not None else None,
        broadcast=broadcast if method.broadcast is not None else None,
        credential_options=(*method.credential_options, "payment_intent_options"),
    )


def _native(credential: Credential) -> Credential:
    payload = credential.payload
    if isinstance(payload, BaseModel):
        return replace(credential, payload=payload.model_dump(mode="json", by_alias=True))
    return credential
