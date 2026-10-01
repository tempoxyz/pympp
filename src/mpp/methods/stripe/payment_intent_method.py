"""Decorate a crypto rail with private, request-scoped Stripe input."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, cast

from mpp import Credential, Receipt
from mpp.methods.stripe.analytics import merge_metadata
from mpp.methods.stripe.payment_intent_options import (
    PaymentIntentInput,
    prepare_options,
    resolve_options,
)
from mpp.server.intent import Intent, VerifiableIntent, broadcast_credential

RecordPayment = Callable[
    [Credential, dict[str, Any], Receipt, dict[str, Any], dict[str, str]], Awaitable[None]
]


def with_payment_intent_input(
    method: Any, record_payment: RecordPayment, configured_metadata: Mapping[str, str] | None = None
) -> Any:
    """Decorate a method in place without changing its public concrete type."""

    def prepare_intent(
        intent: Intent | VerifiableIntent, input: dict[str, Any]
    ) -> tuple[Intent | VerifiableIntent, dict[str, Any]]:
        options = prepare_options(input.pop("payment_intent_options", None))
        wrapper = (
            VerifiableWrappedIntent(intent, options, record_payment, configured_metadata)
            if isinstance(intent, VerifiableIntent)
            else WrappedIntent(intent, options, record_payment, configured_metadata)
        )
        return wrapper, input

    method.prepare_intent = prepare_intent
    return method


class WrappedIntent:
    def __init__(
        self,
        intent: Intent | VerifiableIntent,
        options: PaymentIntentInput,
        record_payment: RecordPayment,
        configured_metadata: Mapping[str, str] | None,
    ) -> None:
        self.name = intent.name
        self._intent = intent
        self._options = options
        self._record_payment = record_payment
        self._configured_metadata = configured_metadata

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        # Legacy rails have no non-mutating validation to run before resolution.
        options = await resolve_options(self._options, credential, request)
        metadata = merge_metadata(credential, self._configured_metadata, options)
        receipt = await cast(Intent, self._intent).verify(credential, request)
        await self._record_payment(credential, request, receipt, options, metadata)
        return receipt


class VerifiableWrappedIntent(WrappedIntent):
    async def validate(self, credential: Credential, request: dict[str, Any]):
        # Replace bare assert with explicit TypeError so validation persists under python -O
        if not isinstance(self._intent, VerifiableIntent):
            msg = "VerifiableWrappedIntent requires a VerifiableIntent"
            raise TypeError(msg)
        return await self._intent.validate(credential, request)

    async def broadcast(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        # Server lifecycle has already run validate. Resolve immediately before
        # the terminal operation so errors prevent settlement.
        options = await resolve_options(self._options, credential, request)
        metadata = merge_metadata(credential, self._configured_metadata, options)
        if not isinstance(self._intent, VerifiableIntent):
            msg = "VerifiableWrappedIntent requires a VerifiableIntent"
            raise TypeError(msg)
        receipt = await self._intent.broadcast(credential, request)
        await self._record_payment(credential, request, receipt, options, metadata)
        return receipt

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        return await broadcast_credential(intent=self, credential=credential, request=request)