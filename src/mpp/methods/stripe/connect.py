"""Server-only Stripe Connect settlement; never part of an MPP challenge."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, TypeAlias

from mpp import Credential
from mpp.errors import VerificationFailedError
from mpp.methods.stripe.payment_intent_options import PaymentIntentContext

_MAX_SAFE_INTEGER = 2**53 - 1


@dataclass(frozen=True, kw_only=True)
class TransferData:
    """Destination transfer created from the PaymentIntent."""

    destination: str
    amount: int | None = None


@dataclass(frozen=True, kw_only=True)
class ConnectSettlement:
    """Stripe Connect settlement parameters for PaymentIntents.

    See https://docs.stripe.com/connect/destination-charges

    Attributes:
        stripe_account: Connected account sent as the ``Stripe-Account`` context.
        application_fee_amount: Platform fee in the currency's smallest unit.
        on_behalf_of: Connected account used as the business of record.
        transfer_data: Destination transfer created from the PaymentIntent.
        transfer_group: Reconciliation token linking related charges and transfers.
    """

    stripe_account: str | None = None
    application_fee_amount: int | None = None
    on_behalf_of: str | None = None
    transfer_data: TransferData | None = None
    transfer_group: str | None = None

    def params(self) -> dict[str, Any]:
        """PaymentIntent body parameters, omitting unset fields."""
        params: dict[str, Any] = {}
        if self.application_fee_amount is not None:
            params["application_fee_amount"] = self.application_fee_amount
        if self.on_behalf_of is not None:
            params["on_behalf_of"] = self.on_behalf_of
        if self.transfer_data is not None:
            transfer: dict[str, Any] = {"destination": self.transfer_data.destination}
            if self.transfer_data.amount is not None:
                transfer["amount"] = self.transfer_data.amount
            params["transfer_data"] = transfer
        if self.transfer_group is not None:
            params["transfer_group"] = self.transfer_group
        return params


ResolveConnect: TypeAlias = Callable[
    [PaymentIntentContext], ConnectSettlement | None | Awaitable[ConnectSettlement | None]
]
ConnectInput: TypeAlias = ConnectSettlement | ResolveConnect | None


async def resolve_settlement(
    value: ConnectInput, credential: Credential, request: dict[str, Any]
) -> ConnectSettlement | None:
    """Resolve and validate the settlement for a verified credential and its request."""
    if callable(value):
        snapshot_credential, snapshot_request = deepcopy(credential), deepcopy(request)
        result = value(
            PaymentIntentContext(
                snapshot_credential.challenge, snapshot_credential, snapshot_request
            )
        )
        value = await result if inspect.isawaitable(result) else result
    if value is None:
        return None
    try:
        amount = int(str(request.get("amount")))
    except ValueError:
        amount = -1
    if not 0 <= amount <= _MAX_SAFE_INTEGER:
        raise VerificationFailedError("Stripe amount must be a non-negative integer.")
    _account(value.stripe_account, "stripe_account")
    _account(value.on_behalf_of, "on_behalf_of")
    _amount(value.application_fee_amount, amount, "application_fee_amount")
    if value.transfer_data is not None:
        _account(value.transfer_data.destination or "", "transfer_data.destination")
        _amount(value.transfer_data.amount, amount, "transfer_data.amount")
    return value


def _account(value: str | None, name: str) -> None:
    if value is not None and not value:
        raise VerificationFailedError(f"Stripe Connect {name} must be non-empty.")


def _amount(value: int | None, payment_amount: int, name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise VerificationFailedError(f"Stripe Connect {name} must be a non-negative integer.")
    if value > payment_amount:
        raise VerificationFailedError(
            f"Stripe Connect {name} must be less than or equal to the PaymentIntent amount."
        )
