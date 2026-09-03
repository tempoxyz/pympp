"""Opinionated Stripe machine payments for SPT and Tempo."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypedDict

import mpp.methods.stripe._defaults as stripe_defaults
import mpp.methods.stripe.intents as stripe_intents
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn
from mpp.methods.stripe.client import StripeMethod, spt
from mpp.methods.tempo._defaults import CHAIN_ID, TESTNET_CHAIN_ID

if TYPE_CHECKING:
    from stripe import StripeClient

    from mpp.methods.tempo.client import TempoMethod

logger = logging.getLogger(__name__)

_SPT_MINIMUM, _RAW_UNITS_PER_CENT, _CENT_ROUNDING = 50, 10_000, 5_000


class DepositAddresses(TypedDict, total=False):
    """Static deposit addresses understood by Stripe machine payments."""

    tempo: str


def _minimum_amount(minimum: int) -> CanOfferFn:
    def can_offer(request: dict[str, Any]) -> bool:
        try:
            return int(request["amount"]) >= minimum
        except (KeyError, TypeError, ValueError):
            return False

    return can_offer


class SptPayments:
    """Build configured Stripe SPT charge methods."""

    def __init__(
        self, network_id: str, client: StripeClient, metadata: dict[str, str] | None
    ) -> None:
        self._network_id = network_id
        self._client = client
        self._metadata = metadata

    def charge(self) -> StripeMethod:
        return spt(
            intents={"charge": stripe_intents.ChargeIntent(client=self._client)},
            currency="usd",
            recipient=self._network_id,
            network_id=self._network_id,
            payment_method_types=["card", "link"],
            can_offer=_minimum_amount(_SPT_MINIMUM),
            metadata=self._metadata,
        )


class TempoPayments:
    """Build configured Tempo charge methods recorded in Stripe."""

    def __init__(
        self,
        livemode: bool,
        client: StripeClient,
        recipient: str | None,
        metadata: dict[str, str] | None,
    ) -> None:
        self._livemode = livemode
        self._client = client
        self._recipient = recipient
        self._metadata = metadata

    def charge(self) -> TempoMethod:
        if self._recipient is None:
            raise ValueError("deposit_addresses['tempo'] is required for Tempo payments")
        from mpp.methods.tempo import ChargeIntent as TempoChargeIntent
        from mpp.methods.tempo import tempo

        return tempo(
            intents={"charge": TempoChargeIntent()},
            chain_id=CHAIN_ID if self._livemode else TESTNET_CHAIN_ID,
            recipient=self._recipient,
            can_offer=_minimum_amount(_RAW_UNITS_PER_CENT),
            on_payment_success=self._record_payment,
        )

    async def _record_payment(self, payload: ServerPaymentSuccessPayload) -> None:
        """Record a verified Tempo payment as a Stripe PaymentIntent."""
        reference = payload["receipt"].reference
        amount_cents = (int(payload["request"]["amount"]) + _CENT_ROUNDING) // _RAW_UNITS_PER_CENT
        if amount_cents < 1:
            return
        params: dict[str, Any] = {
            "amount": amount_cents,
            "currency": "usd",
            "confirm": True,
            "metadata": {**(self._metadata or {}), "machine_payment": "true"},
            "payment_method_data": {"type": "crypto"},
            "payment_method_types": ["crypto"],
            "payment_method_options": {
                "crypto": {
                    "mode": "transaction_verification",
                    "transaction_verification_options": {
                        "network": "tempo",
                        "transaction_hash": reference,
                    },
                }
            },
        }
        try:
            await stripe_intents._create_payment_intent(
                self._client,
                params,
                {
                    "headers": {"X-Request-Source": stripe_defaults.STRIPE_REQUEST_SOURCE},
                    "idempotency_key": reference,
                    "stripe_version": stripe_defaults.MACHINE_PAYMENTS_API_VERSION,
                },
            )
        except Exception as error:
            logger.warning("[stripe] Tempo PI recording failed for %r: %s", reference, error)


class MachinePayments:
    """Configure Stripe SPT and optional Tempo payment methods."""

    def __init__(
        self,
        *,
        network_id: str,
        livemode: bool,
        client: StripeClient,
        deposit_addresses: DepositAddresses | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        stripe_intents._resolve_payment_intents(client)
        tempo_address = deposit_addresses.get("tempo") if deposit_addresses is not None else None

        resolved_metadata = dict(metadata) if metadata is not None else None
        self._tempo_address = tempo_address
        self.spt = SptPayments(network_id, client, resolved_metadata)
        self.tempo = TempoPayments(livemode, client, tempo_address, resolved_metadata)

    def default_methods(self) -> list[StripeMethod | TempoMethod]:
        """Return configured methods in preferred negotiation order."""
        spt: list[StripeMethod | TempoMethod] = [self.spt.charge()]
        return [self.tempo.charge(), *spt] if self._tempo_address is not None else spt


def create(
    *,
    network_id: str,
    livemode: bool,
    client: StripeClient,
    deposit_addresses: DepositAddresses | None = None,
    metadata: Mapping[str, str] | None = None,
) -> MachinePayments:
    """Create machine payments from an initialized StripeClient."""
    return MachinePayments(
        network_id=network_id,
        livemode=livemode,
        client=client,
        deposit_addresses=deposit_addresses,
        metadata=metadata,
    )
