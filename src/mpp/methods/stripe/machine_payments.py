"""Opinionated Stripe machine payments for SPT and Tempo."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypedDict

import mpp.methods.stripe.intents as stripe_intents
from mpp.methods import CanOfferFn
from mpp.methods.stripe import server as stripe
from mpp.methods.stripe.connect import ConnectSettlement
from mpp.methods.tempo._defaults import CHAIN_ID, TESTNET_CHAIN_ID, default_currency_for_chain

if TYPE_CHECKING:
    from stripe import StripeClient

    from mpp import Credential, Receipt
    from mpp.server.method import ServerMethod
    from mpp.store import Store

_SPT_MINIMUM, _RAW_UNITS_PER_CENT = 50, 10_000


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
        self,
        network_id: str,
        client: StripeClient,
        metadata: dict[str, str] | None,
        connect: ConnectSettlement | None = None,
    ) -> None:
        self._network_id = network_id
        self._client = client
        self._metadata = metadata
        self._connect = connect

    def charge(self) -> ServerMethod:
        return stripe.charge(
            client=self._client,
            currency="usd",
            recipient=self._network_id,
            network_id=self._network_id,
            payment_method_types=["card", "link"],
            can_offer=_minimum_amount(_SPT_MINIMUM),
            metadata=self._metadata,
            connect=self._connect,
        )


class TempoPayments:
    """Build configured Tempo charge methods recorded in Stripe."""

    def __init__(
        self,
        livemode: bool,
        client: StripeClient,
        recipient: str | None,
        metadata: dict[str, str] | None,
        store: Store,
        connect: ConnectSettlement | None = None,
    ) -> None:
        self._livemode = livemode
        self._client = client
        self._recipient = recipient
        self._metadata = metadata
        self._store = store
        self._connect = connect

    def charge(self) -> ServerMethod:
        if self._recipient is None:
            raise ValueError("deposit_addresses['tempo'] is required for Tempo payments")
        from mpp.methods.stripe.payment_intent_method import with_payment_intent_input
        from mpp.methods.tempo import server as tempo

        chain_id = CHAIN_ID if self._livemode else TESTNET_CHAIN_ID
        [method] = tempo.charge(
            store=self._store,
            chain_id=chain_id,
            # Keep Stripe's Tempo rail on one currency: USDC.e live, pathUSD test.
            currencies=[default_currency_for_chain(chain_id)],
            recipient=self._recipient,
            can_offer=_minimum_amount(_RAW_UNITS_PER_CENT),
        )
        return with_payment_intent_input(
            method, self._record_payment, configured_metadata=self._metadata
        )

    async def _record_payment(
        self,
        credential: Credential,
        request: dict[str, Any],
        receipt: Receipt,
        payment_intent_options: dict[str, Any],
        resolved_metadata: dict[str, str],
    ) -> None:
        """Record a Tempo receipt with Stripe-only per-attempt inputs."""
        from mpp.methods.stripe.crypto_payment_recorder import record_crypto_payment

        await record_crypto_payment(
            client=self._client,
            network="tempo",
            metadata=self._metadata,
            credential=credential,
            request=request,
            receipt=receipt,
            payment_intent_options=payment_intent_options,
            resolved_metadata=resolved_metadata,
            connect=self._connect,
        )


class MachinePayments:
    """Configure Stripe SPT and optional Tempo payment methods."""

    def __init__(
        self,
        *,
        network_id: str,
        livemode: bool,
        client: StripeClient,
        store: Store,
        deposit_addresses: DepositAddresses | None = None,
        metadata: Mapping[str, str] | None = None,
        connect: ConnectSettlement | None = None,
    ) -> None:
        stripe_intents._resolve_payment_intents(client)
        if not callable(getattr(store, "put_if_absent", None)):
            raise ValueError("create() requires a shared atomic `store` for replay protection")
        tempo_address = deposit_addresses.get("tempo") if deposit_addresses is not None else None

        resolved_metadata = dict(metadata) if metadata is not None else None
        self._tempo_address = tempo_address
        self.spt = SptPayments(network_id, client, resolved_metadata, connect)
        self.tempo = TempoPayments(
            livemode, client, tempo_address, resolved_metadata, store, connect
        )

    def default_methods(self) -> list[ServerMethod]:
        """Return configured methods in preferred negotiation order."""
        spt = [self.spt.charge()]
        return [self.tempo.charge(), *spt] if self._tempo_address is not None else spt


def create(
    *,
    network_id: str,
    livemode: bool,
    client: StripeClient,
    store: Store,
    deposit_addresses: DepositAddresses | None = None,
    metadata: Mapping[str, str] | None = None,
    connect: ConnectSettlement | None = None,
) -> MachinePayments:
    """Create machine payments from an initialized StripeClient.

    ``store`` is the atomic replay store shared by every server instance; Tempo
    charges use it to reject replayed transaction hashes across replicas.
    ``connect`` routes SPT charges and recorded Tempo payments to a Stripe
    Connect account.
    """
    return MachinePayments(
        network_id=network_id,
        livemode=livemode,
        client=client,
        store=store,
        deposit_addresses=deposit_addresses,
        metadata=metadata,
        connect=connect,
    )
