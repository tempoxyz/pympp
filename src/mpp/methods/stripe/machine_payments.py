"""Opinionated Stripe machine payments for SPT, Tempo and Base."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from typing import TYPE_CHECKING, Any, TypedDict

import mpp.methods.stripe.intents as stripe_intents
from mpp.methods import CanOfferFn
from mpp.methods.stripe import server as stripe
from mpp.methods.tempo._defaults import CHAIN_ID, TESTNET_CHAIN_ID, default_currency_for_chain

if TYPE_CHECKING:
    from stripe import StripeClient

    from mpp import Credential, Receipt
    from mpp._validation import Validation
    from mpp.methods.stripe.payment_intent_method import RecordPayment
    from mpp.server.method import ServerMethod, ValidateContext, VerifyContext
    from mpp.store import Store

_SPT_MINIMUM, _RAW_UNITS_PER_CENT = 50, 10_000


class DepositAddresses(TypedDict, total=False):
    """Static deposit addresses understood by Stripe machine payments."""

    base: str
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

    def charge(self) -> ServerMethod:
        return stripe.charge(
            client=self._client,
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
        store: Store,
    ) -> None:
        self._livemode = livemode
        self._client = client
        self._recipient = recipient
        self._metadata = metadata
        self._store = store

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
            method,
            _crypto_recorder(self._client, "tempo", self._metadata),
            configured_metadata=self._metadata,
        )


class BasePayments:
    """Build configured Base USDC charge methods recorded in Stripe."""

    def __init__(
        self,
        livemode: bool,
        client: StripeClient,
        recipient: str | None,
        metadata: dict[str, str] | None,
        store: Store,
    ) -> None:
        self._livemode = livemode
        self._client = client
        self._recipient = recipient
        self._metadata = metadata
        self._store = store

    def charge(self, *, metadata: Mapping[str, str] | None = None, **options: Any) -> ServerMethod:
        """Return an ``evm/charge`` method paying the Base deposit address.

        ``options`` are passed to :func:`mpp.methods.evm.server.charge` (such as
        ``facilitator``). The asset, recipient and shared store are pinned, and a
        ``can_offer`` applies on top of the one-cent minimum, which is also enforced
        before settlement. ``metadata`` is merged over the configured metadata for
        this method's PaymentIntents.
        """
        if self._recipient is None:
            raise ValueError("deposit_addresses['base'] is required for Base payments")
        from mpp.methods.evm import assets
        from mpp.methods.evm import server as evm
        from mpp.methods.stripe.payment_intent_method import with_payment_intent_input

        for key in ("currency", "chain_id", "decimals", "authorization", "recipient"):
            if key in options:
                raise ValueError(f"Stripe Base charges cannot override `{key}`")
        if options.pop("store", self._store) is not self._store:
            raise ValueError("Stripe Base charges must use the factory-level shared atomic `store`")
        minimum = _minimum_amount(_RAW_UNITS_PER_CENT)
        extra: CanOfferFn | None = options.pop("can_offer", None)

        def can_offer(request: dict[str, Any]) -> bool | Awaitable[bool]:
            return minimum(request) and (extra is None or extra(request))

        resolved = {**(self._metadata or {}), **metadata} if metadata else self._metadata
        method = evm.charge(
            **options,
            currency=assets.BASE_USDC if self._livemode else assets.BASE_SEPOLIA_USDC,
            recipient=self._recipient,
            can_offer=can_offer,
            store=self._store,
        )
        return with_payment_intent_input(
            _require_minimum(method, minimum),
            _crypto_recorder(self._client, "base", resolved),
            configured_metadata=resolved,
        )


def _require_minimum(method: ServerMethod, minimum: CanOfferFn) -> ServerMethod:
    """Refuse credentials below ``minimum`` before settlement.

    A single-method handler offers it without ``can_offer``, and Stripe can't
    record a payment under one cent after it settles.
    """
    from dataclasses import replace

    from mpp.errors import VerificationFailedError

    def check(context: VerifyContext) -> None:
        if not minimum(dict(context.challenge.request)):
            raise VerificationFailedError("amount is below the one-cent Stripe minimum")

    validate, broadcast = method.validate, method.broadcast
    assert broadcast is not None

    async def guarded_validate(context: ValidateContext) -> Validation:
        check(context)
        assert validate is not None
        return await validate(context)

    async def guarded_broadcast(context: VerifyContext) -> Receipt:
        check(context)
        return await broadcast(context)

    return replace(
        method,
        validate=guarded_validate if validate is not None else None,
        broadcast=guarded_broadcast,
    )


def _crypto_recorder(
    client: StripeClient, network: str, metadata: dict[str, str] | None
) -> RecordPayment:
    async def record(
        credential: Credential,
        request: dict[str, Any],
        receipt: Receipt,
        payment_intent_options: dict[str, Any],
        resolved_metadata: dict[str, str],
    ) -> None:
        """Record a crypto receipt with Stripe-only per-attempt inputs."""
        from mpp.methods.stripe.crypto_payment_recorder import record_crypto_payment

        await record_crypto_payment(
            client=client,
            network=network,
            metadata=metadata,
            credential=credential,
            request=request,
            receipt=receipt,
            payment_intent_options=payment_intent_options,
            resolved_metadata=resolved_metadata,
        )

    return record


class MachinePayments:
    """Configure Stripe SPT and optional Tempo and Base payment methods."""

    def __init__(
        self,
        *,
        network_id: str,
        livemode: bool,
        client: StripeClient,
        store: Store,
        deposit_addresses: DepositAddresses | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        stripe_intents._resolve_payment_intents(client)
        if not callable(getattr(store, "put_if_absent", None)):
            raise ValueError("create() requires a shared atomic `store` for replay protection")
        addresses = deposit_addresses or {}
        tempo_address = addresses.get("tempo")

        resolved_metadata = dict(metadata) if metadata is not None else None
        self._tempo_address = tempo_address
        self.spt = SptPayments(network_id, client, resolved_metadata)
        self.tempo = TempoPayments(livemode, client, tempo_address, resolved_metadata, store)
        self._base_address = addresses.get("base")
        self.base = BasePayments(livemode, client, self._base_address, resolved_metadata, store)

    def default_methods(self, *, base: Mapping[str, Any] | None = None) -> list[ServerMethod]:
        """Return configured methods in preferred negotiation order.

        ``base`` adds a Base charge after the defaults (keyword arguments for
        ``base.charge``, such as ``facilitator``) when a Base deposit address is set.
        """
        methods = [self.tempo.charge()] if self._tempo_address is not None else []
        methods.append(self.spt.charge())
        if base is not None and self._base_address is not None:
            methods.append(self.base.charge(**base))
        return methods


def create(
    *,
    network_id: str,
    livemode: bool,
    client: StripeClient,
    store: Store,
    deposit_addresses: DepositAddresses | None = None,
    metadata: Mapping[str, str] | None = None,
) -> MachinePayments:
    """Create machine payments from an initialized StripeClient.

    ``store`` is the atomic replay store shared by every server instance; Tempo
    charges use it to reject replayed transaction hashes across replicas.
    """
    return MachinePayments(
        network_id=network_id,
        livemode=livemode,
        client=client,
        store=store,
        deposit_addresses=deposit_addresses,
        metadata=metadata,
    )
