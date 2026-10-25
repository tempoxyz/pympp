"""Stripe machine payments: SPT charges plus crypto rails settled into Stripe deposit addresses.

Crypto rails (Tempo, custom) pay a Stripe crypto deposit address; after each successful
payment the settlement is recorded in Stripe as a PaymentIntent
(``transaction_verification``) so it shows up next to card payments.
"""

import asyncio
import dataclasses
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, model_serializer, model_validator

from mpp.challenge import Challenge
from mpp.method import (
    CanOfferContext,
    MaybeAwaitable,
    Method,
    PaymentSuccessHookContext,
    RequestContext,
    RespondContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerifyContext,
    resolve,
)
from mpp.receipt import Receipt
from mpp.store import AtomicStore
from mpp.stripe._internal.api import StripeRawClient
from mpp.stripe._internal.payment_intent import (
    OPTIONS_KEYS,
    PaymentIntentOptions,
    ResolveContext,
    resolve_options,
    split_request,
    validate_input,
)
from mpp.stripe.server._analytics import build_analytics
from mpp.stripe.server._charge import charge as spt_charge
from mpp.stripe.server._deposit_address import find_or_create_deposit_address
from mpp.stripe.server._record_payment import record_crypto_payment

logger = logging.getLogger("mpp.stripe")

type Network = Literal["tempo", "base", "solana"]
type DepositAddressResolver = Callable[[str], Awaitable[str]]
"""Resolves the deposit address for a network (``"tempo"``, ``"base"``, ``"solana"``, …)."""
type CustomRail = Callable[[str], ServerMethod | Sequence[ServerMethod]]
"""Builds server method(s) paying the given deposit address."""
type DefaultMethodName = Literal["tempo", "spt"]

_MINIMUM_CRYPTO_AMOUNT: Final = 10_000
"""All Stripe-managed crypto rails use 6-decimal stablecoins; Stripe cannot record < 1 cent."""
_OPTIONS_KEY: Final = OPTIONS_KEYS[0]


def _crypto_can_offer(context: CanOfferContext) -> bool:
    try:
        return int(context.request["amount"]) >= _MINIMUM_CRYPTO_AMOUNT
    except (KeyError, TypeError, ValueError):
        return False


class MachinePayments:
    """A configured Stripe machine payments instance (create with :func:`create`).

    Args:
        client: Stripe client supporting ``raw_request`` (e.g. :class:`~mpp.stripe.StripeHttpClient`).
        network_id: Stripe Business Network profile id.
        livemode: Live mode (mainnet tokens) vs test mode (testnets).
        store: Atomic replay store shared by every Stripe-backed Tempo server instance.
        deposit_addresses: Static deposit addresses per network, or an async resolver.
        metadata: Metadata added to SPT challenges and recorded PaymentIntents.

    PaymentIntent option resolvers run after non-mutating method validation (when available)
    and before the terminal payment operation. If Stripe rejects resolved optional fields while
    recording a completed crypto payment, recording is retried once without them.
    """

    def __init__(
        self,
        *,
        client: StripeRawClient,
        network_id: str,
        livemode: bool,
        store: AtomicStore,
        deposit_addresses: Mapping[str, str] | DepositAddressResolver | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        if not callable(getattr(client, "raw_request", None)):
            raise TypeError("stripe.create() requires a Stripe client with raw_request()")
        if not callable(getattr(store, "update", None)):
            raise TypeError(
                "stripe.create() requires a shared atomic `store` for replay protection."
            )
        self.client = client
        self.network_id = network_id
        self.livemode = livemode
        self.store = store
        self.deposit_addresses = deposit_addresses
        self.metadata: dict[str, str] = dict(metadata or {})

    # -- recording ---------------------------------------------------------------------------

    def _recorder(
        self, network: str, metadata: Mapping[str, str] | None = None
    ) -> Callable[[PaymentSuccessHookContext], Awaitable[None] | None]:
        """Payment-success hook recording settlements on ``network`` as PaymentIntents."""
        base_metadata = self.metadata if metadata is None else metadata

        def record(context: PaymentSuccessHookContext) -> Awaitable[None] | None:
            return self._record(
                network,
                base_metadata,
                reference=context.receipt.reference,
                amount=context.request.get("amount"),
                challenge=context.challenge,
                request_input=context.request_input,
            )

        return record

    def _record(
        self,
        network: str,
        metadata: Mapping[str, str],
        *,
        reference: str | None,
        amount: Any,
        challenge: Challenge | None = None,
        intent: str | None = None,
        request_input: Mapping[str, Any] | None = None,
    ) -> Awaitable[None] | None:
        if not reference or not amount:
            return None
        options_input = split_request(request_input)[0] if request_input else None
        # An unresolved resolver is never executed after payment.
        options = None if callable(options_input) else validate_input(options_input)
        resolved_metadata = {**metadata, **((options.metadata if options else None) or {})}
        if resolved_metadata:
            options = (options or PaymentIntentOptions()).model_copy(
                update={"metadata": resolved_metadata}
            )
        if options is not None and not options.to_params():
            options = None
        return record_crypto_payment(
            self.client,
            network=network,  # pyright: ignore[reportArgumentType]
            reference=reference,
            amount=str(amount),
            analytics_metadata=build_analytics(challenge=challenge, intent=intent),
            payment_intent_options=options,
        )

    # -- rails -------------------------------------------------------------------------------

    @property
    def _tempo_currency(self) -> str:
        from mpp.tempo.assets import PATH_USD_ADDRESS, USDC_ADDRESS

        return USDC_ADDRESS if self.livemode else PATH_USD_ADDRESS

    def spt_charge(self, *, payment_method_types: list[str] | None = None) -> ServerMethod:
        """Stripe SPT charge in USD (``card`` + ``link`` by default)."""
        return spt_charge(
            client=self.client,
            network_id=self.network_id,
            currency="usd",
            decimals=2,
            payment_method_types=payment_method_types or ["card", "link"],
            metadata=self.metadata or None,
        )

    def tempo_charge(
        self, *, recipient: str, metadata: Mapping[str, str] | None = None, **options: Any
    ) -> ServerMethod:
        """Tempo charge paying the Stripe deposit address ``recipient``.

        ``options`` are forwarded to :func:`mpp.tempo.server.charge` and override the rail
        defaults (``testnet``, ``fee_payer``, the 1-cent ``can_offer`` minimum and the Stripe
        recording ``on_payment_success``); the store is always this instance's shared store.
        """
        store = options.pop("store", None)
        if store is not None and store is not self.store:
            raise ValueError(
                "stripe.create() Tempo charges must use the factory-level shared atomic `store`."
            )
        if options.pop("store_key_prefix", None) is not None:
            raise ValueError(
                "stripe.create() Tempo charges cannot override the shared store namespace."
            )
        from mpp.tempo import server as tempo

        kwargs: dict[str, Any] = {"currency": self._tempo_currency, "recipient": recipient}
        if not self.livemode:
            kwargs["testnet"] = True
        kwargs["can_offer"] = _crypto_can_offer
        kwargs["on_payment_success"] = self._recorder(
            "tempo", {**self.metadata, **metadata} if metadata else None
        )
        # Caller options win over the rail defaults (mppx spreads them last).
        [method] = tempo.charge(**{**kwargs, **options, "store": self.store})
        return with_payment_intent_input(method)

    # -- deposit addresses -------------------------------------------------------------------

    async def find_or_create_deposit_address(self, network: str) -> str:
        """Resolves the deposit address for ``network`` (resolver or Stripe API, cached)."""
        if callable(self.deposit_addresses):
            return await self.deposit_addresses(network)
        return await find_or_create_deposit_address(self.client, network)

    # -- default methods ---------------------------------------------------------------------

    def default_methods(
        self,
        *,
        exclude: Iterable[DefaultMethodName] = (),
        rails: Mapping[str, CustomRail] | None = None,
    ) -> list[ServerMethod]:
        """Builds the default methods from static deposit addresses.

        Returns the Tempo charge (when a ``tempo`` address is configured) and the SPT charge,
        followed by the optional custom ``rails`` keyed by network.

        Raises:
            TypeError: When ``deposit_addresses`` is a resolver (use
                :meth:`load_default_methods`).
        """
        if callable(self.deposit_addresses):
            raise TypeError(
                "deposit_addresses is an async resolver; use `await load_default_methods()`."
            )
        addresses = dict(self.deposit_addresses or {})
        return self._build(addresses, set(exclude), rails)

    async def load_default_methods(
        self,
        *,
        exclude: Iterable[DefaultMethodName] = (),
        rails: Mapping[str, CustomRail] | None = None,
    ) -> list[ServerMethod]:
        """Like :meth:`default_methods`, resolving deposit addresses with the async resolver.

        Networks whose address cannot be resolved are excluded with a warning.
        """
        excluded = set(exclude)
        if not callable(self.deposit_addresses):
            return self.default_methods(
                exclude=excluded,
                rails=rails,
            )
        networks: list[str] = []
        if "tempo" not in excluded:
            networks.append("tempo")
        networks.extend(rails or {})
        results = await asyncio.gather(
            *(self.find_or_create_deposit_address(network) for network in networks),
            return_exceptions=True,
        )
        addresses: dict[str, str] = {}
        for network, result in zip(networks, results, strict=True):
            if isinstance(result, BaseException):
                logger.warning("[stripe.create] %s method excluded: %s", network, result)
            else:
                addresses[network] = result
        return self._build(addresses, excluded, rails)

    def _build(
        self,
        addresses: Mapping[str, str],
        excluded: set[DefaultMethodName],
        rails: Mapping[str, CustomRail] | None,
    ) -> list[ServerMethod]:
        methods: list[ServerMethod] = []
        if "tempo" not in excluded and (address := addresses.get("tempo")):
            methods.append(self.tempo_charge(recipient=address))
        if "spt" not in excluded:
            methods.append(self.spt_charge())
        for network, factory in (rails or {}).items():
            address = addresses.get(network)
            if not address:
                raise ValueError(f"stripe: missing deposit address for {network}")
            built = factory(address)
            for method in [built] if isinstance(built, ServerMethod) else built:
                methods.append(self._wrap_rail(network, method))
        return methods

    def _wrap_rail(self, network: str, method: ServerMethod) -> ServerMethod:
        recorder = self._recorder(network)
        user_success = method.on_payment_success
        user_offer = method.can_offer

        async def on_payment_success(context: PaymentSuccessHookContext) -> None:
            assert user_success is not None
            await asyncio.gather(resolve(user_success(context)), resolve(recorder(context)))

        def can_offer(context: CanOfferContext) -> MaybeAwaitable[bool]:
            if not _crypto_can_offer(context):
                return False
            return True if user_offer is None else user_offer(context)

        return with_payment_intent_input(
            dataclasses.replace(
                method,
                can_offer=can_offer,
                on_payment_success=on_payment_success if user_success else recorder,  # pyright: ignore[reportArgumentType]
            )
        )


def create(
    *,
    client: StripeRawClient,
    network_id: str,
    livemode: bool,
    store: AtomicStore,
    deposit_addresses: Mapping[str, str] | DepositAddressResolver | None = None,
    metadata: Mapping[str, str] | None = None,
) -> MachinePayments:
    """Creates a configured Stripe machine payments instance.

    Example::

        from mpp import store
        from mpp.server import Mpp
        from mpp.stripe import StripeHttpClient
        from mpp.stripe import server as stripe

        machine_payments = stripe.create(
            client=StripeHttpClient(STRIPE_SECRET_KEY),
            network_id=STRIPE_PROFILE_ID,
            livemode="_test_" not in STRIPE_SECRET_KEY,
            deposit_addresses={"tempo": TEMPO_DEPOSIT_ADDRESS},
            store=store.memory(),
        )
        mppx = Mpp(methods=machine_payments.default_methods(), secret_key=MPP_SECRET_KEY)
    """
    return MachinePayments(
        client=client,
        network_id=network_id,
        livemode=livemode,
        store=store,
        deposit_addresses=deposit_addresses,
        metadata=metadata,
    )


# -- PaymentIntent options on arbitrary rails ------------------------------------------------


def _options_request_model(base: type[BaseModel]) -> type[BaseModel]:
    """Wraps a rail's request model so it also accepts (and strips) PaymentIntent options."""

    class WithPaymentIntentOptions(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        request: Any
        options: Any = None

        @model_validator(mode="before")
        @classmethod
        def _split(cls, data: Any) -> Any:
            if isinstance(data, WithPaymentIntentOptions):
                return data
            options, request = split_request(data)
            return {"options": validate_input(options), "request": base.model_validate(request)}

        @model_serializer
        def _serialize(self) -> dict[str, Any]:
            # Only the base model's wire form is part of the challenge.
            return self.request.model_dump(mode="json", by_alias=True, exclude_none=True)

    WithPaymentIntentOptions.__name__ = f"{base.__name__}WithPaymentIntentOptions"
    return WithPaymentIntentOptions


def _without_options[C: VerifyContext[Any]](context: C) -> C:
    return dataclasses.replace(context, request=split_request(context.request)[1])


async def _resolve_into_request(context: VerifyContext[Any]) -> None:
    """Resolves the options right before the terminal operation, storing them on the request.

    The resolved value is later snapshotted as ``request_input`` for payment recording.
    """
    options_input, _ = split_request(context.request)
    challenge = context.credential.challenge
    resolved = await resolve_options(
        options_input,
        ResolveContext(
            challenge=challenge,
            credential=context.credential,
            envelope=context.envelope,
            request=context.envelope.request if context.envelope else challenge.request,
        ),
    )
    for key in OPTIONS_KEYS:
        context.request.pop(key, None)
    context.request[_OPTIONS_KEY] = resolved


def with_payment_intent_input(method: ServerMethod) -> ServerMethod:
    """Extends a rail's server-only input with Stripe PaymentIntent options.

    The canonical request (and so the challenge) is unchanged, and the rail's own lifecycle
    hooks never see the Stripe-only field.
    """
    base_resolve = method.resolve_request
    base_verify = method.verify
    base_validate = method.validate
    base_broadcast = method.broadcast
    base_respond = method.respond

    async def resolve_request(context: RequestContext) -> dict[str, Any]:
        options, request = split_request(context.request)
        resolved = (
            await resolve(base_resolve(dataclasses.replace(context, request=request)))
            if base_resolve
            else request
        )
        return {**resolved, _OPTIONS_KEY: options}

    async def verify(context: VerifyContext[Any]) -> Receipt:
        assert base_verify is not None
        await _resolve_into_request(context)
        return await base_verify(_without_options(context))

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        assert base_broadcast is not None
        await _resolve_into_request(context)
        return await base_broadcast(_without_options(context))

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        assert base_validate is not None
        return await base_validate(_without_options(context))

    def respond(context: RespondContext[Any]) -> Any:
        assert base_respond is not None
        return base_respond(_without_options(context))

    definition = method.method
    return dataclasses.replace(
        method,
        method=Method(
            name=definition.name,
            intent=definition.intent,
            request_model=_options_request_model(definition.request_model),
            payload_model=definition.payload_model,
        ),
        resolve_request=resolve_request,
        verify=verify if base_verify else None,
        validate=validate if base_validate else None,
        broadcast=broadcast if base_broadcast else None,
        respond=respond if base_respond else None,
    )
