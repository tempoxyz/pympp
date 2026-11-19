"""EVM charge for servers.

Usage::

    from mpp.methods.evm import BASE_USDC
    from mpp.methods.evm import server as evm
    from mpp.server import Mpp

    mpp = Mpp(
        methods=evm.charge(
            currency=BASE_USDC,
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            facilitator="https://facilitator.example.com",
        )
    )
    result = await mpp.charge(amount="0.01")(request)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from mpp._parsing import ParseError, _b64_decode
from mpp.methods.evm.client import AuthorizationConfig, _config
from mpp.methods.evm.intents import ChargeIntent, SettleFn
from mpp.methods.evm.intents import charge as definition
from mpp.server.method import OfferUnavailableError, ServerMethod, ValidateContext, VerifyContext
from mpp.x402._header import InvalidHeaderError, decode_payment_signature
from mpp.x402._types import PAYMENT_SIGNATURE_HEADER
from mpp.x402.facilitator import (
    Facilitator,
    PayToResolver,
    pay_to,
    pay_to_resolver,
    resolve_facilitator,
)

if TYPE_CHECKING:
    from mpp import Credential, Receipt
    from mpp._validation import Validation
    from mpp.methods import CanOfferFn, PaymentSuccessHandler
    from mpp.methods.evm.assets import EvmAsset
    from mpp.server.http import Request
    from mpp.server.method import RequestContext
    from mpp.store import Store
    from mpp.x402._server import RouteBinding
    from mpp.x402.siwx import SiwxOptions

__all__ = ["charge", "facilitator_pay_to", "facilitator_pay_to_resolver"]

RecipientResolver = Callable[[], Awaitable[str]]


async def facilitator_pay_to(
    facilitator: str | Facilitator, *, network: str, scheme: str = "exact"
) -> str:
    """Read the ``payTo`` an x402 facilitator publishes in ``GET /supported``.

    For facilitators that settle into an address of their own
    (``kinds[].extra.payTo``). Reads it once. You rarely need it: leave out
    :func:`charge`'s ``recipient`` and the charge reads the facilitator's ``payTo``
    itself, refreshing it every 5 minutes::

        method = charge(
            currency=BASE_USDC,
            facilitator=FACILITATOR_URL,
            x402_extra={"tempoSettlement": "0x..."},
        )

    Raises:
        FacilitatorError: If the facilitator has no ``supported()``, publishes no
            valid ``payTo`` for the scheme and network, or is a URL that is not
            ``https://`` (loopback hosts excepted).
    """
    return await pay_to(facilitator, network=network, scheme=scheme)


def facilitator_pay_to_resolver(
    facilitator: str | Facilitator,
    *,
    network: str,
    scheme: str = "exact",
    ttl: float = 300.0,
    grace: float = 600.0,
) -> PayToResolver:
    """Like :func:`facilitator_pay_to`, but return a :class:`~mpp.x402.PayToResolver` that
    caches the address for ``ttl`` seconds and refreshes it after, for :func:`charge`'s
    ``recipient``. Payments for an address it replaced still verify for ``grace``
    seconds. A charge that leaves out ``recipient`` uses one for you; call this only to
    change ``ttl`` or ``grace``.
    """
    return pay_to_resolver(facilitator, network=network, scheme=scheme, ttl=ttl, grace=grace)


def charge(
    *,
    currency: EvmAsset | str,
    recipient: str | RecipientResolver | None = None,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    facilitator: str | Facilitator | None = None,
    settle: SettleFn | None = None,
    max_timeout_seconds: int = 300,
    route_binding: RouteBinding = "required",
    max_validity_seconds: int = 3600,
    store: Store | None = None,
    siwx: SiwxOptions | None = None,
    x402_extra: Mapping[str, Any] | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> ServerMethod:
    """Create a server ``evm/charge`` method paid with EIP-3009 authorizations.

    It serves both native MPP clients and x402 ``exact`` clients from the same
    endpoint, and settles through an x402 facilitator or a custom ``settle`` hook.

    Args:
        currency: A known :class:`~mpp.methods.evm.EvmAsset`, or a token address
            together with ``chain_id``, ``decimals`` and ``authorization``.
        recipient: Address that receives payments, or an async function that returns it
            for each challenge. Leave it out when ``facilitator`` settles into an address
            of its own and publishes it as ``payTo`` in ``GET /supported`` (such as the
            Tempo x402 facilitator): it is read on the first challenge, cached and
            refreshed every 5 minutes.
        chain_id: EVM chain ID. Inferred from a known asset.
        decimals: Token decimals. Inferred from a known asset.
        authorization: EIP-712 domain (``name``, ``version``) the token signs
            EIP-3009 authorizations with. Inferred from a known asset.
        facilitator: x402 facilitator URL or client that verifies and settles payments.
        settle: Custom settlement hook used instead of a facilitator. It
            receives the verified authorization and returns its reference.
        max_timeout_seconds: x402 ``maxTimeoutSeconds`` offered to clients.
        route_binding: How x402 payments bind to routes, which are scoped to their
            HTTP method, path and query. ``"required"`` (the default) accepts only
            clients that sign the ``extensions.mppx`` route binding; set
            ``"resource"`` to accept standard x402 clients, which bind by the echoed
            terms and resource URL.
        max_validity_seconds: Longest an authorization may stay valid from now
            (default one hour).
        store: Store that claims each authorization before settlement, shared
            by every worker and replica. Without one (or ``Mpp(store=...)``), claims
            are kept in this process only, which raises in production or on a
            multi-instance platform; pass ``MemoryStore()`` to accept that there.
        siwx: Optional x402 ``sign-in-with-x`` (SIWX) options
            (:class:`~mpp.x402.siwx.SiwxOptions`). The x402 402 then offers the
            ``sign-in-with-x`` extension, and a request with a valid ``SIGN-IN-WITH-X``
            proof from a wallet ``grant`` approves succeeds without payment, with a
            ``did:pkh:eip155:<chain>:<address>`` receipt reference.
        x402_extra: Extra fields added to every x402 payment requirement's
            ``extra``, for facilitators that read their own keys there. They can't
            override ``assetTransferMethod``, ``name`` or ``version``.
        can_offer: Optional callback deciding whether to offer a request.
        on_payment_success: Optional callback for this method's payments.
    """
    config = _config(
        currency=currency,
        chain_id=chain_id,
        decimals=decimals,
        authorization=authorization,
        recipient=recipient if isinstance(recipient, str) else None,
    )
    resolve_recipient: PayToResolver | None = None
    if recipient is None:
        if facilitator is None:
            raise ValueError("EVM charge requires recipient or a facilitator that publishes payTo")
        resolve_recipient = pay_to_resolver(facilitator, network=f"eip155:{config.chain_id}")
    elif isinstance(recipient, PayToResolver):
        resolve_recipient = recipient
    elif not isinstance(recipient, str):
        resolve_recipient = PayToResolver(recipient)
    intent = ChargeIntent(
        name=config.domain_name,
        version=config.domain_version,
        facilitator=resolve_facilitator(facilitator) if facilitator is not None else None,
        settle=settle,
        max_timeout_seconds=max_timeout_seconds,
        route_binding=route_binding,
        store=store,
        max_validity_seconds=max_validity_seconds,
        siwx=siwx,
        x402_extra=x402_extra,
    )

    def use_store(store: Store) -> None:
        if intent._store is None:
            intent._store = store

    async def validate(context: ValidateContext) -> Validation:
        return await intent.validate(_native(context.credential), context.challenge.request)

    async def broadcast(context: VerifyContext) -> Receipt:
        return await intent.broadcast(_native(context.credential), context.challenge.request)

    return ServerMethod(
        method=definition,
        validate=validate,
        broadcast=broadcast,
        resolve_request=(
            config.resolve_request
            if resolve_recipient is None
            else _recipient_hook(config.resolve_request, resolve_recipient)
        ),
        can_offer=can_offer,
        defaults={"currency": config.currency},
        on_payment_success=on_payment_success,
        x402=intent,
        use_store=use_store,
        _has_store=lambda: intent._store is not None,
    )


# Satisfies the request model where no payment is in flight (discovery, route checks).
_PLACEHOLDER_RECIPIENT = "0x0000000000000000000000000000000000000000"


def _recipient_hook(
    resolve_request: Callable[[RequestContext], dict[str, Any]], resolver: PayToResolver
) -> Callable[[RequestContext], dict[str, Any] | Awaitable[dict[str, Any]]]:
    """Fill a route's ``recipient`` from ``resolver`` on each challenge.

    New challenges always carry the current address. A payment still verifies against an
    address the resolver replaced less than its ``grace`` ago, when the payment names it:
    the echoed challenge of a native credential, or an x402 payment's ``accepted.payTo``.
    Neither is trusted on its own (both come from the caller, and a failed check re-issues
    a challenge from this request), so only addresses this process issued qualify.

    Discovery and route checks carry no payment and run synchronously, with the last
    address read or a placeholder.
    """

    def with_recipient(context: RequestContext, recipient: str) -> dict[str, Any]:
        return resolve_request(
            replace(context, request={**context.request, "recipient": recipient})
        )

    async def resolve(context: RequestContext) -> dict[str, Any]:
        try:
            recipient = await resolver()
        except Exception as error:
            raise OfferUnavailableError(f"EVM charge recipient unavailable: {error}") from error
        named = (
            _echoed_recipient(context.credential)
            if context.credential is not None
            else _x402_pay_to(context.input)
        )
        if named is not None:
            recipient = resolver.issued(named) or recipient
        return with_recipient(context, recipient)

    def hook(context: RequestContext) -> dict[str, Any] | Awaitable[dict[str, Any]]:
        if context.request.get("recipient"):
            return resolve_request(context)
        if context.credential is None and context.input is None:
            return with_recipient(context, resolver.current or _PLACEHOLDER_RECIPIENT)
        return resolve(context)

    return hook


def _x402_pay_to(request: Request | None) -> str | None:
    """The ``accepted.payTo`` of an x402 payment the request carries, if any."""
    header = request.headers.get(PAYMENT_SIGNATURE_HEADER) if request is not None else None
    if not header:
        return None
    try:
        accepted = decode_payment_signature(header).get("accepted")
    except InvalidHeaderError:
        return None
    pay_to = accepted.get("payTo") if isinstance(accepted, Mapping) else None
    return pay_to if isinstance(pay_to, str) else None


def _echoed_recipient(credential: Credential | None) -> str | None:
    """The recipient a credential's echoed challenge carries, if any."""
    if credential is None or not credential.challenge.request:
        return None
    try:
        echoed = _b64_decode(credential.challenge.request).get("recipient")
    except ParseError:
        return None
    return echoed if isinstance(echoed, str) else None


def _native(credential: Credential) -> Credential:
    """The credential with its parsed payload as the wire object the intent checks."""
    payload: Any = credential.payload
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json", by_alias=True)
    return replace(credential, payload=payload)
