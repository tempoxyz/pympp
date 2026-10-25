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

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from mpp.methods.evm.client import AuthorizationConfig, _config
from mpp.methods.evm.intents import ChargeIntent, SettleFn
from mpp.methods.evm.intents import charge as definition
from mpp.server.method import ServerMethod, ValidateContext, VerifyContext
from mpp.x402.facilitator import Facilitator, resolve_facilitator

if TYPE_CHECKING:
    from mpp import Credential, Receipt
    from mpp._validation import Validation
    from mpp.methods import CanOfferFn, PaymentSuccessHandler
    from mpp.methods.evm.assets import EvmAsset
    from mpp.store import Store
    from mpp.x402._server import RouteBinding

__all__ = ["charge"]


def charge(
    *,
    currency: EvmAsset | str,
    recipient: str,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    facilitator: str | Facilitator | None = None,
    settle: SettleFn | None = None,
    max_timeout_seconds: int = 300,
    route_binding: RouteBinding = "required",
    max_validity_seconds: int = 3600,
    store: Store | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> ServerMethod:
    """Create a server ``evm/charge`` method paid with EIP-3009 authorizations.

    It serves both native MPP clients and x402 ``exact`` clients from the same
    endpoint, and settles through an x402 facilitator or a custom ``settle`` hook.

    Args:
        currency: A known :class:`~mpp.methods.evm.EvmAsset`, or a token address
            together with ``chain_id``, ``decimals`` and ``authorization``.
        recipient: Address that receives payments.
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
            by every worker and replica. Without one, claims are kept in this
            process only.
        can_offer: Optional callback deciding whether to offer a request.
        on_payment_success: Optional callback for this method's payments.
    """
    config = _config(
        currency=currency,
        chain_id=chain_id,
        decimals=decimals,
        authorization=authorization,
        recipient=recipient,
    )
    intent = ChargeIntent(
        name=config.domain_name,
        version=config.domain_version,
        facilitator=resolve_facilitator(facilitator) if facilitator is not None else None,
        settle=settle,
        max_timeout_seconds=max_timeout_seconds,
        route_binding=route_binding,
        store=store,
        max_validity_seconds=max_validity_seconds,
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
        resolve_request=config.resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        x402=intent,
        use_store=use_store,
    )


def _native(credential: Credential) -> Credential:
    """The credential with its parsed payload as the wire object the intent checks."""
    payload: Any = credential.payload
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json", by_alias=True)
    return replace(credential, payload=payload)
