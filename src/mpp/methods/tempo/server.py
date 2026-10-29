"""Tempo charge for servers.

Usage::

    from mpp.methods.tempo import server as tempo
    from mpp.server import Mpp

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))
    result = await mpp.charge(amount="0.50")(request)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal

from mpp._defaults import DEFAULT_CONFIRMATION_TIMEOUT, DEFAULT_TIMEOUT
from mpp.methods.tempo.client import _CHAIN_ID_UNSET, _tempo_method
from mpp.methods.tempo.intents import ChargeIntent, ValidateSender
from mpp.methods.tempo.schemas import charge as definition
from mpp.server.method import RequestContext, ServerMethod, ValidateContext, VerifyContext

if TYPE_CHECKING:
    import httpx

    from mpp import Credential, Receipt
    from mpp._validation import Validation
    from mpp.methods import CanOfferFn, PaymentSuccessHandler
    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.relay import Relay
    from mpp.methods.tempo.sponsor_budget import SponsorBudget
    from mpp.store import Store

__all__ = ["charge"]


def charge(
    *,
    recipient: str | None = None,
    chain_id: int | None | object = _CHAIN_ID_UNSET,
    rpc_url: str | None = None,
    currency: str | None = None,
    currencies: Sequence[str] | None = None,
    decimals: int = 6,
    fee_payer: TempoAccount | None = None,
    fee_token: str | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    sponsor_budget: SponsorBudget | Literal[False] | None = None,
    store: Store | None = None,
    validate_sender: ValidateSender | None = None,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    confirmation_timeout: float = DEFAULT_CONFIRMATION_TIMEOUT,
    relay: Relay | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> list[ServerMethod]:
    """Create Tempo charge server methods, one per accepted currency in offer order.

    Routes take ``amount`` (decimal string), and optionally ``currency``,
    ``recipient``, ``chain_id``, ``fee_payer`` (sponsor the client's fees),
    ``splits`` (base units) and ``external_id``. A route naming a ``currency``
    offers only that one.

    Args:
        recipient: Default payment recipient.
        chain_id: Tempo chain ID (default: 4217, mainnet; 42431 for Moderato).
        rpc_url: RPC endpoint; overrides the URL resolved from ``chain_id``.
        currency: Deprecated; use ``currencies=[currency]``.
        currencies: Ordered currency addresses to accept. Defaults to OUSD then
            USDC.e on mainnet, OUSD then pathUSD on Moderato.
        decimals: Token decimals used to convert route amounts (default: 6).
        fee_payer: Account that co-signs and broadcasts sponsored transactions.
        fee_token: Token ``fee_payer`` pays gas in. Requires ``fee_payer``.
        allowed_fee_tokens: Tokens a sponsored charge may pay gas in.
        sponsor_budget: Caps the fees ``fee_payer`` has in flight across every
            process sharing it (default: ``SponsorBudget()`` on ``store``).
            Pass ``False`` only when it is enforced elsewhere.
        store: Replay store for transaction hashes. Use a shared store across
            replicas; defaults to a per-process in-memory store.
        validate_sender: Authorizes a hash-credential sender that differs from
            the credential source.
        http_client: HTTP client for RPC calls, owned by the caller.
        timeout: RPC request timeout in seconds.
        confirmation_timeout: Seconds to wait for a broadcast transaction's receipt.
        relay: Serve validation and settlement through the Tempo API relay.
        can_offer: Decides whether to advertise an offer for a wire request.
        on_payment_success: Called with each successful Tempo charge event.
    """
    config = _tempo_method(
        fee_payer=fee_payer,
        chain_id=chain_id,
        rpc_url=rpc_url,
        currency=currency,
        currencies=currencies,
        recipient=recipient,
        decimals=decimals,
        fee_token=fee_token,
        allowed_fee_tokens=allowed_fee_tokens,
    )
    intent = ChargeIntent(
        rpc_url=config.rpc_url,
        http_client=http_client,
        timeout=timeout,
        store=store,
        validate_sender=validate_sender,
        confirmation_timeout=confirmation_timeout,
        fee_payer=fee_payer,
        fee_token=config.fee_token,
        allowed_fee_tokens=config.allowed_fee_tokens,
        sponsor_budget=sponsor_budget,
    )
    verifier: Any = intent if relay is None else relay.configure(intent)

    def use_store(store: Store) -> None:
        if intent._store is None:
            intent._store = store

    def resolve_request(context: RequestContext) -> dict[str, Any]:
        input = {key: value for key, value in context.request.items() if value is not None}
        input.setdefault("recipient", config.recipient)
        input.setdefault("chain_id", config.chain_id)
        input.setdefault("decimals", config.decimals)
        # No route promises sponsorship nobody can give (as mppx). Routes still opt in:
        # local cosigning accepts only secp256k1 sender signatures, so sponsoring by
        # default would refuse access-key and passkey payers.
        if fee_payer is None:
            input.pop("fee_payer", None)
        return input

    def credential(context: VerifyContext) -> Credential:
        payload: Any = context.credential.payload
        return replace(context.credential, payload=payload.model_dump())

    async def validate(context: ValidateContext) -> Validation:
        return await verifier.validate(credential(context), context.challenge.request)

    async def broadcast(context: VerifyContext) -> Receipt:
        return await verifier.broadcast(credential(context), context.challenge.request)

    return [
        ServerMethod(
            method=definition,
            validate=validate,
            broadcast=broadcast,
            resolve_request=resolve_request,
            can_offer=can_offer,
            on_payment_success=on_payment_success,
            defaults={"currency": accepted},
            use_store=use_store,
        )
        for accepted in config.currencies
    ]
