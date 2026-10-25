"""EVM server methods.

Example::

    from mpp.server import Mpp
    from mpp.evm import server as evm

    mppx = Mpp(
        methods=[
            evm.evm(
                currencies=[evm.assets.BASE_USDC],
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                x402=evm.X402Options(facilitator="https://facilitator.example"),
            )
        ]
    )
"""

from collections.abc import Callable, Sequence

from mpp.evm import assets, chains, tokens
from mpp.evm._types import AuthorizationConfig
from mpp.evm.server._charge import (
    EvmHttpTransport,
    SettleParams,
    SettleResult,
    X402Options,
    charge,
)
from mpp.method import CanOfferContext, MaybeAwaitable, PaymentSuccessHookContext, ServerMethod
from mpp.store import AtomicStore
from mpp.x402._evm_charge import RouteBindingMode, SettleAuthorization
from mpp.x402.assets import Currency, KnownAsset, Token, resolve, to_chain_id, to_network


def evm(
    *,
    currencies: Sequence[Currency],
    recipient: str,
    authorization: AuthorizationConfig | None = None,
    chain_id: int | None = None,
    decimals: int | None = None,
    settle: SettleAuthorization | None = None,
    x402: X402Options | None = None,
    max_validity_seconds: int = 3600,
    store: AtomicStore | None = None,
    can_offer: Callable[[CanOfferContext], MaybeAwaitable[bool]] | None = None,
    on_payment_success: Callable[[PaymentSuccessHookContext], MaybeAwaitable[None]] | None = None,
) -> list[ServerMethod]:
    """Creates ordered EVM charge offers, one per accepted currency.

    Token definitions resolve against ``chain_id``; known assets carry their own network.
    Currencies unavailable on the chain and token definitions not denominated in USD are
    skipped (one shared price cannot price them), and duplicate chain/address pairs are removed.
    Token definitions need explicit EIP-3009 domain metadata (``authorization``, or
    :func:`mpp.evm.assets.from_token` per token).

    Raises:
        ValueError: When no currency remains or a currency has no chain.
    """
    seen: set[str] = set()
    methods: list[ServerMethod] = []
    for currency in currencies:
        chain = chain_id
        if chain is None and isinstance(currency, KnownAsset):
            chain = to_chain_id(currency.network)
        if chain is None:
            raise ValueError("EVM currencies require `chainId` or known asset metadata.")
        resolved = resolve(currency, to_network(chain))
        if resolved is None:
            continue
        if isinstance(currency, Token) and currency.currency != "USD":
            continue
        key = f"{chain}:{resolved.address.lower()}"
        if key in seen:
            continue
        seen.add(key)
        methods.append(
            charge(
                currency=currency,
                recipient=recipient,
                authorization=authorization,
                chain_id=chain,
                decimals=decimals,
                settle=settle,
                x402=x402,
                max_validity_seconds=max_validity_seconds,
                store=store,
                can_offer=can_offer,
                on_payment_success=on_payment_success,
            )
        )
    if not methods:
        raise ValueError("No accepted EVM currencies for the configured chain.")
    return methods


__all__ = [
    "AuthorizationConfig",
    "EvmHttpTransport",
    "RouteBindingMode",
    "SettleAuthorization",
    "SettleParams",
    "SettleResult",
    "X402Options",
    "assets",
    "chains",
    "charge",
    "evm",
    "tokens",
]
