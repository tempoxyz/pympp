"""Server-side payment method hooks."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from mpp._validation import Validation
from mpp.methods import CanOfferFn, Method, PaymentSuccessHandler

if TYPE_CHECKING:
    from mpp import Challenge, Credential, Receipt
    from mpp.server.http import Request
    from mpp.store import Store
    from mpp.x402._server import X402Intent

T = TypeVar("T")

# The configured method settling the current payment, so success callbacks reach only it.
SETTLING_METHOD: ContextVar[ServerMethod | None] = ContextVar("mpp_settling_method", default=None)


async def resolve(value: T | Awaitable[T]) -> T:
    """Await `value` when it is awaitable, so hooks may be sync or async."""
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestContext:
    """Arguments for :attr:`ServerMethod.resolve_request`.

    `request` is the route input: the method's defaults merged with the route options.
    """

    request: dict[str, Any]
    credential: Credential | None = None
    input: Request | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyContext:
    """Arguments for `verify` and `broadcast`.

    `credential.payload` is parsed by the method's payload model. `request` is the
    resolved route input; `challenge` is the authenticated challenge the credential
    echoes, whose `request` is the wire request.
    """

    credential: Credential
    request: dict[str, Any]
    challenge: Challenge


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidateContext(VerifyContext):
    """Arguments for `validate`; `operation` says whether a broadcast follows."""

    operation: Literal["broadcast", "validate"] = "validate"


VerifyFn = Callable[[VerifyContext], Awaitable["Receipt"]]
ValidateFn = Callable[[ValidateContext], Awaitable[Validation]]


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class ServerMethod:
    """A payment method configured for servers.

    Provide either `verify` (validation and settlement in one hook) or `broadcast`
    (terminal settlement) with an optional non-mutating `validate`.

    Attributes:
        method: The method definition.
        verify: Validates and settles a credential, returning its receipt.
        validate: Confirms a credential is acceptable without settling or reserving it.
        broadcast: Performs the terminal payment operation and returns its receipt.
        resolve_request: Returns the route input to normalize, given the merged input.
        can_offer: Decides whether to advertise an offer for a wire request.
        on_payment_success: Called with the `payment.success` event of this method.
        defaults: Route input merged under every route's options.
        x402: Lets x402 `exact` clients pay this method's offers.
        use_store: Adopts the `Mpp(store=...)` replay store when the method was
            configured without one of its own.
        credential_options: Keyword options `Mpp.validate_credential` and
            `Mpp.broadcast_credential` accept for this method; others are rejected.
    """

    method: Method[Any, Any]
    verify: VerifyFn | None = None
    validate: ValidateFn | None = None
    broadcast: VerifyFn | None = None
    resolve_request: (
        Callable[[RequestContext], dict[str, Any] | Awaitable[dict[str, Any]]] | None
    ) = None
    can_offer: CanOfferFn | None = None
    on_payment_success: PaymentSuccessHandler | None = None
    defaults: Mapping[str, Any] | None = None
    x402: X402Intent | None = None
    use_store: Callable[[Store], None] | None = None
    credential_options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.verify is None and self.broadcast is None:
            raise TypeError("ServerMethod requires verify or broadcast")
        if self.verify is not None and (self.broadcast is not None or self.validate is not None):
            raise TypeError("ServerMethod accepts either verify or validate/broadcast")
        if self.can_offer is not None and not callable(self.can_offer):
            raise ValueError("can_offer must be callable")
        if self.on_payment_success is not None and not callable(self.on_payment_success):
            raise ValueError("on_payment_success must be callable")

    @property
    def name(self) -> str:
        return self.method.name

    @property
    def intent(self) -> str:
        return self.method.intent

    @property
    def key(self) -> str:
        """The `name/intent` key."""
        return self.method.key

    async def settle(self, context: VerifyContext) -> tuple[Receipt, Validation | None]:
        """Run `validate` then `broadcast`, or `verify`.

        The validation's `payer` is copied to the receipt unless it already has one.
        """
        if self.verify is not None:
            return await self.verify(context), None
        assert self.broadcast is not None
        validation = None
        if self.validate is not None:
            validation = await self.validate(
                ValidateContext(
                    credential=context.credential,
                    request=context.request,
                    challenge=context.challenge,
                    operation="broadcast",
                )
            )
        receipt = await self.broadcast(context)
        if validation is not None and validation.payer is not None and receipt.payer is None:
            receipt = replace(receipt, payer=validation.payer)
        return receipt, validation
