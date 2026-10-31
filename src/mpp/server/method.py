"""Server-side payment method hooks."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from mpp._validation import Validation
from mpp.errors import VerificationFailedError
from mpp.methods import CanOfferFn, Method, PaymentSuccessHandler

if TYPE_CHECKING:
    from mpp import Challenge, Credential, Receipt
    from mpp.server.http import Request, Response
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
    echoes, whose `request` is the wire request. `input` is the HTTP request being
    paid for (mppx's captured request), so a method can classify it by HTTP method, URL,
    headers and body; it is ``None`` outside a route handler, such as in
    `Mpp.validate_credential` and `Mpp.broadcast_credential`.
    """

    credential: Credential
    request: dict[str, Any]
    challenge: Challenge
    input: Request | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidateContext(VerifyContext):
    """Arguments for `validate`; `operation` says whether a broadcast follows."""

    operation: Literal["broadcast", "validate"] = "validate"


@dataclass(frozen=True, slots=True, kw_only=True)
class RespondContext(VerifyContext):
    """Arguments for :attr:`ServerMethod.respond`: the verify context and its receipt."""

    receipt: Receipt


@dataclass(frozen=True, slots=True, kw_only=True)
class PreflightContext:
    """Arguments for :attr:`ServerMethod.preflight` (mppx ``PreflightFn``).

    ``request`` is the route input: the method's defaults merged with the route options.
    ``credential`` is the Payment credential the request carries, of any method, unverified.
    ``expires`` is the route's challenge expiry, when it sets one; ``header`` is the field
    credentials are sent in when it is not ``Authorization``. ``realm`` and ``secret_key`` are
    the server's, so a preflight can issue and authenticate its own challenges.
    """

    input: Request
    request: dict[str, Any]
    credential: Credential | None
    realm: str
    secret_key: str
    expires: str | None = None
    header: str | None = None


VerifyFn = Callable[[VerifyContext], Awaitable["Receipt"]]
ValidateFn = Callable[[ValidateContext], Awaitable[Validation]]
RespondFn = Callable[[RespondContext], "Response | None | Awaitable[Response | None]"]
StableBindingFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]
PreflightFn = Callable[[PreflightContext], "Response | None | Awaitable[Response | None]"]


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
        needs_request_body: Set when `resolve_request` reads `RequestContext.input.body`,
            so framework decorators such as `pay()` read the request body for it.
        respond: Called after a credential is verified, before `payment.success`. A returned
            :class:`~mpp.server.Response` fully handles the request (a management action,
            such as opening or closing a payment channel): the route doesn't run and
            `PaymentVerified.with_receipt` returns that response with the receipt
            attached. ``None`` lets the route serve its content.
        stable_binding: Maps a wire request to the fields a credential's echoed request must
            match (mppx ``stableBinding``). Set, a challenge pays any request to its route whose
            binding matches, such as a reusable session challenge bound to its channel terms
            but not to its quoted amount; unset, the echoed request must equal the route's.
        preflight: Called for each request before its challenge or credential is handled, for
            method-specific management requests such as a session bootstrap (mppx
            ``preflight``). A returned :class:`~mpp.server.Response` fully handles the request:
            the route handler returns it as :class:`~mpp.server.PaymentRequired`, so the route
            doesn't run. ``None`` continues with the normal payment flow.
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
    needs_request_body: bool = False
    respond: RespondFn | None = None
    stable_binding: StableBindingFn | None = None
    preflight: PreflightFn | None = None

    def __post_init__(self) -> None:
        if self.verify is None and self.broadcast is None:
            raise TypeError("ServerMethod requires verify or broadcast")
        if self.verify is not None and (self.broadcast is not None or self.validate is not None):
            raise TypeError("ServerMethod accepts either verify or validate/broadcast")
        if self.can_offer is not None and not callable(self.can_offer):
            raise ValueError("can_offer must be callable")
        if self.on_payment_success is not None and not callable(self.on_payment_success):
            raise ValueError("on_payment_success must be callable")
        if self.respond is not None and not callable(self.respond):
            raise ValueError("respond must be callable")
        if self.stable_binding is not None and not callable(self.stable_binding):
            raise ValueError("stable_binding must be callable")
        if self.preflight is not None and not callable(self.preflight):
            raise ValueError("preflight must be callable")

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
                    input=context.input,
                    operation="broadcast",
                )
            )
            if not isinstance(validation, Validation):
                raise VerificationFailedError("Intent returned an invalid validation result")
        receipt = await self.broadcast(context)
        if validation is not None and validation.payer is not None and receipt.payer is None:
            receipt = replace(receipt, payer=validation.payer)
        return receipt, validation
