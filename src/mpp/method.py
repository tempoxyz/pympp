"""Payment method contract: definitions plus client- and server-side hook bundles.

A payment method is described by a :class:`Method` (wire ``name`` / ``intent`` plus pydantic
models for the request and the credential payload). Clients wrap it in a :class:`ClientMethod`
(credential creation) and servers in a :class:`ServerMethod` (verification and lifecycle hooks).

Request models may transform their input into the wire form, exactly like mppx zod schemas do
(e.g. a decimal ``amount`` + ``decimals`` becoming base units, or route options being moved under
``methodDetails``). The wire form of a request is always::

    method.request_model.model_validate(input).model_dump(mode="json", by_alias=True, exclude_none=True)

so authors express transforms with pydantic validators, ``Field(exclude=True)``, aliases and
``@model_serializer``. Hooks may be plain functions or coroutines unless documented otherwise.
"""

import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import httpx
from pydantic import BaseModel, ValidationError

from mpp import expires as _expires
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import InvalidChallengeError, InvalidPayloadError, VerificationFailedError
from mpp.receipt import Receipt

__all__ = [
    "Attempt",
    "AttemptOutcome",
    "AuthorizeContext",
    "AuthorizeResult",
    "BroadcastFn",
    "CanOfferContext",
    "CapturedRequest",
    "ClientMethod",
    "CredentialParams",
    "MaybeAwaitable",
    "Method",
    "PaymentSuccessHookContext",
    "PreflightContext",
    "PrepareParams",
    "RequestContext",
    "RespondContext",
    "ResponseParams",
    "Send",
    "ServerMethod",
    "ValidateContext",
    "ValidateFn",
    "Validation",
    "VerifiedChallengeEnvelope",
    "VerifyContext",
    "VerifyFn",
    "broadcast_credential",
    "resolve",
    "validate_credential",
]


if TYPE_CHECKING:
    from mpp.server import Request, Response, Transport

type MaybeAwaitable[T] = T | Awaitable[T]


async def resolve[T](value: MaybeAwaitable[T]) -> T:
    """Awaits ``value`` when it is awaitable (supports sync-or-async hooks)."""
    if inspect.isawaitable(value):
        return await value
    return value


# -- definition --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Method[RequestT: BaseModel, PayloadT: BaseModel]:
    """A payment method definition.

    Attributes:
        name: Wire method name (e.g. ``"tempo"``); lowercase per spec.
        intent: Wire intent name (e.g. ``"charge"``).
        request_model: Pydantic model validating (and transforming) the route request.
        payload_model: Pydantic model validating the credential payload.
    """

    name: str
    intent: str
    request_model: type[RequestT]
    payload_model: type[PayloadT]

    def normalize_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Validates ``request`` and returns its wire form (see module docs).

        Raises:
            pydantic.ValidationError: When the request is invalid.
        """
        return self.request_model.model_validate(dict(request)).model_dump(
            mode="json", by_alias=True, exclude_none=True
        )

    def parse_payload(self, payload: Any) -> PayloadT:
        """Validates a credential payload.

        Raises:
            pydantic.ValidationError: When the payload is invalid.
        """
        return self.payload_model.model_validate(payload)


# -- client ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class AttemptOutcome:
    """Outcome of a paid request, reported to :attr:`Attempt.settle`."""

    status: Literal["accepted", "pending", "rejected"]
    challenges: tuple[Challenge, ...] | None = None
    response: httpx.Response | None = None


@dataclass(slots=True, kw_only=True)
class Attempt:
    """Credential state retained between payment retries until the method settles it.

    Only provided to :attr:`ClientMethod.create_credential` when the method defines
    :attr:`ClientMethod.handle_response`. The method may set ``settle`` to learn the outcome;
    returning ``False`` keeps the attempt pending.
    """

    prepare: Callable[[], Awaitable[None]]
    settle: Callable[[AttemptOutcome], MaybeAwaitable[bool]] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialParams[ContextT]:
    """Arguments passed to :attr:`ClientMethod.create_credential`.

    Attributes:
        challenge: The selected challenge.
        context: The parsed per-request context (``None`` when not provided or the method has no
            context model).
        attempt: Retry lifecycle state (only for methods with ``handle_response``).
    """

    challenge: Challenge
    context: ContextT | None = None
    attempt: Attempt | None = None


type Send = Callable[[httpx.Request], Awaitable[httpx.Response]]
"""Sends a request through the raw (non-paying) transport."""


@dataclass(frozen=True, slots=True, kw_only=True)
class PrepareParams:
    """Arguments passed to :attr:`ClientMethod.prepare` before a credential is created."""

    challenge: Challenge
    context: Any
    send: Send
    request: httpx.Request


@dataclass(frozen=True, slots=True, kw_only=True)
class ResponseParams:
    """Arguments passed to :attr:`ClientMethod.handle_response` for a successful paid response."""

    challenge: Challenge
    credential: str
    send: Send
    headers: httpx.Headers
    request: httpx.Request
    response: httpx.Response
    refetch: Callable[[], Awaitable[httpx.Response]] | None = None


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class ClientMethod:
    """A method configured for clients.

    Attributes:
        method: The method definition.
        create_credential: Creates the serialized credential (``"Payment ..."``) for a challenge.
        can_handle_challenge: Optional predicate when several client implementations share a
            wire method/intent (e.g. native ``evm/charge`` vs x402-synthesized challenges).
        context: Optional pydantic model validating the per-request ``context``.
        prepare: Optional pre-credential hook (e.g. channel top-up) run before
            ``create_credential`` with access to the raw transport.
        handle_response: Optional hook that post-processes a successful paid response
            (e.g. metered streaming); enables :class:`Attempt` lifecycle tracking.
        transaction_hash: Optional derivation of the on-chain hash a credential will settle with,
            reported on :class:`~mpp.errors.PaymentOutcomeUnknownError`.
    """

    method: Method[Any, Any]
    create_credential: Callable[[CredentialParams[Any]], Awaitable[str]]
    can_handle_challenge: Callable[[Challenge], bool] | None = None
    context: type[BaseModel] | None = None
    prepare: Callable[[PrepareParams], MaybeAwaitable[None]] | None = None
    handle_response: Callable[[ResponseParams], MaybeAwaitable[httpx.Response]] | None = None
    transaction_hash: Callable[[str], str | None] | None = None

    @property
    def name(self) -> str:
        return self.method.name

    @property
    def intent(self) -> str:
        return self.method.intent

    @property
    def key(self) -> str:
        """Canonical ``name/intent`` key."""
        return f"{self.method.name}/{self.method.intent}"


# -- server hook contexts ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class CapturedRequest:
    """Immutable transport request snapshot used as the authoritative request for hooks."""

    method: str
    url: httpx.URL
    headers: httpx.Headers
    has_body: bool | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedChallengeEnvelope[PayloadT]:
    """A verified challenge + credential pair bound to the captured request snapshot.

    ``request`` is the authoritative route request in wire form (after defaults, the request
    hook and schema transforms).
    """

    captured_request: CapturedRequest
    challenge: Challenge
    credential: Credential[PayloadT]
    request: dict[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestContext:
    """Arguments for :attr:`ServerMethod.resolve_request` (mppx ``request`` hook).

    ``request`` is the merged route input (defaults + route options), before schema transforms.
    """

    request: dict[str, Any]
    captured_request: CapturedRequest | None = None
    credential: Credential[Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifyContext[PayloadT]:
    """Arguments for ``verify`` / ``broadcast``.

    ``credential.payload`` is the parsed payload model; ``request`` is the resolved route input
    (before schema transforms) — the echoed wire request is ``credential.challenge.request``.
    """

    credential: Credential[PayloadT]
    request: dict[str, Any]
    envelope: VerifiedChallengeEnvelope[PayloadT] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidateContext[PayloadT](VerifyContext[PayloadT]):
    """Arguments for ``validate``; ``operation`` says whether a broadcast follows."""

    operation: Literal["broadcast", "validate"] = "validate"


@dataclass(frozen=True, slots=True, kw_only=True)
class RespondContext[PayloadT](VerifyContext[PayloadT]):
    """Arguments for ``respond``; ``input`` is the raw transport input."""

    input: Any = None
    receipt: Receipt | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizeContext:
    """Arguments for ``authorize`` (HTTP only). ``request`` is the wire request."""

    challenge: Challenge
    input: "Request"
    request: dict[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizeResult:
    """Grants access without a fresh credential. ``response`` short-circuits the route."""

    receipt: Receipt
    response: "Response | None" = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PreflightContext:
    """Arguments for ``preflight`` (HTTP only, runs before challenge/verification)."""

    credential: Credential[Any] | None
    input: "Request"
    options: dict[str, Any]
    realm: str
    secret_key: str
    expires: str | None = None
    captured_request: CapturedRequest | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CanOfferContext:
    """Arguments for ``can_offer``. ``request`` is the schema-normalized wire request (a copy)."""

    input: "Request"
    request: Mapping[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentSuccessHookContext:
    """Arguments for the per-method ``on_payment_success`` hook (values are copies)."""

    receipt: Receipt
    request: Mapping[str, Any]
    challenge: Challenge | None = None
    input: Any = None
    payer: str | None = None
    request_input: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Validation[PayloadT]:
    """Non-mutating validation result returned by ``validate``.

    Confirms a credential is currently acceptable; it does not settle or reserve payment.

    Attributes:
        challenge: The echoed (and, via ``Mpp.validate_credential``, verified) challenge.
        credential: The credential with its payload parsed by the method model.
        details: Method-defined, non-mutating validation data (method-specific shape).
        intent: The validated intent.
        method: The validated method name.
        request: The validated wire request.
        payer: Payer identity established by validation, when known.
        source: Payer identity declared by the credential (asserted, not proven).
    """

    challenge: Challenge
    credential: Credential[PayloadT]
    details: Any
    intent: str
    method: str
    request: dict[str, Any]
    payer: str | None = None
    source: str | None = None


type VerifyFn = Callable[[VerifyContext[Any]], Awaitable[Receipt]]
type ValidateFn = Callable[[ValidateContext[Any]], Awaitable[Validation[Any]]]
type BroadcastFn = Callable[[VerifyContext[Any]], Awaitable[Receipt]]


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class ServerMethod:
    """A method configured for servers.

    Provide either ``verify`` (legacy combined validation + settlement) or ``broadcast``
    (terminal settlement) with an optional non-mutating ``validate``.

    Attributes:
        method: The method definition.
        verify: Combined validate-and-settle hook (deprecated in mppx; still supported).
        validate: Non-mutating credential validation.
        broadcast: Terminal payment operation returning the receipt.
        resolve_request: Normalizes/enriches the route input from the captured request and
            credential (mppx ``request`` hook). Returns the new input.
        authorize: Grants access from existing application state without a credential (HTTP).
        preflight: Handles method-specific management requests before the payment flow (HTTP).
        respond: Returns a management response after successful verification; the route
            handler then does not run (``with_receipt()`` returns it).
        can_offer: Decides whether this configured offer is available for an HTTP request.
        on_payment_success: Side-effect hook after a successful payment (errors are swallowed).
        stable_binding: Produces the request fields used to bind credentials to a route.
        defaults: Default route input merged under per-route options.
        alias: Public alias key (``mppx["tempo/<alias>"]`` / ``mppx.tempo.<alias>``).
        extensions: Extra attributes exposed on this method's route handler factories.
        transport: Per-method server transport override.
    """

    method: Method[Any, Any]
    verify: VerifyFn | None = None
    validate: ValidateFn | None = None
    broadcast: BroadcastFn | None = None
    resolve_request: Callable[[RequestContext], MaybeAwaitable[dict[str, Any]]] | None = None
    authorize: Callable[[AuthorizeContext], MaybeAwaitable[AuthorizeResult | None]] | None = None
    preflight: Callable[[PreflightContext], MaybeAwaitable["Response | None"]] | None = None
    respond: Callable[[RespondContext[Any]], MaybeAwaitable[Any]] | None = None
    can_offer: Callable[[CanOfferContext], MaybeAwaitable[bool]] | None = None
    on_payment_success: Callable[[PaymentSuccessHookContext], MaybeAwaitable[None]] | None = None
    stable_binding: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    defaults: Mapping[str, Any] | None = None
    alias: str | None = None
    extensions: Mapping[str, Any] = field(default_factory=dict)
    transport: "Transport[Any, Any, Any, Any] | None" = None

    def __post_init__(self) -> None:
        if self.verify is None and self.broadcast is None:
            raise TypeError("ServerMethod requires `verify` or `broadcast`.")
        if self.verify is not None and (self.broadcast is not None or self.validate is not None):
            raise TypeError("ServerMethod accepts either `verify` or `validate`/`broadcast`.")

    @property
    def name(self) -> str:
        return self.method.name

    @property
    def intent(self) -> str:
        return self.method.intent

    @property
    def key(self) -> str:
        """Canonical ``name/intent`` key."""
        return f"{self.method.name}/{self.method.intent}"

    async def settle(self, context: VerifyContext[Any]) -> tuple[Receipt, Validation[Any] | None]:
        """Runs ``validate`` (when paired with ``broadcast``) then ``broadcast``, or ``verify``.

        Returns:
            The receipt and the validation result (when ``validate`` ran).
        """
        validation: Validation[Any] | None = None
        if self.broadcast is not None:
            if self.validate is not None:
                validation = await self.validate(
                    ValidateContext(
                        credential=context.credential,
                        request=context.request,
                        envelope=context.envelope,
                        operation="broadcast",
                    )
                )
            return await self.broadcast(context), validation
        assert self.verify is not None
        return await self.verify(context), validation


# -- standalone credential helpers -------------------------------------------------------------


def _prepare_credential(
    methods: list[ServerMethod] | tuple[ServerMethod, ...], value: str | Credential[Any]
) -> tuple[ServerMethod, Credential[Any]]:
    credential = Credential.deserialize(value) if isinstance(value, str) else value
    challenge = credential.challenge
    method = next(
        (m for m in methods if m.name == challenge.method and m.intent == challenge.intent), None
    )
    if method is None:
        raise InvalidChallengeError(
            id=challenge.id,
            reason=f"no registered method for {challenge.method}/{challenge.intent}",
        )
    _expires.ensure(challenge.expires, challenge.id)
    try:
        payload = method.method.parse_payload(credential.payload)
    except ValidationError as error:
        raise InvalidPayloadError(reason=str(error)) from error
    return method, credential.with_payload(payload)


async def validate_credential(
    methods: list[ServerMethod] | tuple[ServerMethod, ...], credential: str | Credential[Any]
) -> Validation[Any]:
    """Validates a credential against one of ``methods`` without settling it.

    Checks structure, expiry and method-specific validation. It does **not** prove the challenge
    was issued by a particular server; challenge issuers must verify the HMAC binding
    (``Mpp.validate_credential`` does).
    """
    method, parsed = _prepare_credential(methods, credential)
    if method.validate is None:
        raise VerificationFailedError(
            details={"intent": method.intent, "method": method.name},
            reason=f"{method.name}/{method.intent} does not support non-mutating credential validation",
        )
    return await method.validate(
        ValidateContext(credential=parsed, request=parsed.challenge.request, operation="validate")
    )


async def broadcast_credential(
    methods: list[ServerMethod] | tuple[ServerMethod, ...], credential: str | Credential[Any]
) -> Receipt:
    """Re-validates and settles a credential, returning a receipt.

    Like :func:`validate_credential`, this does not verify challenge issuance.
    """
    method, parsed = _prepare_credential(methods, credential)
    receipt, _ = await method.settle(
        VerifyContext(credential=parsed, request=parsed.challenge.request)
    )
    return receipt
