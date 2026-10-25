"""The server payment engine (mppx ``Mppx.create``)."""

import logging
import warnings
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import ValidationError

from mpp import _env, _url
from mpp import expires as _expires
from mpp.challenge import Challenge
from mpp.constants import Header
from mpp.credential import (
    Credential,
    InvalidCredentialEncodingError,
    MissingAuthorizationHeaderError,
    MissingPaymentSchemeError,
)
from mpp.errors import (
    InternalPaymentError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentError,
    PaymentRequiredError,
    VerificationFailedError,
)
from mpp.expires import DatetimeInput, to_datetime_string
from mpp.method import (
    AuthorizeContext,
    CapturedRequest,
    PreflightContext,
    RequestContext,
    RespondContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerifiedChallengeEnvelope,
    VerifyContext,
    resolve,
)
from mpp.receipt import Receipt
from mpp.server import _binding
from mpp.server._events import (
    ChallengeCreated,
    EventDispatcher,
    EventHandler,
    PaymentFailed,
    PaymentSucceeded,
    Unsubscribe,
    descriptor,
    snapshot,
    snapshot_captured,
    snapshot_input,
    snapshot_mapping,
)
from mpp.server._http import Request, Response
from mpp.server._transport import (
    HttpTransport,
    Transport,
)

logger = logging.getLogger("mpp.server")

DEFAULT_REALM = "MPP Payment"
MINIMUM_SECRET_KEY_BYTES = 32
_ROUTE_OPTION_KEYS = ("description", "meta", "scope")
_warned: set[str] = set()

RESERVED_KEYS = frozenset(
    {
        "challenge",
        "compose",
        "methods",
        "on",
        "onChallengeCreated",
        "onPaymentFailed",
        "onPaymentSuccess",
        "on_challenge_created",
        "on_payment_failed",
        "on_payment_success",
        "realm",
        "broadcastCredential",
        "broadcast_credential",
        "transport",
        "validateCredential",
        "validate_credential",
        "verifyCredential",
        "verify_credential",
    }
)
"""Instance attributes that payment method names and intents cannot shadow."""


def assert_secret_key(secret_key: str) -> None:
    """Validates the minimum entropy required for HMAC-bound payment challenges.

    Raises:
        ValueError: When the key is shorter than 32 bytes.
    """
    if len(secret_key.encode()) >= MINIMUM_SECRET_KEY_BYTES:
        return
    raise ValueError(
        f"Secret key must be at least {MINIMUM_SECRET_KEY_BYTES} bytes. Generate one with "
        "`openssl rand -base64 32` and set MPP_SECRET_KEY or pass it to Mpp()."
    )


class MissingReceiptResponseError(Exception):
    """Raised when ``with_receipt()`` needs a response but none was provided."""

    def __init__(self) -> None:
        super().__init__("withReceipt() requires a response argument")


# -- results -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PaymentRequired[ChallengeT]:
    """Payment is required (or the credential was rejected): return ``challenge`` as-is."""

    challenge: ChallengeT
    status: Literal[402] = 402


class PaymentVerified[ReceiptOutT]:
    """Payment succeeded (or access was authorized): wrap the route response with a receipt.

    ``with_receipt()`` without a response returns the method's management response when one
    exists (e.g. channel open/close) and raises :class:`MissingReceiptResponseError` otherwise.
    """

    status: Literal[200] = 200

    def __init__(
        self,
        with_receipt: Callable[[Any], ReceiptOutT],
        *,
        supports_streaming_receipts: bool = False,
        has_management_response: bool = False,
    ) -> None:
        self._with_receipt = with_receipt
        self.supports_streaming_receipts = supports_streaming_receipts
        self.has_management_response = has_management_response

    def with_receipt(self, response: Any = None) -> ReceiptOutT:
        return self._with_receipt(response)

    def __repr__(self) -> str:
        return "PaymentVerified(status=200)"


type PaymentResult = PaymentRequired[Any] | PaymentVerified[Any]


# -- offers ------------------------------------------------------------------------------------


@dataclass(slots=True, eq=False, kw_only=True)
class OfferInfo:
    """A configured payment offer (discovery metadata and compose dispatch state).

    ``request`` is the schema-normalized wire request; it is refreshed with the request-hook
    output on every invocation, like mppx ``_canonicalRequest``.
    """

    method: ServerMethod
    request: dict[str, Any]
    options: dict[str, Any]
    meta: dict[str, str] | None
    description: str | None
    credential_headers: tuple[str, ...]
    transport: Transport[Any, Any, Any, Any]

    @property
    def name(self) -> str:
        return self.method.name

    @property
    def intent(self) -> str:
        return self.method.intent

    @property
    def key(self) -> str:
        return self.method.key


class ConfiguredHandler:
    """A route handler for one configured offer (the result of ``mppx.charge(...)``)."""

    def __init__(self, fn: Callable[[Any], Awaitable[PaymentResult]], offer: OfferInfo) -> None:
        self._fn = fn
        self.offer = offer

    async def __call__(self, input: Any) -> PaymentResult:
        return await self._fn(input)

    @property
    def offers(self) -> tuple[OfferInfo, ...]:
        return (self.offer,)

    @property
    def method(self) -> ServerMethod:
        return self.offer.method


class ComposedHandler:
    """A route handler presenting several offers (``compose()`` / shared intents)."""

    def __init__(
        self,
        fn: Callable[[Any], Awaitable[PaymentResult]],
        *,
        offers: tuple[OfferInfo, ...],
        handlers: tuple["Handler", ...],
    ) -> None:
        self._fn = fn
        self.offers = offers
        self.handlers = handlers

    async def __call__(self, input: Any) -> PaymentResult:
        return await self._fn(input)


type Handler = ConfiguredHandler | ComposedHandler


class HandlerFactory:
    """Creates route handlers from route options: ``mppx.tempo.charge(amount="1")``.

    Method ``extensions`` are exposed as attributes.
    """

    def __init__(
        self,
        create: Callable[..., Handler],
        *,
        method: ServerMethod | None,
        extensions: Mapping[str, Any] | None = None,
    ) -> None:
        self._create = create
        self.method = method
        self._extensions = dict(extensions or {})

    def __call__(self, **options: Any) -> Handler:
        return self._create(**options)

    def __getattr__(self, name: str) -> Any:
        extensions = self.__dict__.get("_extensions", {})
        if name in extensions:
            return extensions[name]
        raise AttributeError(name)


class _Namespace:
    """Attribute namespace (``mppx.tempo``, ``mppx.challenge.tempo``)."""

    def __init__(self, entries: dict[str, Any]) -> None:
        self._entries = entries

    def __getattr__(self, name: str) -> Any:
        entries = self.__dict__.get("_entries", {})
        if name in entries:
            return entries[name]
        raise AttributeError(name)

    def __getitem__(self, name: str) -> Any:
        return self._entries[name]

    def __contains__(self, name: object) -> bool:
        return name in self._entries

    def __dir__(self) -> list[str]:
        return sorted(self._entries)


type Methods = Sequence[ServerMethod | Sequence[ServerMethod]]


def _flatten(methods: Methods) -> tuple[ServerMethod, ...]:
    flat: list[ServerMethod] = []
    for entry in methods:
        if isinstance(entry, ServerMethod):
            flat.append(entry)
        else:
            flat.extend(entry)
    return tuple(flat)


# -- engine ------------------------------------------------------------------------------------


class Mpp:
    """Server-side payment handler.

    Args:
        methods: Configured server methods (nested sequences are flattened).
        realm: Server realm. Defaults to ``MPP_REALM`` (and platform host variables), then the
            request host, then ``"MPP Payment"``.
        secret_key: HMAC secret for challenge ids (>= 32 bytes). Defaults to ``MPP_SECRET_KEY``.
        requires_auth: Read credentials from ``Payment-Authorization`` so ``Authorization``
            stays available for application authentication (HTTP only).
        transport: Server transport (default :func:`mpp.server.http`).

    Raises:
        ValueError: When the secret key is missing or too short, or a method name/intent
            collides with a reserved attribute.
    """

    def __init__(
        self,
        *,
        methods: Methods,
        realm: str | None = None,
        secret_key: str | None = None,
        requires_auth: bool = False,
        transport: Transport[Any, Any, Any, Any] | None = None,
    ) -> None:
        resolved_secret = secret_key if secret_key is not None else _env.get("secret_key")
        if not resolved_secret:
            raise ValueError(
                "Missing secret key. Set the MPP_SECRET_KEY environment variable or pass "
                "`secret_key` to Mpp()."
            )
        assert_secret_key(resolved_secret)
        self.secret_key = resolved_secret
        self.realm: str | None = realm if realm is not None else _env.get("realm")
        self.transport: Transport[Any, Any, Any, Any] = transport or HttpTransport(
            requires_auth=requires_auth
        )
        self.methods = _flatten(methods)
        self._credential_header = Header.PAYMENT_AUTHORIZATION if requires_auth else None
        self._events = EventDispatcher()

        for method in self.methods:
            if method.name in RESERVED_KEYS:
                raise ValueError(
                    f'Method name "{method.name}" conflicts with a reserved Mpp property.'
                )
            if method.intent in RESERVED_KEYS:
                raise ValueError(
                    f'Method intent "{method.intent}" conflicts with a reserved Mpp property.'
                )

        self._factories: dict[ServerMethod, HandlerFactory] = {}
        handlers: dict[str, HandlerFactory] = {}
        for method in self.methods:
            factory = HandlerFactory(
                self._method_factory(method), method=method, extensions=method.extensions
            )
            self._factories[method] = factory
            wire_key = method.key
            alias_key = f"{method.name}/{method.alias}" if method.alias else None
            if alias_key is None or wire_key not in handlers:
                handlers[wire_key] = factory
            if alias_key is not None:
                handlers[alias_key] = factory

        # Shorthand intent keys: a single method gets its direct handler; several methods
        # sharing an intent get an implicit compose.
        intent_counts: dict[str, int] = {}
        for method in self.methods:
            intent_counts[method.intent] = intent_counts.get(method.intent, 0) + 1
        processed: set[str] = set()
        for method in self.methods:
            if method.intent in processed:
                continue
            processed.add(method.intent)
            if intent_counts[method.intent] == 1:
                handlers[method.intent] = handlers[method.key]
            else:
                group = [m for m in self.methods if m.intent == method.intent]
                handlers[method.intent] = HandlerFactory(self._group_factory(group), method=None)

        # Preserve distinct configured offers sharing a wire key (non-aliased duplicates).
        for key in dict.fromkeys(m.key for m in self.methods if not m.alias):
            matching = [m for m in self.methods if not m.alias and m.key == key]
            if len(matching) < 2:
                continue
            handlers[key] = HandlerFactory(
                self._group_factory(matching),
                method=matching[0],
                extensions=matching[0].extensions,
            )

        namespaces: dict[str, dict[str, Any]] = {}
        for method in self.methods:
            public = method.alias or method.intent
            key = f"{method.name}/{public}"
            namespaces.setdefault(method.name, {})[public] = handlers[key]
        for name, entries in namespaces.items():
            handlers.setdefault(name, _Namespace(entries))  # type: ignore[arg-type]
        self._handlers: dict[str, Any] = handlers

        challenge_entries: dict[str, dict[str, Any]] = {}
        for method in self.methods:
            public = method.alias or method.intent
            group = challenge_entries.setdefault(method.name, {})
            if public not in group:
                group[public] = self._challenge_fn(method)
        self.challenge = _Namespace(
            {name: _Namespace(entries) for name, entries in challenge_entries.items()}
        )

    # -- handler lookup -----------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        """Returns the handler factory (or namespace) registered under ``key``."""
        try:
            return self._handlers[key]
        except KeyError:
            raise KeyError(f'No handler for "{key}".') from None

    def __getattr__(self, name: str) -> Any:
        handlers = self.__dict__.get("_handlers")
        if handlers is not None and name in handlers:
            return handlers[name]
        raise AttributeError(name)

    def __contains__(self, key: object) -> bool:
        return key in self._handlers

    # -- events -------------------------------------------------------------------------------

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Registers a handler for ``challenge.created``, ``payment.failed``,
        ``payment.success`` or ``"*"`` (receives :class:`EventEnvelope`).

        Handlers are awaited inline and sequentially; their errors are swallowed.
        """
        return self._events.on(name, handler)

    def on_challenge_created(self, handler: EventHandler) -> Unsubscribe:
        return self._events.on("challenge.created", handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        return self._events.on("payment.failed", handler)

    def on_payment_success(self, handler: EventHandler) -> Unsubscribe:
        return self._events.on("payment.success", handler)

    # -- compose ------------------------------------------------------------------------------

    def compose(self, *entries: tuple[Any, Mapping[str, Any]]) -> Handler:
        """Combines configured offers into one route handler.

        Each entry is ``(method_or_key_or_factory, options)`` where the first element is a
        configured :class:`ServerMethod`, a ``"name/intent"`` (or alias) key, or a handler
        factory such as ``mppx.tempo.charge``.

        Raises:
            ValueError: For unknown entries or unsupported transports.
        """
        from mpp.server._compose import compose_handlers, compose_mcp_handlers, is_mcp

        mcp = is_mcp(self.transport)
        if not mcp and not isinstance(self.transport, HttpTransport):
            raise ValueError("compose() only supports HTTP and MCP transports")
        if not entries:
            raise ValueError("compose() requires at least one entry")
        configured: list[Handler] = []
        for target, options in entries:
            factory: HandlerFactory | None
            if isinstance(target, str):
                found = self._handlers.get(target)
                factory = found if isinstance(found, HandlerFactory) else None
                key = target
            elif isinstance(target, HandlerFactory):
                factory = target if target in self._handlers.values() else None
                if factory is None and target.method is not None:
                    factory = self._factories.get(target.method)
                key = target.method.key if target.method else "<handler>"
            else:
                factory = self._factories.get(target)
                key = f"{target.name}/{target.alias or target.intent}"
            if factory is None:
                raise ValueError(f'No handler for "{key}". Is this method in your methods array?')
            method = factory.method
            if mcp and method is not None:
                if method.transport is not None and method.transport.name != self.transport.name:
                    raise ValueError(
                        "MCP compose() requires methods using the configured MCP transport"
                    )
                if method.can_offer is not None:
                    raise ValueError("MCP compose() does not support HTTP canOffer hooks")
            configured.append(factory(**options))
        if mcp:
            return compose_mcp_handlers(configured, self.transport)
        return compose_handlers(configured)

    def _group_factory(self, group: list[ServerMethod]) -> Callable[..., Handler]:
        def create(**options: Any) -> Handler:
            from mpp.server._compose import compose_handlers, compose_mcp_handlers, is_mcp

            configured = [self._factories[method](**options) for method in group]
            if is_mcp(self.transport):
                return compose_mcp_handlers(configured, self.transport)
            return compose_handlers(configured)

        return create

    # -- challenges ---------------------------------------------------------------------------

    def _challenge_fn(self, method: ServerMethod) -> Callable[..., Awaitable[Challenge]]:
        async def create_challenge(**options: Any) -> Challenge:
            description, meta, scope, rest = _split_options(options)
            effective_meta = _binding.merge_scope(meta, scope)
            expires = _resolve_expires(options)
            resolved = await _resolve_route_challenge(
                method=method,
                defaults=method.defaults,
                route_request=rest,
                description=description,
                expires=expires,
                header=self._credential_header,
                meta=effective_meta,
                realm=self.realm,
                secret_key=self.secret_key,
            )
            return resolved.challenge

        return create_challenge

    # -- per-method handler -------------------------------------------------------------------

    def _method_factory(self, method: ServerMethod) -> Callable[..., ConfiguredHandler]:
        def create(**options: Any) -> ConfiguredHandler:
            return self._configure(method, options)

        return create

    def _configure(self, method: ServerMethod, options: dict[str, Any]) -> ConfiguredHandler:
        description, meta, scope, rest = _split_options(options)
        static_meta = _binding.merge_scope(meta, scope)
        transport = method.transport or self.transport
        credential_headers = tuple(
            dict.fromkeys(
                [
                    str(self._credential_header or Header.AUTHORIZATION),
                    *transport.credential_headers,
                ]
            )
        )
        defaults = dict(method.defaults or {})
        offer = OfferInfo(
            method=method,
            request=method.method.normalize_request({**defaults, **rest}),
            options=dict(options),
            meta=static_meta,
            description=description,
            credential_headers=credential_headers,
            transport=transport,
        )
        engine = self

        async def handle(input: Any) -> PaymentResult:
            return await engine._handle(
                method=method,
                transport=transport,
                offer=offer,
                options=options,
                description=description,
                static_meta=static_meta,
                scope=scope,
                defaults=defaults,
                route_request=rest,
                input=input,
            )

        return ConfiguredHandler(handle, offer)

    async def _handle(
        self,
        *,
        method: ServerMethod,
        transport: Transport[Any, Any, Any, Any],
        offer: OfferInfo,
        options: Mapping[str, Any],
        description: str | None,
        static_meta: dict[str, str] | None,
        scope: str | None,
        defaults: dict[str, Any],
        route_request: dict[str, Any],
        input: Any,
    ) -> PaymentResult:
        is_http = isinstance(input, Request)
        expires = _resolve_expires(options)
        captured = await transport.capture_request(input)
        if scope is not None:
            effective_meta = static_meta
        elif is_http:
            effective_meta = _binding.merge_scope(static_meta, input.route_scope)
        elif _binding.read_scope(static_meta) is None:
            # Non-HTTP transports may bind a trusted request identity (e.g. the MCP tool name).
            effective_meta = _binding.merge_scope(static_meta, transport.route_scope(input))
        else:
            effective_meta = static_meta

        # Extract the credential once (transports may have side effects).
        credential: Credential[Any] | None = None
        credential_error: Exception | None = None
        try:
            parsed = transport.get_credential(input)
            credential = _binding.hydrate_meta(parsed) if parsed is not None else None
        except Exception as error:
            credential_error = error

        if method.preflight is not None and is_http:
            response = await resolve(
                method.preflight(
                    PreflightContext(
                        captured_request=captured,
                        credential=credential,
                        expires=expires,
                        input=input,
                        options={**defaults, **route_request},
                        realm=self.realm or _hostname(input.url) or DEFAULT_REALM,
                        secret_key=self.secret_key,
                    )
                )
            )
            if response is not None:
                if response.status == 402:
                    return PaymentRequired(response)
                return PaymentVerified(lambda _=None: response, has_management_response=True)

        events = self._events

        async def emit_challenge(
            challenge: Challenge,
            *,
            request: dict[str, Any],
            error: PaymentError | None = None,
            with_credential: Credential[Any] | None = None,
        ) -> Any:
            output = await transport.respond_challenge(
                challenge=challenge,
                input=input,
                error=error,
            )
            if not isinstance(output, Response) or output.status == 402:
                await events.emit(
                    "challenge.created",
                    ChallengeCreated(
                        captured_request=snapshot_captured(captured),
                        challenge=snapshot(challenge),
                        credential=snapshot(with_credential),
                        error=error,
                        input=snapshot_input(input),
                        method=descriptor(method.name, method.intent),
                        request=snapshot_mapping(request),
                    ),
                )
            return output

        async def emit_failed(
            challenge: Challenge,
            *,
            failed_credential: Credential[Any] | None,
            error: PaymentError,
            request: dict[str, Any],
            retry_challenge: Challenge | None = None,
            submitted_challenge: Challenge | None = None,
        ) -> None:
            await events.emit(
                "payment.failed",
                PaymentFailed(
                    captured_request=snapshot_captured(captured),
                    challenge=snapshot(challenge),
                    credential=snapshot(failed_credential),
                    error=error,
                    input=snapshot_input(input),
                    method=descriptor(method.name, method.intent),
                    request=snapshot_mapping(request),
                    retry_challenge=snapshot(retry_challenge),
                    submitted_challenge=snapshot(submitted_challenge),
                ),
            )

        try:
            resolved = await _resolve_route_challenge(
                method=method,
                defaults=defaults,
                route_request=route_request,
                description=description,
                expires=expires,
                header=self._credential_header,
                meta=effective_meta,
                realm=self.realm,
                secret_key=self.secret_key,
                captured=captured,
                credential=credential,
            )
        except PaymentError as error:
            fallback = Challenge.for_method(
                method.method,
                description=description,
                expires=expires,
                header=self._credential_header,
                meta=_binding.with_nonce(effective_meta),
                realm=self.realm or _realm_from_captured(captured),
                request={**defaults, **route_request},
                secret_key=self.secret_key,
            )
            if credential is not None:
                await emit_failed(
                    fallback,
                    failed_credential=credential,
                    error=error,
                    request=fallback.request,
                    retry_challenge=fallback,
                    submitted_challenge=credential.challenge,
                )
            output = await emit_challenge(
                fallback,
                request=fallback.request,
                error=error,
                with_credential=credential,
            )
            return PaymentRequired(output)

        challenge = resolved.challenge
        parsed_request = resolved.parsed_request
        request = resolved.request
        offer.request = parsed_request

        if credential is not None:
            try:
                credential = _binding.hydrate_meta(
                    await transport.bind_credential(
                        challenge=challenge, credential=credential, input=input
                    )
                )
            except Exception as error:
                credential = None
                credential_error = error

        if credential_error is not None:
            reason = _safe_credential_reason(credential_error)
            if isinstance(credential_error, PaymentError):
                error = credential_error
            elif reason:
                error = MalformedCredentialError(reason=reason)
            else:
                error = InternalPaymentError(cause=credential_error)
            await emit_failed(
                challenge,
                failed_credential=None,
                error=error,
                request=parsed_request,
                retry_challenge=challenge,
            )
            output = await emit_challenge(challenge, request=parsed_request, error=error)
            return PaymentRequired(output)

        def success(
            receipt: Receipt,
            *,
            challenge_id: str | None = None,
            credential_for_receipt: Credential[Any] | None = None,
            envelope: VerifiedChallengeEnvelope[Any] | None = None,
            management_response: Any = None,
        ) -> PaymentVerified[Any]:
            receipt_credential = credential_for_receipt or Credential(
                challenge=challenge, payload={}
            )
            receipt_challenge_id = challenge_id or challenge.id

            def with_receipt(response: Any = None) -> Any:
                target = management_response if management_response is not None else response
                if target is None:
                    raise MissingReceiptResponseError()
                return transport.respond_receipt(
                    challenge_id=receipt_challenge_id,
                    credential=receipt_credential,
                    envelope=envelope,
                    input=input,
                    receipt=receipt,
                    response=target,
                )

            return PaymentVerified(
                with_receipt,
                supports_streaming_receipts=transport.supports_streaming_receipts,
                has_management_response=management_response is not None,
            )

        # No credential: authorize from application state, or issue the challenge.
        if credential is None:
            if method.authorize is not None and is_http:
                try:
                    authorized = await resolve(
                        method.authorize(
                            AuthorizeContext(
                                challenge=challenge, input=input, request=challenge.request
                            )
                        )
                    )
                    if authorized is not None:
                        return success(authorized.receipt, management_response=authorized.response)
                except Exception as exc:
                    if not isinstance(exc, PaymentError):
                        logger.error("mppx: internal authorization error", exc_info=exc)
                    error = (
                        exc if isinstance(exc, PaymentError) else InternalPaymentError(cause=exc)
                    )
                    await emit_failed(
                        challenge,
                        failed_credential=None,
                        error=error,
                        request=parsed_request,
                        retry_challenge=challenge,
                    )
                    output = await emit_challenge(challenge, request=parsed_request, error=error)
                    return PaymentRequired(output)
            output = await emit_challenge(
                challenge,
                request=parsed_request,
                error=PaymentRequiredError(description=description),
            )
            return PaymentRequired(output)

        async def reject(error: PaymentError, *, failed: Credential[Any]) -> PaymentResult:
            assert credential is not None
            await emit_failed(
                challenge,
                failed_credential=failed,
                error=error,
                request=parsed_request,
                retry_challenge=challenge,
                submitted_challenge=credential.challenge,
            )
            output = await emit_challenge(
                challenge,
                request=parsed_request,
                error=error,
                with_credential=failed,
            )
            return PaymentRequired(output)

        # Tier 1: HMAC provenance (covers every echoed field, including opaque/expires/digest).
        if not credential.challenge.verify(self.secret_key):
            return await reject(
                InvalidChallengeError(
                    id=credential.challenge.id, reason="challenge was not issued by this server"
                ),
                failed=credential,
            )

        # Tier 2: pinned fields that must be stable across request-hook transforms.
        mismatch = _binding.challenge_mismatch(
            challenge, credential.challenge, method.stable_binding
        )
        if mismatch is not None:
            return await reject(
                InvalidChallengeError(
                    id=credential.challenge.id,
                    reason=f"credential {mismatch} does not match this route's requirements",
                ),
                failed=credential,
            )

        # Fail closed on missing/malformed/past expiry.
        try:
            _expires.ensure(credential.challenge.expires, credential.challenge.id)
        except PaymentError as error:
            return await reject(error, failed=credential)

        try:
            parsed_credential = credential.with_payload(
                method.method.parse_payload(credential.payload)
            )
        except ValidationError:
            return await reject(InvalidPayloadError(), failed=credential)

        envelope = VerifiedChallengeEnvelope(
            captured_request=captured,
            challenge=credential.challenge,
            credential=parsed_credential,
            request=parsed_request,
        )

        try:
            receipt, validation = await method.settle(
                VerifyContext(credential=parsed_credential, request=request, envelope=envelope)
            )
        except Exception as exc:
            if not isinstance(exc, PaymentError):
                logger.error("mppx: internal verification error", exc_info=exc)
            error = exc if isinstance(exc, PaymentError) else InternalPaymentError(cause=exc)
            return await reject(error, failed=parsed_credential)

        # A management response (e.g. channel open) fully handles the request.
        management_response = None
        if method.respond is not None:
            management_response = await resolve(
                method.respond(
                    RespondContext(
                        credential=parsed_credential,
                        envelope=envelope,
                        input=input,
                        receipt=receipt,
                        request=request,
                    )
                )
            )

        await events.emit(
            "payment.success",
            PaymentSucceeded(
                captured_request=snapshot_captured(captured),
                challenge=snapshot(credential.challenge),
                credential=snapshot(parsed_credential),
                envelope=snapshot(envelope),
                input=snapshot_input(input),
                method=descriptor(method.name, method.intent),
                payer=validation.payer if validation is not None else None,
                receipt=receipt,
                request=snapshot_mapping(parsed_request),
                request_input=snapshot_mapping(request),
            ),
            method,
        )

        return success(
            receipt,
            challenge_id=credential.challenge.id,
            credential_for_receipt=parsed_credential,
            envelope=envelope,
            management_response=management_response,
        )

    # -- standalone verification --------------------------------------------------------------

    async def validate_credential(
        self,
        credential: str | Credential[Any],
        *,
        request: Mapping[str, Any] | None = None,
        realm: str | None = None,
        meta: Mapping[str, str] | None = None,
        scope: str | None = None,
        captured_request: CapturedRequest | None = None,
    ) -> Validation[Any]:
        """Validates a credential (HMAC, expiry, route binding, method validation) without
        consuming or broadcasting it. Advisory; use :meth:`broadcast_credential` to accept.
        """
        prepared = await self._prepare_standalone(
            credential,
            request=request,
            realm=realm,
            meta=meta,
            scope=scope,
            captured_request=captured_request,
            emit_failures=False,
            require_validate=True,
        )
        assert prepared.method.validate is not None
        return await prepared.method.validate(
            ValidateContext(
                credential=prepared.parsed_credential,
                envelope=prepared.envelope,
                operation="validate",
                request=prepared.request,
            )
        )

    async def broadcast_credential(
        self,
        credential: str | Credential[Any],
        *,
        request: Mapping[str, Any] | None = None,
        realm: str | None = None,
        meta: Mapping[str, str] | None = None,
        scope: str | None = None,
        captured_request: CapturedRequest | None = None,
    ) -> Receipt:
        """Verifies a credential end-to-end and settles it, returning the receipt.

        Deserializes, checks the HMAC, matches a registered method, checks expiry, validates the
        payload and (when route options are given) the route binding, then runs the method's
        broadcast (or legacy verify). Emits ``payment.failed`` / ``payment.success``.
        """
        prepared = await self._prepare_standalone(
            credential,
            request=request,
            realm=realm,
            meta=meta,
            scope=scope,
            captured_request=captured_request,
            emit_failures=True,
            require_validate=False,
        )
        method = prepared.method
        try:
            receipt, validation = await method.settle(
                VerifyContext(
                    credential=prepared.parsed_credential,
                    envelope=prepared.envelope,
                    request=prepared.request,
                )
            )
        except Exception as exc:
            error = exc if isinstance(exc, PaymentError) else InternalPaymentError(cause=exc)
            await self._events.emit(
                "payment.failed",
                PaymentFailed(
                    captured_request=snapshot_captured(captured_request),
                    challenge=snapshot(prepared.credential.challenge),
                    credential=snapshot(prepared.parsed_credential),
                    error=error,
                    method=descriptor(method.name, method.intent),
                    request=snapshot_mapping(prepared.parsed_request),
                    submitted_challenge=snapshot(prepared.credential.challenge),
                ),
            )
            raise
        await self._events.emit(
            "payment.success",
            PaymentSucceeded(
                captured_request=snapshot_captured(captured_request),
                challenge=snapshot(prepared.credential.challenge),
                credential=snapshot(prepared.parsed_credential),
                envelope=snapshot(prepared.envelope),
                method=descriptor(method.name, method.intent),
                payer=validation.payer if validation is not None else None,
                receipt=receipt,
                request=snapshot_mapping(prepared.parsed_request),
                request_input=snapshot_mapping(prepared.request_input),
            ),
            method,
        )
        return receipt

    async def verify_credential(
        self,
        credential: str | Credential[Any],
        *,
        request: Mapping[str, Any] | None = None,
        realm: str | None = None,
        meta: Mapping[str, str] | None = None,
        scope: str | None = None,
        captured_request: CapturedRequest | None = None,
    ) -> Receipt:
        """Legacy alias of :meth:`broadcast_credential` (mutating; not a pre-check)."""
        return await self.broadcast_credential(
            credential,
            request=request,
            realm=realm,
            meta=meta,
            scope=scope,
            captured_request=captured_request,
        )

    async def _prepare_standalone(
        self,
        value: str | Credential[Any],
        *,
        request: Mapping[str, Any] | None,
        realm: str | None,
        meta: Mapping[str, str] | None,
        scope: str | None,
        captured_request: CapturedRequest | None,
        emit_failures: bool,
        require_validate: bool,
    ) -> "_Prepared":
        credential = _binding.hydrate_meta(
            Credential.deserialize(value) if isinstance(value, str) else value
        )
        submitted = credential.challenge
        candidates = [
            m for m in self.methods if m.name == submitted.method and m.intent == submitted.intent
        ]
        method = candidates[0] if candidates else None
        event_method = descriptor(submitted.method, submitted.intent)

        async def fail(
            error: PaymentError,
            *,
            failed_credential: Credential[Any] | None = None,
            raise_: BaseException | None = None,
        ) -> Any:
            if emit_failures:
                await self._events.emit(
                    "payment.failed",
                    PaymentFailed(
                        captured_request=snapshot_captured(captured_request),
                        challenge=snapshot(submitted),
                        credential=snapshot(failed_credential or credential),
                        error=error,
                        method=event_method,
                        request=snapshot_mapping(submitted.request),
                        submitted_challenge=snapshot(submitted),
                    ),
                )
            raise (raise_ or error)

        if method is None:
            await fail(
                InvalidChallengeError(
                    id=submitted.id,
                    reason=f"no registered method for {submitted.method}/{submitted.intent}",
                )
            )
        assert method is not None
        if not submitted.verify(self.secret_key):
            await fail(
                InvalidChallengeError(
                    id=submitted.id, reason="challenge was not issued by this server"
                )
            )
        try:
            _expires.ensure(submitted.expires, submitted.id)
        except PaymentError as error:
            await fail(error)

        if len(candidates) > 1:
            matches = [
                candidate
                for candidate in dict.fromkeys(candidates)
                if _matches_standalone(candidate, submitted.request, request)
            ]
            if len(matches) != 1:
                await fail(
                    InvalidChallengeError(
                        id=submitted.id,
                        reason=(
                            "no configured method matches the challenge request"
                            if not matches
                            else "multiple configured methods match the challenge request; "
                            "use a configured route handler"
                        ),
                    )
                )
            method = matches[0]

        if require_validate and method.validate is None:
            await fail(
                VerificationFailedError(
                    details={"intent": submitted.intent, "method": submitted.method},
                    reason=(
                        f"{submitted.method}/{submitted.intent} does not support non-mutating "
                        "credential validation"
                    ),
                )
            )

        try:
            parsed_credential = credential.with_payload(
                method.method.parse_payload(credential.payload)
            )
        except ValidationError as exc:
            await fail(InvalidPayloadError(), raise_=exc)
            raise  # pragma: no cover

        expected_meta = _binding.merge_scope(meta, scope)
        if scope is not None and _binding.read_scope(submitted.meta) != scope:
            await fail(
                InvalidChallengeError(
                    id=submitted.id,
                    reason="credential scope does not match this route's requirements",
                ),
                failed_credential=parsed_credential,
            )

        validate_route = (
            captured_request is not None
            or meta is not None
            or realm is not None
            or request is not None
        )
        expected_realm = (
            realm
            if realm is not None
            else self.realm
            if self.realm is not None
            else (submitted.realm if captured_request is None else None)
        )
        parsed_request: dict[str, Any] = submitted.request
        route_input: dict[str, Any] = submitted.request
        if validate_route:
            try:
                resolved = await _resolve_route_challenge(
                    method=method,
                    defaults=method.defaults,
                    route_request=dict(request or {}),
                    expires=submitted.expires,
                    header=submitted.header,
                    meta=expected_meta,
                    realm=expected_realm,
                    secret_key=self.secret_key,
                    captured=captured_request,
                    credential=parsed_credential,
                )
                mismatch = _binding.challenge_mismatch(
                    resolved.challenge, submitted, method.stable_binding
                )
                if mismatch is not None:
                    raise InvalidChallengeError(
                        id=submitted.id,
                        reason=f"credential {mismatch} does not match this route's requirements",
                    )
                parsed_request = resolved.parsed_request
                route_input = resolved.request
            except PaymentError as error:
                await fail(error, failed_credential=parsed_credential)

        envelope = (
            VerifiedChallengeEnvelope(
                captured_request=captured_request,
                challenge=submitted,
                credential=parsed_credential,
                request=parsed_request,
            )
            if captured_request is not None
            else None
        )
        return _Prepared(
            credential=credential,
            envelope=envelope,
            method=method,
            parsed_credential=parsed_credential,
            parsed_request=parsed_request,
            request=route_input,
            request_input=route_input if validate_route else None,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class _Prepared:
    credential: Credential[Any]
    envelope: VerifiedChallengeEnvelope[Any] | None
    method: ServerMethod
    parsed_credential: Credential[Any]
    parsed_request: dict[str, Any]
    request: dict[str, Any]
    request_input: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class _ResolvedChallenge:
    challenge: Challenge
    parsed_request: dict[str, Any]
    request: dict[str, Any]


async def _resolve_route_challenge(
    *,
    method: ServerMethod,
    defaults: Mapping[str, Any] | None,
    route_request: Mapping[str, Any],
    secret_key: str,
    description: str | None = None,
    expires: str | None = None,
    header: str | None = None,
    meta: Mapping[str, str] | None = None,
    realm: str | None = None,
    captured: CapturedRequest | None = None,
    credential: Credential[Any] | None = None,
) -> _ResolvedChallenge:
    """Resolves a route's canonical request and challenge exactly like the handler path."""
    merged = {**(defaults or {}), **route_request}
    if method.resolve_request is not None:
        request = dict(
            await resolve(
                method.resolve_request(
                    RequestContext(request=merged, captured_request=captured, credential=credential)
                )
            )
        )
    else:
        request = merged
    effective_realm = realm or (_realm_from_captured(captured) if captured else DEFAULT_REALM)
    challenge = Challenge.for_method(
        method.method,
        description=description,
        expires=expires,
        header=header,
        meta=_binding.with_nonce(meta),
        realm=effective_realm,
        request=request,
        secret_key=secret_key,
    )
    return _ResolvedChallenge(challenge, challenge.request, request)


def _split_options(
    options: Mapping[str, Any],
) -> tuple[str | None, dict[str, str] | None, str | None, dict[str, Any]]:
    description = options.get("description")
    meta = options.get("meta")
    scope = options.get("scope")
    rest = {key: value for key, value in options.items() if key not in _ROUTE_OPTION_KEYS}
    return description, dict(meta) if meta is not None else None, scope, rest


def _resolve_expires(options: Mapping[str, Any]) -> str | None:
    if "expires" in options:
        value: DatetimeInput | None = options["expires"]
        return None if value is None else to_datetime_string(value)
    return _expires.minutes(5)


def _hostname(url: str) -> str | None:
    """WHATWG ``new URL(url).hostname`` (``None`` when unavailable)."""
    return _url.hostname(url) or None


def _realm_from_captured(captured: CapturedRequest | None) -> str:
    if captured is not None and captured.url.scheme in ("http", "https"):
        host = _hostname(str(captured.url))
        if host:
            return host
    if "realm-fallback" not in _warned:
        _warned.add("realm-fallback")
        warnings.warn(
            f'Could not auto-detect realm from request. Falling back to "{DEFAULT_REALM}". '
            "Set `realm` in Mpp() or the MPP_REALM env var.",
            stacklevel=2,
        )
    return DEFAULT_REALM


def _safe_credential_reason(error: Exception) -> str | None:
    if isinstance(
        error,
        InvalidCredentialEncodingError
        | MissingAuthorizationHeaderError
        | MissingPaymentSchemeError,
    ):
        return str(error)
    return None


def _matches_standalone(
    method: ServerMethod, request: Mapping[str, Any], route_request: Mapping[str, Any] | None
) -> bool:
    try:
        configured = {**(method.defaults or {}), **(route_request or {})}
        try:
            expected = method.method.normalize_request(configured)
        except ValidationError:
            # Standalone callers may omit route-only inputs such as amount; constrain selection
            # by what we have rather than re-transforming the echoed wire request.
            expected = configured

        def binding(value: Mapping[str, Any]) -> dict[str, Any]:
            if method.stable_binding is not None:
                return method.stable_binding(dict(value))
            core, method_fields = _binding.pinned_binding(value)
            return {**core, **method_fields}

        expected_binding = binding(expected)
        actual = binding(request)
        return all(
            value is None
            or _binding.strict_equal(
                _binding.normalize_comparable(value), _binding.normalize_comparable(actual.get(key))
            )
            for key, value in expected_binding.items()
        )
    except Exception:
        return False


__all__ = [
    "ComposedHandler",
    "ConfiguredHandler",
    "HandlerFactory",
    "MissingReceiptResponseError",
    "Mpp",
    "OfferInfo",
    "PaymentRequired",
    "PaymentResult",
    "PaymentVerified",
    "assert_secret_key",
]
