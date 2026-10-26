"""Server payment engine: configured methods, route handlers and events."""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from mpp import PAYMENT_AUTHORIZATION_HEADER, Challenge, Credential, Receipt
from mpp._parsing import ParseError, _b64_decode, _parse_timestamp
from mpp._validation import Validation
from mpp.errors import (
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentExpiredError,
    PaymentMethodUnsupportedError,
    VerificationFailedError,
)
from mpp.events import (
    CHALLENGE_CREATED,
    PAYMENT_FAILED,
    PAYMENT_SUCCESS,
    EventDispatcher,
    EventHandler,
    Unsubscribe,
)
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.compose import ComposedHandler, _Offer, _validate_options
from mpp.server.method import (
    RequestContext,
    ServerMethod,
    ValidateContext,
    VerifyContext,
)
from mpp.server.verify import (
    _application_meta,
    _authenticate_echo,
    _body_digest_error,
    _challenge_from_echo,
)
from mpp.store import Store

if TYPE_CHECKING:
    from mpp.events import ServerPaymentSuccessPayload


class _ContextUnset:
    def __repr__(self) -> str:
        return "<unset>"


_CONTEXT_UNSET: Any = _ContextUnset()


class HandlerFactory:
    """Creates route handlers from route options, such as ``mpp.tempo.charge(amount="1")``."""

    def __init__(self, server: Mpp, methods: Sequence[ServerMethod]) -> None:
        self._server = server
        self.methods = tuple(methods)

    def __call__(self, **options: Any) -> ComposedHandler:
        """Configure the offers of this factory's methods for a route.

        Engine options: ``description``, ``meta`` (opaque challenge metadata),
        ``expires`` or ``expires_in``, and ``body`` (bytes, string or JSON-like dict, or a
        callable receiving the :class:`~mpp.server.Request`, bound as a digest). Every
        other option is method input, merged over the method's ``defaults``.
        """
        options = _validate_options(options)
        methods = _select(self.methods, options)
        for method in methods:
            _check_input(method, options)
        return ComposedHandler._from_offers(
            [_Offer(self._server, method, dict(options)) for method in methods],
            composed=self._server._compose_implicit or len(methods) > 1,
        )


class _Namespace:
    """Handler factories of one method name, such as ``mpp.tempo``."""

    def __init__(self, entries: dict[str, HandlerFactory]) -> None:
        self._entries = entries

    def __getattr__(self, name: str) -> HandlerFactory:
        entries = self.__dict__.get("_entries", {})
        if name in entries:
            return entries[name]
        raise AttributeError(name)

    def __getitem__(self, name: str) -> HandlerFactory:
        return self._entries[name]

    def __contains__(self, name: object) -> bool:
        return name in self._entries


def _select(methods: Sequence[ServerMethod], options: Mapping[str, Any]) -> list[ServerMethod]:
    """Keep the methods whose defaults agree with explicit route options.

    Several configured offers of one method, such as one per accepted currency, collapse
    to the one a route names; when none matches, the first one takes the route's value.
    """
    selected = [
        method
        for method in methods
        if not any(
            options.get(key) is not None and options[key] != value
            for key, value in (method.defaults or {}).items()
        )
    ]
    return selected or [methods[0]]


def _check_input(method: ServerMethod, options: Mapping[str, Any]) -> None:
    """Reject invalid method input when the route is configured, when that runs synchronously."""
    from mpp.server.compose import ROUTE_OPTION_KEYS

    input = {
        **(method.defaults or {}),
        **{
            key: value
            for key, value in options.items()
            if key not in ROUTE_OPTION_KEYS and value is not None
        },
    }
    if method.resolve_request is not None:
        if inspect.iscoroutinefunction(method.resolve_request):
            return
        input = method.resolve_request(RequestContext(request=input))
        if inspect.isawaitable(input):
            if inspect.iscoroutine(input):
                input.close()
            return
    method.method.normalize_request(input)


class Mpp:
    """Server-side payment engine.

    Binds configured payment methods to a realm and secret key for stateless,
    HMAC-bound challenges, and creates route handlers from route options.

    Example:
        from mpp.server import Mpp, Request
        from mpp.methods.tempo import server as tempo

        mpp = Mpp(methods=tempo.charge(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"))

        result = await mpp.charge(amount="0.50")(request)
        if result.status != 200:
            return result.challenge
        return result.with_receipt(Response.json({"data": "..."}))
    """

    def __init__(
        self,
        methods: ServerMethod | Sequence[ServerMethod | Sequence[ServerMethod]],
        *,
        realm: str | None = None,
        secret_key: str | None = None,
        store: Store | None = None,
        requires_auth: bool = False,
        unique_challenges: bool = True,
    ) -> None:
        """Initialize the payment engine.

        Args:
            methods: A configured server method, or a sequence of them (nested sequences
                are flattened). Handlers of a sequence always compose their offers, so
                each method's ``can_offer`` applies; a single method's handler offers it
                directly.
            realm: Server realm. Auto-detected from the environment if omitted.
            secret_key: HMAC secret. Required unless ``MPP_SECRET_KEY`` is set.
            store: Replay store shared by every method configured without its own, such
                as a Tempo or EVM charge built without ``store=``.
            requires_auth: Read Payment credentials from ``Payment-Authorization`` so
                ``Authorization`` remains available for application authentication.
            unique_challenges: Disable only while rolling out nonce-aware verification
                to all replicas; enable afterward to prevent fixed-expiry collisions.
        """
        self.methods = _flatten(methods)
        self._compose_implicit = isinstance(methods, Sequence)
        if not self.methods:
            raise ValueError("methods is required")
        if store is not None:
            for method in self.methods:
                if method.use_store is not None:
                    method.use_store(store)
        self.realm = detect_realm() if realm is None else realm
        self.secret_key = detect_secret_key() if secret_key is None else secret_key
        self.unique_challenges = unique_challenges
        self.requires_auth = requires_auth
        self.credential_header = PAYMENT_AUTHORIZATION_HEADER if requires_auth else None
        self._events = EventDispatcher()
        self._payment_success_hooks: set[tuple[str, str, int]] = set()
        for method in self.methods:
            self._register_payment_success_handler(method)

        keys: dict[str, list[ServerMethod]] = {}
        intents: dict[str, list[ServerMethod]] = {}
        for method in self.methods:
            keys.setdefault(method.key, []).append(method)
            intents.setdefault(method.intent, []).append(method)
        self._handlers: dict[str, Any] = {
            key: HandlerFactory(self, group) for key, group in keys.items()
        }
        names: dict[str, dict[str, HandlerFactory]] = {}
        for key, factory in list(self._handlers.items()):
            name, intent = key.split("/", 1)
            names.setdefault(name, {})[intent] = factory
        for intent, group in intents.items():
            self._handlers.setdefault(intent, HandlerFactory(self, group))
        for name, entries in names.items():
            self._handlers.setdefault(name, _Namespace(entries))

    def __getitem__(self, key: str) -> Any:
        """Return the handler factory for ``"name/intent"`` or an intent, or a method namespace."""
        try:
            return self._handlers[key]
        except KeyError:
            raise KeyError(f"no payment method for {key!r}") from None

    def __getattr__(self, name: str) -> Any:
        handlers = self.__dict__.get("_handlers")
        if handlers is not None and name in handlers:
            return handlers[name]
        raise AttributeError(name)

    def __contains__(self, key: object) -> bool:
        return key in self._handlers

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a server payment event handler."""
        return self._events.on(name, handler)

    def on_challenge_created(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for issued payment challenges."""
        return self.on(CHALLENGE_CREATED, handler)

    def on_payment_success(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for successful payment verification."""
        return self.on(PAYMENT_SUCCESS, handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed payment verification."""
        return self.on(PAYMENT_FAILED, handler)

    def compose(self, *entries: tuple[Any, Mapping[str, Any]]) -> ComposedHandler:
        """Combine configured offers into one route handler.

        Each entry is ``(target, options)``, where ``target`` is a configured
        :class:`ServerMethod`, a ``"name/intent"`` key, or a handler factory such as
        ``mpp.tempo.charge``.
        """
        if not entries:
            raise ValueError("compose() requires at least one entry")
        handlers: list[ComposedHandler] = []
        for entry in entries:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise ValueError("compose() entries must be (method, options) tuples")
            target, options = entry
            if not isinstance(options, Mapping):
                raise ValueError("compose() options must be a mapping")
            if isinstance(target, str):
                factory = self._handlers.get(target if "/" in target else f"{target}/charge")
            elif isinstance(target, HandlerFactory):
                factory = target if target._server is self else None
            elif isinstance(target, ServerMethod) and target in self.methods:
                factory = HandlerFactory(self, [target])
            else:
                factory = None
            if not isinstance(factory, HandlerFactory):
                raise ValueError(f"payment method is not registered: {target!r}")
            handlers.append(factory(**options))
        return ComposedHandler(*handlers)

    def _register_payment_success_handler(self, method: ServerMethod) -> None:
        """Forward successful payments to a method's optional callback."""
        handler = method.on_payment_success
        if handler is None:
            return
        # Copies of one configured method (such as one per accepted currency) share
        # their callback: register it once so each payment calls it once.
        hook = (method.name, method.intent, id(handler))
        if hook in self._payment_success_hooks:
            return
        self._payment_success_hooks.add(hook)

        def dispatch(payload: ServerPaymentSuccessPayload) -> Any:
            if payload["method"] == method.name and payload["intent"] == method.intent:
                return handler(payload)
            return None

        self._events.on(PAYMENT_SUCCESS, dispatch)

    def _prepare_credential(
        self,
        value: Credential | str,
        *,
        intent: str | None,
        request: dict[str, Any] | None,
        meta: dict[str, str] | None = _CONTEXT_UNSET,
        body: str | bytes | dict[str, Any] | None = _CONTEXT_UNSET,
        method_options: Mapping[str, Any] | None = None,
    ) -> tuple[Credential, ServerMethod, dict[str, Any], Challenge]:
        """Authenticate and resolve a credential outside an HTTP route."""
        credential = self._parse_credential(value)

        echo = credential.challenge
        echoed_request, echoed_opaque = _authenticate_echo(
            credential,
            secret_key=self.secret_key,
        )

        if echo.realm != self.realm:
            raise InvalidChallengeError(echo.id, "credential realm does not match")
        candidates = [
            candidate
            for candidate in self.methods
            if candidate.name == echo.method and candidate.intent == echo.intent
        ]
        if not candidates:
            if any(candidate.name == echo.method for candidate in self.methods):
                raise PaymentMethodUnsupportedError(f"{echo.method}/{echo.intent}")
            raise PaymentMethodUnsupportedError(echo.method)
        if intent is not None and echo.intent != intent:
            raise InvalidChallengeError(echo.id, "credential intent does not match")

        if not echo.expires:
            raise PaymentExpiredError(echo.expires)
        try:
            expires = _parse_timestamp(echo.expires)
        except ParseError as error:
            raise PaymentExpiredError(echo.expires) from error
        if expires.tzinfo is None or expires <= datetime.now(UTC):
            raise PaymentExpiredError(echo.expires)

        if request is None:
            method = _select_echoed(candidates, echoed_request, echo.id)
        else:
            echoed = {key: value for key, value in echoed_request.items() if key != "_mppx_scope"}
            matching = [
                candidate
                for candidate in candidates
                if _expected_request(candidate, request, parsed=credential) == echoed
            ]
            if not matching:
                raise InvalidChallengeError(echo.id, "credential request does not match")
            method = matching[0]
        unsupported = sorted(set(method_options or {}) - set(method.credential_options))
        if unsupported:
            raise TypeError(f"unsupported method option: {unsupported[0]}")

        if request is not None or meta is not _CONTEXT_UNSET or body is not _CONTEXT_UNSET:
            expected_meta = None if meta is _CONTEXT_UNSET else meta
            expected_body = None if body is _CONTEXT_UNSET else body
            if _application_meta(echoed_opaque) != (expected_meta or None):
                raise InvalidChallengeError(echo.id, "credential opaque does not match")
            if digest_error := _body_digest_error(echo.digest, expected_body):
                raise InvalidChallengeError(echo.id, digest_error)

        challenge = _challenge_from_echo(echo, echoed_request, echoed_opaque)
        try:
            payload = method.method.parse_payload(credential.payload)
        except ValidationError as error:
            raise InvalidPayloadError(str(error)) from error
        input = {**echoed_request, **(method_options or {})}
        return replace(credential, payload=payload), method, input, challenge

    @staticmethod
    def _parse_credential(value: Credential | str) -> Credential:
        if isinstance(value, Credential):
            return value
        authorization = value if value.lower().startswith("payment ") else f"Payment {value}"
        try:
            return Credential.from_authorization(authorization)
        except ParseError as error:
            raise MalformedCredentialError(str(error)) from error

    async def validate_credential(
        self,
        credential: Credential | str,
        *,
        intent: str | None = None,
        request: dict[str, Any] | None = None,
        meta: dict[str, str] | None = _CONTEXT_UNSET,
        body: str | bytes | dict[str, Any] | None = _CONTEXT_UNSET,
        **method_options: Any,
    ) -> Validation:
        """Validate a bound credential without consuming payment state.

        Authenticates the credential's echoed challenge against this server's
        secret key (HMAC challenge ID, realm, method, expiry) before running
        the intent's non-mutating ``validate`` hook. The result is advisory —
        it confirms the credential is currently acceptable but does not
        settle, reserve, or consume the payment — so no payment events are
        emitted.

        Args:
            credential: A parsed ``Credential`` or its serialized form (the
                ``Authorization`` header value, with or without the
                ``Payment`` scheme prefix).
            intent: If provided, also require the credential to be bound to
                this intent name.
            request: If provided, also require the credential's echoed
                request to match these request parameters.
            meta: Expected opaque challenge metadata. Supplying any request,
                meta, or body context checks all three bindings; omitted
                bindings are treated as absent.
            body: Expected request body for the challenge's digest binding.

        Returns:
            The intent's validation record for the accepted credential.

        Raises:
            MalformedCredentialError: If the credential cannot be parsed.
            InvalidChallengeError: If the challenge was not issued by this
                server or does not match the requested binding.
            PaymentExpiredError: If the echoed challenge has expired.
            PaymentMethodUnsupportedError: If the credential names a method
                or intent this server does not serve.
            VerificationFailedError: If the intent does not support
                non-mutating validation or rejects the credential.
        """
        prepared, method, input, challenge = self._prepare_credential(
            credential,
            intent=intent,
            request=request,
            meta=meta,
            body=body,
            method_options=method_options,
        )
        if method.validate is None:
            raise VerificationFailedError(
                f"{method.intent} does not support non-mutating credential validation"
            )
        result = await method.validate(
            ValidateContext(credential=prepared, request=input, challenge=challenge)
        )
        if not isinstance(result, Validation):
            raise VerificationFailedError("Intent returned an invalid validation result")
        return result

    async def broadcast_credential(
        self,
        credential: Credential | str,
        *,
        intent: str | None = None,
        request: dict[str, Any] | None = None,
        meta: dict[str, str] | None = _CONTEXT_UNSET,
        body: str | bytes | dict[str, Any] | None = _CONTEXT_UNSET,
        **method_options: Any,
    ) -> Receipt:
        """Revalidate and perform a bound credential's terminal operation.

        Applies the same challenge authentication as
        :meth:`validate_credential`, then runs the method's validate-then-broadcast
        lifecycle — the non-mutating ``validate`` hook followed by the terminal
        ``broadcast`` (or its combined ``verify`` hook). Emits the same payment
        success/failure events as HTTP route handlers.

        Args:
            credential: A parsed ``Credential`` or its serialized form.
            intent: If provided, also require the credential to be bound to
                this intent name.
            request: If provided, also require the credential's echoed
                request to match these request parameters.
            meta: Expected opaque challenge metadata. Supplying any request,
                meta, or body context checks all three bindings; omitted
                bindings are treated as absent.
            body: Expected request body for the challenge's digest binding.

        Returns:
            The settlement receipt from the intent's terminal operation.

        Raises:
            The same challenge-authentication errors as
            :meth:`validate_credential`, or the intent's verification error
            if validation or settlement fails.
        """
        parsed = self._parse_credential(credential)
        try:
            prepared, method, input, challenge = self._prepare_credential(
                parsed,
                intent=intent,
                request=request,
                meta=meta,
                body=body,
                method_options=method_options,
            )
        except Exception as error:
            echo = parsed.challenge
            event_method = next(
                (candidate.name for candidate in self.methods if candidate.name == echo.method),
                self.methods[0].name,
            )
            try:
                decoded_request = _b64_decode(echo.request) if echo.request else {}
            except ParseError:
                decoded_request = {}
            failed_request = decoded_request if isinstance(decoded_request, dict) else {}
            await self._events.emit(
                PAYMENT_FAILED,
                {
                    "challenge": _challenge_from_echo(echo, failed_request, None),
                    "credential": parsed,
                    "error": error,
                    "intent": intent or echo.intent,
                    "method": event_method,
                    "request": failed_request,
                },
            )
            raise
        context = {
            "challenge": challenge,
            "credential": parsed,
            "intent": method.intent,
            "method": method.name,
            "request": challenge.request,
        }
        try:
            receipt, _ = await method.settle(
                VerifyContext(credential=prepared, request=input, challenge=challenge)
            )
        except Exception as error:
            await self._events.emit(PAYMENT_FAILED, {**context, "error": error})
            raise
        await self._events.emit(PAYMENT_SUCCESS, {**context, "receipt": receipt})
        return receipt


def _expected_request(
    method: ServerMethod, request: Mapping[str, Any], *, parsed: Credential
) -> dict[str, Any]:
    input = {
        **(method.defaults or {}),
        **{key: value for key, value in request.items() if value is not None},
    }
    if method.resolve_request is not None:
        resolved = method.resolve_request(RequestContext(request=input, credential=parsed))
        if inspect.isawaitable(resolved):
            if inspect.iscoroutine(resolved):
                resolved.close()
            raise TypeError("validate_credential(request=...) needs a synchronous resolve_request")
        input = resolved
    wire = method.method.normalize_request(input)
    return {key: value for key, value in wire.items() if key != "_mppx_scope"}


_IDENTITY_PATHS = (("currency",), ("methodDetails", "chainId"))


def _select_echoed(
    candidates: Sequence[ServerMethod], echoed: Mapping[str, Any], challenge_id: str
) -> ServerMethod:
    """Choose the configured method copy whose configuration issued an echoed request.

    Copies of one method (such as one per currency, or per chain) must agree with
    the echo's currency and chain; among those left, the copy whose configuration
    agrees with the rest of the echo wins. Copies left with different
    configurations are ambiguous.
    """
    if len(candidates) == 1:
        return candidates[0]
    probes = {id(candidate): _probe(candidate) for candidate in candidates}
    matching = [
        candidate
        for candidate in candidates
        if _agrees(candidate, probes[id(candidate)], echoed, _IDENTITY_PATHS)
    ]
    if not matching:
        raise InvalidChallengeError(
            challenge_id, "credential request does not match a configured method"
        )
    if len(matching) > 1:
        narrowed = [
            candidate
            for candidate in matching
            if (probe := probes[id(candidate)]) is not None
            and _agrees(candidate, probe, echoed, tuple(_leaves(probe)))
        ]
        matching = narrowed or matching
    if len(matching) > 1:
        configs = [probes[id(candidate)] for candidate in matching]
        if configs[0] is None or any(config != configs[0] for config in configs):
            raise InvalidChallengeError(
                challenge_id,
                "credential matches several configured methods; pass request= to select one",
            )
    return matching[0]


def _probe(method: ServerMethod) -> dict[str, Any] | None:
    """The wire request a method's configuration produces for a nominal amount."""
    input: dict[str, Any] = {
        **{key: value for key, value in (method.defaults or {}).items() if value is not None},
        "amount": "1",
    }
    try:
        if method.resolve_request is not None:
            resolved = method.resolve_request(RequestContext(request=input))
            if inspect.isawaitable(resolved):
                if inspect.iscoroutine(resolved):
                    resolved.close()
                return None
            input = resolved
        wire = method.method.normalize_request(input)
    except Exception:
        return None
    return {key: value for key, value in wire.items() if key not in ("amount", "_mppx_scope")}


def _leaves(value: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for key, item in value.items():
        if isinstance(item, Mapping):
            paths.extend(_leaves(item, (*prefix, key)))
        else:
            paths.append((*prefix, key))
    return paths


_MISSING: Any = object()


def _at(value: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return _MISSING
        value = value[key]
    return value


def _agrees(
    method: ServerMethod,
    probe: Mapping[str, Any] | None,
    echoed: Mapping[str, Any],
    paths: Sequence[tuple[str, ...]],
) -> bool:
    """Whether the method's defaults and probed configuration agree with the echo."""
    expected: dict[tuple[str, ...], Any] = {
        (key,): value for key, value in (method.defaults or {}).items() if value is not None
    }
    if probe is not None:
        expected.update((path, _at(probe, path)) for path in paths)
    for path, value in expected.items():
        echoed_value = _at(echoed, path)
        if value is _MISSING or echoed_value is _MISSING:
            continue
        if isinstance(value, str) and isinstance(echoed_value, str):
            if value.lower() != echoed_value.lower():
                return False
        elif value != echoed_value:
            return False
    return True


def _flatten(methods: Any) -> tuple[ServerMethod, ...]:
    """Flatten a server method or (nested) sequences of them."""
    if isinstance(methods, ServerMethod):
        return (methods,)
    flat: list[ServerMethod] = []
    for entry in methods:
        if isinstance(entry, ServerMethod):
            flat.append(entry)
        elif isinstance(entry, Sequence) and not isinstance(entry, str):
            flat.extend(_flatten(entry))
        else:
            raise TypeError(f"not a server payment method: {entry!r}")
    return tuple(flat)
