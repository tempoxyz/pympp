"""Payment handler that binds method, realm, and secret_key."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeVar

from mpp import Challenge, Credential, Receipt
from mpp._parsing import ParseError, _b64_decode, _parse_timestamp
from mpp._units import parse_units, transform_units
from mpp.errors import (
    InvalidChallengeError,
    MalformedCredentialError,
    PaymentExpiredError,
    PaymentMethodUnsupportedError,
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
from mpp.server.decorator import (
    BodyParamsType,
    bind_framework_scope,
    resolve_body_param,
    wrap_payment_handler,
)
from mpp.server.intent import Validation
from mpp.server.intent import broadcast_credential as broadcast_intent_credential
from mpp.server.intent import validate_credential as validate_intent_credential
from mpp.server.method import transform_request
from mpp.server.verify import (
    _authenticate_echo,
    _body_digest_error,
    _challenge_from_echo,
    verify_or_challenge,
)
from mpp.store import Store

if TYPE_CHECKING:
    from mpp.server.intent import Intent, VerifiableIntent
    from mpp.server.method import Method

R = TypeVar("R")

DEFAULT_DECIMALS = 6


class _ContextUnset:
    def __repr__(self) -> str:
        return "<unset>"


_CONTEXT_UNSET: Any = _ContextUnset()


class Mpp:
    """Server-side payment handler.

    Binds a payment method with realm and secret_key for stateless
    challenge verification. Currency and recipient are configured once
    on the method, so charge() only needs an amount.

    Example:
        from mpp.server import Mpp
        from mpp.methods.tempo import tempo

        m = Mpp.create(
            method=tempo(
                currency="0x20c0000000000000000000000000000000000000",
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            ),
        )

        result = await m.charge(
            authorization=request.headers.get("Authorization"),
            amount="0.50",
        )

        if isinstance(result, Challenge):
            headers = {"WWW-Authenticate": result.to_www_authenticate(m.realm)}
            return Response(status=402, headers=headers)

        credential, receipt = result
        return Response({"data": "..."}, headers={"Payment-Receipt": ...})
    """

    def __init__(
        self,
        method: Method,
        realm: str,
        secret_key: str,
        defaults: dict[str, Any] | None = None,
        store: Store | None = None,
    ) -> None:
        """Initialize the payment handler.

        Args:
            method: Payment method (e.g., TempoMethod).
            realm: Server realm for WWW-Authenticate header.
            secret_key: Server secret for HMAC-bound challenge IDs.
                Enables stateless challenge verification.
            defaults: Default request values merged with per-call request params.
            store: Optional key-value store for replay protection.
                When provided, automatically wired into intents that
                accept a ``store`` (e.g., ``ChargeIntent``).
        """
        self.method = method
        self.realm = realm
        self.secret_key = secret_key
        self.defaults = defaults or {}
        self._events = EventDispatcher()

        if store is not None:
            self._wire_store(store)

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

    def _wire_store(self, store: Store) -> None:
        """Inject *store* into intents that have a ``_store`` attribute set to None."""
        intents = getattr(self.method, "intents", None)
        if not isinstance(intents, Mapping):
            return
        for intent_obj in intents.values():
            if hasattr(intent_obj, "_store") and intent_obj._store is None:
                intent_obj._store = store

    def _prepare_credential(
        self,
        value: Credential | str,
        *,
        intent: str | None,
        request: dict[str, Any] | None,
        meta: dict[str, str] | None = _CONTEXT_UNSET,
        body: str | bytes | dict[str, Any] | None = _CONTEXT_UNSET,
    ) -> tuple[Credential, Intent | VerifiableIntent, dict[str, Any], Challenge]:
        """Authenticate and resolve a credential outside an HTTP route."""
        credential = self._parse_credential(value)

        echo = credential.challenge
        echoed_request, echoed_opaque = _authenticate_echo(
            credential,
            secret_key=self.secret_key,
        )

        if echo.realm != self.realm:
            raise InvalidChallengeError(echo.id, "credential realm does not match")
        if echo.method != self.method.name:
            raise PaymentMethodUnsupportedError(echo.method)
        if intent is not None and echo.intent != intent:
            raise InvalidChallengeError(echo.id, "credential intent does not match")

        if not echo.expires:
            raise PaymentExpiredError(echo.expires)
        try:
            expires = _parse_timestamp(echo.expires)
        except ParseError as error:
            raise PaymentExpiredError(echo.expires) from error
        if expires.tzinfo is None or expires < datetime.now(UTC):
            raise PaymentExpiredError(echo.expires)

        if request is not None:
            expected_request = transform_request(
                self.method,
                transform_units(request),
                credential,
            )
            if expected_request != echoed_request:
                raise InvalidChallengeError(echo.id, "credential request does not match")

        if request is not None or meta is not _CONTEXT_UNSET or body is not _CONTEXT_UNSET:
            expected_meta = None if meta is _CONTEXT_UNSET else meta
            expected_body = None if body is _CONTEXT_UNSET else body
            if echoed_opaque != expected_meta:
                raise InvalidChallengeError(echo.id, "credential opaque does not match")
            if digest_error := _body_digest_error(echo.digest, expected_body):
                raise InvalidChallengeError(echo.id, digest_error)

        intent_obj = self.method.intents.get(echo.intent)
        if intent_obj is None:
            raise PaymentMethodUnsupportedError(f"{echo.method}/{echo.intent}")
        challenge = _challenge_from_echo(echo, echoed_request, echoed_opaque)
        return credential, intent_obj, echoed_request, challenge

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
        prepared, intent_obj, echoed_request, _ = self._prepare_credential(
            credential,
            intent=intent,
            request=request,
            meta=meta,
            body=body,
        )
        return await validate_intent_credential(
            intent=intent_obj,
            credential=prepared,
            request=echoed_request,
        )

    async def broadcast_credential(
        self,
        credential: Credential | str,
        *,
        intent: str | None = None,
        request: dict[str, Any] | None = None,
        meta: dict[str, str] | None = _CONTEXT_UNSET,
        body: str | bytes | dict[str, Any] | None = _CONTEXT_UNSET,
    ) -> Receipt:
        """Revalidate and perform a bound credential's terminal operation.

        Applies the same challenge authentication as
        :meth:`validate_credential`, then runs the intent's validate-then-broadcast
        lifecycle — the non-mutating ``validate`` hook followed by the terminal
        ``broadcast`` (legacy intents fall back to their combined ``verify``
        hook). Emits the same payment success/failure events as HTTP route
        handlers.

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
            prepared, intent_obj, echoed_request, challenge = self._prepare_credential(
                parsed,
                intent=intent,
                request=request,
                meta=meta,
                body=body,
            )
        except Exception as error:
            echo = parsed.challenge
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
                    "method": self.method.name,
                    "request": failed_request,
                },
            )
            raise
        context = {
            "challenge": challenge,
            "credential": prepared,
            "intent": intent_obj.name,
            "method": self.method.name,
            "request": echoed_request,
        }
        try:
            receipt = await broadcast_intent_credential(
                intent=intent_obj,
                credential=prepared,
                request=echoed_request,
            )
        except Exception as error:
            await self._events.emit(PAYMENT_FAILED, {**context, "error": error})
            raise
        await self._events.emit(PAYMENT_SUCCESS, {**context, "receipt": receipt})
        return receipt

    @classmethod
    def create(
        cls,
        method: Method,
        realm: str | None = None,
        secret_key: str | None = None,
        store: Store | None = None,
    ) -> Mpp:
        """Create an Mpp instance with smart defaults.

        Args:
            method: Payment method (e.g., tempo(currency=..., recipient=...)).
            realm: Server realm. Auto-detected from environment if omitted.
            secret_key: HMAC secret. Required unless `MPP_SECRET_KEY` is set.
            store: Optional key-value store for replay protection.
                Automatically wired into intents that accept a store.
        """
        return cls(
            method=method,
            realm=detect_realm() if realm is None else realm,
            secret_key=detect_secret_key() if secret_key is None else secret_key,
            store=store,
        )

    async def charge(
        self,
        authorization: str | None,
        amount: str,
        *,
        currency: str | None = None,
        recipient: str | None = None,
        expires: str | None = None,
        description: str | None = None,
        memo: str | None = None,
        splits: list[dict[str, str]] | None = None,
        fee_payer: bool = False,
        chain_id: int | None = None,
        extra: dict[str, str] | None = None,
        body: str | bytes | dict[str, Any] | None = None,
    ) -> Challenge | tuple[Credential, Receipt]:
        """Handle a charge intent.

        Args:
            authorization: The Authorization header value (or None).
            amount: Payment amount in human units (e.g., "0.50" for $0.50).
                Automatically converted to base units (6 decimals for pathUSD).
            currency: Override the method's default currency.
            recipient: Override the method's default recipient.
            expires: Challenge expiration as auth-param (ISO 8601).
                Defaults to now + 5 minutes. Not included in the request body.
            description: Optional human-readable description.
            memo: Optional 32-byte memo (hex string) for transferWithMemo.
            splits: Optional split recipients/amounts for multi-transfer charges.
            fee_payer: Whether to use a fee payer for gas sponsorship.
            chain_id: Override the default chain ID (e.g., 42431 for moderato).
            extra: Optional string metadata embedded in the charge request.
            body: Actual request body bytes, string, or JSON-like dict to bind
                with a SHA-256 digest. If provided, new challenges include a
                digest and submitted credentials must echo a matching digest.

        Returns:
            Challenge if payment required, or (Credential, Receipt) if verified.
        """
        intent = self.method.intents.get("charge")
        if intent is None:
            raise ValueError(f"Method {self.method.name} does not support charge intent")

        resolved_currency = currency or getattr(self.method, "currency", None)
        resolved_recipient = recipient or getattr(self.method, "recipient", None)
        if not resolved_currency:
            raise ValueError("currency must be set on the method or passed to charge()")
        if not resolved_recipient:
            raise ValueError("recipient must be set on the method or passed to charge()")

        decimals = getattr(self.method, "decimals", DEFAULT_DECIMALS)
        base_amount = str(parse_units(amount, decimals))

        request: dict[str, Any] = {
            "amount": base_amount,
            "currency": resolved_currency,
            "recipient": resolved_recipient,
        }

        # Optional server-provided metadata that will be echoed back by the client
        # because it is embedded in the base64url-encoded `request`.
        if extra is not None:
            if any((not isinstance(k, str) or not isinstance(v, str)) for k, v in extra.items()):
                raise ValueError("extra must be a dict[str, str]")
            request["extra"] = extra

        resolved_chain_id = chain_id
        if resolved_chain_id is None:
            resolved_chain_id = getattr(self.method, "chain_id", None)

        if splits and fee_payer:
            raise ValueError("splits and fee_payer cannot be used together")

        if memo or splits or fee_payer or resolved_chain_id is not None:
            method_details: dict[str, Any] = {}
            if resolved_chain_id is not None:
                method_details["chainId"] = resolved_chain_id
            if memo:
                method_details["memo"] = memo
            if splits:
                method_details["splits"] = splits
            if fee_payer:
                method_details["feePayer"] = True
            request["methodDetails"] = method_details

        request = transform_request(self.method, request, None)

        return await verify_or_challenge(
            authorization=authorization,
            intent=intent,
            request=request,
            realm=self.realm,
            secret_key=self.secret_key,
            method=self.method.name,
            description=description,
            expires=expires,
            body=body,
            events=self._events,
        )

    def pay(
        self,
        amount: str,
        *,
        intent: str = "charge",
        currency: str | None = None,
        recipient: str | None = None,
        description: str | None = None,
        expires_in: timedelta | None = None,
        chain_id: int | None = None,
        extra: dict[str, str] | None = None,
        body: BodyParamsType = None,
    ) -> Callable[  # noqa: UP047
        [Callable[[Any, Credential, Receipt], Awaitable[R]]],
        Callable[[Any], Awaitable[R | Any]],
    ]:
        """Decorator that wraps payment verification for protected endpoints.

        Uses the server's configured method, realm, secret_key, currency,
        and recipient as defaults. Only ``amount`` is required per-endpoint.

        The handler **must** use parameter names ``credential`` and ``receipt``
        for the injected payment objects.

        Args:
            amount: Payment amount in human units (e.g., "0.50").
            intent: Intent name to look up on the method (default: "charge").
            currency: Override the method's default currency.
            recipient: Override the method's default recipient.
            description: Optional human-readable description.
            expires_in: Challenge validity duration. Defaults to 5 minutes.
            chain_id: Override the default chain ID (e.g., 42431 for moderato).
            extra: Optional string metadata embedded in the charge request.
            body: Optional static body bytes/string/dict or callback receiving
                the request object. The resolved value is bound into issued
                challenges via digest and used to verify paid retries.

        Example:
            server = Mpp.create(method=tempo(currency=..., recipient=...))

            @app.get("/paid")
            @server.pay(amount="0.50")
            async def handler(request, credential, receipt):
                return {"data": "paid content"}

            @app.get("/session")
            @server.pay(amount="0.000075", intent="session")
            async def session_handler(request, credential, receipt):
                return {"data": "session content"}
        """
        intent_obj = self.method.intents.get(intent)
        if intent_obj is None:
            raise ValueError(f"Method {self.method.name} does not support {intent} intent")

        def decorator(
            handler: Callable[[Any, Credential, Receipt], Awaitable[R]],
        ) -> Callable[[Any], Awaitable[R | Any]]:
            async def _verify(
                authorization: str | None, _request_obj: Any
            ) -> Challenge | tuple[Credential, Receipt]:
                resolved_currency = currency or getattr(self.method, "currency", None)
                resolved_recipient = recipient or getattr(self.method, "recipient", None)
                if not resolved_currency:
                    raise ValueError("currency must be set on the method or passed to pay()")
                if not resolved_recipient:
                    raise ValueError("recipient must be set on the method or passed to pay()")

                decimals = getattr(self.method, "decimals", DEFAULT_DECIMALS)
                base_amount = str(parse_units(amount, decimals))

                challenge_expires: str | None = None
                if expires_in is not None:
                    challenge_expires = (datetime.now(UTC) + expires_in).isoformat()

                request: dict[str, Any] = {
                    "amount": base_amount,
                    "currency": resolved_currency,
                    "recipient": resolved_recipient,
                }

                if extra is not None:
                    if any(
                        not isinstance(k, str) or not isinstance(v, str) for k, v in extra.items()
                    ):
                        raise ValueError("extra must be a dict[str, str]")
                    request["extra"] = extra

                resolved_chain_id = chain_id
                if resolved_chain_id is None:
                    resolved_chain_id = getattr(self.method, "chain_id", None)
                if resolved_chain_id is not None:
                    request["methodDetails"] = {"chainId": resolved_chain_id}

                request = transform_request(
                    self.method,
                    request,
                    None,
                )
                request = bind_framework_scope(request, _request_obj)

                return await verify_or_challenge(
                    authorization=authorization,
                    intent=intent_obj,
                    request=request,
                    realm=self.realm,
                    secret_key=self.secret_key,
                    method=self.method.name,
                    description=description,
                    expires=challenge_expires,
                    body=await resolve_body_param(body, _request_obj),
                    events=self._events,
                )

            return wrap_payment_handler(handler, _verify, lambda: self.realm)

        return decorator
