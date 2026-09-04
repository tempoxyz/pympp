"""Composition of configured server payment offers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Required, TypeAlias, TypedDict, TypeVar, cast

from mpp import Challenge, Credential, Receipt, _body_digest
from mpp._parsing import ParseError, _b64_decode
from mpp._units import parse_units
from mpp.errors import InvalidChallengeError, MalformedCredentialError
from mpp.server.decorator import BodyParamsType, resolve_body_param, wrap_payment_handler
from mpp.server.method import Method, _SupportsCanOffer
from mpp.server.verify import _authenticate_echo, _extract_payment_scheme, verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.intent import Intent, VerifiableIntent
    from mpp.server.mpp import Mpp

R = TypeVar("R")


class ComposeOptions(TypedDict, total=False):
    """Options for one configured payment offer."""

    amount: Required[str]
    currency: str | None
    recipient: str | None
    description: str | None
    expires: str | None
    expires_in: timedelta | None
    memo: str | None
    splits: list[dict[str, str]] | None
    fee_payer: bool
    chain_id: int | None
    extra: dict[str, str] | None
    meta: dict[str, str] | None


ComposeEntry: TypeAlias = tuple[Method | str, ComposeOptions]


@dataclass
class ComposedChallenges:
    """Challenges issued by an unpaid composed handler."""

    challenges: tuple[Challenge, ...]


ComposedResult: TypeAlias = ComposedChallenges | tuple[Credential, Receipt]
_OPTION_KEYS = frozenset(ComposeOptions.__annotations__)


@dataclass
class _Offer:
    """One payment offer configured on a particular Mpp server."""

    server: Mpp
    method: Method
    intent: str
    options: ComposeOptions
    body: BodyParamsType

    def owns(self, credential: Credential) -> bool:
        """Return whether this offer's server authenticated the credential."""
        if credential.challenge.realm != self.server.realm:
            return False
        try:
            _authenticate_echo(credential, secret_key=self.server.secret_key)
        except (InvalidChallengeError, MalformedCredentialError):
            return False
        return True


@dataclass
class _PreparedOffer:
    """One configured offer resolved for the current request."""

    offer: _Offer
    intent: Intent | VerifiableIntent
    request: dict[str, Any]
    expires: str | None
    body: str | bytes | dict[str, Any] | None

    async def is_available(self) -> bool:
        """Return whether the method wants to advertise this prepared offer."""
        callback = (
            self.offer.method.can_offer
            if isinstance(self.offer.method, _SupportsCanOffer)
            else None
        )
        if callback is None:
            return True
        if not callable(callback):
            raise ValueError("can_offer must be callable")
        available = callback(deepcopy(self.request))
        if inspect.isawaitable(available):
            available = await available
        if not isinstance(available, bool):
            raise ValueError("can_offer must return bool")
        return available

    async def verify(self, authorization: str | None) -> Challenge | tuple[Credential, Receipt]:
        """Verify this offer using its originating server."""
        server = self.offer.server
        return await verify_or_challenge(
            authorization=authorization,
            intent=self.intent,
            request=self.request,
            realm=server.realm,
            secret_key=server.secret_key,
            method=self.offer.method.name,
            description=self.offer.options.get("description"),
            meta=self.offer.options.get("meta"),
            expires=self.expires,
            body=self.body,
            events=server._events,
            header=server.credential_header,
        )


class _AmbiguousOffersError(Exception):
    """Credential authenticates against indistinguishable configured offers."""

    def __init__(self, offers: Sequence[_PreparedOffer]) -> None:
        self.offers = tuple(offers)
        super().__init__("credential matches multiple configured offers")


def _parse_credential(authorization: str | None) -> Credential | None:
    """Parse a Payment authorization header for offer routing."""
    payment_scheme = _extract_payment_scheme(authorization) if authorization else None
    try:
        return Credential.from_authorization(payment_scheme) if payment_scheme else None
    except ParseError:
        return None


async def _prepare_offer(
    offer: _Offer,
    request: Any,
    body_cache: dict[int, str | bytes | dict[str, Any] | None],
) -> _PreparedOffer:
    """Resolve an offer's request and body for this call."""
    intent, payment_request, expires = offer.server._build_offer_request(
        offer.method,
        offer.intent,
        offer.options,
        request,
        api_name="compose",
    )
    key = id(offer.body)
    if key not in body_cache:
        body_cache[key] = await resolve_body_param(offer.body, request)
    return _PreparedOffer(offer, intent, payment_request, expires, body_cache[key])


class ComposedHandler:
    """A configured handler containing one or more payment offers."""

    def __init__(self, *handlers: ComposedHandler) -> None:
        """Combine previously configured handlers."""
        if not handlers:
            raise ValueError("compose() requires at least one configured handler")
        if any(not isinstance(handler, ComposedHandler) for handler in handlers):
            raise TypeError("compose() accepts only configured handlers")
        self._offers = tuple(offer for handler in handlers for offer in handler._offers)

    @classmethod
    def _from_offers(cls, offers: Sequence[_Offer]) -> ComposedHandler:
        """Create a handler from newly configured offers."""
        handler = cls.__new__(cls)
        handler._offers = tuple(offers)
        return handler

    async def verify(self, authorization: str | None, request: Any = None) -> ComposedResult:
        """Verify a matching credential or issue every configured challenge."""
        body_cache: dict[int, str | bytes | dict[str, Any] | None] = {}
        credential = _parse_credential(authorization)
        if credential is not None:
            prepared_offers = [
                await _prepare_offer(offer, request, body_cache)
                for offer in self._offers
                if offer.method.name == credential.challenge.method
                and offer.intent == credential.challenge.intent
            ]
            try:
                selected_offer = self._select_offer(credential, prepared_offers)
            except _AmbiguousOffersError as error:
                challenges: list[Challenge] = []
                for prepared_offer in error.offers:
                    result = await prepared_offer.verify(None)
                    if not isinstance(result, Challenge):
                        raise RuntimeError(
                            "offer without a credential returned a receipt"
                        ) from error
                    challenges.append(result)
                return ComposedChallenges(tuple(challenges))
            if selected_offer is not None:
                result = await selected_offer.verify(authorization)
                return ComposedChallenges((result,)) if isinstance(result, Challenge) else result

        challenges: list[Challenge] = []
        for offer in self._offers:
            prepared_offer = await _prepare_offer(offer, request, body_cache)
            if not await prepared_offer.is_available():
                continue
            result = await prepared_offer.verify(authorization)
            if not isinstance(result, Challenge):
                return result
            challenges.append(result)
        if not challenges:
            raise ValueError("No payment offers are available for this request")
        return ComposedChallenges(tuple(challenges))

    def __call__(
        self,
        handler: Callable[[Any, Credential, Receipt], Awaitable[R]],
    ) -> Callable[[Any], Awaitable[R | Any]]:
        """Wrap a payment-protected endpoint."""
        server = self._offers[0].server
        return wrap_payment_handler(
            handler,
            self.verify,
            lambda: server.realm,
            requires_auth=server.requires_auth,
        )

    @staticmethod
    def _select_offer(
        credential: Credential,
        offers: Sequence[_PreparedOffer],
    ) -> _PreparedOffer | None:
        """Choose the offer addressed by a credential."""
        try:
            echoed_request = (
                _b64_decode(credential.challenge.request) if credential.challenge.request else {}
            )
            echoed_meta = (
                _b64_decode(credential.challenge.opaque) if credential.challenge.opaque else None
            )
        except ParseError:
            return None

        request_matches = [offer for offer in offers if offer.request == echoed_request]
        digest = credential.challenge.digest
        binding_matches = [
            offer
            for offer in request_matches
            if digest == (_body_digest.compute(offer.body) if offer.body is not None else None)
            and echoed_meta == offer.offer.options.get("meta")
        ]
        authenticated_matches = [offer for offer in binding_matches if offer.offer.owns(credential)]
        if len(authenticated_matches) > 1:
            raise _AmbiguousOffersError(authenticated_matches)
        if authenticated_matches:
            return authenticated_matches[0]

        for prepared_offer in (*binding_matches, *request_matches, *offers):
            if prepared_offer.offer.owns(credential):
                return prepared_offer
        if binding_matches:
            return binding_matches[0]
        if request_matches:
            return request_matches[0]
        return offers[0] if offers else None


def compose(*handlers: ComposedHandler) -> ComposedHandler:
    """Combine configured handlers while preserving each handler's server."""
    return ComposedHandler(*handlers)


def _configure_entries(
    server: Mpp,
    entries: Sequence[ComposeEntry],
    body: BodyParamsType,
) -> ComposedHandler:
    """Validate compose entries and bind them to a server."""
    if not entries:
        raise ValueError("compose() requires at least one entry")

    registered = {method.name: method for method in server.methods}
    offers: list[_Offer] = []
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise ValueError("compose() entries must be (method, options) tuples")
        method_ref, raw_options = entry
        if isinstance(method_ref, str):
            parts = method_ref.split("/")
            if len(parts) not in (1, 2) or not all(parts):
                raise ValueError(f"invalid payment method reference: {method_ref}")
            method = registered.get(parts[0])
            if method is None:
                raise ValueError(f"unknown payment method: {parts[0]}")
            intent = parts[1] if len(parts) == 2 else "charge"
        else:
            method = registered.get(getattr(method_ref, "name", ""))
            if method is None or method is not method_ref:
                raise ValueError("payment method is not registered")
            intent = "charge"
        if intent not in method.intents:
            raise ValueError(f"Method {method.name} does not support {intent} intent")

        if not isinstance(raw_options, Mapping):
            raise ValueError("compose() options must be a mapping")
        unknown = raw_options.keys() - _OPTION_KEYS
        if unknown:
            raise ValueError(f"unsupported compose option: {sorted(unknown, key=str)[0]}")
        amount = raw_options.get("amount")
        if not isinstance(amount, str) or not amount.strip():
            raise ValueError("compose() offer requires a non-empty string amount")
        if raw_options.get("expires") is not None and raw_options.get("expires_in") is not None:
            raise ValueError("compose() options expires and expires_in cannot both be set")
        if raw_options.get("splits") and raw_options.get("fee_payer"):
            raise ValueError("splits and fee_payer cannot be used together")
        meta = raw_options.get("meta")
        if meta is not None and (
            not isinstance(meta, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in meta.items()
            )
        ):
            raise ValueError("meta must be a dict[str, str]")
        options = cast(ComposeOptions, raw_options)
        if not (options.get("currency") or getattr(method, "currency", None)):
            raise ValueError("currency must be set on the method or compose() offer")
        if not (options.get("recipient") or getattr(method, "recipient", None)):
            raise ValueError("recipient must be set on the method or compose() offer")
        parse_units(options["amount"], getattr(method, "decimals", 6))
        offers.append(_Offer(server, method, intent, options, body))
    return ComposedHandler._from_offers(offers)
