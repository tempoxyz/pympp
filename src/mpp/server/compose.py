"""Route handlers: configured server payment offers and their composition."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeAlias

from pydantic import ValidationError

from mpp import PAYMENT_AUTHORIZATION_HEADER, Challenge, Credential, Receipt, _body_digest
from mpp._parsing import ParseError, _b64_decode
from mpp.errors import (
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentError,
    PaymentRequiredError,
    VerificationFailedError,
)
from mpp.events import PAYMENT_FAILED
from mpp.server.http import PaymentRequired, PaymentResult, PaymentVerified, Request, Response
from mpp.server.method import (
    SETTLING_METHOD,
    RequestContext,
    ServerMethod,
    VerifyContext,
    resolve,
)
from mpp.server.verify import (
    _application_meta,
    _authenticate_echo,
    _challenge_from_echo,
    _extract_payment_scheme,
    verify_or_challenge,
)
from mpp.x402._header import InvalidHeaderError, decode_payment_signature
from mpp.x402._server import X402Input, challenges_payment_required_header
from mpp.x402._types import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    PaymentPayload,
    PaymentRequirements,
    requirements_match,
)

if TYPE_CHECKING:
    from mpp.server.mpp import Mpp

BodyType = str | bytes | dict[str, Any]
BodyParamsType = BodyType | Callable[[Request], BodyType | Awaitable[BodyType]] | None
ROUTE_OPTION_KEYS = frozenset({"body", "description", "expires", "expires_in", "meta"})


@dataclass
class ComposedChallenges:
    """Challenges issued by an unpaid handler.

    ``error`` is set when a submitted credential matched no offer, such as an
    x402 payment for requirements this route does not offer.
    """

    challenges: tuple[Challenge, ...]
    error: Exception | None = None


ComposedResult: TypeAlias = ComposedChallenges | tuple[Credential, Receipt]


class _MethodIntent:
    """Runs a server method's hooks for one prepared offer."""

    def __init__(self, method: ServerMethod, input: dict[str, Any]) -> None:
        self.name = method.intent
        self._method = method
        self._input = input

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        try:
            payload = self._method.method.parse_payload(credential.payload)
        except ValidationError as error:
            raise InvalidPayloadError(str(error)) from error
        echo = credential.challenge
        try:
            opaque = _b64_decode(echo.opaque) if echo.opaque else None
        except ParseError:
            opaque = None
        receipt, _ = await self._method.settle(
            VerifyContext(
                credential=replace(credential, payload=payload),
                request=self._input,
                challenge=_challenge_from_echo(
                    echo, request, opaque if isinstance(opaque, dict) else None
                ),
            )
        )
        return receipt


class _X402MethodIntent(_MethodIntent):
    """A method intent that x402 clients can also pay."""

    @property
    def route_binding(self) -> str:
        return getattr(self._method.x402, "route_binding", "required")

    def x402_requirements(self, request: dict[str, Any]) -> PaymentRequirements:
        assert self._method.x402 is not None
        return self._method.x402.x402_requirements(request)

    def x402_credential_payload(
        self, payment: PaymentPayload, request: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None]:
        assert self._method.x402 is not None
        return self._method.x402.x402_credential_payload(payment, request)


@dataclass
class _Offer:
    """One payment offer configured on a particular Mpp server."""

    server: Mpp
    method: ServerMethod
    options: dict[str, Any]

    def owns(self, credential: Credential) -> bool:
        """Return whether this offer's server authenticated the credential."""
        if credential.challenge.realm != self.server.realm:
            return False
        try:
            _authenticate_echo(credential, secret_key=self.server.secret_key)
        except (InvalidChallengeError, MalformedCredentialError):
            return False
        return True

    @property
    def meta(self) -> dict[str, str] | None:
        return self.options.get("meta")


@dataclass
class _PreparedOffer:
    """One configured offer resolved for the current request."""

    offer: _Offer
    intent: _MethodIntent
    request: dict[str, Any]
    expires: str | None
    body: BodyType | None

    async def is_available(self) -> bool:
        """Return whether the method wants to advertise this prepared offer."""
        callback = self.offer.method.can_offer
        if callback is None:
            return True
        available = callback(deepcopy(self.request))
        if inspect.isawaitable(available):
            available = await available
        if not isinstance(available, bool):
            raise ValueError("can_offer must return bool")
        return available

    async def verify(
        self, authorization: str | None, x402: X402Input | None = None
    ) -> Challenge | tuple[Credential, Receipt]:
        """Verify this offer using its originating server."""
        server = self.offer.server
        token = SETTLING_METHOD.set(self.offer.method)
        try:
            return await self._verify(server, authorization, x402)
        finally:
            SETTLING_METHOD.reset(token)

    async def _verify(
        self, server: Mpp, authorization: str | None, x402: X402Input | None
    ) -> Challenge | tuple[Credential, Receipt]:
        return await verify_or_challenge(
            authorization=authorization,
            intent=self.intent,
            request=self.request,
            realm=server.realm,
            secret_key=server.secret_key,
            method=self.offer.method.name,
            description=self.offer.options.get("description"),
            meta=self.offer.meta,
            expires=self.expires,
            body=self.body,
            events=server._events,
            header=server.credential_header,
            unique_challenges=server.unique_challenges,
            x402=x402,
        )


@dataclass
class _Call:
    """State shared by the offers prepared for one request."""

    bodies: dict[int, BodyType | None] = field(default_factory=dict)
    prepared: list[_PreparedOffer] = field(default_factory=list)


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
    request: Request,
    credential: Credential | None,
    call: _Call,
) -> _PreparedOffer:
    """Resolve an offer's wire request, expiry and body for this call."""
    method = offer.method
    options = {
        key: value
        for key, value in offer.options.items()
        if key not in ROUTE_OPTION_KEYS and value is not None
    }
    input = {**(method.defaults or {}), **options}
    if method.resolve_request is not None:
        input = await resolve(
            method.resolve_request(
                RequestContext(request=input, credential=credential, input=request)
            )
        )
    wire = method.method.normalize_request(input)
    scope: dict[str, Any] = request.scope()
    if wire.get("_mppx_scope") is not None:
        scope = {**scope, "custom": wire["_mppx_scope"]}
    wire = {**wire, "_mppx_scope": scope}

    expires = offer.options.get("expires")
    expires_in = offer.options.get("expires_in")
    if expires_in is not None:
        expires = (datetime.now(UTC) + expires_in).isoformat()

    body = offer.options.get("body")
    key = id(body)
    if key not in call.bodies:
        value: Any = body(request) if callable(body) else body
        if inspect.isawaitable(value):
            value = await value
        call.bodies[key] = value
    prepared = _PreparedOffer(offer, _intent(method, input), wire, expires, call.bodies[key])
    call.prepared.append(prepared)
    return prepared


def _intent(method: ServerMethod, input: dict[str, Any]) -> _MethodIntent:
    if method.x402 is not None:
        return _X402MethodIntent(method, input)
    return _MethodIntent(method, input)


def _validate_options(options: Mapping[str, Any]) -> dict[str, Any]:
    """Check route options shared by every method."""
    if options.get("expires") is not None and options.get("expires_in") is not None:
        raise ValueError("expires and expires_in cannot both be set")
    expires_in = options.get("expires_in")
    if expires_in is not None and not isinstance(expires_in, timedelta):
        raise ValueError("expires_in must be a timedelta")
    meta = options.get("meta")
    if meta is not None and (
        not isinstance(meta, dict)
        or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in meta.items()
        )
    ):
        raise ValueError("meta must be a dict[str, str]")
    return dict(options)


class ComposedHandler:
    """A route handler presenting one or more payment offers.

    Call it with a :class:`~mpp.server.Request` to get :class:`~mpp.server.PaymentRequired`
    or :class:`~mpp.server.PaymentVerified`.
    """

    def __init__(self, *handlers: ComposedHandler) -> None:
        """Combine previously configured handlers."""
        if not handlers:
            raise ValueError("compose() requires at least one configured handler")
        if any(not isinstance(handler, ComposedHandler) for handler in handlers):
            raise TypeError("compose() accepts only configured handlers")
        self._offers = tuple(offer for handler in handlers for offer in handler._offers)
        self._composed = True

    @classmethod
    def _from_offers(cls, offers: Sequence[_Offer], *, composed: bool) -> ComposedHandler:
        """Create a handler from newly configured offers."""
        handler = cls.__new__(cls)
        handler._offers = tuple(offers)
        handler._composed = composed
        return handler

    @property
    def needs_request_body(self) -> bool:
        """Whether an offer's ``body`` option is a callable reading the request."""
        return any(callable(offer.options.get("body")) for offer in self._offers)

    @property
    def methods(self) -> tuple[ServerMethod, ...]:
        """The configured method of each offer."""
        return tuple(offer.method for offer in self._offers)

    async def __call__(self, request: Request) -> PaymentResult:
        """Verify the request's credential, or return the challenges to pay."""
        server = self._offers[0].server
        authorization = request.headers.get(
            PAYMENT_AUTHORIZATION_HEADER if server.requires_auth else "Authorization"
        )
        x402 = (
            X402Input(
                resource_url=request.url,
                payment_signature=request.headers.get(PAYMENT_SIGNATURE_HEADER),
                http_method=request.method,
            )
            if request.url.startswith(("http://", "https://"))
            else None
        )
        call = _Call()
        try:
            result = await self._verify(authorization, request, x402, call)
        except PaymentError as error:
            if isinstance(error.retry_challenge, Challenge):
                return PaymentRequired(
                    self._challenge_response(request, (error.retry_challenge,), error, call)
                )
            if error.status == 403:
                return PaymentRequired(
                    Response(
                        status=error.status,
                        headers={
                            "Cache-Control": "no-store",
                            "Content-Type": "application/problem+json",
                        },
                        body=json.dumps(error.to_problem_details()),
                    )
                )
            raise
        if isinstance(result, ComposedChallenges):
            return PaymentRequired(
                self._challenge_response(request, result.challenges, result.error, call)
            )
        credential, receipt = result
        return PaymentVerified(credential=credential, receipt=receipt)

    def _challenge_response(
        self,
        request: Request,
        challenges: Sequence[Challenge],
        error: Exception | None,
        call: _Call,
    ) -> Response:
        """Build a 402 response with RFC 9457 problem details."""
        realm = self._offers[0].server.realm
        problem = (
            error
            if isinstance(error, PaymentError)
            else PaymentRequiredError(realm=realm, description=challenges[0].description)
        )
        headers = [
            ("WWW-Authenticate", challenge.to_www_authenticate(challenge.realm or realm))
            for challenge in challenges
        ]
        headers += [("Cache-Control", "no-store"), ("Content-Type", "application/problem+json")]
        if request.url.startswith(("http://", "https://")):
            x402 = challenges_payment_required_header(
                challenges,
                lambda challenge: _x402_accepts(call, challenge),
                request.url,
                request.method,
                str(error) if error is not None else None,
            )
            if x402 is not None:
                headers.append((PAYMENT_REQUIRED_HEADER, x402))
        return Response(
            status=402,
            headers=headers,
            body=json.dumps(problem.to_problem_details(challenges[0].id)),
        )

    async def _available(self, offer: _PreparedOffer) -> bool:
        """Whether to advertise a prepared offer; a direct single-offer handler always does."""
        return not self._composed or await offer.is_available()

    async def _verify(
        self, authorization: str | None, request: Request, x402: X402Input | None, call: _Call
    ) -> ComposedResult:
        """Verify a matching credential or issue every configured challenge.

        Without a Payment credential, an x402 ``PAYMENT-SIGNATURE`` pays the offer
        whose x402 requirements it echoes.
        """
        credential = _parse_credential(authorization)
        if credential is None and x402 is not None and x402.payment_signature:
            x402_result = await self._verify_x402(x402, request, call)
            if x402_result is not None:
                return x402_result
        if credential is not None:
            prepared_offers = [
                await _prepare_offer(offer, request, credential, call)
                for offer in self._offers
                if offer.method.name == credential.challenge.method
                and offer.method.intent == credential.challenge.intent
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
            prepared_offer = await _prepare_offer(offer, request, None, call)
            if not await self._available(prepared_offer):
                continue
            result = await prepared_offer.verify(authorization)
            if not isinstance(result, Challenge):
                return result
            challenges.append(result)
        if not challenges:
            raise ValueError("No payment offers are available for this request")
        return ComposedChallenges(tuple(challenges))

    async def _verify_x402(
        self,
        x402: X402Input,
        request: Request,
        call: _Call,
    ) -> ComposedResult | None:
        """Pay the offer an x402 payload addresses, or return every challenge."""
        prepared = [await _prepare_offer(offer, request, None, call) for offer in self._offers]
        x402_offers = [offer for offer in prepared if isinstance(offer.intent, _X402MethodIntent)]
        if not x402_offers:
            return None
        assert x402.payment_signature is not None
        error: Exception
        try:
            payment = decode_payment_signature(x402.payment_signature)
        except InvalidHeaderError as decode_error:
            error = MalformedCredentialError(
                f"invalid {PAYMENT_SIGNATURE_HEADER} header: {decode_error}"
            )
        else:
            for offer in x402_offers:
                intent = offer.intent
                assert isinstance(intent, _X402MethodIntent)
                if not requirements_match(
                    payment["accepted"], intent.x402_requirements(offer.request)
                ):
                    continue
                # Like a native credential, an x402 payment can only pay an offer
                # this request would have advertised.
                if await self._available(offer):
                    result = await offer.verify(None, x402)
                    return (
                        ComposedChallenges((result,)) if isinstance(result, Challenge) else result
                    )
            error = VerificationFailedError(
                "x402 payment payload does not match route requirements"
            )
        challenges: list[Challenge] = []
        for offer in prepared:
            if not await self._available(offer):
                continue
            result = await offer.verify(None)
            if not isinstance(result, Challenge):
                raise RuntimeError("offer without a credential returned a receipt")
            challenges.append(result)
        if not challenges:
            raise ValueError("No payment offers are available for this request")
        # Report the rejected payment like a rejected Payment credential.
        reporter = x402_offers[0]
        await reporter.offer.server._events.emit(
            PAYMENT_FAILED,
            {
                "challenge": challenges[0],
                "credential": None,
                "error": error,
                "intent": reporter.intent.name,
                "method": reporter.offer.method.name,
                "request": reporter.request,
            },
        )
        return ComposedChallenges(tuple(challenges), error=error)

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

        if echoed_meta is not None and not isinstance(echoed_meta, dict):
            return None
        request_matches = [offer for offer in offers if offer.request == echoed_request]
        digest = credential.challenge.digest
        binding_matches = [
            offer
            for offer in request_matches
            if (
                digest is None
                if offer.body is None
                else digest is not None and _body_digest.verify(digest, offer.body)
            )
            and _application_meta(echoed_meta) == (offer.offer.meta or None)
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


def _x402_accepts(call: _Call, challenge: Challenge) -> PaymentRequirements | None:
    """Return the x402 requirements of the prepared offer that issued a challenge.

    Composed servers may share a realm with different tokens: the issuing offer's
    method decides the EIP-712 domain.
    """
    for prepared in call.prepared:
        offer = prepared.offer
        if (
            isinstance(prepared.intent, _X402MethodIntent)
            and offer.method.name == challenge.method
            and offer.method.intent == challenge.intent
            and offer.server.realm == challenge.realm
            and prepared.request == challenge.request
        ):
            return prepared.intent.x402_requirements(challenge.request)
    return None


def compose(*handlers: ComposedHandler) -> ComposedHandler:
    """Combine configured handlers while preserving each handler's server."""
    return ComposedHandler(*handlers)
