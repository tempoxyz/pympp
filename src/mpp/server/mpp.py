"""Payment handler that binds method, realm, and secret_key."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeVar

from mpp import Challenge, Credential, Receipt
from mpp._parsing import ParseError
from mpp._units import parse_units
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.decorator import wrap_payment_handler
from mpp.server.method import transform_request
from mpp.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.method import Method

R = TypeVar("R")

DEFAULT_DECIMALS = 6


def _credential_for_transform(authorization: str | None) -> Credential | None:
    """Best-effort credential parsing for method transform hooks.

    Transform hooks should be able to branch on authenticated context when
    a valid Payment credential is present. Parsing failures return None so
    verification remains fail-closed inside verify_or_challenge.
    """
    if authorization is None:
        return None

    payment_scheme = next(
        (
            scheme.strip()
            for scheme in authorization.split(",")
            if scheme.strip().lower().startswith("payment ")
        ),
        None,
    )
    if payment_scheme is None:
        return None

    try:
        return Credential.from_authorization(payment_scheme)
    except ParseError:
        return None


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
    ) -> None:
        """Initialize the payment handler.

        Args:
            method: Payment method (e.g., TempoMethod).
            realm: Server realm for WWW-Authenticate header.
            secret_key: Server secret for HMAC-bound challenge IDs.
                Enables stateless challenge verification.
            defaults: Default request values merged with per-call request params.
        """
        self.method = method
        self.realm = realm
        self.secret_key = secret_key
        self.defaults = defaults or {}

    @classmethod
    def create(
        cls,
        method: Method,
        realm: str | None = None,
        secret_key: str | None = None,
    ) -> Mpp:
        """Create an Mpp instance with smart defaults.

        Args:
            method: Payment method (e.g., tempo(currency=..., recipient=...)).
            realm: Server realm. Auto-detected from environment if omitted.
            secret_key: HMAC secret. Required unless `MPP_SECRET_KEY` is set.
        """
        return cls(
            method=method,
            realm=detect_realm() if realm is None else realm,
            secret_key=detect_secret_key() if secret_key is None else secret_key,
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
        fee_payer: bool = False,
        chain_id: int | None = None,
        extra: dict[str, str] | None = None,
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
            fee_payer: Whether to use a fee payer for gas sponsorship.
            chain_id: Override the default chain ID (e.g., 42431 for moderato).

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

        if memo or fee_payer or resolved_chain_id is not None:
            method_details: dict[str, Any] = {}
            if resolved_chain_id is not None:
                method_details["chainId"] = resolved_chain_id
            if memo:
                method_details["memo"] = memo
            if fee_payer:
                method_details["feePayer"] = True
            request["methodDetails"] = method_details

        request = transform_request(self.method, request, _credential_for_transform(authorization))

        return await verify_or_challenge(
            authorization=authorization,
            intent=intent,
            request=request,
            realm=self.realm,
            secret_key=self.secret_key,
            method=self.method.name,
            description=description,
            expires=expires,
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
                    _credential_for_transform(authorization),
                )

                return await verify_or_challenge(
                    authorization=authorization,
                    intent=intent_obj,
                    request=request,
                    realm=self.realm,
                    secret_key=self.secret_key,
                    method=self.method.name,
                    description=description,
                    expires=challenge_expires,
                )

            return wrap_payment_handler(handler, _verify, lambda: self.realm)

        return decorator
