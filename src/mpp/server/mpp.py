"""Payment handler that binds method, realm, and secret_key."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential, Receipt
from mpp._units import parse_units
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.method import Method

DEFAULT_EXPIRY_SECONDS = 300
DEFAULT_DECIMALS = 6


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
            secret_key: HMAC secret. Auto-generated and persisted to .env if omitted.
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
    ) -> Challenge | tuple[Credential, Receipt]:
        """Handle a charge intent.

        Args:
            authorization: The Authorization header value (or None).
            amount: Payment amount in human units (e.g., "0.50" for $0.50).
                Automatically converted to base units (6 decimals for pathUSD).
            currency: Override the method's default currency.
            recipient: Override the method's default recipient.
            expires: Challenge expiration (ISO 8601). Defaults to now + 5 minutes.
            description: Optional human-readable description.

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

        if expires is None:
            expires = (datetime.now(UTC) + timedelta(seconds=DEFAULT_EXPIRY_SECONDS)).isoformat()

        decimals = getattr(self.method, "decimals", DEFAULT_DECIMALS)
        base_amount = str(parse_units(amount, decimals))

        request: dict[str, Any] = {
            "amount": base_amount,
            "currency": resolved_currency,
            "recipient": resolved_recipient,
            "expires": expires,
        }

        return await verify_or_challenge(
            authorization=authorization,
            intent=intent,
            request=request,
            realm=self.realm,
            secret_key=self.secret_key,
            method=self.method.name,
            description=description,
        )
