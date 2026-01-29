"""Payment handler that binds method, realm, and secret_key."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mpay import Challenge, Credential, Receipt
from mpay.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpay.server.method import Method


class Mpay:
    """Server-side payment handler.
    
    Binds a payment method with realm and secret_key for stateless
    challenge verification. Matches TypeScript's Mpay.create() pattern.
    
    Example:
        from mpay.server import Mpay
        from mpay.methods.tempo import TempoMethod
        
        payment = Mpay(
            method=TempoMethod(rpc_url="https://rpc.tempo.xyz"),
            realm="api.example.com",
            secret_key="my-server-secret",
        )
        
        # In request handler:
        result = await payment.charge(
            authorization=request.headers.get("Authorization"),
            request={"amount": "1000", "currency": "0x...", "recipient": "0x..."},
        )
        
        if isinstance(result, Challenge):
            return Response(status=402, headers={"WWW-Authenticate": result.to_www_authenticate(payment.realm)})
        
        credential, receipt = result
        return Response({"data": "..."}, headers={"Payment-Receipt": receipt.to_payment_receipt()})
    """
    
    def __init__(
        self,
        method: Method,
        realm: str,
        secret_key: str,
    ) -> None:
        """Initialize the payment handler.
        
        Args:
            method: Payment method (e.g., TempoMethod).
            realm: Server realm for WWW-Authenticate header.
            secret_key: Server secret for HMAC-bound challenge IDs.
                Enables stateless challenge verification.
        """
        self.method = method
        self.realm = realm
        self.secret_key = secret_key
    
    async def charge(
        self,
        authorization: str | None,
        request: dict[str, Any],
    ) -> Challenge | tuple[Credential, Receipt]:
        """Handle a charge intent.
        
        If no valid Authorization header is provided, returns a Challenge
        that should be sent as a 402 response.
        
        If a valid credential is provided, verifies it and returns
        the (Credential, Receipt) tuple.
        
        Args:
            authorization: The Authorization header value (or None).
            request: Payment request parameters (amount, currency, recipient, etc.).
        
        Returns:
            Challenge if payment required, or (Credential, Receipt) if verified.
        """
        intent = self.method.intents.get("charge")
        if intent is None:
            raise ValueError(f"Method {self.method.name} does not support charge intent")
        
        return await verify_or_challenge(
            authorization=authorization,
            intent=intent,
            request=request,
            realm=self.realm,
            secret_key=self.secret_key,
            method=self.method.name,
        )
    
    async def authorize(
        self,
        authorization: str | None,
        request: dict[str, Any],
    ) -> Challenge | tuple[Credential, Receipt]:
        """Handle an authorize intent.
        
        Args:
            authorization: The Authorization header value (or None).
            request: Authorization request parameters.
        
        Returns:
            Challenge if payment required, or (Credential, Receipt) if verified.
        """
        intent = self.method.intents.get("authorize")
        if intent is None:
            raise ValueError(f"Method {self.method.name} does not support authorize intent")
        
        return await verify_or_challenge(
            authorization=authorization,
            intent=intent,
            request=request,
            realm=self.realm,
            secret_key=self.secret_key,
            method=self.method.name,
        )
