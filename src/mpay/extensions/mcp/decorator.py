"""Decorator for payment-protected MCP tools.

The @requires_payment decorator is a convenience wrapper for FastMCP-style
frameworks where tool params are unpacked as **kwargs.

For other MCP server implementations, use verify_or_challenge() directly:

    from mpay.extensions.mcp import (
        MCPChallenge,
        PaymentRequiredError,
        verify_or_challenge,
    )

    async def handle_tool(params: dict):
        result = await verify_or_challenge(
            meta=params.get("_meta"),
            intent=intent,
            request={"amount": "1000"},
            realm="api.example.com",
        )
        if isinstance(result, MCPChallenge):
            raise PaymentRequiredError(challenges=[result])
        credential, receipt = result
        # ... execute tool
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta
from functools import wraps
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

from mpay.extensions.mcp.constants import META_CREDENTIAL
from mpay.extensions.mcp.errors import (
    MalformedCredentialError,
    PaymentRequiredError,
    PaymentVerificationError,
)
from mpay.extensions.mcp.types import MCPCredential, MCPReceipt
from mpay.extensions.mcp.verify import DEFAULT_CHALLENGE_TTL, create_challenge

if TYPE_CHECKING:
    from mpay.server.intent import Intent

P = ParamSpec("P")
R = TypeVar("R")

RequestParamsType = dict[str, Any] | Callable[..., dict[str, Any]]


def requires_payment(
    *,
    intent: Intent,
    request: RequestParamsType,
    realm: str,
    method: str | None = None,
    expires_in: timedelta = DEFAULT_CHALLENGE_TTL,
    description: str | None = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorator to require payment for an MCP tool (FastMCP-style).

    This decorator is designed for FastMCP and similar frameworks where tool
    parameters are unpacked as **kwargs. For other MCP server implementations,
    use verify_or_challenge() directly.

    Handles the full 402 challenge flow:
    1. Extracts _meta from kwargs
    2. Checks for org.paymentauth/credential in _meta
    3. If missing or invalid, raises PaymentRequiredError with challenge
    4. If valid, verifies credential and injects credential + receipt into handler

    The decorated function receives two additional keyword arguments:
    - credential: MCPCredential with the verified payment credential
    - receipt: MCPReceipt confirming the payment

    Args:
        intent: The payment intent to verify against.
        request: Payment request params - either a static dict or a callable
            that takes **kwargs and returns the params.
        realm: Protection space identifier for the challenge.
        method: Payment method name (defaults to "tempo").
        expires_in: Challenge validity duration (default: 5 minutes).
        description: Human-readable description of what the payment is for.

    Example:
        @mcp.tool()
        @requires_payment(
            intent=ChargeIntent(rpc_url="..."),
            request={"amount": "1000", "asset": "0x...", "destination": "0x..."},
            realm="api.example.com",
        )
        async def expensive_tool(query: str, *, credential, receipt) -> str:
            return f"Result for {query}, paid by {credential.source}"

        # With dynamic request params:
        @mcp.tool()
        @requires_payment(
            intent=ChargeIntent(rpc_url="..."),
            request=lambda query, **kw: {"amount": str(len(query) * 10), ...},
            realm="api.example.com",
        )
        async def dynamic_pricing(query: str, *, credential, receipt) -> str:
            return f"Result for {query}"

    Raises:
        PaymentRequiredError: When no credential provided (returns -32042).
        PaymentVerificationError: When credential verification fails (-32043).
        MalformedCredentialError: When credential structure is invalid (-32602).
    """
    method_name = method or "tempo"

    def decorator(
        handler: Callable[P, Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        @wraps(handler)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            meta = kwargs.pop("_meta", None) or {}

            if callable(request):
                request_params = request(*args, **kwargs)
            else:
                request_params = request

            credential_data = meta.get(META_CREDENTIAL)

            if credential_data is None:
                challenge = create_challenge(
                    method=method_name,
                    intent_name=intent.name,
                    request=request_params,
                    realm=realm,
                    expires_in=expires_in,
                    description=description,
                )
                raise PaymentRequiredError(challenges=[challenge])

            try:
                mcp_credential = MCPCredential.from_dict(credential_data)
            except (KeyError, TypeError) as e:
                raise MalformedCredentialError(
                    detail=f"Invalid credential structure: {e}"
                ) from e

            from mpay.server.intent import VerificationError

            core_credential = mcp_credential.to_core()

            try:
                core_receipt = await intent.verify(core_credential, request_params)
            except VerificationError as e:
                challenge = create_challenge(
                    method=method_name,
                    intent_name=intent.name,
                    request=request_params,
                    realm=realm,
                    expires_in=expires_in,
                    description=description,
                )
                raise PaymentVerificationError(
                    challenges=[challenge],
                    reason="verification-failed",
                    detail=str(e),
                ) from e

            mcp_receipt = MCPReceipt.from_core(
                receipt=core_receipt,
                challenge_id=mcp_credential.challenge.id,
                method=mcp_credential.challenge.method,
                settlement=_extract_settlement(request_params),
            )

            kwargs["credential"] = mcp_credential
            kwargs["receipt"] = mcp_receipt

            return await handler(*args, **kwargs)

        return wrapper

    return decorator


def _extract_settlement(request: dict[str, Any]) -> dict[str, Any] | None:
    """Extract settlement info from request if available."""
    settlement: dict[str, Any] = {}
    if "amount" in request:
        settlement["amount"] = request["amount"]
    if "currency" in request:
        settlement["currency"] = request["currency"]
    return settlement if settlement else None
