"""Decorator for payment-protected endpoints."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from mpay import Challenge, Credential, Receipt
from mpay.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpay.server.intent import Intent

R = TypeVar("R")

RequestParamsType = dict[str, Any] | Callable[[Any], dict[str, Any]]


def _get_authorization(request: Any) -> str | None:
    """Extract Authorization header from various request types."""
    if hasattr(request, "headers"):
        return request.headers.get("authorization") or request.headers.get("Authorization")
    if hasattr(request, "META"):
        return request.META.get("HTTP_AUTHORIZATION")
    return None


def _make_challenge_response(challenge: Challenge, realm: str) -> Any:
    """Build 402 response for a challenge."""
    try:
        from starlette.responses import Response

        return Response(
            content=None,
            status_code=402,
            headers={"WWW-Authenticate": challenge.to_www_authenticate(realm)},
        )
    except ImportError:
        return {
            "_mpay_challenge": True,
            "status": 402,
            "headers": {"WWW-Authenticate": challenge.to_www_authenticate(realm)},
        }


def requires_payment(
    *,
    intent: Intent,
    request: RequestParamsType,
    realm: str,
    secret_key: str,
    method: str | None = None,
) -> Callable[
    [Callable[[Any, Credential, Receipt], Awaitable[R]]],
    Callable[[Any], Awaitable[R | Any]],
]:
    """Decorator to require payment for an endpoint.

    Automatically handles the 402 challenge flow by:
    1. Extracting the Authorization header from the request
    2. Calling verify_or_challenge
    3. Returning 402 with WWW-Authenticate if payment is required
    4. Calling the handler with (request, credential, receipt) if verified

    Args:
        intent: The payment intent to verify against.
        request: Payment request params - either a static dict or a callable
            that takes the request and returns the params.
        realm: The realm for the WWW-Authenticate header.
        secret_key: Server secret for HMAC-bound challenge IDs. Required.
            Enables stateless challenge verification.
        method: The payment method name (defaults to "tempo").

    Example:
        @app.get("/resource")
        @requires_payment(
            intent=ChargeIntent(rpc_url="..."),
            request={"amount": "1000", "currency": "0x...", "recipient": "0x..."},
            realm="api.example.com",
            secret_key="my-server-secret",  # Enables HMAC-bound IDs
        )
        async def get_resource(request: Request, credential: Credential, receipt: Receipt):
            return {"data": "paid content", "payer": credential.source}

        # With dynamic request params:
        @requires_payment(
            intent=ChargeIntent(rpc_url="..."),
            request=lambda req: {"amount": req.query_params.get("price"), ...},
            realm="api.example.com",
            secret_key="my-server-secret",
        )
        async def dynamic_pricing(request: Request, credential: Credential, receipt: Receipt):
            return {"data": "..."}
    """

    def decorator(
        handler: Callable[[Any, Credential, Receipt], Awaitable[R]],
    ) -> Callable[[Any], Awaitable[R | Any]]:
        sig = inspect.signature(handler)
        params = [p for name, p in sig.parameters.items() if name not in ("credential", "receipt")]
        new_sig = sig.replace(parameters=params)

        request_param_name = params[0].name if params else "request"

        @wraps(handler)
        async def wrapper(*args: Any, **kwargs: Any) -> R | Any:
            if args:
                request_obj = args[0]
            else:
                request_obj = kwargs.get(request_param_name)
            authorization = _get_authorization(request_obj)

            if callable(request):
                request_params = request(request_obj)
            else:
                request_params = request

            result = await verify_or_challenge(
                authorization=authorization,
                intent=intent,
                request=request_params,
                realm=realm,
                secret_key=secret_key,
                method=method,
            )

            if isinstance(result, Challenge):
                return _make_challenge_response(result, realm)

            credential, receipt_obj = result
            return await handler(request_obj, credential, receipt_obj)

        wrapper.__signature__ = new_sig  # type: ignore[attr-defined]
        del wrapper.__wrapped__

        return wrapper

    return decorator
