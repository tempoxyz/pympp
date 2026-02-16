"""Decorator for payment-protected endpoints."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from mpp import Challenge, Credential, Receipt
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.intent import Intent

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
            "_mpp_challenge": True,
            "status": 402,
            "headers": {"WWW-Authenticate": challenge.to_www_authenticate(realm)},
        }


def pay(
    *,
    intent: Intent,
    request: RequestParamsType,
    realm: str | None = None,
    secret_key: str | None = None,
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
            Auto-detected from environment if omitted.
        secret_key: Server secret for HMAC-bound challenge IDs.
            Auto-generated and persisted to .env if omitted.
        method: The payment method name (defaults to "tempo").

    Example:
        @app.get("/resource")
        @pay(
            intent=ChargeIntent(rpc_url="..."),
            request={"amount": "1000", "currency": "0x...", "recipient": "0x..."},
        )
        async def get_resource(request: Request, credential: Credential, receipt: Receipt):
            return {"data": "paid content", "payer": credential.source}
    """

    resolved_realm = realm if realm is not None else detect_realm()
    resolved_secret_key = secret_key if secret_key is not None else detect_secret_key()

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
                realm=resolved_realm,
                secret_key=resolved_secret_key,
                method=method,
            )

            if isinstance(result, Challenge):
                return _make_challenge_response(result, resolved_realm)

            credential, receipt_obj = result
            return await handler(request_obj, credential, receipt_obj)

        wrapper.__signature__ = new_sig  # type: ignore[attr-defined]
        del wrapper.__wrapped__

        return wrapper

    return decorator
