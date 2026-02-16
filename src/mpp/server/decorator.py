"""Decorator for payment-protected endpoints."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any

import json as _json

from mpp import Challenge, Credential, Receipt
from mpp.errors import PaymentRequiredError
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.intent import Intent

RequestParamsType = dict[str, Any] | Callable[[Any], dict[str, Any]]

def get_authorization(request: Any) -> str | None:
    """Extract Authorization header from various request types.

    Supports Starlette/FastAPI (request.headers), Django (request.META),
    and any object with a ``headers`` dict-like attribute.
    """
    if hasattr(request, "headers"):
        return request.headers.get("authorization") or request.headers.get("Authorization")
    if hasattr(request, "META"):
        return request.META.get("HTTP_AUTHORIZATION")
    return None

def make_challenge_response(challenge: Challenge, realm: str) -> Any:
    """Build a 402 response for a payment challenge with RFC 9457 problem details body.

    Returns a Starlette ``Response`` when starlette is installed,
    otherwise a plain dict with ``_mpp_challenge``, ``status``, and ``headers``.
    """
    error = PaymentRequiredError(realm=realm, description=challenge.description)
    body = _json.dumps(error.to_problem_details(challenge.id))
    headers = {
        "WWW-Authenticate": challenge.to_www_authenticate(realm),
        "Cache-Control": "no-store",
        "Content-Type": "application/problem+json",
    }
    try:
        from starlette.responses import Response

        return Response(
            content=body,
            status_code=402,
            headers=headers,
            media_type="application/problem+json",
        )
    except ImportError:
        return {
            "_mpp_challenge": True,
            "status": 402,
            "headers": headers,
            "body": body,
        }

def wrap_payment_handler[R](
    handler: Callable[..., Awaitable[R]],
    verify_fn: Callable[[str | None, Any], Awaitable[Challenge | tuple[Credential, Receipt]]],
    realm_fn: Callable[[], str],
) -> Callable[..., Awaitable[R | Any]]:
    """Wrap a handler with the payment challenge/verify flow.

    Shared logic used by both the standalone ``pay()`` decorator and
    ``Mpp.pay()``.  Strips ``credential`` and ``receipt`` from the handler
    signature (for FastAPI compatibility) and injects them after verification.

    The handler **must** use parameter names ``credential`` and ``receipt``
    for the injected payment objects.

    Args:
        handler: The async endpoint handler to wrap.
        verify_fn: Called with ``(authorization, request_obj)``; must return
            a ``Challenge`` or ``(Credential, Receipt)`` tuple.
        realm_fn: Returns the realm string for challenge responses.
    """
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

        if request_obj is None:
            raise TypeError(
                f"Missing request argument '{request_param_name}'. "
                "The decorated handler must receive a request object as its first argument."
            )

        authorization = get_authorization(request_obj)

        result = await verify_fn(authorization, request_obj)

        if isinstance(result, Challenge):
            return make_challenge_response(result, realm_fn())

        credential, receipt = result
        return await handler(request_obj, credential, receipt)

    wrapper.__signature__ = new_sig  # type: ignore[attr-defined]
    del wrapper.__wrapped__

    return wrapper

def pay[R](
    *,
    intent: Intent,
    request: RequestParamsType,
    realm: str | None = None,
    secret_key: str | None = None,
    method: str | None = None,
    description: str | None = None,
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

    The handler **must** use parameter names ``credential`` and ``receipt``
    for the injected payment objects.

    Args:
        intent: The payment intent to verify against.
        request: Payment request params - either a static dict or a callable
            that takes the request and returns the params.
        realm: The realm for the WWW-Authenticate header.
            Auto-detected from environment if omitted.
        secret_key: Server secret for HMAC-bound challenge IDs.
            Auto-generated and persisted to .env if omitted.
        method: The payment method name (defaults to "tempo").
        description: Human-readable description of what the payment is for.

    Example:
        @app.get("/resource")
        @pay(
            intent=ChargeIntent(),
            request={"amount": "1000"},
        )
        async def get_resource(request: Request, credential: Credential, receipt: Receipt):
            return {"data": "paid content", "payer": credential.source}
    """

    resolved_realm = realm if realm is not None else detect_realm()
    resolved_secret_key = secret_key if secret_key is not None else detect_secret_key()

    def decorator(
        handler: Callable[[Any, Credential, Receipt], Awaitable[R]],
    ) -> Callable[[Any], Awaitable[R | Any]]:
        async def _verify(
            authorization: str | None, request_obj: Any
        ) -> Challenge | tuple[Credential, Receipt]:
            if callable(request):
                request_params = request(request_obj)
            else:
                request_params = request

            return await verify_or_challenge(
                authorization=authorization,
                intent=intent,
                request=request_params,
                realm=resolved_realm,
                secret_key=resolved_secret_key,
                method=method,
                description=description,
            )

        return wrap_payment_handler(handler, _verify, lambda: resolved_realm)

    return decorator
