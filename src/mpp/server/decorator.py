"""Decorator for payment-protected endpoints."""

from __future__ import annotations

import inspect
import json as _json
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from mpp import Challenge, Credential, Receipt
from mpp.errors import PaymentRequiredError
from mpp.events import EventDispatcher
from mpp.server._defaults import detect_realm, detect_secret_key
from mpp.server.verify import verify_or_challenge

if TYPE_CHECKING:
    from mpp.server.intent import Intent

R = TypeVar("R")

RequestParamsType = dict[str, Any] | Callable[[Any], dict[str, Any]]
BodyType = str | bytes | dict[str, Any]
BodyParamsType = BodyType | Callable[[Any], BodyType | Awaitable[BodyType]] | None


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


def framework_scope(request: Any) -> dict[str, str]:
    """Extract route/resource/query scope from common framework request objects."""
    scope: dict[str, str] = {}

    raw_scope = getattr(request, "scope", None)
    if isinstance(raw_scope, dict):
        route = raw_scope.get("route")
        route_path = getattr(route, "path", None)
        if isinstance(route_path, str) and route_path:
            scope["route"] = route_path
        if "route" not in scope:
            endpoint = raw_scope.get("endpoint")
            router = raw_scope.get("router")
            routes = getattr(router, "routes", None)
            if isinstance(routes, list):
                for candidate in routes:
                    if getattr(candidate, "endpoint", None) is endpoint:
                        matched_path = getattr(candidate, "path", None)
                        if isinstance(matched_path, str) and matched_path:
                            scope["route"] = matched_path
                        break
        path = raw_scope.get("path")
        if isinstance(path, str) and path:
            scope["resource"] = path
        query_string = raw_scope.get("query_string")
        if isinstance(query_string, bytes):
            query_string = query_string.decode()
        if isinstance(query_string, str) and query_string:
            scope["query"] = query_string

    resolver_match = getattr(request, "resolver_match", None)
    route = getattr(resolver_match, "route", None)
    if isinstance(route, str) and route:
        scope.setdefault("route", route)

    url_rule = getattr(request, "url_rule", None)
    rule = getattr(url_rule, "rule", None)
    if isinstance(rule, str) and rule:
        scope.setdefault("route", rule)

    for attr in ("route", "path_template"):
        value = getattr(request, attr, None)
        if isinstance(value, str) and value:
            scope.setdefault("route", value)

    path = getattr(request, "path", None)
    if isinstance(path, str) and path:
        scope.setdefault("resource", path)

    url = getattr(request, "url", None)
    url_path = getattr(url, "path", None)
    if isinstance(url_path, str) and url_path:
        scope.setdefault("resource", url_path)
    url_query = getattr(url, "query", None)
    if isinstance(url_query, str) and url_query:
        scope.setdefault("query", url_query)

    query_string = getattr(request, "query_string", None)
    if isinstance(query_string, bytes):
        query_string = query_string.decode()
    if isinstance(query_string, str) and query_string:
        scope.setdefault("query", query_string)

    meta = getattr(request, "META", None)
    if isinstance(meta, dict):
        query = meta.get("QUERY_STRING")
        if isinstance(query, str) and query:
            scope.setdefault("query", query)

    return scope


def bind_framework_scope(request_params: dict[str, Any], request_obj: Any) -> dict[str, Any]:
    """Return request params with automatic framework scope when available."""
    if "_mppx_scope" in request_params:
        return request_params
    scope = framework_scope(request_obj)
    if not scope:
        return request_params
    return {**request_params, "_mppx_scope": scope}


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


async def resolve_body_param(body: BodyParamsType, request_obj: Any) -> BodyType | None:
    """Resolve a static or request-derived body value for digest verification."""
    if body is None:
        return None
    if callable(body):
        value = body(request_obj)
        if inspect.isawaitable(value):
            value = await value
        return value
    return body


def wrap_payment_handler(
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

    return wrapper


def pay(
    *,
    intent: Intent,
    request: RequestParamsType,
    realm: str | None = None,
    secret_key: str | None = None,
    method: str | None = None,
    description: str | None = None,
    body: BodyParamsType = None,
    events: EventDispatcher | None = None,
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
            Required unless `MPP_SECRET_KEY` is set.
        method: The payment method name (defaults to "tempo").
        description: Human-readable description of what the payment is for.
        body: Optional static body bytes/string/dict or callback receiving the
            request object. The resolved value is bound into issued challenges
            via digest and used to verify paid retries.

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
            request_params = bind_framework_scope(request_params, request_obj)

            return await verify_or_challenge(
                authorization=authorization,
                intent=intent,
                request=request_params,
                realm=resolved_realm,
                secret_key=resolved_secret_key,
                method=method,
                description=description,
                body=await resolve_body_param(body, request_obj),
                events=events,
            )

        return wrap_payment_handler(handler, _verify, lambda: resolved_realm)

    return decorator
