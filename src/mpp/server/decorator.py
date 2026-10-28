"""Decorator for payment-protected framework endpoints."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

import httpx

from mpp._typing import is_dict, is_list
from mpp.server.http import PaymentRequired, Request, Response
from mpp.x402._server import X402Input
from mpp.x402._types import PAYMENT_SIGNATURE_HEADER

if TYPE_CHECKING:
    from mpp.server.compose import ComposedHandler

R = TypeVar("R")


def get_header(request: Any, name: str) -> str | None:
    """Extract an HTTP header from various request types.

    Supports Starlette/FastAPI (request.headers), Django (request.META),
    and any object with a ``headers`` dict-like attribute.
    """
    canonical = "-".join(part.capitalize() for part in name.split("-"))
    if hasattr(request, "headers"):
        return (
            request.headers.get(name)
            or request.headers.get(name.lower())
            or request.headers.get(canonical)
        )
    if hasattr(request, "META"):
        return request.META.get("HTTP_" + name.upper().replace("-", "_"))
    return None


def get_request_url(request: Any) -> str | None:
    """Return the absolute URL of a framework request, when it exposes one.

    Supports Starlette/FastAPI and Flask (``request.url``) and Django
    (``request.build_absolute_uri()``).
    """
    build_absolute_uri = getattr(request, "build_absolute_uri", None)
    if callable(build_absolute_uri):
        try:
            url = build_absolute_uri()
        except Exception:
            url = None
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            return url
    url = getattr(request, "url", None)
    if url is None:
        return None
    text = str(url)
    if not text.startswith(("http://", "https://")):
        return None
    # Starlette rebuilds the URL from the decoded path; take the path from ASGI raw_path
    # so encoded delimiters such as %2F stay distinct from the characters they encode.
    scope = getattr(request, "scope", None)
    raw_path = scope.get("raw_path") if is_dict(scope) else None
    if isinstance(raw_path, bytes) and raw_path:
        try:
            parsed = httpx.URL(text)
            query = parsed.query
            text = str(parsed.copy_with(raw_path=raw_path + (b"?" + query if query else b"")))
        except (httpx.InvalidURL, UnicodeError):
            pass
    return text


def x402_input(request: Any) -> X402Input | None:
    """Return the x402 context of a framework request, or ``None`` without a URL."""
    if request is None:
        return None
    resource_url = get_request_url(request)
    if resource_url is None:
        return None
    return X402Input(
        resource_url=resource_url,
        payment_signature=get_header(request, PAYMENT_SIGNATURE_HEADER.lower()),
        http_method=framework_scope(request).get("http_method", "GET"),
    )


def framework_scope(request: Any) -> dict[str, str]:
    """Extract route/resource/query scope from common framework request objects."""
    scope: dict[str, str] = {}

    raw_scope = getattr(request, "scope", None)
    if is_dict(raw_scope):
        route = raw_scope.get("route")
        route_path = getattr(route, "path", None)
        if isinstance(route_path, str) and route_path:
            scope["route"] = route_path
        if "route" not in scope:
            endpoint = raw_scope.get("endpoint")
            router = raw_scope.get("router")
            routes = getattr(router, "routes", None)
            if is_list(routes):
                for candidate in routes:
                    if getattr(candidate, "endpoint", None) is endpoint:
                        matched_path = getattr(candidate, "path", None)
                        if isinstance(matched_path, str) and matched_path:
                            scope["route"] = matched_path
                        break
        # ASGI raw_path keeps percent-encoding, so distinct paths keep distinct scopes.
        path = raw_scope.get("raw_path")
        path = path.decode("latin-1") if isinstance(path, bytes) else raw_scope.get("path")
        if isinstance(path, str) and path:
            scope["resource"] = path
        query_string = raw_scope.get("query_string")
        if isinstance(query_string, bytes):
            query_string = query_string.decode("latin-1")
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
        query_string = query_string.decode("latin-1")
    if isinstance(query_string, str) and query_string:
        scope.setdefault("query", query_string)

    meta = getattr(request, "META", None)
    if is_dict(meta):
        query = meta.get("QUERY_STRING")
        if isinstance(query, str) and query:
            scope.setdefault("query", query)

    method = getattr(request, "method", None)
    if not isinstance(method, str) and is_dict(raw_scope):
        method = raw_scope.get("method")
    if isinstance(method, str) and method:
        scope["http_method"] = method.upper()
    return scope


def _framework_headers(request: Any) -> list[tuple[str, str]]:
    headers = getattr(request, "headers", None)
    if headers is not None:
        items = headers.items() if hasattr(headers, "items") else headers
        return [(str(name), str(value)) for name, value in items]
    meta = getattr(request, "META", None)
    if is_dict(meta):
        return [
            (key[5:].replace("_", "-").title(), str(value))
            for key, value in meta.items()
            if key.startswith("HTTP_")
        ]
    return []


async def _framework_body(request: Any) -> bytes | None:
    try:
        body = getattr(request, "body", None)
        if body is None and callable(get_data := getattr(request, "get_data", None)):
            # Flask/werkzeug: get_data() caches the body for the endpoint.
            body = get_data()
        if callable(body):
            body = body()
        if inspect.isawaitable(body):
            body = await body
    except Exception:
        return None
    if isinstance(body, str):
        return body.encode()
    return body if isinstance(body, bytes) and body else None


async def to_request(request: Any, *, read_body: bool = True) -> Request:
    """Convert a framework request (Starlette, FastAPI, Django, Flask) to a :class:`Request`.

    With ``read_body=False`` the request body stream is left untouched.
    """
    scope = framework_scope(request)
    url = get_request_url(request)
    if url is None:
        resource = scope.get("resource", "/")
        url = f"{resource}?{scope['query']}" if scope.get("query") else resource
    return Request(
        scope.get("http_method", "GET"),
        url,
        headers=_framework_headers(request),
        body=await _framework_body(request) if read_body else None,
        route=scope.get("route"),
    )


def to_framework_response(response: Response) -> Any:
    """Convert an engine :class:`Response` to a Starlette response when Starlette is installed.

    Otherwise returns a plain dict with ``status``, ``headers`` and ``body``, marked with
    ``_mpp_challenge`` for 402 responses and ``_mpp_error`` for final errors.
    """
    body = (response.body or b"").decode()
    try:
        from starlette.responses import Response as StarletteResponse
    except ImportError:
        headers: dict[str, Any] = {}
        encoding = response.headers.encoding
        for raw_name, raw_value in response.headers.raw:
            name, value = raw_name.decode(encoding), raw_value.decode(encoding)
            key = "WWW-Authenticate" if name.lower() == "www-authenticate" else name
            if key in headers:
                previous = headers[key]
                headers[key] = (
                    [*previous, value] if isinstance(previous, list) else [previous, value]
                )
            else:
                headers[key] = value
        marker = "_mpp_challenge" if response.status == 402 else "_mpp_error"
        return {marker: True, "status": response.status, "headers": headers, "body": body}
    result = StarletteResponse(
        content=body,
        status_code=response.status,
        media_type=response.headers.get("content-type"),
    )
    for name, value in response.headers.multi_items():
        if name.lower() == "www-authenticate":
            result.headers.append(name, value)
        elif name.lower() != "content-length":
            result.headers[name] = value
    return result


def pay(
    handler: ComposedHandler,
) -> Callable[
    [Callable[..., Awaitable[R]]],
    Callable[..., Awaitable[R | Any]],
]:
    """Require payment for a framework endpoint.

    Converts the framework request to a :class:`Request`, runs the route handler, and
    returns its 402 challenge or calls the endpoint with ``(request, credential, receipt)``
    and attaches the receipt to its response. The endpoint **must** name the injected
    parameters ``credential`` and ``receipt``.

    Example:
        mpp = Mpp(methods=tempo.charge(recipient="0x..."))

        @app.get("/paid")
        @pay(mpp.charge(amount="0.50"))
        async def paid(request, credential, receipt):
            return JSONResponse({"payer": receipt.payer})
    """

    def decorator(endpoint: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R | Any]]:
        sig = inspect.signature(endpoint)
        params = [p for name, p in sig.parameters.items() if name not in ("credential", "receipt")]
        request_param_name = params[0].name if params else "request"

        @wraps(endpoint)
        async def wrapper(*args: Any, **kwargs: Any) -> R | Any:
            request_obj = args[0] if args else kwargs.get(request_param_name)
            if request_obj is None:
                raise TypeError(
                    f"Missing request argument '{request_param_name}'. "
                    "The decorated handler must receive a request object as its first argument."
                )
            # Read the body only for an offer whose ``body`` option reads the request.
            read_body = getattr(handler, "needs_request_body", True)
            result = await handler(await to_request(request_obj, read_body=read_body))
            if isinstance(result, PaymentRequired):
                return to_framework_response(result.challenge)
            if result.response is not None:
                # The payment method handled the request (a management action).
                return to_framework_response(result.response)
            response = await endpoint(request_obj, result.credential, result.receipt)
            return result.with_receipt(response)

        wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
        return wrapper

    return decorator
