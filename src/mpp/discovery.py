"""OpenAPI payment discovery: ``x-service-info`` and ``x-payment-info`` documents.

Generate an OpenAPI 3.1 document describing a server's paid routes and validate
discovery documents. Discovery is advisory: runtime 402 challenges remain authoritative.

Example:
    from mpp import discovery

    search = discovery.HandlerRoute(
        method="POST", path="/search", handler=mpp.tempo.charge(amount="0.01")
    )
    document = discovery.generate(
        mpp,
        [search],
        service_info={"categories": ["search"]},
    )
    # Serve json.dumps(document) at GET /openapi.json
"""

from __future__ import annotations

import inspect
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)
from pydantic import ValidationError as _PydanticValidationError
from pydantic_core import PydanticCustomError

from mpp.server.compose import ROUTE_OPTION_KEYS, ComposedHandler
from mpp.server.method import RequestContext, ServerMethod

if TYPE_CHECKING:
    from mpp.server.mpp import Mpp

__all__ = [
    "HandlerRoute",
    "IntentRoute",
    "ProxyRoute",
    "ValidationIssue",
    "generate",
    "generate_proxy",
    "validate",
]


def _not_null(value: object) -> object:
    # An optional field may be absent but not null.
    if value is None:
        raise PydanticCustomError("not_null", "Expected a value, received null")
    return value


_NotNull = BeforeValidator(_not_null)
_OptionalString = Annotated[str | None, _NotNull]
_Amount = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]*)$")]
# ECMAScript whitespace, spelled out so the pattern matches the same characters everywhere.
_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_UriOrPath = Annotated[
    str | None,
    _NotNull,
    StringConstraints(
        pattern=f"^([a-zA-Z][a-zA-Z0-9+.-]*://[^{_WHITESPACE}]+|/[^{_WHITESPACE}]*)$"
    ),
]
_FLAT_FIELDS = frozenset({"amount", "currency", "description", "intent", "method"})


class _Loose(BaseModel):
    model_config = ConfigDict(extra="allow")


class _PaymentOffer(_Loose):
    amount: _Amount | None = None
    currency: _OptionalString = None
    description: _OptionalString = None
    intent: _OptionalString = None
    method: _OptionalString = None


class _PaymentInfo(_PaymentOffer):
    offers: Annotated[list[_PaymentOffer] | None, _NotNull, Field(min_length=1)] = None

    @model_validator(mode="after")
    def _not_mixed(self) -> _PaymentInfo:
        if self.offers is not None and self.model_fields_set & _FLAT_FIELDS:
            raise PydanticCustomError(
                "payment_info_mixed", "Cannot mix offers with flat payment info fields"
            )
        return self


class _ServiceDocs(_Loose):
    api_reference: _UriOrPath = Field(default=None, alias="apiReference")
    homepage: _UriOrPath = None
    llms: _UriOrPath = None


class _ServiceInfo(_Loose):
    categories: Annotated[list[str] | None, _NotNull] = None
    docs: Annotated[_ServiceDocs | None, _NotNull] = None


class _Operation(_Loose):
    payment_info: Annotated[_PaymentInfo | None, _NotNull] = Field(
        default=None, alias="x-payment-info"
    )
    responses: Annotated[dict[str, Any] | None, _NotNull] = None
    summary: _OptionalString = None


_OptionalOperation = Annotated[_Operation | None, _NotNull]


class _PathItem(_Loose):
    delete: _OptionalOperation = None
    get: _OptionalOperation = None
    head: _OptionalOperation = None
    options: _OptionalOperation = None
    patch: _OptionalOperation = None
    post: _OptionalOperation = None
    put: _OptionalOperation = None
    trace: _OptionalOperation = None


class _Info(_Loose):
    title: str
    version: str


class _DiscoveryDocument(_Loose):
    openapi: str
    info: _Info
    service_info: Annotated[_ServiceInfo | None, _NotNull] = Field(
        default=None, alias="x-service-info"
    )
    paths: Annotated[dict[str, _PathItem] | None, _NotNull] = None


@dataclass(frozen=True, slots=True, kw_only=True)
class HandlerRoute:
    """A route whose payment offers come from a configured handler.

    Attributes:
        method: HTTP method (any case).
        path: OpenAPI path, such as ``"/api/search"``.
        handler: The route's handler, such as ``mpp.tempo.charge(amount="1")``.
        request_body: OpenAPI ``requestBody`` object.
        summary: Operation summary.
    """

    method: str
    path: str
    handler: ComposedHandler
    request_body: Mapping[str, Any] | None = None
    summary: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class IntentRoute:
    """A route described by a method intent and its route options.

    ``intent`` is a ``"name/intent"`` key, or an intent only one configured method
    serves. ``options`` are route options; ``description`` becomes the offer description.
    """

    method: str
    path: str
    intent: str
    options: Mapping[str, Any] = field(default_factory=dict)
    request_body: Mapping[str, Any] | None = None
    summary: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ProxyRoute:
    """A route with precomputed ``x-payment-info`` (``None`` for a free route)."""

    method: str
    path: str
    payment: Mapping[str, Any] | None = None
    request_body: Mapping[str, Any] | None = None
    summary: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidationIssue:
    """A discovery document problem at a dotted path (``"(root)"`` for the document)."""

    message: str
    path: str
    severity: Literal["error", "warning"]


def generate(
    mpp: Mpp,
    routes: Iterable[HandlerRoute | IntentRoute],
    *,
    title: str | None = None,
    version: str | None = None,
    service_info: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate an OpenAPI 3.1.0 discovery document for a server's routes.

    The title defaults to the server realm and the version to ``"1.0.0"``.
    ``service_info`` becomes ``x-service-info``, such as
    ``{"categories": [...], "docs": {"llms": "/llms.txt"}}``.

    Raises:
        ValueError: When a route has no payment offers or names an unknown intent.
    """
    by_key: dict[str, ServerMethod] = {}
    intent_count: dict[str, int] = {}
    for method in mpp.methods:
        by_key.setdefault(method.key, method)
        intent_count[method.intent] = intent_count.get(method.intent, 0) + 1
    for method in mpp.methods:
        if intent_count[method.intent] == 1:
            by_key[method.intent] = method

    return _document(
        title=mpp.realm if title is None else title,
        version="1.0.0" if version is None else version,
        routes=[_resolve(route, by_key) for route in routes],
        service_info=service_info,
    )


def generate_proxy(
    routes: Iterable[ProxyRoute],
    *,
    base_path: str | None = None,
    title: str | None = None,
    version: str | None = None,
    service_info: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate an OpenAPI 3.1.0 discovery document for a proxy.

    Route paths are prefixed with ``base_path``.
    """
    prefix = ""
    if base_path:
        prefix = (base_path if base_path.startswith("/") else f"/{base_path}").removesuffix("/")
    return _document(
        title="API Proxy" if title is None else title,
        version="1.0.0" if version is None else version,
        routes=[
            ProxyRoute(
                method=route.method,
                path=prefix + route.path,
                payment=route.payment,
                request_body=route.request_body,
                summary=route.summary,
            )
            for route in routes
        ],
        service_info=service_info,
    )


def validate(document: Any) -> list[ValidationIssue]:
    """Validate a discovery document structurally and semantically.

    Structural errors are reported alone. Otherwise every operation with
    ``x-payment-info`` must declare a ``402`` response (error), and ``POST``, ``PUT`` and
    ``PATCH`` operations should declare a ``requestBody`` (warning).
    """
    try:
        _DiscoveryDocument.model_validate(document)
    except _PydanticValidationError as error:
        return _issues(error, None)

    issues: list[ValidationIssue] = []
    paths = document.get("paths")
    if not paths:
        return issues
    for path_key, path_item in paths.items():
        for method, operation in path_item.items():
            if not isinstance(operation, Mapping):
                continue
            operation_path = f"paths.{path_key}.{method}"
            payment_info = operation.get("x-payment-info")
            if not _truthy(payment_info):
                continue
            try:
                _PaymentInfo.model_validate(payment_info)
            except _PydanticValidationError as error:
                issues.extend(_issues(error, f"{operation_path}.x-payment-info"))
                continue
            responses = operation.get("responses")
            if not isinstance(responses, Mapping) or "402" not in responses:
                issues.append(
                    ValidationIssue(
                        message="Operation with x-payment-info MUST have a 402 response",
                        path=f"{operation_path}.responses",
                        severity="error",
                    )
                )
            if not _truthy(operation.get("requestBody")) and method.upper() in (
                "POST",
                "PUT",
                "PATCH",
            ):
                issues.append(
                    ValidationIssue(
                        message="Operation with x-payment-info has no requestBody",
                        path=operation_path,
                        severity="warning",
                    )
                )
    return issues


def _resolve(route: HandlerRoute | IntentRoute, by_key: Mapping[str, ServerMethod]) -> ProxyRoute:
    label = f"{route.method.upper()} {route.path}"
    if isinstance(route, HandlerRoute):
        if not isinstance(route.handler, ComposedHandler):
            raise ValueError(f"Route {label} is missing discovery metadata")
        payment: dict[str, Any] = {
            "offers": [
                _payment_offer(offer.method, offer.options, offer.options.get("description"))
                for offer in route.handler._offers
            ]
        }
    else:
        method = by_key.get(route.intent)
        if method is None:
            raise ValueError(
                f'Unknown intent "{route.intent}" for route {label}. Available: {", ".join(by_key)}'
            )
        options = dict(route.options)
        payment = _payment_offer(method, options, options.pop("description", None))
    return ProxyRoute(
        method=route.method,
        path=route.path,
        payment=payment,
        request_body=route.request_body,
        summary=route.summary,
    )


def _payment_offer(
    method: ServerMethod, options: Mapping[str, Any], description: object
) -> dict[str, Any]:
    """Describe one offer by the wire request its route options produce."""
    input = {
        **(method.defaults or {}),
        **{
            key: value
            for key, value in options.items()
            if key not in ROUTE_OPTION_KEYS and value is not None
        },
    }
    if method.resolve_request is not None:
        resolved = method.resolve_request(RequestContext(request=input))
        if inspect.isawaitable(resolved):
            close = getattr(resolved, "close", None)
            if close is not None:
                close()
            raise TypeError(f"{method.key} resolve_request must be synchronous for discovery")
        input = resolved
    request = method.method.normalize_request(input)

    details = request.get("methodDetails")
    details = details if isinstance(details, Mapping) else {}
    amount = _string(request.get("amount"))
    if amount is None:
        amount = _string(details.get("amount"))
    currency = _string(request.get("currency"))
    if currency is None:
        currency = _string(details.get("currency"))
    text = _string(description)
    if text is None:
        text = _string(request.get("description"))

    offer: dict[str, Any] = {"amount": amount}
    if currency:
        offer["currency"] = currency
    if text:
        offer["description"] = text
    offer["intent"] = method.intent
    offer["method"] = method.name
    for key, value in request.items():
        if key not in ("amount", "currency", "description", "methodDetails"):
            offer[key] = value
    return offer


def _document(
    *,
    title: str,
    version: str,
    routes: Iterable[ProxyRoute],
    service_info: Mapping[str, Any] | None,
) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for route in routes:
        responses: dict[str, Any] = {}
        if route.payment is not None:
            responses["402"] = {"description": "Payment Required"}
        responses["200"] = {"description": "Successful response"}
        operation: dict[str, Any] = {"responses": responses}
        if route.payment is not None:
            operation["x-payment-info"] = _normalize_payment_info(route.payment)
        if route.summary:
            operation["summary"] = route.summary
        if route.request_body is not None:
            operation["requestBody"] = deepcopy(dict(route.request_body))
        paths.setdefault(route.path, {})[route.method.lower()] = operation

    document: dict[str, Any] = {
        "info": {"title": title, "version": version},
        "openapi": "3.1.0",
        "paths": paths,
    }
    if service_info is not None:
        document["x-service-info"] = deepcopy(dict(service_info))
    return document


def _normalize_payment_info(payment: Mapping[str, Any]) -> dict[str, Any]:
    """Validate ``x-payment-info`` and return its ``{"offers": [...]}`` form.

    Raises:
        pydantic.ValidationError: When the payment info is invalid.
    """
    _PaymentInfo.model_validate(payment)
    payment = deepcopy(dict(payment))
    if "offers" in payment:
        return {"offers": payment["offers"]}
    return {"offers": [payment]}


def _issues(error: _PydanticValidationError, prefix: str | None) -> list[ValidationIssue]:
    issues = []
    for detail in error.errors():
        parts = [str(part) for part in detail["loc"]]
        path = ".".join([prefix, *parts] if prefix is not None else parts) or "(root)"
        issues.append(ValidationIssue(message=detail["msg"], path=path, severity="error"))
    return issues


def _truthy(value: object) -> bool:
    # JSON truthiness: empty objects and arrays count as present.
    return value is not None and value is not False and value != 0 and value != ""


def _string(value: object) -> str | None:
    return value if isinstance(value, str) else None
