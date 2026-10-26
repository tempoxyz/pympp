"""OpenAPI payment discovery documents."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from mpp import Receipt
from mpp.discovery import (
    HandlerRoute,
    IntentRoute,
    ProxyRoute,
    ValidationIssue,
    generate,
    generate_proxy,
    validate,
)
from mpp.methods import Method
from mpp.methods.tempo import server as tempo
from mpp.server import Mpp, ServerMethod, VerifyContext, compose
from tests import challenges, http_request

RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
OUSD = "0x20c0000000000000000000006a37DA5C996874BE"


class SessionInput(BaseModel):
    amount: str | None = None
    recipient: str


class _Payload(BaseModel):
    pass


async def _verify(context: VerifyContext) -> Receipt:
    del context
    return Receipt.success("ref")


def _session() -> ServerMethod:
    return ServerMethod(
        method=Method(
            name="tempo", intent="session", request_model=SessionInput, payload_model=_Payload
        ),
        verify=_verify,
        defaults={"recipient": RECIPIENT},
    )


def _mpp(*methods: Any) -> Mpp:
    return Mpp(methods=list(methods), realm="api.example.com", secret_key="s" * 32)


def _offers(document: dict[str, Any], path: str, method: str) -> list[dict[str, Any]]:
    return document["paths"][path][method]["x-payment-info"]["offers"]


async def test_handler_route_matches_runtime_challenge() -> None:
    mpp = _mpp(tempo.charge(recipient=RECIPIENT, currencies=[OUSD]))
    handler = mpp.tempo.charge(amount="0.5", description="Search")
    document = generate(
        mpp,
        [HandlerRoute(method="POST", path="/search", handler=handler, summary="Search")],
        service_info={"categories": ["search"], "docs": {"llms": "/llms.txt"}},
    )

    operation = document["paths"]["/search"]["post"]
    assert document["openapi"] == "3.1.0"
    assert document["info"] == {"title": "api.example.com", "version": "1.0.0"}
    assert document["x-service-info"] == {"categories": ["search"], "docs": {"llms": "/llms.txt"}}
    assert list(operation["responses"]) == ["402", "200"]
    assert operation["summary"] == "Search"
    [offer] = operation["x-payment-info"]["offers"]
    assert offer == {
        "amount": "500000",
        "currency": OUSD,
        "description": "Search",
        "intent": "charge",
        "method": "tempo",
        "recipient": RECIPIENT,
    }

    [issued] = challenges(await handler(http_request(method="POST")))
    wire = {
        key: value
        for key, value in issued.request.items()
        if key not in ("_mppx_scope", "methodDetails")
    }
    assert {key: offer[key] for key in wire} == wire
    assert validate(document) == [
        ValidationIssue(
            message="Operation with x-payment-info has no requestBody",
            path="paths./search.post",
            severity="warning",
        )
    ]


def test_composed_handler_lists_offers_in_order() -> None:
    mpp = _mpp(tempo.charge(recipient=RECIPIENT, currencies=[OUSD]), _session())
    handler = compose(mpp.tempo.session(amount="7"), mpp.tempo.charge(amount="1"))
    document = generate(mpp, [HandlerRoute(method="get", path="/r", handler=handler)])

    offers = _offers(document, "/r", "get")
    assert [(offer["intent"], offer["amount"]) for offer in offers] == [
        ("session", "7"),
        ("charge", "1000000"),
    ]
    assert validate(document) == []


def test_intent_route_and_null_amount() -> None:
    mpp = _mpp(tempo.charge(recipient=RECIPIENT, currencies=[OUSD]), _session())
    document = generate(
        mpp,
        [
            IntentRoute(
                method="GET",
                path="/a",
                intent="tempo/charge",
                options={"amount": "2", "description": "Two"},
            ),
            IntentRoute(method="GET", path="/s", intent="session"),
        ],
        title="API",
        version="2.0.0",
    )

    assert document["info"] == {"title": "API", "version": "2.0.0"}
    assert _offers(document, "/a", "get")[0]["description"] == "Two"
    assert _offers(document, "/s", "get") == [
        {"amount": None, "intent": "session", "method": "tempo", "recipient": RECIPIENT}
    ]
    assert validate(document) == []
    with pytest.raises(ValueError, match='Unknown intent "stripe/charge"'):
        generate(mpp, [IntentRoute(method="get", path="/x", intent="stripe/charge")])


def test_generate_proxy() -> None:
    document = generate_proxy(
        [
            ProxyRoute(
                method="POST",
                path="/v1/chat",
                payment={"amount": "10", "intent": "charge", "method": "tempo", "x": 1},
                request_body={"content": {}},
            ),
            ProxyRoute(method="GET", path="/v1/models"),
        ],
        base_path="openai/",
    )

    assert document["info"] == {"title": "API Proxy", "version": "1.0.0"}
    paid = document["paths"]["/openai/v1/chat"]["post"]
    assert paid["x-payment-info"] == {
        "offers": [{"amount": "10", "intent": "charge", "method": "tempo", "x": 1}]
    }
    assert paid["requestBody"] == {"content": {}}
    free = document["paths"]["/openai/v1/models"]["get"]
    assert free == {"responses": {"200": {"description": "Successful response"}}}
    assert validate(document) == []


@pytest.mark.parametrize(
    ("document", "path"),
    [
        ({"openapi": "3.1.0"}, "info"),
        ({"openapi": "3.1.0", "info": {"title": "t", "version": None}}, "info.version"),
        (
            {
                "openapi": "3.1.0",
                "info": {"title": "t", "version": "1"},
                "x-service-info": {"docs": {"apiReference": "not a uri"}},
            },
            "x-service-info.docs.apiReference",
        ),
        (
            {
                "openapi": "3.1.0",
                "info": {"title": "t", "version": "1"},
                "paths": {"/x": {"get": {"x-payment-info": {"amount": "1.5"}}}},
            },
            "paths./x.get.x-payment-info.amount",
        ),
        (
            {
                "openapi": "3.1.0",
                "info": {"title": "t", "version": "1"},
                "paths": {
                    "/x": {"get": {"x-payment-info": {"amount": "1", "offers": [{"amount": "1"}]}}}
                },
            },
            "paths./x.get.x-payment-info",
        ),
    ],
)
def test_validate_structural_errors(document: dict[str, Any], path: str) -> None:
    [issue] = validate(document)
    assert (issue.path, issue.severity) == (path, "error")


def test_validate_semantic_errors() -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/x": {
                "put": {"x-payment-info": {"amount": "1"}, "responses": {"200": {}}},
                "x-custom": {"x-payment-info": {"amount": "-1"}},
                "get": {"x-payment-info": {}, "responses": {}},
            }
        },
    }

    assert [(issue.path, issue.severity) for issue in validate(document)] == [
        ("paths./x.put.responses", "error"),
        ("paths./x.put", "warning"),
        ("paths./x.x-custom.x-payment-info.amount", "error"),
        ("paths./x.get.responses", "error"),
    ]
