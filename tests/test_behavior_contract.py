"""Server and client payment contract the engine refactor must preserve (0.15 API).

Fast, network-free tests over real HTTP plumbing: a Starlette app served
through `httpx.ASGITransport`, protected with `@server.pay` /
`server.compose`, and paid by `mpp.client.PaymentTransport` with an
in-process payment method. They pin observable behaviour (status codes, problem
types, headers, event names and payload keys, challenge bindings, offer order)
rather than internals, so they can be ported to the new API unchanged in intent.

Behaviour already pinned elsewhere is not repeated here:
- realm and secret detection: tests/test_mpp_create.py
- can_offer and on_payment_success hooks: tests/test_method_hooks.py
- store wiring and replay stores: tests/test_stores_wiring.py, tests/test_store.py,
  tests/test_store_expiry.py, tests/test_replay_store_ttl.py
- client retry limits, redirects and origin allowlists: tests/test_client.py
- HTTP verb and nonce binding: tests/test_request_binding.py
- challenge expiry and HMAC binding: tests/test_server.py, tests/test_challenge_id.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any, cast

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp.client import PaymentTransport
from mpp.errors import (
    CredentialReplayedError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentMethodUnsupportedError,
    VerificationFailedError,
)
from mpp.server import ComposedHandler, Intent, Mpp, VerifiableIntent, compose

REALM = "contract.example.com"
SECRET = "contract-secret"
PROBLEMS = "https://paymentauth.org/problems"

SERVER_EVENT_KEYS = {
    "challenge.created": {"challenge", "intent", "method", "request"},
    "payment.success": {"challenge", "credential", "intent", "method", "receipt", "request"},
    "payment.failed": {"challenge", "credential", "error", "intent", "method", "request"},
}
CLIENT_EVENT_KEYS = {
    "challenge.received": {"challenge", "challenges", "method", "request", "response"},
    "credential.created": {
        "challenge",
        "challenges",
        "credential",
        "method",
        "request",
        "response",
    },
    "payment.response": {"challenge", "credential", "method", "request", "response"},
}

# Tokens the in-process intent maps to outcomes.
REJECTIONS: dict[str, Exception] = {
    "invalid-payload": InvalidPayloadError("payload is not understood"),
    "unsupported": PaymentMethodUnsupportedError("contract/other"),
    "verification-failed": VerificationFailedError("payment was not found"),
    "replayed": CredentialReplayedError(),
}


class ContractIntent:
    """Charge intent that settles any token not listed in REJECTIONS."""

    name = "charge"

    def __init__(self) -> None:
        self._store = None
        self.settled: list[str] = []

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        del request
        token = str(credential.payload.get("token"))
        if token in REJECTIONS:
            raise REJECTIONS[token]
        self.settled.append(token)
        return Receipt.success(f"ref-{token}", method=credential.challenge.method)


class ContractMethod:
    """A payment method usable on both the server and the client."""

    def __init__(self, name: str = "contract", token: str = "ok", decimals: int = 2) -> None:
        self.name = name
        self.currency = f"{name}-usd"
        self.recipient = f"{name}-merchant"
        self.decimals = decimals
        self.token = token
        self.intent = ContractIntent()
        self.intents: Mapping[str, Intent | VerifiableIntent] = {"charge": self.intent}

    async def create_credential(self, challenge: Challenge) -> Credential:
        return Credential(challenge=challenge.to_echo(), payload={"token": self.token})


def make_server(*methods: ContractMethod, **options: Any) -> Mpp:
    if len(methods) == 1:
        return Mpp.create(method=methods[0], realm=REALM, secret_key=SECRET, **options)
    return Mpp.create(methods=list(methods), realm=REALM, secret_key=SECRET, **options)


def record(target: Any) -> list[tuple[str, dict[str, Any]]]:
    """Record every event a server or client emits, in order."""
    events: list[tuple[str, dict[str, Any]]] = []
    target.on("*", lambda event: events.append((str(event.name), dict(event.payload))))
    return events


def paid_endpoint(decorate: Callable[..., Any]) -> Any:
    @decorate
    async def endpoint(request: Request, credential: Credential, receipt: Receipt) -> Any:
        return JSONResponse(
            {"payer": credential.payload.get("token"), "reference": receipt.reference},
            headers={"Payment-Receipt": receipt.to_payment_receipt()},
        )

    return endpoint


def app(routes: Mapping[str, Callable[..., Any]], methods: list[str] | None = None) -> Starlette:
    return Starlette(
        routes=[
            Route(path, paid_endpoint(decorate), methods=methods or ["GET", "POST"])
            for path, decorate in routes.items()
        ]
    )


def http(application: Starlette) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://testserver"
    )


def paying(
    application: Starlette, *methods: ContractMethod, **options: Any
) -> tuple[httpx.AsyncClient, PaymentTransport]:
    transport = PaymentTransport(
        methods=list(methods), inner=httpx.ASGITransport(app=application), **options
    )
    return httpx.AsyncClient(transport=transport, base_url="http://testserver"), transport


def offers(response: httpx.Response) -> list[Challenge]:
    return [
        Challenge.from_www_authenticate(value)
        for value in response.headers.get_list("www-authenticate")
    ]


def authorization(challenge: Challenge, token: str = "ok") -> dict[str, str]:
    credential = Credential(challenge=challenge.to_echo(), payload={"token": token})
    return {"Authorization": credential.to_authorization()}


def failures(events: list[tuple[str, dict[str, Any]]]) -> list[Exception]:
    return [payload["error"] for name, payload in events if name == "payment.failed"]


class TestRoundTrip:
    async def test_client_pays_and_both_sides_emit_events_in_order(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        server_events = record(server)
        client, transport = paying(app({"/paid": server.pay(amount="1.25")}), ContractMethod())
        client_events = record(transport)

        async with client:
            response = await client.get("/paid")

        assert response.status_code == 200
        assert response.json() == {"payer": "ok", "reference": "ref-ok"}
        receipt = Receipt.from_payment_receipt(response.headers["payment-receipt"])
        assert (receipt.status, receipt.reference, receipt.method) == (
            "success",
            "ref-ok",
            "contract",
        )
        assert method.intent.settled == ["ok"]

        assert [name for name, _ in server_events] == ["challenge.created", "payment.success"]
        assert [name for name, _ in client_events] == [
            "challenge.received",
            "credential.created",
            "payment.response",
        ]
        for name, payload in server_events:
            assert payload.keys() == SERVER_EVENT_KEYS[name], name
        for name, payload in client_events:
            assert payload.keys() == CLIENT_EVENT_KEYS[name], name

        created, success = (payload for _, payload in server_events)
        assert created["method"] == success["method"] == "contract"
        assert created["intent"] == success["intent"] == "charge"
        assert created["request"]["amount"] == "125"
        # The success event carries the challenge the client paid.
        assert success["challenge"].id == created["challenge"].id
        assert success["receipt"].reference == "ref-ok"
        assert client_events[2][1]["response"].status_code == 200

    async def test_unpaid_response_shape(self) -> None:
        server = make_server(ContractMethod())
        async with http(app({"/paid": server.pay(amount="1", description="One item")})) as c:
            response = await c.get("/paid")

        assert response.status_code == 402
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"].startswith("application/problem+json")
        [challenge] = offers(response)
        assert challenge.realm == REALM
        assert (challenge.method, challenge.intent) == ("contract", "charge")
        assert challenge.description == "One item"
        assert challenge.expires is not None
        assert challenge.request["amount"] == "100"
        assert challenge.request["currency"] == "contract-usd"
        assert challenge.request["recipient"] == "contract-merchant"
        problem = response.json()
        assert problem["type"] == f"{PROBLEMS}/payment-required"
        assert problem["status"] == 402
        assert problem["challengeId"] == challenge.id

    async def test_each_unpaid_request_gets_a_distinct_challenge(self) -> None:
        server = make_server(ContractMethod())
        async with http(app({"/paid": server.pay(amount="1")})) as c:
            first, second = offers(await c.get("/paid")), offers(await c.get("/paid"))
        assert first[0].id != second[0].id
        assert first[0].request == second[0].request


class TestChallengeBinding:
    """A credential pays only for the route, path, query, method and body it was issued for."""

    @pytest.mark.parametrize(
        ("verb", "url"),
        [
            ("GET", "/items/1?page=2"),
            ("GET", "/items/2?page=1"),
            ("GET", "/other/1?page=1"),
            ("POST", "/items/1?page=1"),
        ],
        ids=["query", "path", "route", "method"],
    )
    async def test_credential_is_bound_to_its_request(self, verb: str, url: str) -> None:
        method = ContractMethod()
        server = make_server(method)
        events = record(server)
        decorate = server.pay(amount="1")
        application = app({"/items/{id}": decorate, "/other/{id}": decorate})
        async with http(application) as c:
            [issued] = offers(await c.get("/items/1?page=1"))
            assert issued.request["_mppx_scope"] == {
                "http_method": "GET",
                "query": "page=1",
                "resource": "/items/1",
                "route": "/items/{id}",
            }
            refused = await c.request(verb, url, headers=authorization(issued))
            assert refused.status_code == 402
            assert offers(refused)[0].id != issued.id
            assert method.intent.settled == []
            [error] = failures(events)
            assert isinstance(error, InvalidChallengeError)

            accepted = await c.get("/items/1?page=1", headers=authorization(issued))
            assert accepted.status_code == 200
        assert method.intent.settled == ["ok"]

    async def test_async_body_callback_binds_the_body_digest(self) -> None:
        method = ContractMethod()
        server = make_server(method)

        async def body(request: Request) -> bytes:
            return await request.body()

        async with http(app({"/paid": server.pay(amount="1", body=body)})) as c:
            [issued] = offers(await c.post("/paid", content=b'{"q": 1}'))
            assert issued.digest is not None and issued.digest.startswith("sha-256=")
            tampered = await c.post("/paid", content=b'{"q": 2}', headers=authorization(issued))
            assert tampered.status_code == 402
            assert method.intent.settled == []
            paid = await c.post("/paid", content=b'{"q": 1}', headers=authorization(issued))
            assert paid.status_code == 200
        assert method.intent.settled == ["ok"]

    async def test_body_bound_route_refuses_credential_without_digest(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        events = record(server)
        issued = await server.charge(None, "1")
        assert isinstance(issued, Challenge)
        assert issued.digest is None

        result = await server.charge(authorization(issued)["Authorization"], "1", body=b"{}")
        assert isinstance(result, Challenge)
        assert result.digest is not None
        [error] = failures(events)
        assert isinstance(error, InvalidChallengeError)
        assert "missing body digest" in str(error)
        assert method.intent.settled == []

    async def test_amount_is_bound(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        cheap = await server.charge(None, "0.01")
        assert isinstance(cheap, Challenge)
        result = await server.charge(authorization(cheap)["Authorization"], "1")
        assert isinstance(result, Challenge)
        assert result.request["amount"] == "100"
        assert method.intent.settled == []

    async def test_credential_from_another_server_secret_is_refused(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        events = record(server)
        other = Mpp.create(method=ContractMethod(), realm=REALM, secret_key="other-secret")
        foreign = await other.charge(None, "1")
        assert isinstance(foreign, Challenge)
        result = await server.charge(authorization(foreign)["Authorization"], "1")
        assert isinstance(result, Challenge)
        assert isinstance(failures(events)[0], InvalidChallengeError)
        assert method.intent.settled == []


class TestFailureResponses:
    """Status codes, problem types and challenges for rejected credentials over HTTP."""

    async def _paid_route(self) -> tuple[Mpp, ContractMethod, list[Any], Starlette]:
        method = ContractMethod()
        server = make_server(method)
        return server, method, record(server), app({"/paid": server.pay(amount="1")})

    @pytest.mark.parametrize(
        "header",
        ["Payment !!!not-base64!!!", "Payment " + "A" * 20_000],
        ids=["unparseable", "oversized"],
    )
    async def test_malformed_credential_gets_a_fresh_challenge(self, header: str) -> None:
        server, method, events, application = await self._paid_route()
        async with http(application) as c:
            response = await c.get("/paid", headers={"Authorization": header})
        assert response.status_code == 402
        assert response.json()["type"] == f"{PROBLEMS}/payment-required"
        assert len(offers(response)) == 1
        [error] = failures(events)
        assert isinstance(error, MalformedCredentialError)
        assert method.intent.settled == []

    async def test_non_payment_authorization_is_a_silent_challenge(self) -> None:
        server, _, events, application = await self._paid_route()
        async with http(application) as c:
            response = await c.get("/paid", headers={"Authorization": "Bearer app-token"})
        assert response.status_code == 402
        assert [name for name, _ in events] == ["challenge.created"]

    async def test_credential_for_an_unknown_method_gets_a_fresh_challenge(self) -> None:
        server, method, events, application = await self._paid_route()
        other = Mpp.create(method=ContractMethod("other"), realm=REALM, secret_key=SECRET)
        foreign = await other.charge(None, "1")
        assert isinstance(foreign, Challenge)
        async with http(application) as c:
            response = await c.get("/paid", headers=authorization(foreign))
        assert response.status_code == 402
        assert offers(response)[0].method == "contract"
        [error] = failures(events)
        assert isinstance(error, InvalidChallengeError)
        assert method.intent.settled == []

    @pytest.mark.parametrize(
        ("token", "status", "problem", "same_challenge"),
        [
            ("verification-failed", 402, "verification-failed", True),
            ("invalid-payload", 402, "invalid-payload", False),
            ("unsupported", 402, "method-unsupported", True),
            ("replayed", 403, "verification-failed", None),
        ],
    )
    async def test_intent_rejections(
        self, token: str, status: int, problem: str, same_challenge: bool | None
    ) -> None:
        server, _, events, application = await self._paid_route()
        async with http(application) as c:
            [issued] = offers(await c.get("/paid"))
            response = await c.get("/paid", headers=authorization(issued, token))

        assert response.status_code == status
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["type"] == f"{PROBLEMS}/{problem}"
        assert "payment-receipt" not in response.headers
        if same_challenge is None:
            # A spent payment is final: no challenge invites the client to pay again.
            assert "www-authenticate" not in response.headers
        else:
            [retry] = offers(response)
            assert (retry.id == issued.id) is same_challenge
            assert response.json()["challengeId"] == retry.id
        [error] = failures(events)
        assert error is REJECTIONS[token]
        assert [name for name, _ in events][-1] == "payment.failed"

    async def test_rejection_is_reported_to_the_paying_client(self) -> None:
        server = make_server(ContractMethod())
        client, transport = paying(
            app({"/paid": server.pay(amount="1")}), ContractMethod(token="replayed")
        )
        client_events = record(transport)
        async with client:
            response = await client.get("/paid")
        # The client tries once and returns the server's final answer.
        assert response.status_code == 403
        assert [name for name, _ in client_events] == [
            "challenge.received",
            "credential.created",
        ]

    async def test_responses_without_starlette(self, monkeypatch: pytest.MonkeyPatch) -> None:
        server = make_server(ContractMethod("first"), ContractMethod("second"))
        decorated = paid_endpoint(server.pay(amount="1"))
        monkeypatch.setitem(sys.modules, "starlette.responses", None)

        class PlainRequest:
            method = "GET"
            path = "/paid"

            def __init__(self, headers: dict[str, str] | None = None) -> None:
                self.headers = headers or {}

        unpaid = await decorated(PlainRequest())
        assert unpaid["_mpp_challenge"] is True
        assert unpaid["status"] == 402
        assert unpaid["headers"]["Cache-Control"] == "no-store"
        values = unpaid["headers"]["WWW-Authenticate"]
        assert [Challenge.from_www_authenticate(v).method for v in values] == ["first", "second"]
        assert json.loads(unpaid["body"])["type"] == f"{PROBLEMS}/payment-required"

        issued = Challenge.from_www_authenticate(values[0])
        replay = await decorated(PlainRequest(authorization(issued, "replayed")))
        assert replay == {
            "_mpp_error": True,
            "status": 403,
            "headers": {"Cache-Control": "no-store", "Content-Type": "application/problem+json"},
            "body": replay["body"],
        }
        assert json.loads(replay["body"])["status"] == 403


class TestComposedOffers:
    async def test_offers_follow_entry_order_and_server_preference_wins(self) -> None:
        first, second = ContractMethod("first"), ContractMethod("second")
        server = make_server(first, second)
        handler = server.compose(
            ("second/charge", {"amount": "2"}),
            (first, {"amount": "1"}),
        )
        application = app({"/paid": handler})
        async with http(application) as c:
            unpaid = await c.get("/paid")
        assert [(o.method, o.request["amount"]) for o in offers(unpaid)] == [
            ("second", "200"),
            ("first", "100"),
        ]
        assert unpaid.json()["challengeId"] == offers(unpaid)[0].id

        # The client pays the server's first offer it supports, whatever its own order.
        client, _ = paying(application, ContractMethod("first"), ContractMethod("second"))
        async with client:
            assert (await client.get("/paid")).status_code == 200
        assert (first.intent.settled, second.intent.settled) == ([], ["ok"])

        # A client that supports only a later offer pays that one.
        client, _ = paying(application, ContractMethod("first"))
        async with client:
            assert (await client.get("/paid")).status_code == 200
        assert (first.intent.settled, second.intent.settled) == (["ok"], ["ok"])

    async def test_server_with_methods_offers_every_method_in_order(self) -> None:
        server = make_server(ContractMethod("first"), ContractMethod("second"))
        async with http(app({"/paid": server.pay(amount="1")})) as c:
            unpaid = await c.get("/paid")
        assert [o.method for o in offers(unpaid)] == ["first", "second"]

        charged = await server.charge(None, "1")
        assert not isinstance(charged, Challenge)
        assert [c.method for c in cast(Any, charged).challenges] == ["first", "second"]

    async def test_multi_currency_method_offers_each_currency_in_order(self) -> None:
        method = ContractMethod()
        method.currencies = ("usd-a", "usd-b")  # type: ignore[attr-defined]
        server = make_server(method)
        async with http(app({"/paid": server.pay(amount="1")})) as c:
            unpaid = await c.get("/paid")
            assert [o.request["currency"] for o in offers(unpaid)] == ["usd-a", "usd-b"]
            # A per-route currency yields a single offer.
            single = make_server(method).pay(amount="1", currency="usd-b")
        async with http(app({"/paid": single})) as c:
            assert [o.request["currency"] for o in offers(await c.get("/paid"))] == ["usd-b"]

    async def test_static_compose_keeps_each_server(self) -> None:
        first, second = ContractMethod("first"), ContractMethod("second")
        one = Mpp.create(method=first, realm="one.example.com", secret_key="one")
        two = Mpp.create(method=second, realm="two.example.com", secret_key="two")
        handler = compose(
            one.compose((first, {"amount": "1"})), two.compose((second, {"amount": "2"}))
        )
        application = app({"/paid": handler})
        async with http(application) as c:
            unpaid = await c.get("/paid")
        assert [o.realm for o in offers(unpaid)] == ["one.example.com", "two.example.com"]
        client, _ = paying(application, ContractMethod("second"))
        async with client:
            assert (await client.get("/paid")).status_code == 200
        assert second.intent.settled == ["ok"]

    async def test_no_available_offer_is_a_configuration_error(self) -> None:
        method = ContractMethod()
        method.can_offer = lambda request: False  # type: ignore[attr-defined]
        handler = make_server(method).compose((method, {"amount": "1"}))
        with pytest.raises(ValueError, match="No payment offers are available"):
            await handler.verify(None)

    def test_compose_rejects_invalid_handlers(self) -> None:
        with pytest.raises(ValueError, match="at least one configured handler"):
            compose()
        with pytest.raises(TypeError, match="only configured handlers"):
            ComposedHandler(cast(Any, object()))

    @pytest.mark.parametrize(
        ("entry", "message"),
        [
            (("contract/charge/extra", {"amount": "1"}), "invalid payment method reference"),
            (("/charge", {"amount": "1"}), "invalid payment method reference"),
            (("contract",), "tuples"),
            ((ContractMethod(), {"amount": "1"}), "not registered"),
            (("contract", [("amount", "1")]), "mapping"),
            (("contract", {"amount": "  "}), "non-empty string amount"),
            (
                ("contract", {"amount": "1", "expires": "x", "expires_in": timedelta(1)}),
                "cannot both be set",
            ),
            (
                ("contract", {"amount": "1", "splits": [{}], "fee_payer": True}),
                "splits and fee_payer",
            ),
        ],
    )
    def test_compose_rejects_invalid_entries(self, entry: Any, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            make_server(ContractMethod()).compose(entry)

    @pytest.mark.parametrize("missing", ["currency", "recipient"])
    def test_compose_requires_currency_and_recipient(self, missing: str) -> None:
        method = ContractMethod()
        setattr(method, missing, None)
        with pytest.raises(ValueError, match=f"{missing} must be set"):
            make_server(method).compose((method, {"amount": "1"}))


class TestRouteConfiguration:
    @pytest.mark.parametrize(
        ("options", "message"),
        [
            ({"splits": [{"amount": "1", "recipient": "x"}], "fee_payer": True}, "splits"),
            ({"expires": "2030-01-01T00:00:00Z", "expires_in": timedelta(minutes=1)}, "both"),
            ({"meta": {"_mpp_nonce": "x"}}, "reserved"),
            ({"unknown_option": True}, "unsupported charge option"),
        ],
    )
    async def test_charge_rejects_invalid_options(
        self, options: dict[str, Any], message: str
    ) -> None:
        with pytest.raises((ValueError, TypeError), match=message):
            await make_server(ContractMethod()).charge(None, "1", **options)

    async def test_meta_is_bound_into_opaque(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        issued = await server.charge(None, "1", meta={"account": "acct_1"})
        assert isinstance(issued, Challenge)
        assert issued.opaque is not None and issued.opaque["account"] == "acct_1"
        header = authorization(issued)["Authorization"]
        other = await server.charge(header, "1", meta={"account": "acct_2"})
        assert isinstance(other, Challenge)
        paid = await server.charge(header, "1", meta={"account": "acct_1"})
        assert isinstance(paid, tuple)
        assert method.intent.settled == ["ok"]

    async def test_requires_auth_reads_only_payment_authorization(self) -> None:
        method = ContractMethod()
        server = make_server(method, requires_auth=True)
        application = app({"/paid": server.pay(amount="1")})
        async with http(application) as c:
            [issued] = offers(await c.get("/paid"))
            assert issued.credential_header == "Payment-Authorization"
            wrong_header = await c.get("/paid", headers=authorization(issued))
            assert wrong_header.status_code == 402
        assert method.intent.settled == []

        client, _ = paying(application, ContractMethod())
        async with client:
            response = await client.get("/paid", headers={"Authorization": "Bearer app"})
        assert response.status_code == 200
        assert method.intent.settled == ["ok"]


class TestFrameworkScope:
    """Route scope bound into challenges for non-Starlette request objects."""

    @staticmethod
    async def scope_of(request: Any) -> dict[str, str]:
        server = make_server(ContractMethod())
        response = await paid_endpoint(server.pay(amount="1"))(request)
        return offers_from(response)[0].request["_mppx_scope"]

    async def test_flask_style_request(self) -> None:
        class Rule:
            rule = "/items/<int:id>"

        class URL:
            path = "/items/7"
            query = "page=2"

        class FlaskRequest:
            headers: dict[str, str] = {}
            method = "get"
            url_rule = Rule()
            url = URL()

        assert await self.scope_of(FlaskRequest()) == {
            "http_method": "GET",
            "query": "page=2",
            "resource": "/items/7",
            "route": "/items/<int:id>",
        }

    async def test_django_style_request(self) -> None:
        class Match:
            route = "items/<int:id>/"

        class DjangoRequest:
            META = {"QUERY_STRING": "page=3"}
            method = "POST"
            path = "/items/9/"
            resolver_match = Match()

        assert await self.scope_of(DjangoRequest()) == {
            "http_method": "POST",
            "query": "page=3",
            "resource": "/items/9/",
            "route": "items/<int:id>/",
        }

    async def test_path_template_request(self) -> None:
        class Generic:
            headers: dict[str, str] = {}
            method = "PUT"
            path = "/a/1"
            path_template = "/a/{id}"
            query_string = b"x=1"

        assert await self.scope_of(Generic()) == {
            "http_method": "PUT",
            "query": "x=1",
            "resource": "/a/1",
            "route": "/a/{id}",
        }

    async def test_asgi_scope_matched_through_the_router(self) -> None:
        async def endpoint() -> None: ...

        class Candidate:
            path = "/r/{id}"

        candidate = Candidate()
        candidate.endpoint = endpoint  # type: ignore[attr-defined]

        class Router:
            routes = [candidate]

        class AsgiRequest:
            headers: dict[str, str] = {}
            scope = {
                "endpoint": endpoint,
                "method": "DELETE",
                "path": "/r/5",
                "query_string": b"",
                "router": Router(),
            }

        assert await self.scope_of(AsgiRequest()) == {
            "http_method": "DELETE",
            "resource": "/r/5",
            "route": "/r/{id}",
        }


def offers_from(response: Any) -> list[Challenge]:
    return [
        Challenge.from_www_authenticate(value.decode())
        for name, value in response.raw_headers
        if name.lower() == b"www-authenticate"
    ]


class TestAmounts:
    @pytest.mark.parametrize(
        ("amount", "wire"),
        [(" 0.01 ", "1"), ("1", "100"), ("0", "0"), ("12.34", "1234")],
    )
    async def test_human_amounts_convert_to_base_units(self, amount: str, wire: str) -> None:
        issued = await make_server(ContractMethod(decimals=2)).charge(None, amount)
        assert isinstance(issued, Challenge)
        assert issued.request["amount"] == wire

    @pytest.mark.parametrize("amount", ["abc", "-1", "0.001", "", "nan"])
    async def test_invalid_amounts_are_rejected(self, amount: str) -> None:
        with pytest.raises(ValueError):
            await make_server(ContractMethod(decimals=2)).charge(None, amount)


class TestMcpToolIdentity:
    async def test_tool_identity_is_required(self) -> None:
        pytest.importorskip("mcp")
        from mpp.extensions.mcp import create_challenge, verify_or_challenge

        with pytest.raises(ValueError, match="tool must be"):
            await verify_or_challenge(
                meta=None,
                intent=ContractIntent(),
                request={"amount": "1"},
                realm=REALM,
                secret_key=SECRET,
                tool="",
                method="contract",
            )
        with pytest.raises(ValueError, match="tool must be"):
            create_challenge(
                method="contract",
                intent_name="charge",
                request={"amount": "1"},
                realm=REALM,
                secret_key=SECRET,
                tool="",
            )
