"""Server and client payment contract the engine refactor must preserve.

Ported from the 0.15 API to the Mpp engine: fast, network-free tests over real
HTTP plumbing: a Starlette app served through `httpx.ASGITransport`, protected
with `mpp.server.pay` / `server.compose`, and paid by `mpp.client.PaymentTransport`
with an in-process payment method. They pin observable behaviour (status codes,
problem types, headers, event names and payload keys, challenge bindings, offer
order) rather than internals.

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
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, model_serializer, model_validator
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from mpp import Challenge, Credential, Receipt
from mpp._units import parse_units
from mpp.client import PaymentTransport
from mpp.errors import (
    CredentialReplayedError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentMethodUnsupportedError,
    VerificationFailedError,
)
from mpp.methods import Method
from mpp.runtime import ClientMethod, CredentialParams
from mpp.server import (
    ComposedHandler,
    Mpp,
    PaymentRequired,
    PaymentVerified,
    Request,
    ServerMethod,
    VerifyContext,
    compose,
    pay,
)

REALM = "contract.example.com"
SECRET = "contract-secret"
PROBLEMS = "https://paymentauth.org/problems"
URL = "https://contract.example.com/paid"

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

# Tokens the in-process method maps to outcomes.
REJECTIONS: dict[str, Exception] = {
    "invalid-payload": InvalidPayloadError("payload is not understood"),
    "unsupported": PaymentMethodUnsupportedError("contract/other"),
    "verification-failed": VerificationFailedError("payment was not found"),
    "replayed": CredentialReplayedError(),
}


class ContractInput(BaseModel):
    """Route input: a decimal amount converted to base units with the SDK's parse_units."""

    model_config = ConfigDict(extra="forbid")

    amount: str
    currency: str
    recipient: str
    decimals: int = 2
    fee_payer: bool = False
    splits: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def _check(self) -> ContractInput:
        parse_units(self.amount, self.decimals)
        if self.splits and self.fee_payer:
            raise ValueError("splits and fee_payer cannot be used together")
        return self

    @model_serializer
    def _wire(self) -> dict[str, Any]:
        return {
            "amount": str(parse_units(self.amount, self.decimals)),
            "currency": self.currency,
            "recipient": self.recipient,
        }


class ContractPayload(BaseModel):
    token: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ContractDefinition(Method[ContractInput, ContractPayload]):
    pass


class ContractMethod:
    """A payment method usable on both the server and the client.

    `server` holds its configured server methods, one per currency like
    `tempo.charge(currencies=[...])`; `client` pays with `token`.
    """

    def __init__(
        self,
        name: str = "contract",
        token: str = "ok",
        decimals: int = 2,
        currencies: tuple[str, ...] | None = None,
        *,
        omit: str | None = None,
        can_offer: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        self.name = name
        self.token = token
        self.settled: list[str] = []
        self.definition = ContractDefinition(
            name=name,
            intent="charge",
            request_model=ContractInput,
            payload_model=ContractPayload,
        )
        self.server = []
        for currency in currencies or (f"{name}-usd",):
            defaults: dict[str, Any] = {
                "currency": currency,
                "decimals": decimals,
                "recipient": f"{name}-merchant",
            }
            if omit is not None:
                del defaults[omit]
            self.server.append(
                ServerMethod(
                    method=self.definition,
                    verify=self._verify,
                    defaults=defaults,
                    can_offer=can_offer,
                )
            )
        self.client = ClientMethod(method=self.definition, create_credential=self._credential)

    async def _verify(self, context: VerifyContext) -> Receipt:
        token = cast(ContractPayload, context.credential.payload).token
        if token in REJECTIONS:
            raise REJECTIONS[token]
        self.settled.append(token)
        return Receipt.success(f"ref-{token}", method=context.credential.challenge.method)

    async def _credential(self, params: CredentialParams) -> str:
        credential = Credential(challenge=params.challenge.to_echo(), payload={"token": self.token})
        return credential.to_authorization()


def make_server(*methods: ContractMethod, **options: Any) -> Mpp:
    configured: Any = (
        methods[0].server[0]
        if len(methods) == 1 and len(methods[0].server) == 1
        else [m.server for m in methods]
    )
    return Mpp(methods=configured, realm=REALM, secret_key=SECRET, **options)


def record(target: Any) -> list[tuple[str, dict[str, Any]]]:
    """Record every event a server or client emits, in order."""
    events: list[tuple[str, dict[str, Any]]] = []
    target.on("*", lambda event: events.append((str(event.name), dict(event.payload))))
    return events


def paid_endpoint(decorate: Callable[..., Any]) -> Any:
    @decorate
    async def endpoint(request: Any, credential: Credential, receipt: Receipt) -> Any:
        payload = credential.payload
        token = payload.get("token") if isinstance(payload, dict) else payload.token
        return JSONResponse(
            {"payer": token, "reference": receipt.reference},
            headers={"Payment-Receipt": receipt.to_payment_receipt()},
        )

    return endpoint


def app(routes: Mapping[str, ComposedHandler], methods: list[str] | None = None) -> Starlette:
    return Starlette(
        routes=[
            Route(path, paid_endpoint(pay(handler)), methods=methods or ["GET", "POST"])
            for path, handler in routes.items()
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
        methods=[m.client for m in methods], inner=httpx.ASGITransport(app=application), **options
    )
    return httpx.AsyncClient(transport=transport, base_url="http://testserver"), transport


def offers(response: Any) -> list[Challenge]:
    headers = (
        response.challenge.headers if isinstance(response, PaymentRequired) else response.headers
    )
    return [
        Challenge.from_www_authenticate(value) for value in headers.get_list("www-authenticate")
    ]


def authorization(challenge: Challenge, token: str = "ok") -> dict[str, str]:
    credential = Credential(challenge=challenge.to_echo(), payload={"token": token})
    return {"Authorization": credential.to_authorization()}


def engine_request(headers: dict[str, str] | None = None) -> Request:
    return Request("GET", URL, headers=headers)


async def issue(handler: ComposedHandler) -> Challenge:
    [issued] = offers(await handler(engine_request()))
    return issued


def failures(events: list[tuple[str, dict[str, Any]]]) -> list[Exception]:
    return [payload["error"] for name, payload in events if name == "payment.failed"]


class TestRoundTrip:
    async def test_client_pays_and_both_sides_emit_events_in_order(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        server_events = record(server)
        client, transport = paying(app({"/paid": server.charge(amount="1.25")}), ContractMethod())
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
        assert method.settled == ["ok"]

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
        async with http(app({"/paid": server.charge(amount="1", description="One item")})) as c:
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
        async with http(app({"/paid": server.charge(amount="1")})) as c:
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
        handler = server.charge(amount="1")
        application = app({"/items/{id}": handler, "/other/{id}": handler})
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
            assert method.settled == []
            [error] = failures(events)
            assert isinstance(error, InvalidChallengeError)

            accepted = await c.get("/items/1?page=1", headers=authorization(issued))
            assert accepted.status_code == 200
        assert method.settled == ["ok"]

    async def test_async_body_callback_binds_the_body_digest(self) -> None:
        method = ContractMethod()
        server = make_server(method)

        async def body(request: Request) -> bytes:
            return request.body or b""

        async with http(app({"/paid": server.charge(amount="1", body=body)})) as c:
            [issued] = offers(await c.post("/paid", content=b'{"q": 1}'))
            assert issued.digest is not None and issued.digest.startswith("sha-256=")
            tampered = await c.post("/paid", content=b'{"q": 2}', headers=authorization(issued))
            assert tampered.status_code == 402
            assert method.settled == []
            paid = await c.post("/paid", content=b'{"q": 1}', headers=authorization(issued))
            assert paid.status_code == 200
        assert method.settled == ["ok"]

    async def test_body_bound_route_refuses_credential_without_digest(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        events = record(server)
        issued = await issue(server.charge(amount="1"))
        assert issued.digest is None

        result = await server.charge(amount="1", body=b"{}")(engine_request(authorization(issued)))
        [retry] = offers(result)
        assert retry.digest is not None
        [error] = failures(events)
        assert isinstance(error, InvalidChallengeError)
        assert "missing body digest" in str(error)
        assert method.settled == []

    async def test_amount_is_bound(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        cheap = await issue(server.charge(amount="0.01"))
        result = await server.charge(amount="1")(engine_request(authorization(cheap)))
        [retry] = offers(result)
        assert retry.request["amount"] == "100"
        assert method.settled == []

    async def test_credential_from_another_server_secret_is_refused(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        events = record(server)
        other = Mpp(methods=ContractMethod().server[0], realm=REALM, secret_key="other-secret")
        foreign = await issue(other.charge(amount="1"))
        result = await server.charge(amount="1")(engine_request(authorization(foreign)))
        assert offers(result)
        assert isinstance(failures(events)[0], InvalidChallengeError)
        assert method.settled == []


class TestFailureResponses:
    """Status codes, problem types and challenges for rejected credentials over HTTP."""

    async def _paid_route(self) -> tuple[Mpp, ContractMethod, list[Any], Starlette]:
        method = ContractMethod()
        server = make_server(method)
        return server, method, record(server), app({"/paid": server.charge(amount="1")})

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
        assert method.settled == []

    async def test_non_payment_authorization_is_a_silent_challenge(self) -> None:
        server, _, events, application = await self._paid_route()
        async with http(application) as c:
            response = await c.get("/paid", headers={"Authorization": "Bearer app-token"})
        assert response.status_code == 402
        assert [name for name, _ in events] == ["challenge.created"]

    async def test_credential_for_an_unknown_method_gets_a_fresh_challenge(self) -> None:
        server, method, events, application = await self._paid_route()
        other = Mpp(methods=ContractMethod("other").server[0], realm=REALM, secret_key=SECRET)
        foreign = await issue(other.charge(amount="1"))
        async with http(application) as c:
            response = await c.get("/paid", headers=authorization(foreign))
        assert response.status_code == 402
        assert offers(response)[0].method == "contract"
        [error] = failures(events)
        assert isinstance(error, InvalidChallengeError)
        assert method.settled == []

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
            app({"/paid": server.charge(amount="1")}), ContractMethod(token="replayed")
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
        decorated = paid_endpoint(pay(server.charge(amount="1")))
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
            (first.server[0], {"amount": "1"}),
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
        assert (first.settled, second.settled) == ([], ["ok"])

        # A client that supports only a later offer pays that one.
        client, _ = paying(application, ContractMethod("first"))
        async with client:
            assert (await client.get("/paid")).status_code == 200
        assert (first.settled, second.settled) == (["ok"], ["ok"])

    async def test_server_with_methods_offers_every_method_in_order(self) -> None:
        server = make_server(ContractMethod("first"), ContractMethod("second"))
        async with http(app({"/paid": server.charge(amount="1")})) as c:
            unpaid = await c.get("/paid")
        assert [o.method for o in offers(unpaid)] == ["first", "second"]

        charged = await server.charge(amount="1")(engine_request())
        assert [c.method for c in offers(charged)] == ["first", "second"]

    async def test_multi_currency_method_offers_each_currency_in_order(self) -> None:
        method = ContractMethod(currencies=("usd-a", "usd-b"))
        server = make_server(method)
        async with http(app({"/paid": server.charge(amount="1")})) as c:
            unpaid = await c.get("/paid")
            assert [o.request["currency"] for o in offers(unpaid)] == ["usd-a", "usd-b"]
            # A per-route currency yields a single offer.
            single = make_server(method).charge(amount="1", currency="usd-b")
        async with http(app({"/paid": single})) as c:
            assert [o.request["currency"] for o in offers(await c.get("/paid"))] == ["usd-b"]

    async def test_static_compose_keeps_each_server(self) -> None:
        first, second = ContractMethod("first"), ContractMethod("second")
        one = Mpp(methods=first.server[0], realm="one.example.com", secret_key="one")
        two = Mpp(methods=second.server[0], realm="two.example.com", secret_key="two")
        handler = compose(
            one.compose((first.server[0], {"amount": "1"})),
            two.compose((second.server[0], {"amount": "2"})),
        )
        application = app({"/paid": handler})
        async with http(application) as c:
            unpaid = await c.get("/paid")
        assert [o.realm for o in offers(unpaid)] == ["one.example.com", "two.example.com"]
        client, _ = paying(application, ContractMethod("second"))
        async with client:
            assert (await client.get("/paid")).status_code == 200
        assert second.settled == ["ok"]

    async def test_no_available_offer_is_a_configuration_error(self) -> None:
        method = ContractMethod(can_offer=lambda request: False)
        handler = make_server(method).compose((method.server[0], {"amount": "1"}))
        with pytest.raises(ValueError, match="No payment offers are available"):
            await handler(engine_request())

    def test_compose_rejects_invalid_handlers(self) -> None:
        with pytest.raises(ValueError, match="at least one configured handler"):
            compose()
        with pytest.raises(TypeError, match="only configured handlers"):
            ComposedHandler(cast(Any, object()))

    @pytest.mark.parametrize(
        ("entry", "message"),
        [
            (("contract/charge/extra", {"amount": "1"}), "not registered"),
            (("/charge", {"amount": "1"}), "not registered"),
            (("contract",), "tuples"),
            ((ContractMethod().server[0], {"amount": "1"}), "not registered"),
            (("contract", [("amount", "1")]), "mapping"),
            (("contract", {"amount": "  "}), "amount is required"),
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
        method = ContractMethod(omit=missing)
        with pytest.raises(ValueError, match=missing):
            make_server(method).compose((method.server[0], {"amount": "1"}))


class TestRouteConfiguration:
    @pytest.mark.parametrize(
        ("options", "message"),
        [
            ({"splits": [{"amount": "1", "recipient": "x"}], "fee_payer": True}, "splits"),
            ({"expires": "2030-01-01T00:00:00Z", "expires_in": timedelta(minutes=1)}, "both"),
            ({"meta": {"_mpp_nonce": "x"}}, "reserved"),
            ({"unknown_option": True}, "unknown_option"),
        ],
    )
    async def test_charge_rejects_invalid_options(
        self, options: dict[str, Any], message: str
    ) -> None:
        # Rejected when the route is configured, or at the latest when it issues a challenge.
        with pytest.raises((ValueError, TypeError), match=message):
            await make_server(ContractMethod()).charge(amount="1", **options)(engine_request())

    async def test_meta_is_bound_into_opaque(self) -> None:
        method = ContractMethod()
        server = make_server(method)
        issued = await issue(server.charge(amount="1", meta={"account": "acct_1"}))
        assert issued.opaque is not None and issued.opaque["account"] == "acct_1"
        header = authorization(issued)
        other = await server.charge(amount="1", meta={"account": "acct_2"})(engine_request(header))
        assert isinstance(other, PaymentRequired)
        paid = await server.charge(amount="1", meta={"account": "acct_1"})(engine_request(header))
        assert isinstance(paid, PaymentVerified)
        assert method.settled == ["ok"]

    async def test_requires_auth_reads_only_payment_authorization(self) -> None:
        method = ContractMethod()
        server = make_server(method, requires_auth=True)
        application = app({"/paid": server.charge(amount="1")})
        async with http(application) as c:
            [issued] = offers(await c.get("/paid"))
            assert issued.credential_header == "Payment-Authorization"
            wrong_header = await c.get("/paid", headers=authorization(issued))
            assert wrong_header.status_code == 402
        assert method.settled == []

        client, _ = paying(application, ContractMethod())
        async with client:
            response = await client.get("/paid", headers={"Authorization": "Bearer app"})
        assert response.status_code == 200
        assert method.settled == ["ok"]


class TestFrameworkScope:
    """Route scope bound into challenges for non-Starlette request objects."""

    @staticmethod
    async def scope_of(request: Any) -> dict[str, str]:
        server = make_server(ContractMethod())
        response = await paid_endpoint(pay(server.charge(amount="1")))(request)
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
        issued = await issue(make_server(ContractMethod(decimals=2)).charge(amount=amount))
        assert issued.request["amount"] == wire

    @pytest.mark.parametrize("amount", ["abc", "-1", "0.001", "", "nan"])
    async def test_invalid_amounts_are_rejected(self, amount: str) -> None:
        with pytest.raises(ValueError):
            await make_server(ContractMethod(decimals=2)).charge(amount=amount)(engine_request())


class TestMcpToolIdentity:
    async def test_tool_identity_is_required(self) -> None:
        pytest.importorskip("mcp")
        from mpp.extensions.mcp import pay as mcp_pay
        from mpp.extensions.mcp import verify_or_challenge

        handler = make_server(ContractMethod()).charge(amount="1")
        with pytest.raises(ValueError, match="tool must be"):
            await verify_or_challenge(handler, meta=None, tool="")
        with pytest.raises(ValueError, match="tool must be"):
            mcp_pay(handler, tool="")
