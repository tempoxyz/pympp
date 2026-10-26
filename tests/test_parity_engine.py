"""Parity checks for engine behaviour the 0.15 tests covered through removed APIs.

Each test pins a behaviour that 047202c tested through Mpp.create,
server.charge(None, ...), create_challenge or similar APIs, or a changed
source branch no other test reaches.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from typing import Any, cast

import httpx
import pytest

from mpp import Challenge, Credential, Receipt
from mpp.errors import MalformedCredentialError
from mpp.methods.evm import BASE_SEPOLIA_USDC
from mpp.methods.evm import server as evm_server
from mpp.methods.tempo import server as tempo_server
from mpp.runtime import ClientMethod, CredentialParams, PaymentRuntime
from mpp.server import (
    Mpp,
    PaymentRequired,
    PaymentVerified,
    Request,
    Response,
    ServerMethod,
)
from mpp.server.method import resolve
from mpp.store import MemoryStore
from tests import challenge, challenges, http_request, server_method

REALM = "api.example.com"
SECRET = "test-secret"
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
OTHER = "0x" + "22" * 20


def tempo_mpp(**kwargs: Any) -> Mpp:
    return Mpp(
        methods=tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY, **kwargs),
        realm=REALM,
        secret_key=SECRET,
    )


async def _verified(context: Any) -> Receipt:
    return Receipt.success("paid")


async def _settle(*args: Any) -> str:
    return "0x" + "ab" * 32


def raw_mpp(**hooks: Any) -> Mpp:
    hooks = hooks or {"verify": _verified}
    return Mpp(
        methods=server_method(request={"amount": "1"}, **hooks), realm=REALM, secret_key=SECRET
    )


def authorization(issued: Challenge, payload: Any = None) -> str:
    return Credential(challenge=issued.to_echo(), payload=payload or {}).to_authorization()


class TestSharedStore:
    """Mpp(store=) reaches every method configured without a store (was Mpp.create)."""

    def test_one_store_serves_tempo_and_evm(self) -> None:
        store = MemoryStore()
        evm = evm_server.charge(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=_settle)
        server = Mpp(
            methods=[tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY), evm],
            realm=REALM,
            secret_key=SECRET,
            store=store,
        )
        assert evm.x402 is not None
        assert evm.x402._store is store  # type: ignore[attr-defined]
        assert {method.key for method in server.methods} == {"tempo/charge", "evm/charge"}

    async def test_tempo_route_of_a_multi_method_server_uses_the_store(self) -> None:
        from mpp.errors import CredentialReplayedError

        store = MemoryStore()
        tx_hash = "0x" + "12" * 32
        await store.put(f"mpp:charge:{tx_hash}", tx_hash)
        evm = evm_server.charge(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=_settle)
        server = Mpp(
            methods=[tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY), evm],
            realm=REALM,
            secret_key=SECRET,
            store=store,
        )
        issued = challenge(await server.tempo.charge(amount="0.50")(http_request()))
        credential = Credential(
            challenge=issued.to_echo(), payload={"type": "hash", "hash": tx_hash}
        )
        with pytest.raises(CredentialReplayedError):
            await server.validate_credential(credential)


class TestRouteConfiguration:
    """Route options are validated when the route is configured (was server.charge(None, ...))."""

    @pytest.mark.parametrize(
        "options",
        [
            {"amount": "abc"},
            {"amount": "-1"},
            {"amount": "1", "memo": "x"},
            {"amount": "1", "extra": {"a": 1}},
            {"amount": "1", "expires_in": 60},
        ],
    )
    def test_invalid_route_options_fail_at_configuration(self, options: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            tempo_mpp().charge(**options)

    def test_route_without_a_recipient_fails_at_configuration(self) -> None:
        server = Mpp(methods=tempo_server.charge(currency=CURRENCY), realm=REALM, secret_key=SECRET)
        with pytest.raises(ValueError, match="recipient"):
            server.charge(amount="1")

    async def test_amount_whitespace_is_stripped_without_rounding(self) -> None:
        issued = challenge(await tempo_mpp().charge(amount=" 0.000001 ")(http_request()))
        assert issued.request["amount"] == "1"

    async def test_route_options_override_method_defaults(self) -> None:
        handler = tempo_mpp().charge(amount="1", recipient=OTHER, extra={"order": "42"})
        issued = challenge(await handler(http_request()))
        assert issued.request["recipient"] == OTHER
        assert issued.request["extra"] == {"order": "42"}

    async def test_route_currency_outside_configured_list_is_offered(self) -> None:
        currency = "0x" + "33" * 20
        handler = tempo_mpp().charge(amount="1", currency=currency)
        offered = challenges(await handler(http_request()))
        assert [item.request["currency"] for item in offered] == [currency]

    async def test_route_splits_enter_method_details(self) -> None:
        split = {"amount": "300000", "recipient": OTHER}
        issued = challenge(await tempo_mpp().charge(amount="1", splits=[split])(http_request()))
        assert issued.request["methodDetails"]["splits"] == [split]

    async def test_async_resolve_request_runs_per_request(self) -> None:
        seen: list[dict[str, Any]] = []

        async def resolve_request(context: Any) -> dict[str, Any]:
            seen.append(dict(context.request))
            return {**context.request, "amount": "7"}

        method = replace(server_method(verify=_verified), resolve_request=resolve_request)
        server = Mpp(methods=method, realm=REALM, secret_key=SECRET)
        handler = server.charge(amount="not-checked-at-configuration")
        assert seen == []
        issued = challenge(await handler(http_request()))
        assert issued.request["amount"] == "7"
        assert seen == [{"amount": "not-checked-at-configuration"}]


class TestEngineErrors:
    def test_construction_errors(self) -> None:
        with pytest.raises(ValueError, match="methods is required"):
            Mpp(methods=[], realm=REALM, secret_key=SECRET)
        with pytest.raises(TypeError, match="not a server payment method"):
            Mpp(methods=[object()], realm=REALM, secret_key=SECRET)  # type: ignore[list-item]

    def test_nested_method_sequences_are_flattened(self) -> None:
        first = server_method(verify=_verified)
        second = server_method(name="other", verify=_verified)
        server = Mpp(methods=cast(Any, [[first], [[second]]]), realm=REALM, secret_key=SECRET)
        assert server.methods == (first, second)

    def test_lookup_errors(self) -> None:
        server = tempo_mpp()
        with pytest.raises(KeyError, match="no payment method"):
            server["stripe/charge"]
        with pytest.raises(AttributeError):
            server.stripe  # noqa: B018
        with pytest.raises(AttributeError):
            server.tempo.session  # noqa: B018
        assert server.tempo["charge"] is server["tempo/charge"]
        assert "charge" in server.tempo
        assert "tempo/charge" in server

    def test_compose_errors(self) -> None:
        server = tempo_mpp()
        foreign = tempo_mpp()
        with pytest.raises(ValueError, match="at least one entry"):
            server.compose()
        with pytest.raises(ValueError, match="not registered"):
            server.compose((foreign.tempo.charge, {"amount": "1"}))
        with pytest.raises(ValueError, match="not registered"):
            server.compose((foreign.methods[0], {"amount": "1"}))

    async def test_compose_accepts_each_target_form(self) -> None:
        server = tempo_mpp()
        handler = server.compose(
            ("tempo", {"amount": "1"}),
            (server.tempo.charge, {"amount": "2"}),
            (server.methods[0], {"amount": "3"}),
        )
        assert handler.methods == (server.methods[0],) * 3
        offered = challenges(await handler(http_request()))
        assert [item.request["amount"] for item in offered] == ["1000000", "2000000", "3000000"]

    async def test_credential_strings_must_parse(self) -> None:
        with pytest.raises(MalformedCredentialError):
            await tempo_mpp().validate_credential("not-a-credential!!")
        with pytest.raises(MalformedCredentialError):
            await tempo_mpp().broadcast_credential("Payment not-a-credential!!")

    async def test_validate_credential_request_needs_sync_resolve_request(self) -> None:
        async def resolve_request(context: Any) -> dict[str, Any]:
            return context.request

        async def validate(context: Any) -> Any:
            raise AssertionError("not reached")

        method = replace(
            server_method(broadcast=_verified, validate=validate, request={"amount": "1"}),
            resolve_request=resolve_request,
        )
        server = Mpp(methods=method, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge()(http_request()))
        with pytest.raises(TypeError, match="synchronous resolve_request"):
            await server.validate_credential(
                Credential(challenge=issued.to_echo(), payload={}), request={"amount": "1"}
            )

    async def test_route_rejects_payloads_the_method_cannot_parse(self) -> None:
        handler = tempo_mpp().charge(amount="1")
        issued = challenge(await handler(http_request()))
        result = await handler(http_request(authorization(issued, {"type": "bogus"})))
        assert isinstance(result, PaymentRequired)
        assert result.status == 402
        assert b"invalid-payload" in (result.challenge.body or b"")
        assert challenges(result)


class TestServerMethod:
    def test_hook_combinations(self) -> None:
        definition = server_method(verify=_verified).method
        with pytest.raises(TypeError, match="verify or broadcast"):
            ServerMethod(method=definition)
        with pytest.raises(TypeError, match="either verify or validate/broadcast"):
            ServerMethod(method=definition, verify=_verified, validate=cast(Any, _verified))
        with pytest.raises(TypeError, match="either verify or validate/broadcast"):
            ServerMethod(method=definition, verify=_verified, broadcast=_verified)
        with pytest.raises(ValueError, match="can_offer"):
            ServerMethod(method=definition, verify=_verified, can_offer="yes")  # type: ignore[arg-type]

    async def test_resolve_accepts_sync_and_async_values(self) -> None:
        async def value() -> int:
            return 2

        assert await resolve(1) == 1
        assert await resolve(value()) == 2


class TestHttpTypes:
    def test_headers_keep_repeated_values(self) -> None:
        headers = httpx.Headers(
            [("WWW-Authenticate", "Payment a"), ("WWW-Authenticate", "Payment b")]
        )
        response = Response(402, headers=headers)
        assert response.headers.get_list("www-authenticate") == ["Payment a", "Payment b"]
        assert response.headers is not headers

    def test_json_bodies(self) -> None:
        assert Request("post", "https://x/y", body='{"a": 1}').json() == {"a": 1}
        response = Response.json({"ok": True}, status=201)
        assert response.status == 201
        assert response.headers["content-type"] == "application/json"
        assert response.body == b'{"ok": true}'
        custom = Response.json({}, headers={"Content-Type": "application/problem+json"})
        assert custom.headers["content-type"] == "application/problem+json"

    async def test_with_receipt_on_engine_responses(self) -> None:
        handler = raw_mpp().charge()
        issued = challenge(await handler(http_request()))
        result = await handler(http_request(authorization(issued)))
        assert isinstance(result, PaymentVerified)

        original = Response.json({"ok": True}, headers={"Cache-Control": "public, max-age=60"})
        paid = result.with_receipt(original)
        assert paid is not original
        assert "payment-receipt" not in original.headers
        assert paid.headers["cache-control"] == "private, max-age=60"
        assert paid.headers["content-type"] == "application/json"
        assert Receipt.from_payment_receipt(paid.headers["payment-receipt"]).reference == "paid"

        kept = result.with_receipt(Response(200, headers={"Cache-Control": "no-store"}))
        assert kept.headers["cache-control"] == "no-store"

        assert result.with_receipt({"plain": True}) == {"plain": True}


class TestFrameworkAdapters:
    async def test_django_style_requests(self) -> None:
        from mpp.server.decorator import to_request

        class DjangoRequest:
            method = "post"
            path = "/paid"
            META = {
                "HTTP_AUTHORIZATION": "Payment abc",
                "HTTP_X_TRACE_ID": "1",
                "QUERY_STRING": "a=1",
            }

            @property
            def body(self) -> bytes:
                raise RuntimeError("stream already consumed")

        request = await to_request(DjangoRequest())
        assert request.method == "POST"
        assert request.url == "/paid?a=1"
        assert request.headers["authorization"] == "Payment abc"
        assert request.headers["x-trace-id"] == "1"
        assert request.body is None

        class TextRequest:
            headers = {"a": "b"}
            method = "GET"
            path = "/x"
            body = "text"

        assert (await to_request(TextRequest())).body == b"text"

    async def test_pay_reads_the_body_only_when_an_offer_needs_it(self) -> None:
        from mpp.server import pay

        reads: list[str] = []

        class StarletteRequest:
            headers: dict[str, str] = {}
            method = "POST"
            path = "/paid"

            async def body(self) -> bytes:
                reads.append("body")
                return b"{}"

        async def endpoint(request: Any, credential: Any, receipt: Any) -> dict[str, str]:
            return {}

        server = tempo_mpp()
        await pay(server.charge(amount="1"))(endpoint)(StarletteRequest())
        await pay(server.charge(amount="1", body=b"{}"))(endpoint)(StarletteRequest())
        assert reads == []
        handler = server.charge(amount="1", body=lambda request: request.body or b"")
        assert handler.needs_request_body
        await pay(handler)(endpoint)(StarletteRequest())
        assert reads == ["body"]

    async def test_flask_style_requests_read_get_data(self) -> None:
        from mpp.server.decorator import to_request

        class FlaskRequest:
            headers = {"a": "b"}
            method = "POST"
            path = "/paid"

            def get_data(self) -> bytes:
                return b'{"q": 1}'

        assert (await to_request(FlaskRequest())).body == b'{"q": 1}'
        assert (await to_request(FlaskRequest(), read_body=False)).body is None

    def test_responses_without_starlette(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mpp.server.decorator import to_framework_response

        monkeypatch.setitem(sys.modules, "starlette.responses", None)
        unpaid = to_framework_response(
            Response(
                402,
                headers=[("WWW-Authenticate", "Payment a"), ("www-authenticate", "Payment b")],
                body="{}",
            )
        )
        assert unpaid["_mpp_challenge"] is True
        assert unpaid["status"] == 402
        assert unpaid["headers"]["WWW-Authenticate"] == ["Payment a", "Payment b"]
        final = to_framework_response(Response(403, body="spent"))
        assert final == {"_mpp_error": True, "status": 403, "headers": {}, "body": "spent"}


class TestClientRuntime:
    def _method(self) -> ClientMethod:
        from mpp.methods import Method

        async def create_credential(params: CredentialParams) -> str:
            raise NotImplementedError

        return ClientMethod(
            method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
            create_credential=create_credential,
        )

    def test_nested_methods_are_flattened(self) -> None:
        from mpp.client import Mpp as ClientMpp

        first, second = self._method(), self._method()
        assert PaymentRuntime(cast(Any, [[first], [[second]]])).methods == (first, second)
        assert ClientMpp(methods=[first, [second]]).methods == (first, second)
        with pytest.raises(TypeError, match="not a client payment method"):
            PaymentRuntime([object()])  # type: ignore[list-item]
        with pytest.raises(TypeError, match="not a client payment method"):
            PaymentRuntime(["tempo"])  # type: ignore[list-item]

    async def test_stripe_client_charge_creates_spt_credentials(self) -> None:
        from mpp.methods.stripe import client as stripe_client
        from mpp.methods.stripe import server as stripe_server

        seen: list[Any] = []

        async def create_token(params: Any) -> str:
            seen.append(params)
            return "spt_test"

        method = stripe_client.charge(create_token=create_token, payment_method="pm_card_visa")
        assert method.key == "stripe/charge"
        server = Mpp(
            methods=stripe_server.charge(secret_key="sk_test", network_id="bn_1", currency="usd"),
            realm=REALM,
            secret_key=SECRET,
        )
        issued = challenge(await server.charge(amount="0.50")(http_request()))
        runtime = PaymentRuntime([method])
        matched, selected = runtime.match_challenge([issued])
        credential = await runtime.create_credential(matched, selected)
        assert credential.payload == {"spt": "spt_test"}
        assert credential.challenge.id == issued.id
        [params] = seen
        assert params.amount == "50"
        assert params.challenge.id == issued.id
        assert params.payment_method == "pm_card_visa"


class TestStripePaymentIntentInput:
    def test_parsed_payloads_reach_recorders_as_wire_json(self) -> None:
        from mpp.methods.stripe.payment_intent_method import _native
        from mpp.methods.tempo.schemas import charge

        tx_hash = "0x" + "ab" * 32
        parsed = charge.parse_payload({"type": "hash", "hash": tx_hash})
        issued = Challenge.create(
            secret_key=SECRET, realm=REALM, method="tempo", intent="charge", request={}
        )
        native = _native(Credential(challenge=issued.to_echo(), payload=cast(Any, parsed)))
        assert native.payload == {"type": "hash", "hash": tx_hash}
        raw = Credential(challenge=issued.to_echo(), payload={"type": "hash"})
        assert _native(raw) is raw


class TestMcpProblemBodies:
    async def _run(self, response: Response) -> Any:
        from mpp.extensions.mcp import verify_or_challenge

        async def handler(request: Request) -> PaymentRequired:
            return PaymentRequired(response)

        return await verify_or_challenge(handler, tool="paid")  # type: ignore[arg-type]

    def _header(self) -> str:
        issued = Challenge.create(
            secret_key=SECRET, realm=REALM, method="tempo", intent="charge", request={"amount": "1"}
        )
        return issued.to_www_authenticate(REALM)

    @pytest.mark.parametrize("body", [b"not json", b"[1, 2]", None])
    async def test_unparseable_402_bodies_are_payment_required(self, body: bytes | None) -> None:
        response = Response(402, headers={"WWW-Authenticate": self._header()}, body=body)
        result = await self._run(response)
        assert isinstance(result, list)
        assert len(result) == 1

    async def test_unparseable_final_bodies_are_verification_errors(self) -> None:
        from mpp.extensions.mcp import PaymentVerificationError

        with pytest.raises(PaymentVerificationError):
            await self._run(Response(403, body=b"[]"))


class TestReviewFixes:
    """Regressions for the PR #339 review findings."""

    @staticmethod
    def _faked(methods: list[ServerMethod], seen: list[str]) -> list[ServerMethod]:
        """Copies of tempo methods whose hooks record their currency instead of calling RPC."""
        from mpp._validation import Validation

        def hooks(currency: str) -> dict[str, Any]:
            async def validate(context: Any) -> Validation:
                seen.append(currency)
                return Validation(
                    credential=context.credential,
                    details=None,
                    intent="charge",
                    request=context.challenge.request,
                )

            async def broadcast(context: Any) -> Receipt:
                return Receipt.success("0x" + "ab" * 32)

            return {"validate": validate, "broadcast": broadcast}

        return [
            replace(method, **hooks(cast(Any, method.defaults)["currency"])) for method in methods
        ]

    async def test_validate_credential_picks_the_currency_copy_that_issued_it(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        methods = self._faked(
            tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC]), seen
        )
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.tempo.charge(amount="1", currency=USDC)(http_request()))
        await server.validate_credential(authorization(issued, {"type": "hash", "hash": "0x12"}))
        assert seen == [USDC]

    async def test_validate_credential_rejects_ambiguous_or_unknown_copies(self) -> None:
        from mpp.errors import InvalidChallengeError

        seen: list[str] = []
        first, second = (
            self._faked(tempo_server.charge(recipient=recipient, currency=CURRENCY), seen)[0]
            for recipient in (RECIPIENT, OTHER)
        )
        server = Mpp(methods=[first, second], realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x12"}
        # A route recipient matching neither configuration leaves both copies.
        issued = challenge(
            await server.compose((first, {"amount": "1", "recipient": "0x" + "33" * 20}))(
                http_request()
            )
        )
        with pytest.raises(InvalidChallengeError, match="several configured methods"):
            await server.validate_credential(authorization(issued, payload))
        # The configured recipient selects its copy.
        issued = challenge(await server.compose((second, {"amount": "1"}))(http_request()))
        await server.validate_credential(authorization(issued, payload))
        assert seen == [CURRENCY]
        other = Mpp(
            methods=self._faked(
                tempo_server.charge(recipient=RECIPIENT, currency="0x" + "44" * 20), seen
            )
            + [first],
            realm=REALM,
            secret_key=SECRET,
        )
        foreign = Challenge.create(
            secret_key=SECRET,
            realm=REALM,
            method="tempo",
            intent="charge",
            request={**issued.request, "currency": "0x" + "55" * 20},
            expires=issued.expires,
        )
        with pytest.raises(InvalidChallengeError, match="does not match a configured method"):
            await other.validate_credential(authorization(foreign, payload))

    async def test_unknown_credential_options_are_rejected(self) -> None:
        from mpp.errors import VerificationFailedError
        from mpp.methods.stripe import server as stripe_server

        seen: list[str] = []
        server = Mpp(
            methods=self._faked(tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY), seen),
            realm=REALM,
            secret_key=SECRET,
        )
        issued = challenge(await server.charge(amount="1")(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0x12"})
        with pytest.raises(TypeError, match="unsupported method option: bogus"):
            await server.validate_credential(credential, bogus=1)
        with pytest.raises(TypeError, match="unsupported method option: payment_intent_options"):
            await server.broadcast_credential(credential, payment_intent_options={})
        assert seen == []

        stripe = Mpp(
            methods=stripe_server.charge(secret_key="sk_test", network_id="bn_1", currency="usd"),
            realm=REALM,
            secret_key=SECRET,
        )
        issued = challenge(await stripe.charge(amount="0.50")(http_request()))
        credential = authorization(issued, {"spt": "spt_test"})
        with pytest.raises(VerificationFailedError, match="non-mutating"):
            await stripe.validate_credential(credential, payment_intent_options={})
        with pytest.raises(TypeError, match="unsupported method option: bogus"):
            await stripe.validate_credential(credential, bogus=1)

    async def test_explicit_none_route_options_keep_method_defaults(self) -> None:
        seen: list[str] = []
        methods = self._faked(tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY), seen)
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge(amount="1", currency=None)(http_request()))
        assert issued.request["currency"] == CURRENCY
        composed = server.compose((methods[0], {"amount": "1", "currency": None}))
        assert challenge(await composed(http_request())).request["currency"] == CURRENCY
        await server.validate_credential(
            authorization(issued, {"type": "hash", "hash": "0x12"}),
            request={"amount": "1", "currency": None},
            meta=None,
        )
        assert seen == [CURRENCY]

    async def test_payment_success_hook_runs_once_per_payment(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        calls: list[Any] = []
        methods = self._faked(
            tempo_server.charge(
                recipient=RECIPIENT, currencies=[PATH_USD, USDC], on_payment_success=calls.append
            ),
            [],
        )
        assert len(methods) == 2
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x12"}
        issued = challenge(await server.tempo.charge(amount="1", currency=USDC)(http_request()))
        await server.broadcast_credential(authorization(issued, payload))
        assert len(calls) == 1
        route = server.tempo.charge(amount="1", currency=PATH_USD)
        issued = challenge(await route(http_request()))
        result = await route(http_request(authorization(issued, payload)))
        assert isinstance(result, PaymentVerified)
        assert len(calls) == 2

    async def test_payment_success_hooks_stay_with_their_configuration(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        first: list[Any] = []
        second: list[Any] = []
        methods = [
            *self._faked(
                tempo_server.charge(
                    recipient=RECIPIENT, currencies=[PATH_USD], on_payment_success=first.append
                ),
                [],
            ),
            *self._faked(
                tempo_server.charge(
                    recipient=RECIPIENT, currencies=[USDC], on_payment_success=second.append
                ),
                [],
            ),
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x34"}
        issued = challenge(await server.tempo.charge(amount="1", currency=USDC)(http_request()))
        await server.broadcast_credential(authorization(issued, payload))
        assert (len(first), len(second)) == (0, 1)
        route = server.tempo.charge(amount="1", currency=PATH_USD)
        issued = challenge(await route(http_request()))
        result = await route(http_request(authorization(issued, payload)))
        assert isinstance(result, PaymentVerified)
        assert (len(first), len(second)) == (1, 1)
