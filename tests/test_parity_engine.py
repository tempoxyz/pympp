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
                Credential(challenge=issued.to_echo(), payload={}), request={"amount": "2"}
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
        from mpp.errors import InvalidChallengeError
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        methods = self._faked(
            tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC]), seen
        )
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.tempo.charge(amount="1", currency=USDC)(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0x12"})
        with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
            await server.validate_credential(credential)
        # Each copy's configured currency fills in the request: only USDC's matches.
        await server.validate_credential(credential, request={"amount": "1"})
        assert seen == [USDC]

    async def test_validate_credential_rejects_ambiguous_copies(self) -> None:
        from mpp.errors import InvalidChallengeError

        seen: list[str] = []
        first, second = (
            replace(
                self._faked(tempo_server.charge(recipient=recipient, currency=CURRENCY), [])[0],
                validate=self._recording(label, seen),
            )
            for label, recipient in (("first", RECIPIENT), ("second", OTHER))
        )
        server = Mpp(methods=[first, second], realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x12"}
        for method, label in ((first, "first"), (second, "second")):
            # A route recipient matching neither configuration: both copies expect it.
            options = {"amount": "1", "recipient": "0x" + "33" * 20}
            issued = challenge(await server.compose((method, options))(http_request()))
            credential = authorization(issued, payload)
            with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
                await server.validate_credential(credential)
            with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
                await server.validate_credential(credential, request=options)
            # The configured recipient selects its copy.
            issued = challenge(await server.compose((method, {"amount": "1"}))(http_request()))
            await server.validate_credential(
                authorization(issued, payload), request={"amount": "1"}
            )
            assert seen[-1] == label
        assert seen == ["first", "second"]

    @staticmethod
    def _recording(label: str, seen: list[str]) -> Any:
        from mpp._validation import Validation

        async def validate(context: Any) -> Validation:
            seen.append(label)
            return Validation(
                credential=context.credential,
                details=None,
                intent="charge",
                request=context.challenge.request,
            )

        return validate

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
        await server.broadcast_credential(authorization(issued, payload), request={"amount": "1"})
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
                    recipient=OTHER, currencies=[USDC], on_payment_success=second.append
                ),
                [],
            ),
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x34"}
        options = {"amount": "1", "currency": USDC}
        issued = challenge(await server.tempo.charge(**options)(http_request()))
        await server.broadcast_credential(authorization(issued, payload), request=options)
        assert (len(first), len(second)) == (0, 1)
        route = server.tempo.charge(amount="1", currency=PATH_USD)
        issued = challenge(await route(http_request()))
        result = await route(http_request(authorization(issued, payload)))
        assert isinstance(result, PaymentVerified)
        assert (len(first), len(second)) == (1, 1)

    async def test_broadcast_credential_settles_route_currency_or_chain_overrides(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        methods = self._faked(
            tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC]), seen
        )
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        payload = {"type": "hash", "hash": "0x12"}
        # A chain override leaves the configured currency to select the copy.
        issued = challenge(
            await server.tempo.charge(amount="1", currency=USDC, chain_id=42431)(http_request())
        )
        receipt = await server.broadcast_credential(
            authorization(issued, payload), request={"amount": "1", "chain_id": 42431}
        )
        assert receipt.status == "success"
        assert seen == [USDC]
        # A currency override every copy accepts leaves them indistinguishable.
        options = {"amount": "1", "currency": "0x" + "33" * 20, "chain_id": 42431}
        issued = challenge(await server.tempo.charge(**options)(http_request()))
        with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
            await server.broadcast_credential(authorization(issued, payload), request=options)
        assert seen == [USDC]

    async def test_credential_request_accepts_route_input_or_wire_request(self) -> None:
        from mpp.errors import InvalidChallengeError

        seen: list[str] = []
        methods = self._faked(tempo_server.charge(recipient=RECIPIENT, currency=CURRENCY), seen)
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge(amount="1")(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0x12"})
        wire = {key: value for key, value in issued.request.items() if key != "_mppx_scope"}
        assert wire["amount"] == "1000000"
        await server.validate_credential(credential, request={"amount": "1"})
        await server.validate_credential(credential, request=wire)
        await server.validate_credential(credential, request=dict(issued.request))
        receipt = await server.broadcast_credential(credential, request=wire)
        assert receipt.status == "success"
        assert seen == [CURRENCY] * 4
        for mismatched in ({**wire, "amount": "2000000"}, {**wire, "recipient": OTHER}):
            with pytest.raises(InvalidChallengeError, match="request does not match"):
                await server.validate_credential(credential, request=mismatched)
            with pytest.raises(InvalidChallengeError, match="request does not match"):
                await server.broadcast_credential(credential, request=mismatched)
        assert seen == [CURRENCY] * 4

    async def test_ambiguous_request_is_checked_as_route_input(self) -> None:
        from decimal import Decimal

        from pydantic import BaseModel, ConfigDict, field_validator

        from mpp.errors import InvalidChallengeError
        from mpp.methods import Method
        from mpp.server import ServerMethod

        class Input(BaseModel):
            model_config = ConfigDict(extra="forbid")
            amount: str
            currency: str
            recipient: str

            @field_validator("amount")
            @classmethod
            def to_base_units(cls, value: str) -> str:
                return str(int(Decimal(value) * 10**6))

        method = ServerMethod(
            method=Method(name="units", intent="charge", request_model=Input, payload_model=Input),
            verify=_verified,
            defaults={"currency": CURRENCY, "recipient": RECIPIENT},
        )
        server = Mpp(methods=method, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge(amount="0.000001")(http_request()))
        credential = authorization(
            issued, {"amount": "1", "currency": CURRENCY, "recipient": RECIPIENT}
        )
        wire = {key: value for key, value in issued.request.items() if key != "_mppx_scope"}
        assert wire == {"amount": "1", "currency": CURRENCY, "recipient": RECIPIENT}
        # The same dict reads as route input for 1 token: a 1-base-unit credential must not pass.
        with pytest.raises(InvalidChallengeError, match="request does not match"):
            await server.validate_credential(credential, request=wire)
        with pytest.raises(InvalidChallengeError, match="request does not match"):
            await server.broadcast_credential(credential, request=wire)
        receipt = await server.broadcast_credential(credential, request={"amount": "0.000001"})
        assert receipt.status == "success"

    async def test_evm_credential_request_accepts_the_wire_form(self) -> None:
        from mpp._validation import Validation
        from mpp.errors import InvalidChallengeError

        async def validate(context: Any) -> Validation:
            return Validation(
                credential=context.credential,
                details=None,
                intent="charge",
                request=context.challenge.request,
            )

        async def broadcast(context: Any) -> Receipt:
            return Receipt.success("0x" + "cd" * 32)

        method = replace(
            evm_server.charge(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=_settle),
            validate=validate,
            broadcast=broadcast,
        )
        server = Mpp(methods=method, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge(amount="1")(http_request()))
        wire = {key: value for key, value in issued.request.items() if key != "_mppx_scope"}
        assert "methodDetails" in wire
        credential = authorization(
            issued,
            {
                "type": "authorization",
                "from": "0x" + "11" * 20,
                "to": wire["recipient"],
                "value": wire["amount"],
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": "0x" + "00" * 32,
                "signature": "0x" + "22" * 65,
            },
        )
        await server.validate_credential(credential, request=wire)
        receipt = await server.broadcast_credential(credential, request=wire)
        assert receipt.status == "success"
        with pytest.raises(InvalidChallengeError, match="request does not match"):
            await server.validate_credential(credential, request={**wire, "amount": "2"})

    async def test_mcp_tools_can_be_paid_when_requires_auth(self) -> None:
        from mpp.extensions.mcp import MCPCredential, verify_or_challenge

        server = Mpp(
            methods=server_method(request={"amount": "1"}, verify=_verified),
            realm=REALM,
            secret_key=SECRET,
            requires_auth=True,
        )
        handler = server.charge()
        issued = await verify_or_challenge(handler, tool="search")
        assert isinstance(issued, list)
        [mcp_challenge] = issued
        credential = MCPCredential(challenge=mcp_challenge, payload={})
        result = await verify_or_challenge(handler, tool="search", meta=credential.to_meta())
        assert isinstance(result, tuple)
        assert result[1].status == "success"
        # HTTP routes still bind the credential header.
        http = challenge(await handler(http_request()))
        assert http.header == "Payment-Authorization"


class TestReviewFixesRound2:
    """Regressions for the second round of PR #339 review findings."""

    @staticmethod
    def _stored(
        methods: list[ServerMethod], store: MemoryStore, seen: list[str]
    ) -> list[ServerMethod]:
        """Copies whose broadcast claims the hash in the store, like the Tempo intent."""
        from mpp._validation import Validation
        from mpp.errors import VerificationFailedError

        async def validate(context: Any) -> Validation:
            return Validation(
                credential=context.credential,
                details=None,
                intent="charge",
                request=context.challenge.request,
            )

        async def broadcast(context: Any) -> Receipt:
            tx_hash = context.credential.payload.model_dump()["hash"]
            if not await store.put_if_absent(f"tempo:charge:{tx_hash}", True):
                raise VerificationFailedError("transaction hash already used")
            seen.append(tx_hash)
            return Receipt.success(tx_hash)

        return [replace(method, validate=validate, broadcast=broadcast) for method in methods]

    def test_only_currency_defaults_compare_case_insensitively(self) -> None:
        upper = server_method(name="plan", request={"amount": "1"}, verify=_verified)
        upper = replace(upper, defaults={"sku": "PlanA"})
        lower = replace(upper, defaults={"sku": "plana"})
        server = Mpp(methods=[upper, lower], realm=REALM, secret_key=SECRET)
        assert [m.defaults for m in server.plan.charge(sku="PlanA").methods] == [{"sku": "PlanA"}]

    async def test_evm_route_currency_selects_its_asset(self) -> None:
        from mpp.methods.evm import BASE_USDC

        server = Mpp(
            methods=[
                evm_server.charge(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=_settle),
                evm_server.charge(currency=BASE_USDC, recipient=RECIPIENT, settle=_settle),
            ],
            realm=REALM,
            secret_key=SECRET,
        )
        for currency in (BASE_USDC.address, BASE_USDC.address.lower()):
            handler = server.evm.charge(amount="1", currency=currency)
            assert [method.defaults for method in handler.methods] == [
                {"currency": BASE_USDC.address}
            ]
            issued = challenge(await handler(http_request()))
            assert issued.request["currency"] == BASE_USDC.address
            assert issued.request["methodDetails"]["chainId"] == BASE_USDC.chain_id

    async def test_broadcast_requires_a_validation_result(self) -> None:
        from mpp.errors import VerificationFailedError

        broadcasts: list[Any] = []

        async def validate(context: Any) -> Any:
            return None

        async def broadcast(context: Any) -> Receipt:
            broadcasts.append(context)
            return Receipt.success("paid")

        server = raw_mpp(validate=validate, broadcast=broadcast)
        route = server.charge()
        issued = challenge(await route(http_request()))
        with pytest.raises(VerificationFailedError, match="invalid validation result"):
            await server.broadcast_credential(authorization(issued))
        result = await route(http_request(authorization(issued)))
        assert isinstance(result, PaymentRequired)
        assert broadcasts == []

        from mpp.server.verify import verify_or_challenge

        class Intent:
            name = "charge"

            async def validate(self, credential: Any, request: Any) -> Any:
                return None

            async def broadcast(self, credential: Any, request: Any) -> Receipt:
                broadcasts.append(credential)
                return Receipt.success("paid")

        options: dict[str, Any] = {
            "intent": Intent(),
            "request": {"amount": "1"},
            "realm": REALM,
            "secret_key": SECRET,
            "method": "tempo",
        }
        issued = await verify_or_challenge(authorization=None, **options)
        assert isinstance(issued, Challenge)
        with pytest.raises(VerificationFailedError, match="invalid validation result"):
            await verify_or_challenge(authorization=authorization(issued), **options)
        assert broadcasts == []

    async def test_credential_request_checks_custom_scope(self) -> None:
        from mpp.errors import InvalidChallengeError

        server = raw_mpp()
        issued = challenge(
            await server.charge(_mppx_scope={"account": "invoice:42"})(http_request())
        )
        assert issued.request["_mppx_scope"]["custom"] == {"account": "invoice:42"}
        credential = authorization(issued)
        wire = dict(issued.request)
        # This method accepts the wire request as route input: a scope naming another
        # custom scope does not match, while the whole signed scope it passes through does.
        for request in (
            {"amount": "1", "_mppx_scope": {"account": "invoice:43"}},
            {**wire, "_mppx_scope": {**wire["_mppx_scope"], "custom": {"account": "invoice:43"}}},
        ):
            with pytest.raises(InvalidChallengeError, match="scope does not match"):
                await server.broadcast_credential(credential, request=request)
        # The issued custom scope, the whole signed scope, or no scope at all match.
        for request in (
            {"amount": "1", "_mppx_scope": {"account": "invoice:42"}},
            {"amount": "1"},
            wire,
        ):
            receipt = await server.broadcast_credential(credential, request=request)
            assert receipt.status == "success"

    def test_signed_resource_keeps_percent_encoding(self) -> None:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from mpp.server import pay

        server = raw_mpp()

        @pay(server.charge())
        async def endpoint(request: Any, credential: Any, receipt: Any) -> JSONResponse:
            return JSONResponse({})

        client = TestClient(Starlette(routes=[Route("/files/{name:path}", endpoint)]))
        resources = {}
        for path in ("/files/a/b", "/files/a%2Fb", "/files/x", "/files/x%23y", "/files/x%3Fy"):
            response = client.get(path)
            issued = Challenge.from_www_authenticate(response.headers["www-authenticate"])
            resources[path] = issued.request["_mppx_scope"]["resource"]
        assert resources == {path: path for path in resources}
        assert Request("GET", "https://h/files/a%2Fb?q=1").scope()["resource"] == "/files/a%2Fb"

    async def test_pay_accepts_non_ascii_header_bytes(self) -> None:
        from mpp.server import pay

        class StarletteRequest:
            headers = {"x-name": "caf\xe9"}
            method = "GET"
            path = "/paid"

        async def endpoint(request: Any, credential: Any, receipt: Any) -> dict[str, str]:
            return {}

        result: Any = await pay(raw_mpp().charge())(endpoint)(StarletteRequest())
        assert result.status_code == 402
        assert Request("GET", "/", headers={"x-name": "caf\xe9"}).headers["x-name"] == "caf\xe9"

    async def test_pay_reads_the_body_for_methods_that_need_it(self) -> None:
        from mpp.server import RequestContext, pay

        bodies: list[bytes | None] = []

        def resolve_request(context: RequestContext) -> dict[str, Any]:
            bodies.append(context.input.body if context.input is not None else None)
            return context.request

        class StarletteRequest:
            headers: dict[str, str] = {}
            method = "POST"
            path = "/paid"

            async def body(self) -> bytes:
                return b"{}"

        async def endpoint(request: Any, credential: Any, receipt: Any) -> dict[str, str]:
            return {}

        server = Mpp(
            methods=server_method(
                request={"amount": "1"},
                verify=_verified,
                resolve_request=resolve_request,
                needs_request_body=True,
            ),
            realm=REALM,
            secret_key=SECRET,
        )
        handler = server.charge()
        assert handler.needs_request_body
        await pay(handler)(endpoint)(StarletteRequest())
        assert bodies[-1] == b"{}"


class TestOutOfBandSelection:
    """Out of band, separately configured methods of one name and intent need request=."""

    _stored = staticmethod(TestReviewFixesRound2._stored)

    @staticmethod
    def _groups(
        first: dict[str, Any], second: dict[str, Any], seen: list[str]
    ) -> tuple[list[ServerMethod], list[ServerMethod], MemoryStore, MemoryStore]:
        stores = MemoryStore(), MemoryStore()
        groups = [
            TestOutOfBandSelection._stored(tempo_server.charge(store=store, **options), store, seen)
            for options, store in zip((first, second), stores, strict=True)
        ]
        return groups[0], groups[1], stores[0], stores[1]

    async def test_copies_sharing_one_intents_bound_methods_settle_alike(self) -> None:
        from mpp._validation import Validation

        class Intent:
            def __init__(self) -> None:
                self.settled: list[str] = []

            async def validate(self, context: Any) -> Validation:
                return Validation(
                    credential=context.credential,
                    details=None,
                    intent="charge",
                    request=context.challenge.request,
                )

            async def broadcast(self, context: Any) -> Receipt:
                self.settled.append(context.challenge.request["currency"])
                return Receipt.success("0x" + "ab" * 32)

        intent = Intent()
        base = server_method(request={"amount": "1"}, verify=_verified)
        methods = [
            replace(
                base,
                verify=None,
                validate=intent.validate,
                broadcast=intent.broadcast,
                defaults={"currency": currency},
            )
            for currency in ("usd", "eur")
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        issued = challenge(await server.charge(amount="1", currency="eur")(http_request()))
        await server.broadcast_credential(authorization(issued, {}))
        assert intent.settled == ["eur"]

    async def test_groups_settle_through_the_issuing_group_with_request(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        first, second, first_store, second_store = self._groups(
            {"recipient": RECIPIENT, "currencies": [PATH_USD]},
            {"recipient": OTHER, "currencies": [USDC]},
            seen,
        )
        server = Mpp(methods=[*first, *second], realm=REALM, secret_key=SECRET)
        for currency, store, other, tx_hash in (
            (PATH_USD, first_store, second_store, "0x12"),
            (USDC, second_store, first_store, "0x34"),
        ):
            options = {"amount": "1", "currency": currency}
            route = server.tempo.charge(**options)
            issued = challenge(await route(http_request()))
            credential = authorization(issued, {"type": "hash", "hash": tx_hash})
            for settle in (server.broadcast_credential, server.validate_credential):
                with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
                    await settle(credential)
            receipt = await server.broadcast_credential(credential, request=options)
            assert receipt.reference == tx_hash
            assert await store.get(f"tempo:charge:{tx_hash}") is True
            assert await other.get(f"tempo:charge:{tx_hash}") is None
            # The issuing route's store already holds the hash: no second payment.
            assert isinstance(await route(http_request(credential)), PaymentRequired)
        assert seen == ["0x12", "0x34"]

    async def test_request_naming_a_shared_override_cannot_tell_groups_apart(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        first, second, first_store, second_store = self._groups(
            {"recipient": RECIPIENT, "currencies": [PATH_USD]},
            {"recipient": RECIPIENT, "currencies": [USDC]},
            seen,
        )
        server = Mpp(methods=[*first, *second], realm=REALM, secret_key=SECRET)
        route = server.tempo.charge(amount="1", currency=USDC)
        issued = challenge(await route(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0x45"})
        # The currency overrides the only field the groups differ in.
        with pytest.raises(InvalidChallengeError, match="cannot be told apart by request"):
            await server.broadcast_credential(credential, request={"amount": "1", "currency": USDC})
        assert seen == []
        await server.broadcast_credential(credential, request={"amount": "1"})
        assert await second_store.get("tempo:charge:0x45") is True
        assert await first_store.get("tempo:charge:0x45") is None

    async def test_route_overriding_into_another_group(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.methods.tempo import PATH_USD, USDC

        for second_recipient, overrides, distinct in (
            (OTHER, {"recipient": RECIPIENT}, True),
            (OTHER, {"currency": PATH_USD}, True),
            (OTHER, {"recipient": RECIPIENT, "currency": PATH_USD}, False),
            (RECIPIENT, {"currency": PATH_USD}, False),
        ):
            seen: list[str] = []
            first, second, first_store, second_store = self._groups(
                {"recipient": RECIPIENT, "currencies": [PATH_USD]},
                {"recipient": second_recipient, "currencies": [USDC]},
                seen,
            )
            server = Mpp(methods=[*first, *second], realm=REALM, secret_key=SECRET)
            options = {"amount": "1", **overrides}
            route = server.compose((second[0], options))
            issued = challenge(await route(http_request()))
            credential = authorization(issued, {"type": "hash", "hash": "0x56"})
            if not distinct:
                # Both groups expect the same request: refuse rather than guess.
                with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
                    await server.broadcast_credential(credential, request=options)
                assert seen == []
                continue
            await server.broadcast_credential(credential, request=options)
            assert await second_store.get("tempo:charge:0x56") is True
            assert await first_store.get("tempo:charge:0x56") is None
            assert isinstance(await route(http_request(credential)), PaymentRequired)
            assert seen == ["0x56"]

    async def test_identical_groups_cannot_settle_out_of_band(self) -> None:
        from mpp.errors import InvalidChallengeError

        seen: list[str] = []
        first, second, first_store, second_store = self._groups(
            {"recipient": RECIPIENT, "currency": CURRENCY},
            {"recipient": RECIPIENT, "currency": CURRENCY},
            seen,
        )
        server = Mpp(methods=[*first, *second], realm=REALM, secret_key=SECRET)
        for method, store, other, tx_hash in (
            (first[0], first_store, second_store, "0x81"),
            (second[0], second_store, first_store, "0x82"),
        ):
            route = server.compose((method, {"amount": "1"}))
            issued = challenge(await route(http_request()))
            credential = authorization(issued, {"type": "hash", "hash": tx_hash})
            with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
                await server.broadcast_credential(credential)
            for request in ({"amount": "1"}, dict(issued.request)):
                with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
                    await server.validate_credential(credential, request=request)
            assert isinstance(await route(http_request(credential)), PaymentVerified)
            assert await store.get(f"tempo:charge:{tx_hash}") is True
            assert await other.get(f"tempo:charge:{tx_hash}") is None
        assert seen == ["0x81", "0x82"]

    async def test_one_configurations_currency_copies_settle_out_of_band(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        configured = tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC])
        # Copies of one configuration share their settlement hooks.
        assert configured[0].validate is configured[1].validate
        assert configured[0].broadcast is configured[1].broadcast

        seen: list[str] = []
        store = MemoryStore()
        methods = self._stored(
            tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC], store=store),
            store,
            seen,
        )
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        for currency, plain, named in ((USDC, "0xd1", "0xd2"), (PATH_USD, "0xd3", "0xd4")):
            options = {"amount": "1", "currency": currency}
            for tx_hash, request in ((plain, None), (named, options)):
                issued = challenge(await server.tempo.charge(**options)(http_request()))
                credential = authorization(issued, {"type": "hash", "hash": tx_hash})
                _, method, _, _ = server._prepare_credential(
                    credential, intent=None, request=request
                )
                assert cast(Any, method.defaults)["currency"] == currency
                receipt = await server.broadcast_credential(credential, request=request)
                assert receipt.reference == tx_hash
        assert seen == ["0xd1", "0xd2", "0xd3", "0xd4"]

    async def test_reordered_methods_settle_through_the_issuing_group(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        first, second, first_store, second_store = self._groups(
            {"recipient": RECIPIENT, "currencies": [PATH_USD]},
            {"recipient": OTHER, "currencies": [USDC]},
            seen,
        )
        issuing = Mpp(methods=[*first, *second], realm=REALM, secret_key=SECRET)
        settling = Mpp(methods=[*second, *first], realm=REALM, secret_key=SECRET)
        for currency, store, other, tx_hash in (
            (USDC, second_store, first_store, "0x91"),
            (PATH_USD, first_store, second_store, "0x92"),
        ):
            options = {"amount": "1", "currency": currency}
            issued = challenge(await issuing.tempo.charge(**options)(http_request()))
            credential = authorization(issued, {"type": "hash", "hash": tx_hash})
            receipt = await settling.broadcast_credential(credential, request=options)
            assert receipt.reference == tx_hash
            assert await store.get(f"tempo:charge:{tx_hash}") is True
            assert await other.get(f"tempo:charge:{tx_hash}") is None
        assert seen == ["0x91", "0x92"]

    async def test_a_single_method_settles_without_request(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        seen: list[str] = []
        store = MemoryStore()
        issuing = Mpp(
            methods=tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC]),
            realm=REALM,
            secret_key=SECRET,
        )
        worker = Mpp(
            methods=self._stored(
                tempo_server.charge(recipient=RECIPIENT, currencies=[USDC], store=store),
                store,
                seen,
            ),
            realm=REALM,
            secret_key=SECRET,
        )
        issued = challenge(await issuing.tempo.charge(amount="1", currency=USDC)(http_request()))
        receipt = await worker.broadcast_credential(
            authorization(issued, {"type": "hash", "hash": "0xc1"})
        )
        assert receipt.reference == "0xc1"
        assert seen == ["0xc1"]

    async def test_several_single_currency_stripe_charges(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.methods.stripe import server as stripe_server

        seen: list[str] = []

        def recording(currency: str) -> Any:
            async def verify(context: Any) -> Receipt:
                seen.append(currency)
                return Receipt.success("pi_" + currency)

            return verify

        methods = [
            replace(
                stripe_server.charge(secret_key="sk_test", network_id="bn_1", currency=currency),
                verify=recording(currency),
            )
            for currency in ("usd", "eur")
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        for currency in ("eur", "usd"):
            options = {"amount": "0.50", "currency": currency}
            issued = challenge(await server.stripe.charge(**options)(http_request()))
            credential = authorization(issued, {"spt": "spt_1"})
            with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
                await server.broadcast_credential(credential)
            # Naming the currency overrides each method's own: both expect it alike.
            with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
                await server.broadcast_credential(credential, request=options)
            # Each method's configured currency tells them apart.
            receipt = await server.broadcast_credential(credential, request={"amount": "0.50"})
            assert receipt.reference == "pi_" + currency
        assert seen == ["eur", "usd"]

    async def test_challenges_carry_no_offer_tag(self) -> None:
        from mpp.methods.tempo import PATH_USD, USDC

        methods = tempo_server.charge(recipient=RECIPIENT, currencies=[PATH_USD, USDC])
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        route = server.tempo.charge(amount="1", currency=USDC, meta={"order": "1"})
        issued = challenge(await route(http_request()))
        assert set(issued.opaque or {}) == {"_mpp_nonce", "order"}
        plain = Mpp(methods=methods, realm=REALM, secret_key=SECRET, unique_challenges=False)
        route = plain.tempo.charge(amount="1", currency=USDC, meta={"order": "1"})
        issued = challenge(await route(http_request()))
        assert issued.opaque == {"order": "1"}
        # The same challenge a direct issuance produces, byte for byte.
        expected = Challenge.create(
            secret_key=SECRET,
            realm=REALM,
            method="tempo",
            intent="charge",
            request=issued.request,
            expires=issued.expires,
            description=issued.description,
            digest=issued.digest,
            meta={"order": "1"},
        )
        assert issued.to_www_authenticate(REALM) == expected.to_www_authenticate(REALM)

    async def test_route_input_scope_is_compared_normalized(self) -> None:
        from mpp.errors import InvalidChallengeError

        server = raw_mpp()
        issued = challenge(await server.charge(_mppx_scope={"ids": ("a", "b")})(http_request()))
        assert issued.request["_mppx_scope"]["custom"] == {"ids": ["a", "b"]}
        credential = authorization(issued)
        receipt = await server.broadcast_credential(
            credential, request={"amount": "1", "_mppx_scope": {"ids": ("a", "b")}}
        )
        assert receipt.status == "success"
        with pytest.raises(InvalidChallengeError, match="scope does not match"):
            await server.broadcast_credential(
                credential, request={"amount": "1", "_mppx_scope": {"ids": ("a", "c")}}
            )

    async def test_route_input_scope_is_compared_without_unwrapping(self) -> None:
        from mpp.errors import InvalidChallengeError

        server = raw_mpp()
        scope = {"http_method": "POST", "resource": "invoice:43"}
        unscoped = authorization(challenge(await server.charge()(http_request())))
        with pytest.raises(InvalidChallengeError, match="credential scope does not match"):
            await server.broadcast_credential(
                unscoped, request={"amount": "1", "_mppx_scope": scope}
            )
        issued = challenge(await server.charge(_mppx_scope=scope)(http_request()))
        assert issued.request["_mppx_scope"]["custom"] == scope
        receipt = await server.broadcast_credential(
            authorization(issued), request={"amount": "1", "_mppx_scope": scope}
        )
        assert receipt.status == "success"

    async def test_scope_derived_by_resolve_request_is_enforced(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.server import RequestContext

        def resolve_request(context: RequestContext) -> dict[str, Any]:
            input = dict(context.request)
            account = input.pop("account", None)
            if account is not None:
                input["_mppx_scope"] = {"account": account}
            return input

        server = Mpp(
            methods=server_method(
                request={"amount": "1"}, verify=_verified, resolve_request=resolve_request
            ),
            realm=REALM,
            secret_key=SECRET,
        )
        issued = challenge(await server.charge(account="acct_1")(http_request()))
        assert issued.request["_mppx_scope"]["custom"] == {"account": "acct_1"}
        assert "account" not in issued.request
        credential = authorization(issued)
        with pytest.raises(InvalidChallengeError, match="scope does not match"):
            await server.validate_credential(credential, request={"account": "acct_2"})
        with pytest.raises(InvalidChallengeError, match="scope does not match"):
            await server.broadcast_credential(credential, request={"account": "acct_2"})
        receipt = await server.broadcast_credential(credential, request={"account": "acct_1"})
        assert receipt.status == "success"

    @staticmethod
    def _bound_to(recipient: str) -> Any:
        """A resolve_request that needs a recipient and accepts only its own."""
        from mpp.server import RequestContext

        def resolve_request(context: RequestContext) -> dict[str, Any]:
            if context.request.get("recipient") != recipient:
                raise ValueError("recipient is not this method's")
            return dict(context.request)

        return resolve_request

    async def test_methods_bound_by_resolve_request_settle_with_request(self) -> None:
        from mpp.errors import InvalidChallengeError

        def verify(label: str) -> Any:
            async def hook(context: Any) -> Receipt:
                return Receipt.success(label)

            return hook

        # Equal name, intent and defaults: only the route's request selects one.
        methods = [
            server_method(verify=verify(label), resolve_request=self._bound_to(recipient))
            for label, recipient in (("first", RECIPIENT), ("second", OTHER))
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        for method, recipient, label in (
            (methods[0], RECIPIENT, "first"),
            (methods[1], OTHER, "second"),
        ):
            options = {"amount": "1", "recipient": recipient}
            issued = challenge(await server.compose((method, options))(http_request()))
            credential = authorization(issued)
            with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
                await server.broadcast_credential(credential)
            receipt = await server.broadcast_credential(credential, request=options)
            assert receipt.reference == label
            route = server.compose((method, options))
            assert not isinstance(await route(http_request(credential)), PaymentRequired)

    async def test_methods_bound_by_resolve_request_are_not_resolved_by_position(self) -> None:
        from mpp.errors import InvalidChallengeError

        stores = {RECIPIENT: MemoryStore(), OTHER: MemoryStore()}
        seen: dict[str, list[str]] = {RECIPIENT: [], OTHER: []}

        def method(recipient: str) -> ServerMethod:
            from mpp.errors import VerificationFailedError

            async def broadcast(context: Any) -> Receipt:
                # Claims the hash in this method's own replay store.
                tx_hash = context.credential.payload["hash"]
                if not await stores[recipient].put_if_absent(f"charge:{tx_hash}", True):
                    raise VerificationFailedError("transaction hash already used")
                seen[recipient].append(tx_hash)
                return Receipt.success(tx_hash)

            return server_method(broadcast=broadcast, resolve_request=self._bound_to(recipient))

        first, second = method(RECIPIENT), method(OTHER)
        issuing = Mpp(methods=[first, second], realm=REALM, secret_key=SECRET)
        # A settlement worker listing the same methods in another order.
        settling = Mpp(methods=[second, first], realm=REALM, secret_key=SECRET)

        options = {"amount": "1", "recipient": RECIPIENT}
        issued = challenge(await issuing.compose((first, options))(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0xa"})
        with pytest.raises(InvalidChallengeError, match="pass request= to select one"):
            await settling.broadcast_credential(credential)
        with pytest.raises(InvalidChallengeError, match="request does not match"):
            await settling.broadcast_credential(
                credential, request={"amount": "2", "recipient": RECIPIENT}
            )
        receipt = await settling.broadcast_credential(credential, request=options)
        assert receipt.reference == "0xa"
        assert seen == {RECIPIENT: ["0xa"], OTHER: []}

        # The other copy's replay store was left alone: its own payment still settles.
        other = {"amount": "1", "recipient": OTHER}
        issued = challenge(await issuing.compose((second, other))(http_request()))
        credential = authorization(issued, {"type": "hash", "hash": "0xa"})
        receipt = await settling.broadcast_credential(credential, request=other)
        assert receipt.reference == "0xa"
        assert seen == {RECIPIENT: ["0xa"], OTHER: ["0xa"]}

    async def test_identical_copies_are_not_settled_out_of_band(self) -> None:
        from mpp.errors import InvalidChallengeError
        from mpp.server import RequestContext

        def resolve_request(context: RequestContext) -> dict[str, Any]:
            if "recipient" not in context.request:
                raise ValueError("recipient is required")
            return dict(context.request)

        def verified() -> Any:
            # Each copy settles through its own hook, as separately configured methods do.
            async def verify(context: Any) -> Receipt:
                return await _verified(context)

            return verify

        methods = [
            server_method(verify=verified(), resolve_request=resolve_request) for _ in range(2)
        ]
        server = Mpp(methods=methods, realm=REALM, secret_key=SECRET)
        options = {"amount": "1", "recipient": RECIPIENT}
        issued = challenge(await server.compose((methods[1], options))(http_request()))
        credential = authorization(issued)
        with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
            await server.broadcast_credential(credential, request=options)
        with pytest.raises(InvalidChallengeError, match="cannot be told apart"):
            await server.broadcast_credential(credential, request=dict(issued.request))

    async def test_whole_wire_scope_is_accepted_as_route_input(self) -> None:
        server = raw_mpp()
        issued = challenge(await server.charge()(http_request()))
        assert "custom" not in issued.request["_mppx_scope"]
        # This method's model passes the whole wire request through as route input.
        receipt = await server.broadcast_credential(
            authorization(issued), request=dict(issued.request)
        )
        assert receipt.status == "success"
