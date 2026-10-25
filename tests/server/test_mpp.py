import json
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from mpp import (
    AuthorizeResult,
    CapturedRequest,
    Challenge,
    Credential,
    Header,
    InternalPaymentError,
    Method,
    PaymentError,
    Receipt,
    RequestContext,
    ServerMethod,
    VerificationFailedError,
    VerifyContext,
    _base64url,
    _json,
    payment_request,
)
from mpp.credential import MAX_AUTHORIZATION_LENGTH
from mpp.server import Mpp, Request, Response, http
from mpp.server._transport import HttpTransport

from ._fixtures import (
    REALM,
    SECRET_KEY,
    SigPayload,
    TokenPayload,
    credential_header,
    future,
    http_request,
    mock_server,
    receipt,
    simple_method,
    tempo_charge_server,
)

ASSET = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"


def charge_options(**overrides: Any) -> dict[str, Any]:
    return {
        "amount": "1000",
        "currency": ASSET,
        "expires": future(),
        "recipient": RECIPIENT,
        **overrides,
    }


async def body_json(response: Response) -> Any:
    return json.loads(await response.read())


async def challenge_of(handle: Any, url: str = "https://example.com/resource") -> Challenge:
    result = await handle(http_request(url))
    assert result.status == 402
    return Challenge.from_response(result.challenge)


class TestCreate:
    def test_default(self) -> None:
        mppx = Mpp(methods=[tempo_charge_server()], realm=REALM, secret_key=SECRET_KEY)
        assert mppx.realm == REALM
        assert isinstance(mppx.transport, HttpTransport)
        assert mppx.transport.name == "http"
        assert callable(mppx.charge)
        assert callable(mppx["tempo/charge"])
        assert mppx.tempo.charge is mppx["tempo/charge"]

    async def test_requires_auth_uses_payment_authorization(self) -> None:
        mppx = Mpp(methods=[mock_server()], realm=REALM, secret_key=SECRET_KEY, requires_auth=True)
        handle = mppx.charge(amount="1", currency="usd")
        result = await handle(http_request(Authorization="Bearer app-token"))
        assert result.status == 402
        challenge = Challenge.from_response(result.challenge)
        assert challenge.header == Header.PAYMENT_AUTHORIZATION
        assert challenge.credential_header == Header.PAYMENT_AUTHORIZATION
        paid = await handle(
            http_request(
                Authorization="Bearer app-token",
                **{"Payment-Authorization": credential_header(challenge, {"token": "x"})},
            )
        )
        assert paid.status == 200

    def test_rejects_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            Mpp(methods=[mock_server()], realm=REALM, secret_key="short")

    def test_rejects_short_env_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MPP_SECRET_KEY", "short")
        with pytest.raises(ValueError, match="at least 32 bytes"):
            Mpp(methods=[mock_server()], realm=REALM)

    def test_missing_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
        with pytest.raises(ValueError, match="Missing secret key"):
            Mpp(methods=[mock_server()], realm=REALM)

    def test_env_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MPP_SECRET_KEY", SECRET_KEY)
        monkeypatch.setenv("MPP_REALM", "env.example.com")
        assert Mpp(methods=[mock_server()]).realm == "env.example.com"

    def test_rejects_reserved_names(self) -> None:
        with pytest.raises(ValueError, match='Method name "challenge" conflicts'):
            Mpp(methods=[mock_server("challenge")], realm=REALM, secret_key=SECRET_KEY)
        with pytest.raises(ValueError, match='Method intent "compose" conflicts'):
            Mpp(methods=[mock_server("x", "compose")], realm=REALM, secret_key=SECRET_KEY)

    def test_flattens_nested_methods(self) -> None:
        mppx = Mpp(
            methods=[[mock_server("a"), mock_server("b", "session")]],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        assert [m.name for m in mppx.methods] == ["a", "b"]


class TestMultiMethodIntent:
    def methods(self, second_intent: str) -> list[ServerMethod]:
        foo = simple_method("foo")
        bar = simple_method("bar", second_intent)

        async def verify(_: VerifyContext[Any]) -> Receipt:
            return receipt("foo")

        return [
            ServerMethod(method=foo, defaults={"currency": "usd"}, verify=verify),
            ServerMethod(method=bar, defaults={"currency": "eur"}, verify=verify),
        ]

    async def test_composes_shared_intent(self) -> None:
        mppx = Mpp(methods=self.methods("charge"), secret_key=SECRET_KEY, realm=REALM)
        result = await mppx.charge(amount="100")(Request("GET", "http://localhost"))
        assert result.status == 402
        www = result.challenge.headers.get("www-authenticate")
        assert 'method="foo"' in www
        assert 'method="bar"' in www

    async def test_unique_intent_direct_handler(self) -> None:
        mppx = Mpp(methods=self.methods("session"), secret_key=SECRET_KEY, realm=REALM)
        result = await mppx.charge(amount="100", currency="usd")(Request("GET", "http://localhost"))
        www = result.challenge.headers.get("www-authenticate")
        assert 'method="foo"' in www
        assert 'method="bar"' not in www


class TestRequestHandler:
    def mppx(self, **kwargs: Any) -> Mpp:
        return Mpp(methods=[tempo_charge_server()], realm=REALM, secret_key=SECRET_KEY, **kwargs)

    async def test_402_without_authorization(self) -> None:
        result = await self.mppx().charge(**charge_options())(http_request())
        assert result.status == 402
        assert "Payment" in result.challenge.headers["WWW-Authenticate"]
        assert result.challenge.headers["Cache-Control"] == "no-store"
        assert result.challenge.headers["Content-Type"] == "application/problem+json"
        body = await body_json(result.challenge)
        assert body.pop("challengeId")
        assert body == {
            "detail": "Payment is required.",
            "hint": "Use a supported wallet to pay for this resource using one of the supported payment methods returned in the WWW-Authenticate header. See https://mpp.dev/tools/wallet.md",
            "status": 402,
            "title": "Payment Required",
            "type": "https://paymentauth.org/problems/payment-required",
        }

    async def test_malformed_credential(self) -> None:
        result = await self.mppx().charge(**charge_options())(
            http_request(Authorization="Payment invalid")
        )
        assert result.status == 402
        body = await body_json(result.challenge)
        assert body["detail"] == "Credential is malformed: Invalid base64url or JSON.."
        assert body["title"] == "Malformed Credential"
        assert body["type"] == "https://paymentauth.org/problems/malformed-credential"

    async def test_sanitized_internal_error_for_transport_failures(self) -> None:
        class LeakingHttp(HttpTransport):
            def get_credential(self, input: Request) -> Credential[Any] | None:
                raise RuntimeError("request to https://rpc.example.com/?key=secret-key failed")

        result = await self.mppx(transport=LeakingHttp()).charge(**charge_options())(
            http_request(Authorization="Payment invalid")
        )
        assert result.status == 402
        assert result.challenge.status == 500
        body = await body_json(result.challenge)
        assert body["detail"] == "An internal payment error occurred."
        assert "secret-key" not in json.dumps(body)

    async def test_challenge_id_mismatch(self) -> None:
        wrong = Challenge.create(
            id="wrong-id",
            intent="charge",
            method="tempo",
            realm=REALM,
            request={"amount": "1000", "currency": ASSET, "recipient": RECIPIENT},
        )
        result = await self.mppx().charge(**charge_options())(
            http_request(
                Authorization=credential_header(
                    wrong, {"signature": "0x123", "type": "transaction"}
                )
            )
        )
        body = await body_json(result.challenge)
        assert (
            body["detail"]
            == 'Challenge "wrong-id" is invalid: challenge was not issued by this server.'
        )
        assert body["title"] == "Invalid Challenge"

    async def test_threads_captured_request_and_envelope(self) -> None:
        captures: list[CapturedRequest] = []
        seen: dict[str, Any] = {}

        class CountingHttp(HttpTransport):
            async def capture_request(self, input: Request) -> CapturedRequest:
                captured = await super().capture_request(input)
                captures.append(captured)
                return captured

            def respond_receipt(self, **kwargs: Any) -> Response:
                seen["receipt_envelope"] = kwargs.get("envelope")
                return super().respond_receipt(**kwargs)

        def resolve_request(ctx: RequestContext) -> dict[str, Any]:
            if ctx.credential is not None:
                seen["request_captured"] = ctx.captured_request
            return ctx.request

        async def verify(ctx: VerifyContext[Any]) -> Receipt:
            seen["verify_envelope"] = ctx.envelope
            assert ctx.request["amount"] == "1000"
            assert isinstance(ctx.credential.payload, TokenPayload)
            return receipt()

        def respond(ctx: Any) -> Response:
            seen["respond_envelope"] = ctx.envelope
            return Response(200, body=b"ok")

        method = mock_server(verify=verify, resolve_request=resolve_request, respond=respond)
        mppx = Mpp(methods=[method], realm=REALM, secret_key=SECRET_KEY, transport=CountingHttp())
        options = {"amount": "1000", "currency": "0x1", "recipient": "0x2", "expires": future()}
        challenge = await challenge_of(
            mppx.charge(**options), "https://example.com/resource?first=1"
        )
        result = await mppx.charge(**options)(
            http_request(
                "https://example.com/resource?second=1",
                Authorization=credential_header(challenge, {"token": "valid"}),
            )
        )
        assert result.status == 200
        assert result.with_receipt().status == 200
        assert len(captures) == 2
        captured = seen["request_captured"]
        assert captured.url.path == "/resource"
        assert captured.url.query == b"second=1"
        assert seen["verify_envelope"].captured_request is captured
        assert seen["respond_envelope"].captured_request is captured
        assert seen["receipt_envelope"].captured_request is captured
        assert seen["receipt_envelope"].challenge.id == challenge.id

    async def test_cross_route_credential_rejected(self) -> None:
        mppx = self.mppx()
        cheap = await challenge_of(
            mppx.charge(**charge_options(amount="1")), "https://example.com/cheap"
        )
        result = await mppx.charge(**charge_options(amount="1000000"))(
            http_request(
                "https://example.com/expensive",
                Authorization=credential_header(cheap, {"signature": "0x1", "type": "transaction"}),
            )
        )
        assert result.status == 402
        assert "does not match" in (await body_json(result.challenge))["detail"]

    async def test_expired_challenge(self) -> None:
        handle = self.mppx().charge(**charge_options(expires=future(-60)))
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(
                Authorization=credential_header(
                    challenge, {"signature": "0x1", "type": "transaction"}
                )
            )
        )
        body = await body_json(result.challenge)
        assert body["title"] == "Payment Expired"
        assert body["type"] == "https://paymentauth.org/problems/payment-expired"
        assert "Payment expired at" in body["detail"]

    async def test_missing_expires_fails_closed(self) -> None:
        handle = self.mppx().charge(**charge_options())
        server_challenge = await challenge_of(handle)
        no_expires = Challenge.create(
            secret_key=SECRET_KEY,
            realm=server_challenge.realm,
            method=server_challenge.method,
            intent=server_challenge.intent,
            request=server_challenge.request,
            opaque=server_challenge.opaque,
        )
        result = await handle(
            http_request(
                Authorization=credential_header(
                    no_expires, {"signature": "0x1", "type": "transaction"}
                )
            )
        )
        body = await body_json(result.challenge)
        assert body["title"] == "Invalid Challenge"
        assert "missing required expires" in body["detail"]

    async def test_malformed_expires(self) -> None:
        handle = self.mppx().charge(**charge_options())
        server_challenge = await challenge_of(handle)
        wire = {
            "challenge": {
                **{
                    k: v
                    for k, v in server_challenge.to_dict().items()
                    if k not in ("meta", "request")
                },
                "expires": "not-a-timestamp",
                "request": payment_request.serialize(server_challenge.request),
            },
            "payload": {"signature": "0x123", "type": "transaction"},
        }
        header = "Payment " + _base64url.encode(_json.dumps(wire))
        result = await handle(http_request(Authorization=header))
        assert (await body_json(result.challenge))["title"] == "Malformed Credential"

    async def test_payload_validation_failure(self) -> None:
        handle = self.mppx().charge(**charge_options())
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(Authorization=credential_header(challenge, {"invalidField": "bad"}))
        )
        body = await body_json(result.challenge)
        assert body["title"] == "Invalid Payload"
        assert body["detail"] == "Credential payload is invalid."

    async def test_sanitized_internal_error_for_verifier_failures(self) -> None:
        async def verify(_: VerifyContext[Any]) -> Receipt:
            raise RuntimeError("request to https://mainnet.infura.io/v3/secret-key failed")

        mppx = Mpp(methods=[mock_server(verify=verify)], realm=REALM, secret_key=SECRET_KEY)
        handle = mppx["mock/charge"](
            amount="1000", currency=ASSET, recipient=RECIPIENT, expires=future()
        )
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert result.challenge.status == 500
        body = await body_json(result.challenge)
        assert body["detail"] == "An internal payment error occurred."
        assert "infura" not in json.dumps(body)

    async def test_success_attaches_receipt(self) -> None:
        handle = self.mppx().charge(**charge_options())
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(
                Authorization=credential_header(
                    challenge, {"signature": "0x1", "type": "transaction"}
                )
            )
        )
        assert result.status == 200
        response = result.with_receipt(
            Response.json({"ok": True}, headers={"Cache-Control": "max-age=60"})
        )
        assert response.status == 200
        assert response.headers["Cache-Control"] == "max-age=60, private"
        assert Receipt.from_headers(response.headers).reference == "0xhash"
        assert await body_json(response) == {"ok": True}


class EventCharge(BaseModel):
    amount: str
    currency: str
    decimals: int
    recipient: str


EVENT_METHOD = Method(
    name="mock", intent="charge", request_model=EventCharge, payload_model=TokenPayload
)


def event_options() -> dict[str, Any]:
    return {
        "amount": "1000",
        "currency": "0x0000000000000000000000000000000000000001",
        "decimals": 6,
        "expires": future(),
        "recipient": "0x0000000000000000000000000000000000000002",
    }


def event_server(reference: str = "tx-events", **hooks: Any) -> ServerMethod:
    async def verify(_: VerifyContext[Any]) -> Receipt:
        return receipt("mock", reference)

    hooks.setdefault("verify", verify)
    return ServerMethod(method=EVENT_METHOD, **hooks)


def bad_credential() -> str:
    challenge = Challenge.create(
        id="wrong-id",
        intent="charge",
        method="mock",
        realm=REALM,
        request={k: v for k, v in event_options().items() if k != "expires"},
    )
    return credential_header(challenge, {"token": "valid"})


class TestServerEvents:
    async def test_challenge_then_success(self) -> None:
        events: list[str] = []
        seen: dict[str, Any] = {}
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)

        def on_challenge(ctx: Any) -> None:
            events.append(f"challenge:{ctx.error.name}")
            seen.update(
                challenge_method=ctx.method.name,
                challenge_path=ctx.captured_request.url.path,
                challenge_amount=ctx.request["amount"],
                challenge_credential=ctx.credential,
            )

        def on_success(ctx: Any) -> None:
            events.append(f"payment:{ctx.receipt.reference}")
            seen.update(
                payment_challenge=ctx.challenge.id,
                payment_envelope=ctx.envelope.challenge.id,
                payment_token=ctx.credential.payload.token,
                payment_amount=ctx.request["amount"],
            )

        mppx.on_challenge_created(on_challenge)
        mppx.on_payment_success(on_success)
        mppx.on_payment_failed(lambda _: events.append("failed"))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        paid = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert paid.status == 200
        assert paid.with_receipt(Response.json({"ok": True})).headers.get("Payment-Receipt")
        assert events == ["challenge:PaymentRequiredError", "payment:tx-events"]
        assert seen == {
            "challenge_method": "mock",
            "challenge_path": "/resource",
            "challenge_amount": "1000",
            "challenge_credential": None,
            "payment_challenge": challenge.id,
            "payment_envelope": challenge.id,
            "payment_token": "valid",
            "payment_amount": "1000",
        }

    async def test_event_errors_do_not_alter_flow(self) -> None:
        events: list[str] = []
        mppx = Mpp(methods=[event_server("tx-event-error")], realm=REALM, secret_key=SECRET_KEY)

        def record(name: str) -> Any:
            def handler(_: Any) -> None:
                events.append(name)
                raise RuntimeError(f"{name} failed")

            return handler

        async def failing_catchall(_: Any) -> None:
            events.append("*")
            raise RuntimeError("catchall failed")

        mppx.on("*", failing_catchall)
        mppx.on_challenge_created(record("challenge.created"))
        mppx.on_payment_failed(record("failed"))
        mppx.on_payment_success(record("success"))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        invalid = await handle(http_request(Authorization=bad_credential()))
        assert invalid.status == 402
        paid = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert paid.status == 200
        assert paid.with_receipt(Response.json({"ok": True})).status == 200
        assert events == [
            "challenge.created",
            "*",
            "failed",
            "*",
            "challenge.created",
            "*",
            "success",
            "*",
        ]

    async def test_listener_isolation(self) -> None:
        events: list[str] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)

        def first(_: Any) -> None:
            events.append("first")
            raise RuntimeError("listener failed")

        mppx.on_payment_success(first)
        mppx.on_payment_success(lambda _: events.append("second"))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        await handle(http_request(Authorization=credential_header(challenge, {"token": "valid"})))
        assert events == ["first", "second"]

    async def test_registration_and_unsubscribe(self) -> None:
        events: list[str] = []
        mppx = Mpp(
            methods=[event_server("tx-registered-event")], realm=REALM, secret_key=SECRET_KEY
        )
        off_failed = mppx.on(
            "payment.failed", lambda ctx: events.append(f"failed:{ctx.error.name}")
        )
        off_created = mppx.on(
            "challenge.created", lambda ctx: events.append(f"runtime:{ctx.error.name}")
        )
        off_all = mppx.on("*", lambda env: events.append(f"runtime:*:{env.name}"))
        off_success = mppx.on_payment_success(
            lambda ctx: events.append(f"success:{ctx.receipt.reference}")
        )
        off_failed()
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        off_created()
        off_all()
        await handle(http_request(Authorization=bad_credential()))
        await handle(http_request(Authorization=credential_header(challenge, {"token": "valid"})))
        off_success()
        assert events == [
            "runtime:PaymentRequiredError",
            "runtime:*:challenge.created",
            "success:tx-registered-event",
        ]
        with pytest.raises(ValueError, match='Unknown server event "nope"'):
            mppx.on("nope", lambda _: None)

    async def test_failure_before_reissued_challenge(self) -> None:
        events: list[str] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_challenge_created(lambda ctx: events.append(f"challenge:{ctx.error.name}"))
        mppx.on_payment_failed(
            lambda ctx: events.append(f"failed:{ctx.error.name}:{ctx.credential.challenge.id}")
        )
        await mppx.charge(**event_options())(http_request(Authorization=bad_credential()))
        assert events == [
            "failed:InvalidChallengeError:wrong-id",
            "challenge:InvalidChallengeError",
        ]

    async def test_malformed_credential_events(self) -> None:
        events: list[str] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_challenge_created(
            lambda ctx: events.append(f"challenge:{ctx.error.name}:{ctx.credential}")
        )
        mppx.on_payment_failed(
            lambda ctx: events.append(f"failed:{ctx.error.name}:{ctx.credential}")
        )
        await mppx.charge(**event_options())(http_request(Authorization="Payment invalid"))
        assert events == [
            "failed:MalformedCredentialError:None",
            "challenge:MalformedCredentialError:None",
        ]

    async def test_oversized_payment_authorization_events(self) -> None:
        # pympp#308: oversized Payment credentials emit payment.failed; others stay silent.
        events: list[str] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_failed(lambda ctx: events.append(f"failed:{ctx.error.name}"))
        handle = mppx.charge(**event_options())
        for authorization in (
            "Bearer " + "a" * MAX_AUTHORIZATION_LENGTH,
            "Bearer x" + "payment " * (MAX_AUTHORIZATION_LENGTH // 8),
        ):
            result = await handle(http_request(Authorization=authorization))
            assert result.status == 402
        assert events == []
        for authorization in (
            "Payment " + "a" * MAX_AUTHORIZATION_LENGTH,
            "Bearer " + "a" * MAX_AUTHORIZATION_LENGTH + ", PAYMENT abc",
        ):
            result = await handle(http_request(Authorization=authorization))
            assert result.status == 402
        assert events == ["failed:MalformedCredentialError"] * 2

    async def test_verification_rejection_events(self) -> None:
        events: list[str] = []

        async def verify(_: VerifyContext[Any]) -> Receipt:
            raise VerificationFailedError(reason="declined")

        mppx = Mpp(methods=[event_server(verify=verify)], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_challenge_created(lambda ctx: events.append(f"challenge:{ctx.error.name}"))
        mppx.on_payment_success(lambda _: events.append("payment"))
        mppx.on_payment_failed(lambda ctx: events.append(f"failed:{ctx.error.name}"))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert result.status == 402
        assert events == [
            "challenge:PaymentRequiredError",
            "failed:VerificationFailedError",
            "challenge:VerificationFailedError",
        ]

    async def test_authorize_grants_without_success_event(self) -> None:
        events: list[str] = []

        async def authorize(_: Any) -> AuthorizeResult:
            return AuthorizeResult(receipt=receipt("mock", "tx-authorized"))

        mppx = Mpp(methods=[event_server(authorize=authorize)], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_success(lambda ctx: events.append("success"))
        result = await mppx.charge(**event_options())(http_request())
        assert result.status == 200
        response = result.with_receipt(Response(200))
        assert Receipt.from_headers(response.headers).reference == "tx-authorized"
        assert events == []

    async def test_authorize_rejection(self) -> None:
        events: list[str] = []

        async def authorize(_: Any) -> AuthorizeResult:
            raise VerificationFailedError(reason="not active")

        mppx = Mpp(methods=[event_server(authorize=authorize)], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_failed(
            lambda ctx: events.append(f"failed:{ctx.error.name}:{ctx.credential}")
        )
        result = await mppx.charge(**event_options())(http_request())
        assert result.status == 402
        assert events == ["failed:VerificationFailedError:None"]

    @pytest.mark.parametrize("site", ["authorize", "get_credential", "verify"])
    async def test_exposes_cause_without_leaking(self, site: str) -> None:
        cause = RuntimeError("request to https://rpc.example.com/?key=secret-key failed")
        failures: list[PaymentError] = []

        async def raise_cause(_: Any) -> Any:
            raise cause

        hooks: dict[str, Any] = {"verify": raise_cause}
        if site == "authorize":
            hooks["authorize"] = raise_cause

        class LeakingHttp(HttpTransport):
            def get_credential(self, input: Request) -> Credential[Any] | None:
                raise cause

        transport = LeakingHttp() if site == "get_credential" else http()
        mppx = Mpp(
            methods=[event_server(**hooks)], realm=REALM, secret_key=SECRET_KEY, transport=transport
        )
        mppx.on_payment_failed(lambda ctx: failures.append(ctx.error))
        handle = mppx.charge(**event_options())
        headers: dict[str, str] = {}
        if site == "get_credential":
            headers["Authorization"] = "Payment invalid"
        if site == "verify":
            challenge = await challenge_of(handle)
            headers["Authorization"] = credential_header(challenge, {"token": "valid"})
        result = await handle(Request("GET", "https://example.com/resource", headers=headers))
        assert len(failures) == 1
        assert isinstance(failures[0], InternalPaymentError)
        assert failures[0].__cause__ is cause
        assert result.challenge.status == 500
        text = (await result.challenge.read()).decode()
        assert "secret-key" not in text
        assert json.loads(text)["type"] == "https://paymentauth.org/problems/internal-payment-error"

    async def test_standalone_failure_cause(self) -> None:
        cause = RuntimeError("rpc unavailable")
        failures: list[PaymentError] = []

        async def verify(_: Any) -> Receipt:
            raise cause

        mppx = Mpp(methods=[event_server(verify=verify)], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_failed(lambda ctx: failures.append(ctx.error))
        challenge = await challenge_of(mppx.charge(**event_options()))
        with pytest.raises(RuntimeError) as raised:
            await mppx.verify_credential(
                Credential(challenge=challenge, payload={"token": "valid"}), request=event_options()
            )
        assert raised.value is cause
        assert isinstance(failures[0], InternalPaymentError)
        assert failures[0].__cause__ is cause

    async def test_standalone_events(self) -> None:
        events: list[str] = []
        captured = CapturedRequest(
            method="POST",
            url=httpx.URL("https://example.com/standalone"),
            headers=httpx.Headers({"x-route": "standalone"}),
            has_body=False,
        )
        mppx = Mpp(methods=[event_server("tx-standalone")], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_success(
            lambda ctx: events.append(
                f"success:{ctx.receipt.reference}:{ctx.input}:{ctx.captured_request.url.path}:{ctx.request_input['amount']}"
            )
        )
        challenge = await challenge_of(mppx.charge(**event_options()))
        result = await mppx.verify_credential(
            Credential(challenge=challenge, payload={"token": "valid"}),
            captured_request=captured,
            request=event_options(),
        )
        assert result.reference == "tx-standalone"
        assert events == ["success:tx-standalone:None:/standalone:1000"]

    async def test_standalone_without_route_options_omits_request_input(self) -> None:
        contexts: list[Any] = []
        mppx = Mpp(
            methods=[event_server("tx-standalone", on_payment_success=contexts.append)],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        mppx.on_payment_success(contexts.append)
        challenge = await challenge_of(mppx.charge(**event_options()))
        await mppx.verify_credential(Credential(challenge=challenge, payload={"token": "valid"}))
        assert len(contexts) == 2
        assert all(ctx.request_input is None for ctx in contexts)

    async def test_per_method_hook(self) -> None:
        calls: list[str] = []

        async def hook(ctx: Any) -> None:
            calls.append(f"{ctx.receipt.reference}:{ctx.challenge.id}")

        other = ServerMethod(
            method=simple_method("other"),
            verify=lambda _: receipt("other"),
            on_payment_success=hook,
        )  # type: ignore[arg-type]
        mppx = Mpp(
            methods=[event_server("tx-hook", on_payment_success=hook), other],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        challenge = await challenge_of(mppx["mock/charge"](**event_options()))
        await mppx.verify_credential(
            Credential(challenge=challenge, payload={"token": "valid"}), request=event_options()
        )
        assert calls == [f"tx-hook:{challenge.id}"]

    async def test_per_method_hook_errors_do_not_propagate(self) -> None:
        def hook(_: Any) -> None:
            raise RuntimeError("hook failed")

        mppx = Mpp(
            methods=[event_server(on_payment_success=hook)], realm=REALM, secret_key=SECRET_KEY
        )
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        assert (
            await handle(
                http_request(Authorization=credential_header(challenge, {"token": "valid"}))
            )
        ).status == 200

    async def test_standalone_failure_events(self) -> None:
        events: list[str] = []

        async def verify(_: Any) -> Receipt:
            raise VerificationFailedError(reason="declined")

        mppx = Mpp(methods=[event_server(verify=verify)], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_failed(
            lambda ctx: events.append(f"failed:{ctx.error.name}:{ctx.submitted_challenge.id}")
        )
        challenge = await challenge_of(mppx.charge(**event_options()))
        with pytest.raises(VerificationFailedError):
            await mppx.verify_credential(
                Credential(challenge=challenge, payload={"token": "valid"})
            )
        assert events == [f"failed:VerificationFailedError:{challenge.id}"]

    async def test_standalone_forged_hmac_emits_failure(self) -> None:
        events: list[str] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_failed(lambda ctx: events.append(ctx.error.name))
        challenge = await challenge_of(mppx.charge(**event_options()))
        forged = Challenge(**{**challenge.to_dict(), "id": "forged"})
        with pytest.raises(PaymentError, match="not issued by this server"):
            await mppx.verify_credential(Credential(challenge=forged, payload={"token": "valid"}))
        assert events == ["InvalidChallengeError"]

    async def test_request_hook_rejection_with_credential(self) -> None:
        events: list[str] = []

        def resolve_request(ctx: RequestContext) -> dict[str, Any]:
            if ctx.credential is not None:
                raise VerificationFailedError(reason="hook rejected")
            return ctx.request

        mppx = Mpp(
            methods=[event_server(resolve_request=resolve_request)],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        mppx.on_payment_failed(lambda ctx: events.append(f"failed:{ctx.error.name}"))
        mppx.on_challenge_created(lambda ctx: events.append(f"challenge:{ctx.error.name}"))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert result.status == 402
        assert events == [
            "challenge:PaymentRequiredError",
            "failed:VerificationFailedError",
            "challenge:VerificationFailedError",
        ]

    async def test_event_inputs_are_bodyless_snapshots(self) -> None:
        inputs: list[Any] = []
        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_challenge_created(lambda ctx: inputs.append(ctx.input))
        request = Request(
            "POST", "https://example.com/resource", headers={"x-test": "1"}, body=b"secret body"
        )
        await mppx.charge(**event_options())(request)
        assert inputs[0] is not request
        assert inputs[0].body is None
        assert inputs[0].headers["x-test"] == "1"

    async def test_success_payload_snapshots(self) -> None:
        payloads: list[Any] = []

        def mutate(ctx: Any) -> None:
            ctx.request["amount"] = "mutated"
            payloads.append(ctx)

        mppx = Mpp(methods=[event_server()], realm=REALM, secret_key=SECRET_KEY)
        mppx.on_payment_success(mutate)
        mppx.on_payment_success(lambda ctx: payloads.append(ctx.request["amount"]))
        handle = mppx.charge(**event_options())
        challenge = await challenge_of(handle)
        result = await handle(
            http_request(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert result.status == 200
        assert challenge.request["amount"] == "1000"


def test_reserved_keys_snapshot() -> None:
    from mpp.server._mpp import RESERVED_KEYS

    assert {
        "challenge",
        "compose",
        "methods",
        "on",
        "realm",
        "transport",
        "verify_credential",
    } <= RESERVED_KEYS


_ = SigPayload
