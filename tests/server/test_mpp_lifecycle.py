"""Ported from mppx src/server/Mpp.test.ts: withReceipt, realm, challenge(), verifyCredential."""

import json
from dataclasses import replace
from typing import Any, Literal

import pytest
from pydantic import BaseModel, Field, ValidationError, model_serializer

from mpp import (
    Challenge,
    Credential,
    Method,
    Receipt,
    RequestContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerificationFailedError,
    VerifyContext,
    expires,
    mcp,
)
from mpp.server import MissingReceiptResponseError, Mpp, Request, Response
from mpp.server._transport import HttpTransport

from ._fixtures import REALM, SECRET_KEY, TokenPayload, credential_header, future, receipt
from ._mcp_transport import mcp_transport


class ChargeRequest(BaseModel):
    amount: str
    currency: str
    decimals: int
    recipient: str


class SessionRequest(BaseModel):
    amount: str
    currency: str
    recipient: str
    unitType: str


class OpenPayload(BaseModel):
    action: Literal["open"]
    token: str


class VoucherPayload(BaseModel):
    action: Literal["voucher"]
    amount: str


class SessionPayload(BaseModel):
    root: OpenPayload | VoucherPayload = Field(discriminator="action")

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "SessionPayload":  # type: ignore[override]
        return super().model_validate({"root": obj}, **kwargs)


class Transformed(ChargeRequest):
    @model_serializer(mode="plain")
    def _wire(self) -> dict[str, Any]:
        return {
            "amount": str(round(float(self.amount) * 10**self.decimals)),
            "currency": self.currency,
            "recipient": self.recipient,
        }


def method(
    name: str,
    intent: str = "charge",
    request_model: type[BaseModel] = ChargeRequest,
    payload: type[BaseModel] = TokenPayload,
) -> Method[Any, Any]:
    return Method(name=name, intent=intent, request_model=request_model, payload_model=payload)


def server(
    name: str,
    intent: str = "charge",
    request_model: type[BaseModel] = ChargeRequest,
    payload: type[BaseModel] = TokenPayload,
    reference: str | None = None,
    **hooks: Any,
) -> ServerMethod:
    async def verify(_: VerifyContext[Any]) -> Receipt:
        return receipt(reference or name, f"tx-{name}")

    if "broadcast" not in hooks:
        hooks.setdefault("verify", verify)
    return ServerMethod(method=method(name, intent, request_model, payload), **hooks)


OPTS = {
    "amount": "1000",
    "currency": "0x0000000000000000000000000000000000000001",
    "decimals": 6,
    "expires": future(3600),
    "recipient": "0x0000000000000000000000000000000000000002",
}


def req(url: str = "https://example.com/resource", **headers: str) -> Request:
    return Request("GET", url, headers=headers)


async def paid_result(mppx: Mpp, handle: Any) -> Any:
    first = await handle(req())
    challenge = Challenge.from_response(first.challenge)
    return await handle(req(Authorization=credential_header(challenge, {"token": "valid"})))


class TestWithReceipt:
    async def test_attaches_receipt(self) -> None:
        mppx = Mpp(methods=[server("mock")], realm=REALM, secret_key=SECRET_KEY)
        result = await paid_result(mppx, mppx.charge(**OPTS))
        response = result.with_receipt(Response.json({"data": "ok"}))
        assert response.headers.get("Payment-Receipt")
        assert json.loads(await response.read()) == {"data": "ok"}

    async def test_streaming_capability_from_transport(self) -> None:
        class StreamingHttp(HttpTransport):
            name = "custom-stream"
            supports_streaming_receipts = True

        mppx = Mpp(
            methods=[server("mock")], realm=REALM, secret_key=SECRET_KEY, transport=StreamingHttp()
        )
        result = await paid_result(mppx, mppx.charge(**OPTS))
        assert result.supports_streaming_receipts is True
        plain = Mpp(methods=[server("mock")], realm=REALM, secret_key=SECRET_KEY)
        assert (await paid_result(plain, plain.charge(**OPTS))).supports_streaming_receipts is False

    async def test_requires_response(self) -> None:
        mppx = Mpp(methods=[server("mock")], realm=REALM, secret_key=SECRET_KEY)
        result = await paid_result(mppx, mppx.charge(**OPTS))
        with pytest.raises(
            MissingReceiptResponseError, match="withReceipt\\(\\) requires a response argument"
        ):
            result.with_receipt()

    async def test_management_response(self) -> None:
        respond_method = server("mock", respond=lambda _: Response(204))
        mppx = Mpp(methods=[respond_method], realm=REALM, secret_key=SECRET_KEY)
        result = await paid_result(mppx, mppx.charge(**OPTS))
        assert result.has_management_response
        response = result.with_receipt()
        assert response.status == 204
        assert response.headers.get("Payment-Receipt")
        # The management response wins even when the route passes its own response.
        assert result.with_receipt(Response(200)).status == 204

    async def test_streaming_body_passes_through(self) -> None:
        mppx = Mpp(methods=[server("mock")], realm=REALM, secret_key=SECRET_KEY)
        result = await paid_result(mppx, mppx.charge(**OPTS))

        async def stream() -> Any:
            yield b"a"
            yield b"b"

        response = result.with_receipt(
            Response(200, {"Content-Type": "text/event-stream"}, stream())
        )
        assert response.is_streaming
        assert await response.read() == b"ab"


class SimpleRequest(BaseModel):
    amount: str
    currency: str
    recipient: str


REALM_OPTS = {
    "amount": "100",
    "currency": "0x0000000000000000000000000000000000000001",
    "recipient": "0x0000000000000000000000000000000000000002",
}


class TestRealm:
    @pytest.fixture(autouse=True)
    def _no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (
            "MPP_REALM",
            "FLY_APP_NAME",
            "HEROKU_APP_NAME",
            "RAILWAY_PUBLIC_DOMAIN",
            "RENDER_EXTERNAL_HOSTNAME",
            "VERCEL_URL",
            "WEBSITE_HOSTNAME",
        ):
            monkeypatch.delenv(name, raising=False)

    def mppx(self, **kwargs: Any) -> Mpp:
        return Mpp(
            methods=[server("mock", request_model=SimpleRequest)], secret_key=SECRET_KEY, **kwargs
        )

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://mpp.dev/resource", "mpp.dev"),
            ("https://api.example.com/v1/resource", "api.example.com"),
            ("https://localhost:8787/resource", "localhost"),
            ("https://MPP.DEV/resource", "mpp.dev"),
            ("http://staging.mpp.dev:3000/api", "staging.mpp.dev"),
        ],
    )
    async def test_derives_realm(self, url: str, expected: str) -> None:
        result = await self.mppx().charge(**REALM_OPTS)(req(url))
        assert Challenge.from_response(result.challenge).realm == expected

    async def test_casing_of_same_host(self) -> None:
        mppx = self.mppx()
        challenge = Challenge.from_response(
            (await mppx.charge(**REALM_OPTS)(req("https://MPP.DEV/resource"))).challenge
        )
        result = await mppx.charge(**REALM_OPTS)(
            req(
                "https://mpp.dev/resource",
                Authorization=credential_header(challenge, {"token": "valid"}),
            )
        )
        assert result.status == 200

    async def test_explicit_realm_wins(self) -> None:
        result = await self.mppx(realm="explicit.example.com").charge(**REALM_OPTS)(
            req("https://other.example.com/resource")
        )
        assert Challenge.from_response(result.challenge).realm == "explicit.example.com"

    async def test_cross_host_rejected_with_realm_mismatch(self) -> None:
        mppx = self.mppx()
        challenge = Challenge.from_response(
            (await mppx.charge(**REALM_OPTS)(req("https://host-a.example.com/resource"))).challenge
        )
        result = await mppx.charge(**REALM_OPTS)(
            req(
                "https://host-b.example.com/resource",
                Authorization=credential_header(challenge, {"token": "valid"}),
            )
        )
        assert result.status == 402
        assert "realm" in json.loads(await result.challenge.read())["detail"]

    def test_realm_none_when_unset(self) -> None:
        assert self.mppx().realm is None

    async def test_fallback_realm(self) -> None:
        from mpp.server import _mpp

        _mpp._warned.discard("realm-fallback")
        handler = self.mppx().charge(**REALM_OPTS)
        with pytest.warns(UserWarning, match="Could not auto-detect realm"):
            result = await handler(Request("GET", ""))
        assert Challenge.from_response(result.challenge).realm == "MPP Payment"


class TestChallengeGenerators:
    def mppx(self, *methods: ServerMethod) -> Mpp:
        return Mpp(methods=list(methods), realm=REALM, secret_key=SECRET_KEY)

    async def test_returns_challenges(self) -> None:
        mppx = self.mppx(
            server("alpha"),
            server("alpha", "session", SessionRequest, SessionPayload),
            server("beta"),
        )
        challenge = await mppx.challenge.alpha.charge(**OPTS)
        assert (challenge.method, challenge.intent, challenge.realm) == ("alpha", "charge", REALM)
        assert challenge.request == {
            "amount": "1000",
            "currency": OPTS["currency"],
            "decimals": 6,
            "recipient": OPTS["recipient"],
        }
        assert challenge.verify(SECRET_KEY)
        session = await mppx.challenge.alpha.session(
            amount="500", currency="0x1", recipient="0x2", unitType="token"
        )
        assert (session.intent, session.request["unitType"]) == ("session", "token")
        assert (await mppx.challenge.beta.charge(**OPTS)).method == "beta"

    async def test_description_meta_and_scope(self) -> None:
        mppx = self.mppx(server("alpha"))
        challenge = await mppx.challenge.alpha.charge(
            **OPTS, description="Order #123", meta={"checkout_id": "chk_abc"}
        )
        assert challenge.description == "Order #123"
        assert challenge.meta is not None
        assert challenge.meta["checkout_id"] == "chk_abc"
        assert set(challenge.meta) == {"checkout_id", "_mppx_nonce"}
        scoped = await mppx.challenge.alpha.charge(**OPTS, scope="GET /premium")
        assert scoped.meta is not None
        assert scoped.meta["_mppx_scope"] == "GET /premium"
        with pytest.raises(ValueError, match="Conflicting scope values"):
            await mppx.challenge.alpha.charge(
                **OPTS, meta={"_mppx_scope": "GET /other"}, scope="GET /premium"
            )

    async def test_schema_transforms_and_async_hooks(self) -> None:
        mppx = self.mppx(server("transform", request_model=Transformed))
        challenge = await mppx.challenge.transform.charge(
            amount="25.92", currency="0x1", decimals=6, recipient="0x2"
        )
        assert challenge.request["amount"] == "25920000"

        class WithChain(ChargeRequest):
            chainId: int | None = None

            @model_serializer(mode="plain")
            def _wire(self) -> dict[str, Any]:
                return {
                    "amount": str(round(float(self.amount) * 10**self.decimals)),
                    "currency": self.currency,
                    "methodDetails": {"chainId": self.chainId},
                    "recipient": self.recipient,
                }

        async def resolve_request(ctx: RequestContext) -> dict[str, Any]:
            return {**ctx.request, "chainId": 42431}

        mppx = self.mppx(server("async", request_model=WithChain, resolve_request=resolve_request))
        challenge = await mppx.challenge["async"].charge(
            amount="25.92", currency="0x1", decimals=6, recipient="0x2"
        )
        assert challenge.request["methodDetails"] == {"chainId": 42431}

    async def test_request_hook_errors_become_402(self) -> None:
        class AmountOnly(BaseModel):
            amount: str

        def resolve_request(_: RequestContext) -> dict[str, Any]:
            raise VerificationFailedError(reason="request rejected")

        mppx = self.mppx(server("error", request_model=AmountOnly, resolve_request=resolve_request))
        result = await mppx.error.charge(amount="1")(req())
        assert result.status == 402
        assert (
            json.loads(await result.challenge.read())["detail"]
            == "Payment verification failed: request rejected."
        )

    async def test_generated_challenge_is_accepted(self) -> None:
        mppx = self.mppx(server("alpha"))
        challenge = await mppx.challenge.alpha.charge(**OPTS)
        result = await mppx.charge(**OPTS)(
            req(Authorization=credential_header(challenge, {"token": "valid"}))
        )
        assert result.status == 200

    async def test_mcp_internal_errors(self) -> None:
        async def verify(_: VerifyContext[Any]) -> Receipt:
            raise RuntimeError("processor unavailable")

        mppx = Mpp(
            methods=[server("alpha", verify=verify)],
            realm=REALM,
            secret_key=SECRET_KEY,
            transport=mcp_transport(),
        )
        message = {"id": 1, "jsonrpc": "2.0", "method": "tools/call", "params": {}}
        first = await mppx.alpha.charge(**OPTS)(message)
        assert first.status == 402
        error = first.challenge["error"]
        assert error["code"] == mcp.PAYMENT_REQUIRED_CODE
        assert error["data"]["httpStatus"] == 402
        challenge_obj = error["data"]["challenges"][0]
        credential_obj = {"challenge": challenge_obj, "payload": {"token": "valid"}}
        result = await mppx.alpha.charge(**OPTS)(
            {**message, "params": {"_meta": {mcp.CREDENTIAL_META_KEY: credential_obj}}}
        )
        assert result.status == 402
        error = result.challenge["error"]
        assert error["code"] == mcp.INTERNAL_ERROR_CODE
        assert error["data"]["httpStatus"] == 500
        assert error["data"]["problem"]["detail"] == "An internal payment error occurred."


def split_server(
    calls: list[str], *, fail: bool = False, details: Any = None, payer: str | None = None
) -> ServerMethod:
    async def validate(ctx: ValidateContext[Any]) -> Validation[Any]:
        calls.append("validate")
        if fail:
            raise VerificationFailedError(reason="risk denied")
        return Validation(
            challenge=ctx.credential.challenge,
            credential=ctx.credential,
            details=details(ctx) if callable(details) else {},
            intent="charge",
            method="alpha",
            request=ctx.request,
            payer=payer,
            source=ctx.credential.source,
        )

    async def broadcast(_: VerifyContext[Any]) -> Receipt:
        calls.append("broadcast")
        return receipt("broadcast")

    return ServerMethod(method=method("alpha"), validate=validate, broadcast=broadcast)


class TestVerifyCredential:
    def mppx(self, *methods: ServerMethod, **kwargs: Any) -> Mpp:
        kwargs.setdefault("realm", REALM)
        return Mpp(methods=list(methods), secret_key=SECRET_KEY, **kwargs)

    async def credential(self, mppx: Mpp, name: str = "alpha", **options: Any) -> Credential[Any]:
        challenge = await mppx.challenge[name].charge(**{**OPTS, **options})
        return Credential(challenge=challenge, payload={"token": "valid"})

    async def test_serialized_and_object(self) -> None:
        seen: list[Any] = []

        async def verify(ctx: VerifyContext[Any]) -> Receipt:
            seen.append(ctx)
            return receipt("alpha")

        mppx = self.mppx(
            server("alpha", verify=verify),
            server("alpha", "session", SessionRequest, SessionPayload),
            server("beta"),
        )
        credential = await self.credential(mppx)
        receipt_ = await mppx.verify_credential(credential.serialize())
        assert (receipt_.status, receipt_.method) == ("success", "alpha")
        assert isinstance(seen[0].credential.payload, TokenPayload)
        assert (await mppx.verify_credential(credential)).method == "alpha"

    async def test_validate_without_broadcast(self) -> None:
        calls: list[str] = []
        mppx = self.mppx(
            split_server(calls, details=lambda ctx: {"token": ctx.credential.payload.token})
        )
        validation = await mppx.validate_credential(await self.credential(mppx))
        assert validation.details == {"token": "valid"}
        assert calls == ["validate"]

    async def test_broadcast_and_legacy_alias(self) -> None:
        for name in ("broadcast_credential", "verify_credential"):
            calls: list[str] = []
            mppx = self.mppx(split_server(calls))
            receipt_ = await getattr(mppx, name)(await self.credential(mppx))
            assert receipt_.method == "broadcast"
            assert calls == ["validate", "broadcast"]

    async def test_validate_rejects_legacy_methods_without_events(self) -> None:
        events: list[str] = []
        mppx = self.mppx(server("alpha"))
        mppx.on_payment_failed(lambda ctx: events.append(ctx.error.name))
        with pytest.raises(
            VerificationFailedError, match="does not support non-mutating credential validation"
        ):
            await mppx.validate_credential(await self.credential(mppx))
        assert events == []

    async def test_validate_enforces_route_requirements(self) -> None:
        mppx = self.mppx(split_server([], details=lambda ctx: {"amount": ctx.request["amount"]}))
        credential = await self.credential(mppx)
        assert (await mppx.validate_credential(credential, request=OPTS)).details == {
            "amount": "1000"
        }
        with pytest.raises(
            VerificationFailedError.__mro__[1], match="credential amount does not match this route"
        ):
            await mppx.validate_credential(credential, request={**OPTS, "amount": "2000"})

    async def test_broadcast_emits_failure_on_validation_error(self) -> None:
        calls: list[str] = []
        events: list[str] = []
        mppx = self.mppx(split_server(calls, fail=True))
        mppx.on_payment_failed(lambda ctx: events.append(ctx.error.name))
        with pytest.raises(VerificationFailedError, match="risk denied"):
            await mppx.broadcast_credential(await self.credential(mppx))
        assert calls == ["validate"]
        assert events == ["VerificationFailedError"]

    async def test_route_handlers_revalidate_before_broadcast(self) -> None:
        calls: list[str] = []
        mppx = self.mppx(split_server(calls))
        result = await paid_result(mppx, mppx.charge(**OPTS))
        assert result.status == 200
        assert calls == ["validate", "broadcast"]

    @pytest.mark.parametrize("payer", ["0x00000000000000000000000000000000000000aa", None])
    async def test_success_exposes_payer(self, payer: str | None) -> None:
        contexts: list[Any] = []
        calls: list[str] = []
        split = split_server(calls, payer=payer)
        split = replace(split, on_payment_success=contexts.append)
        mppx = self.mppx(split)
        mppx.on_payment_success(contexts.append)
        handle = mppx.charge(**OPTS)
        challenge = Challenge.from_response((await handle(req())).challenge)
        credential = Credential(challenge=challenge, payload={"token": "valid"})
        assert (await handle(req(Authorization=credential.serialize()))).status == 200
        await mppx.broadcast_credential(credential, request=OPTS)
        assert [ctx.payer for ctx in contexts] == [payer] * 4

    async def test_scope(self) -> None:
        mppx = self.mppx(server("alpha"))
        challenge = await mppx.challenge.alpha.charge(**OPTS, scope="GET /premium")
        credential = Credential(challenge=challenge, payload={"token": "valid"})
        assert (await mppx.verify_credential(credential, scope="GET /premium")).method == "alpha"
        raw = Credential(
            challenge=Challenge.deserialize(challenge.serialize()), payload={"token": "valid"}
        )
        assert (await mppx.verify_credential(raw, scope="GET /premium")).method == "alpha"
        with pytest.raises(
            Exception, match="credential scope does not match this route's requirements"
        ):
            await mppx.verify_credential(credential, scope="GET /other")

    async def test_forged_meta_with_valid_opaque(self) -> None:
        mppx = self.mppx(server("alpha"))
        challenge = await mppx.challenge.alpha.charge(**OPTS, scope="GET /public")
        forged = Credential(
            challenge=replace(challenge, meta={"_mppx_scope": "GET /admin"}),
            payload={"token": "valid"},
        )
        with pytest.raises(Exception, match="credential scope does not match"):
            await mppx.verify_credential(forged, scope="GET /admin")

    async def test_echoed_realm_when_auto_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MPP_REALM", raising=False)
        mppx = Mpp(methods=[server("alpha")], secret_key=SECRET_KEY)
        request = {k: v for k, v in OPTS.items() if k != "expires"}
        first = await mppx.charge(**request)(req("https://api.example.com/premium"))
        challenge = Challenge.from_response(first.challenge)
        assert challenge.realm == "api.example.com"
        receipt_ = await mppx.verify_credential(
            Credential(challenge=challenge, payload={"token": "valid"}), request=request
        )
        assert receipt_.method == "alpha"

    async def test_session_intent_and_dispatch(self) -> None:
        mppx = self.mppx(
            server("alpha"),
            server("alpha", "session", SessionRequest, SessionPayload, reference="alpha-session"),
            server("beta"),
        )
        challenge = await mppx.challenge.alpha.session(
            amount="500", currency="0x1", recipient="0x2", unitType="token"
        )
        receipt_ = await mppx.verify_credential(
            Credential(challenge=challenge, payload={"action": "open", "token": "valid"})
        )
        assert receipt_.method == "alpha-session"
        assert (await mppx.verify_credential(await self.credential(mppx, "beta"))).method == "beta"

    async def test_rejections(self) -> None:
        events: list[str] = []
        mppx = self.mppx(server("alpha"))
        mppx.on_payment_failed(
            lambda ctx: events.append(f"{ctx.method.name}/{ctx.method.intent}:{ctx.error.name}")
        )
        credential = await self.credential(mppx)
        with pytest.raises(Exception, match="does not match"):
            await mppx.verify_credential(credential, request={**OPTS, "amount": "100000"})
        wrong = Challenge.create(
            id="tampered-id",
            intent="charge",
            method="alpha",
            realm=REALM,
            request=credential.challenge.request,
        )
        with pytest.raises(Exception, match="challenge was not issued by this server"):
            await mppx.verify_credential(Credential(challenge=wrong, payload={"token": "valid"}))
        expired = await self.credential(mppx, expires=expires.seconds(-1))
        with pytest.raises(Exception, match="Payment expired"):
            await mppx.verify_credential(expired)
        with pytest.raises(ValidationError):  # mppx rethrows the schema error itself
            await mppx.verify_credential(
                Credential(challenge=credential.challenge, payload={"wrong_field": 123})
            )
        unknown = Challenge.create(
            secret_key=SECRET_KEY,
            intent="charge",
            method="unknown",
            realm=REALM,
            expires=future(),
            request={"amount": "1000", "currency": "0x1"},
        )
        events.clear()
        with pytest.raises(Exception, match="no registered method for unknown/charge"):
            await mppx.verify_credential(Credential(challenge=unknown, payload={"token": "valid"}))
        assert events == ["unknown/charge:InvalidChallengeError"]
        with pytest.raises(ValueError, match="Missing Payment scheme"):
            await mppx.verify_credential("not-valid-base64")

    async def test_transform_round_trip(self) -> None:
        mppx = self.mppx(server("transform", request_model=Transformed))
        challenge = await mppx.challenge.transform.charge(
            amount="25.92", currency="0x1", decimals=6, recipient="0x2"
        )
        assert challenge.request["amount"] == "25920000"
        assert (
            await mppx.verify_credential(
                Credential(challenge=challenge, payload={"token": "valid"})
            )
        ).method == "transform"
        # Route options are matched after the same schema transform.
        receipt_ = await mppx.verify_credential(
            Credential(challenge=challenge, payload={"token": "valid"}),
            request={"amount": "25.92", "currency": "0x1", "decimals": 6, "recipient": "0x2"},
        )
        assert receipt_.method == "transform"

    async def test_duplicate_methods_require_matching_route(self) -> None:
        first = server("alpha", defaults={"currency": "0x1"})
        second = server("alpha", defaults={"currency": "0x2"})
        mppx = self.mppx(first, second)
        handle = mppx["alpha/charge"]
        assert handle.method is first
        challenge = await mppx.challenge.alpha.charge(**{**OPTS, "currency": "0x2"})
        credential = Credential(challenge=challenge, payload={"token": "valid"})
        assert (await mppx.verify_credential(credential)).method == "alpha"
        with pytest.raises(Exception, match="multiple configured methods match"):
            await mppx.verify_credential(credential, request={"currency": "0x2"}, realm=REALM)
        with pytest.raises(Exception, match="no configured method matches the challenge request"):
            await mppx.verify_credential(credential, request={"currency": "0x3"})
