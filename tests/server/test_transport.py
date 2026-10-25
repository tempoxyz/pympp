import asyncio
import json
from typing import Any, Literal

import pytest
from pydantic import BaseModel

from mpp import (
    AuthorizeResult,
    BadRequestError,
    Challenge,
    ChannelClosedError,
    Credential,
    CredentialReplayedError,
    Method,
    Receipt,
    ServerMethod,
    VerificationFailedError,
    VerifyContext,
    mcp,
    payment_request,
)
from mpp.server import Mpp, Request, Response, compose, require_payment
from mpp.server import http as http_transport

from ._fixtures import SECRET_KEY, TokenPayload, receipt
from ._mcp_transport import mcp_transport

CHALLENGE = Challenge.create(
    secret_key="test-secret-key",
    realm="api.example.com",
    method="tempo",
    intent="charge",
    expires="2025-01-01T00:00:00.000Z",
    request={
        "amount": "1000000000",
        "currency": "0x20c0000000000000000000000000000000000001",
        "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
    },
)
CREDENTIAL = Credential(challenge=CHALLENGE, payload={"signature": "0x1", "type": "transaction"})
RECEIPT = Receipt(method="tempo", reference="0xtxhash", timestamp="2025-01-01T00:00:00.000Z")
MCP_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}}


class TestHttp:
    async def test_capture_request(self) -> None:
        request = Request("POST", "https://example.com/path?x=1", headers={"x-a": "1"}, body=b"b")
        captured = await http_transport().capture_request(request)
        assert (captured.method, str(captured.url), captured.has_body) == (
            "POST",
            "https://example.com/path?x=1",
            True,
        )
        assert captured.headers is not request.headers
        assert captured.headers["x-a"] == "1"

    def test_get_credential(self) -> None:
        transport = http_transport()
        assert (
            transport.get_credential(
                Request("GET", "https://e.com", {"Authorization": CREDENTIAL.serialize()})
            )
            == CREDENTIAL
        )
        assert transport.get_credential(Request("GET", "https://e.com")) is None
        assert (
            transport.get_credential(Request("GET", "https://e.com", {"Authorization": "Bearer x"}))
            is None
        )
        auth = http_transport(requires_auth=True)
        assert auth.credential_headers == ("Payment-Authorization",)
        assert (
            auth.get_credential(
                Request("GET", "https://e.com", {"Authorization": CREDENTIAL.serialize()})
            )
            is None
        )
        assert (
            auth.get_credential(
                Request("GET", "https://e.com", {"Payment-Authorization": CREDENTIAL.serialize()})
            )
            == CREDENTIAL
        )

    async def test_respond_challenge(self) -> None:
        response = await http_transport().respond_challenge(
            challenge=CHALLENGE, input=Request("GET", "https://e.com")
        )
        assert response.status == 402
        assert response.body is None
        assert Challenge.deserialize(response.headers["WWW-Authenticate"]) == CHALLENGE
        assert response.headers["Cache-Control"] == "no-store"

    @pytest.mark.parametrize(
        ("error", "status", "type_"),
        [
            (
                BadRequestError(reason="invalid parameters"),
                400,
                "https://paymentauth.org/problems/bad-request",
            ),
            (
                ChannelClosedError(reason="channel finalized"),
                410,
                "https://paymentauth.org/problems/session/channel-finalized",
            ),
        ],
    )
    async def test_error_status_codes(self, error: Any, status: int, type_: str) -> None:
        response = await http_transport().respond_challenge(
            challenge=CHALLENGE, input=Request("GET", "https://e.com"), error=error
        )
        assert response.status == status
        body = json.loads(await response.read())
        assert (body["type"], body["status"], body["challengeId"]) == (type_, status, CHALLENGE.id)

    @pytest.mark.parametrize(
        ("error", "status", "challenged"),
        [
            (VerificationFailedError(reason="amount mismatch"), 402, True),
            (CredentialReplayedError(reason="Transaction hash has already been used"), 403, False),
            (CredentialReplayedError(reason="memo is not bound to this challenge"), 403, False),
        ],
    )
    async def test_replay_omits_challenge(self, error: Any, status: int, challenged: bool) -> None:
        response = await http_transport().respond_challenge(
            challenge=CHALLENGE,
            input=Request("GET", "https://e.com", {"Accept": "text/html"}),
            error=error,
        )
        assert response.status == status
        assert ("www-authenticate" in response.headers) is challenged
        assert response.headers["Cache-Control"] == "no-store"
        if not challenged:
            assert response.headers["Content-Type"] == "application/problem+json"
            assert json.loads(await response.read()) == error.to_problem_details()

    def test_respond_receipt(self) -> None:
        transport = http_transport()
        response = transport.respond_receipt(
            credential=CREDENTIAL,
            input=Request("GET", "https://e.com"),
            receipt=RECEIPT,
            response=Response.text("OK"),
            challenge_id=CHALLENGE.id,
        )
        assert response.status == 200
        assert dict(response.headers) == {
            "content-type": "text/plain;charset=UTF-8",
            "cache-control": "private",
            "payment-receipt": "eyJtZXRob2QiOiJ0ZW1wbyIsInJlZmVyZW5jZSI6IjB4dHhoYXNoIiwic3RhdHVzIjoic3VjY2VzcyIsInRpbWVzdGFtcCI6IjIwMjUtMDEtMDFUMDA6MDA6MDAuMDAwWiJ9",
        }
        cached = transport.respond_receipt(
            credential=CREDENTIAL,
            input=Request("GET", "https://e.com"),
            receipt=RECEIPT,
            response=Response(200, {"Cache-Control": "max-age=60"}),
            challenge_id=CHALLENGE.id,
        )
        assert cached.headers["Cache-Control"] == "max-age=60, private"
        private = transport.respond_receipt(
            credential=CREDENTIAL,
            input=Request("GET", "https://e.com"),
            receipt=RECEIPT,
            response=Response(200, {"Cache-Control": "Private, max-age=1"}),
            challenge_id=CHALLENGE.id,
        )
        assert private.headers["Cache-Control"] == "Private, max-age=1"


async def test_require_payment() -> None:
    response = require_payment(CHALLENGE)
    assert response.status == 402
    assert response.headers["WWW-Authenticate"] == CHALLENGE.serialize()
    assert response.body is None
    with_error = require_payment(CHALLENGE, VerificationFailedError(reason="nope"))
    assert with_error.headers["Content-Type"] == "application/problem+json"
    assert json.loads(await with_error.read())["detail"] == "Payment verification failed: nope."


class MockRequest(BaseModel):
    amount: str
    currency: str


def mock(
    name: str = "mock",
    intent: str = "charge",
    request_model: type[BaseModel] = MockRequest,
    **hooks: Any,
) -> ServerMethod:
    async def verify(ctx: VerifyContext[Any]) -> Receipt:
        return receipt(name, "paid")

    hooks.setdefault("verify", verify)
    method = ServerMethod(
        method=Method(
            name=name, intent=intent, request_model=request_model, payload_model=TokenPayload
        ),
        **hooks,
    )
    return method


NONCE_OPTS = {"amount": "1", "currency": "USD", "expires": "2099-01-01T00:00:00Z"}


def req(challenge: Challenge | None = None) -> Request:
    headers = (
        {"Authorization": Credential(challenge=challenge, payload={"token": "valid"}).serialize()}
        if challenge
        else {}
    )
    return Request("GET", "https://example.test/paid", headers)


class TestNonce:
    @pytest.mark.parametrize("expires", [None, NONCE_OPTS["expires"]])
    async def test_fresh_ids(self, expires: str | None) -> None:
        mppx = Mpp(methods=[mock()], realm="example.test", secret_key=SECRET_KEY)
        challenges = await asyncio.gather(
            *[mppx.challenge.mock.charge(**{**NONCE_OPTS, "expires": expires}) for _ in range(10)]
        )
        assert len({c.id for c in challenges}) == 10
        for challenge in challenges:
            assert challenge.meta is not None
            assert isinstance(challenge.meta["_mppx_nonce"], str)
            assert challenge.verify(SECRET_KEY)

    async def test_http_issuance_preserves_metadata(self) -> None:
        mppx = Mpp(methods=[mock()], realm="example.test", secret_key=SECRET_KEY)
        handler = mppx.charge(**NONCE_OPTS, meta={"order": "one"}, scope="paid")
        first, second = await handler(req()), await handler(req())
        challenge = Challenge.from_response(first.challenge)
        assert challenge.id != Challenge.from_response(second.challenge).id
        opaque = payment_request.deserialize(challenge.opaque or "")
        assert opaque["order"] == "one"
        assert opaque["_mppx_scope"] == "paid"
        assert (await handler(req(challenge))).status == 200

    async def test_nonce_does_not_weaken_route_binding(self) -> None:
        method = mock()
        mppx = Mpp(methods=[method], realm="example.test", secret_key=SECRET_KEY)
        challenge = await mppx.challenge.mock.charge(**NONCE_OPTS, meta={"order": "one"})
        assert (
            await mppx.compose((method, {**NONCE_OPTS, "meta": {"order": "one"}}))(req(challenge))
        ).status == 200
        assert (
            await mppx.compose((method, {**NONCE_OPTS, "meta": {"order": "two"}}))(req(challenge))
        ).status == 402

    async def test_nonce_changes_invalidate_hmac(self) -> None:
        mppx = Mpp(methods=[mock()], realm="example.test", secret_key=SECRET_KEY)
        challenge = await mppx.challenge.mock.charge(**NONCE_OPTS)
        assert challenge.meta is not None
        modified = Challenge(
            **{
                **challenge.to_dict(),
                "opaque": None,
                "meta": {**challenge.meta, "_mppx_nonce": "changed"},
            }
        )
        assert not modified.verify(SECRET_KEY)
        assert (await mppx.charge(**NONCE_OPTS)(req(modified))).status == 402

    async def test_signed_challenges_without_nonce_remain_valid(self) -> None:
        mppx = Mpp(methods=[mock()], realm="example.test", secret_key=SECRET_KEY)
        challenge = Challenge.create(
            expires=NONCE_OPTS["expires"],
            method="mock",
            intent="charge",
            realm="example.test",
            request={"amount": "1", "currency": "USD"},
            secret_key=SECRET_KEY,
        )
        assert (await mppx.charge(**NONCE_OPTS)(req(challenge))).status == 200


class TestAuthorize:
    async def test_grants_access_with_management_response(self) -> None:
        async def authorize(ctx: Any) -> AuthorizeResult:
            assert ctx.request == {"amount": "1", "currency": "usd"}
            return AuthorizeResult(
                receipt=receipt("mock", "sub"), response=Response(200, body=b"subscribed")
            )

        mppx = Mpp(methods=[mock(authorize=authorize)], realm="example.test", secret_key=SECRET_KEY)
        result = await mppx.charge(amount="1", currency="usd")(req())
        assert result.status == 200
        response = result.with_receipt()
        assert await response.read() == b"subscribed"
        assert Receipt.from_headers(response.headers).reference == "sub"

    async def test_compose_evaluates_authorize_sequentially(self) -> None:
        calls: list[str] = []

        def make(name: str, grant: bool) -> ServerMethod:
            async def authorize(_: Any) -> AuthorizeResult | None:
                calls.append(f"{name}:start")
                await asyncio.sleep(0)
                calls.append(f"{name}:end")
                return AuthorizeResult(receipt=receipt(name)) if grant else None

            return mock(name, authorize=authorize)

        alpha, beta = make("alpha", False), make("beta", True)
        mppx = Mpp(methods=[alpha, beta], realm="example.test", secret_key=SECRET_KEY)
        result = await mppx.compose(
            (alpha, {"amount": "1", "currency": "usd"}), (beta, {"amount": "1", "currency": "usd"})
        )(req())
        assert result.status == 200
        assert calls == ["alpha:start", "alpha:end", "beta:start", "beta:end"]

    async def test_stable_binding_rejects_mismatched_routes(self) -> None:
        class SubscriptionRequest(BaseModel):
            amount: str
            chainId: int | None = None
            currency: str
            periodCount: str
            periodUnit: Literal["day", "week"]
            recipient: str
            subscriptionExpires: str

        def stable_binding(request: dict[str, Any]) -> dict[str, Any]:
            keys = (
                "amount",
                "chainId",
                "currency",
                "periodCount",
                "periodUnit",
                "recipient",
                "subscriptionExpires",
            )
            return {key: request.get(key) for key in keys}

        method = mock("mock", "subscription", SubscriptionRequest, stable_binding=stable_binding)
        mppx = Mpp(methods=[method], realm="example.test", secret_key=SECRET_KEY)
        base = {
            "amount": "1",
            "currency": "usd",
            "periodUnit": "day",
            "recipient": "alice",
            "subscriptionExpires": "2026-01-01T00:00:00Z",
        }
        first = await mppx["mock/subscription"](**base, periodCount="30")(
            Request("GET", "https://example.com/cheap")
        )
        challenge = Challenge.from_response(first.challenge)
        second = await mppx["mock/subscription"](**base, periodCount="60")(req(challenge))
        assert second.status == 402
        assert "periodCount" in json.loads(await second.challenge.read())["detail"]


class TestIdentity:
    def test_unregistered_method_reference(self) -> None:
        a, b = mock(), mock()
        with pytest.raises(ValueError, match="No handler"):
            Mpp(methods=[a], realm="example.test", secret_key=SECRET_KEY).compose(
                (b, {"amount": "1", "currency": "usd"})
            )

    @pytest.mark.parametrize(
        "operation", ["broadcast_credential", "verify_credential", "validate_credential"]
    )
    async def test_standalone_selects_later_currency(self, operation: str) -> None:
        from mpp import ValidateContext, Validation

        calls: list[str] = []

        def make(name: str, currency: str) -> ServerMethod:
            async def validate(ctx: ValidateContext[Any]) -> Validation[Any]:
                calls.append(f"{name}:validate")
                return Validation(
                    challenge=ctx.credential.challenge,
                    credential=ctx.credential,
                    details={},
                    intent="charge",
                    method="mock",
                    request=ctx.request,
                )

            async def broadcast(_: Any) -> Receipt:
                calls.append(f"{name}:broadcast")
                return receipt()

            return ServerMethod(
                method=Method(
                    name="mock",
                    intent="charge",
                    request_model=MockRequest,
                    payload_model=TokenPayload,
                ),
                defaults={"currency": currency},
                validate=validate,
                broadcast=broadcast,
                on_payment_success=lambda _: calls.append(f"{name}:success"),
            )

        first, second = make("first", "0x1"), make("second", "0x2")
        mppx = Mpp(methods=[first, second], realm="example.test", secret_key=SECRET_KEY)
        offered = await mppx.compose((first, {"amount": "1"}), (second, {"amount": "1"}))(req())
        challenge = Challenge.from_response_list(offered.challenge)[1]
        await getattr(mppx, operation)(Credential(challenge=challenge, payload={"token": "x"}))
        assert not [c for c in calls if c.startswith("first")]
        if operation == "validate_credential":
            assert calls == ["second:validate"]
        else:
            assert calls == ["second:validate", "second:broadcast", "second:success"]

    async def test_indistinguishable_methods_rejected(self) -> None:
        first = mock(defaults={"currency": "0x1"})
        second = mock(defaults={"currency": "0x1"})
        mppx = Mpp(methods=[first, second], realm="example.test", secret_key=SECRET_KEY)
        offered = await mppx.compose((second, {"amount": "1"}))(req())
        credential = Credential(
            challenge=Challenge.from_response(offered.challenge), payload={"token": "x"}
        )
        with pytest.raises(Exception, match="multiple configured methods"):
            await mppx.broadcast_credential(credential)


class TestComposeMcp:
    def mppx(self, *methods: ServerMethod) -> Mpp:
        return Mpp(
            methods=list(methods),
            realm="example.test",
            secret_key=SECRET_KEY,
            transport=mcp_transport(),
        )

    async def test_gathers_offers_and_settles_chosen(self) -> None:
        calls: list[str] = []

        def make(currency: str) -> ServerMethod:
            async def verify(_: Any) -> Receipt:
                calls.append(currency)
                return receipt()

            return mock(defaults={"currency": currency}, verify=verify)

        usd, eur = make("usd"), make("eur")
        mppx = self.mppx(usd, eur)
        handler = mppx.compose((usd, {"amount": "1"}), (eur, {"amount": "1"}))
        result = await handler(MCP_REQUEST)
        assert result.status == 402
        challenges = result.challenge["error"]["data"]["challenges"]
        assert [c["request"]["currency"] for c in challenges] == ["usd", "eur"]
        meta = {mcp.CREDENTIAL_META_KEY: {"challenge": challenges[1], "payload": {"token": "x"}}}
        paid = await handler({**MCP_REQUEST, "id": 9, "params": {"_meta": meta}})
        assert paid.status == 200
        assert calls == ["eur"]
        response = paid.with_receipt({"jsonrpc": "2.0", "id": 9, "result": {"content": []}})
        assert response["id"] == 9
        assert (
            response["result"]["_meta"][mcp.RECEIPT_META_KEY]["challengeId"] == challenges[1]["id"]
        )

    async def test_implicit_intent_compose_uses_mcp(self) -> None:
        mppx = self.mppx(mock("a"), mock("b"))
        result = await mppx.charge(amount="1", currency="usd")(MCP_REQUEST)
        assert [c["method"] for c in result.challenge["error"]["data"]["challenges"]] == ["a", "b"]

    async def test_failed_verification_keeps_code(self) -> None:
        async def verify(_: Any) -> Receipt:
            raise VerificationFailedError(reason="declined")

        failing = mock(verify=verify)
        other = mock(defaults={"currency": "eur"})
        mppx = self.mppx(failing, other)
        handler = mppx.compose(
            (failing, {"amount": "1", "currency": "usd"}), (other, {"amount": "1"})
        )
        challenge = (await handler(MCP_REQUEST)).challenge["error"]["data"]["challenges"][0]
        result = await handler(
            {
                **MCP_REQUEST,
                "params": {
                    "_meta": {
                        mcp.CREDENTIAL_META_KEY: {"challenge": challenge, "payload": {"token": "x"}}
                    }
                },
            }
        )
        assert result.challenge["error"]["code"] == mcp.PAYMENT_VERIFICATION_FAILED_CODE

    async def test_malformed_credentials_keep_invalid_params(self) -> None:
        method = mock()
        handler = self.mppx(method).compose((method, {"amount": "1", "currency": "usd"}))
        result = await handler(
            {
                **MCP_REQUEST,
                "params": {"_meta": {mcp.CREDENTIAL_META_KEY: {"challenge": {}, "payload": 1}}},
            }
        )
        assert result.challenge["error"]["code"] == mcp.INVALID_PARAMS_CODE

    def test_rejects_empty_and_incompatible(self) -> None:
        method = mock()
        mppx = self.mppx(method)
        with pytest.raises(ValueError, match="at least one entry"):
            mppx.compose()
        offered = mock("x", can_offer=lambda _: True)
        with pytest.raises(ValueError, match="canOffer"):
            self.mppx(offered).compose((offered, {"amount": "1", "currency": "usd"}))
        http_method = mock("y", transport=http_transport())
        with pytest.raises(ValueError, match="configured MCP transport"):
            self.mppx(http_method).compose((http_method, {"amount": "1", "currency": "usd"}))


def test_static_compose_requires_handlers() -> None:
    with pytest.raises(ValueError, match="at least one handler"):
        compose()


async def test_mcp_null_credential_is_malformed() -> None:
    failures: list[str] = []
    server = Mpp(
        methods=[mock()], realm="example.test", secret_key=SECRET_KEY, transport=mcp_transport()
    )
    server.on_payment_failed(lambda ctx: failures.append(ctx.error.name))
    request = {**MCP_REQUEST, "params": {"_meta": {mcp.CREDENTIAL_META_KEY: None}}}
    result = await server.charge(amount="1", currency="usd")(request)
    assert result.challenge["error"]["code"] == mcp.INVALID_PARAMS_CODE
    assert failures == ["MalformedCredentialError"]


async def test_server_event_handlers_have_set_semantics() -> None:
    calls: list[str] = []

    def handler(ctx: Any) -> None:
        calls.append(ctx.method.name)

    server = Mpp(methods=[mock()], realm="example.test", secret_key=SECRET_KEY)
    off = server.on_challenge_created(handler)
    server.on("challenge.created", handler)
    await server.charge(amount="1", currency="usd")(req())
    assert calls == ["mock"]
    off()
    await server.charge(amount="1", currency="usd")(req())
    assert calls == ["mock"]


@pytest.mark.parametrize(
    ("url", "realm"),
    [
        ("https://münchen.de/x", "xn--mnchen-3ya.de"),
        ("http://[::1]:3000/x", "[::1]"),
        ("http://127.1/x", "127.0.0.1"),
        ("http://0x7f.1/x", "127.0.0.1"),
        ("https://API.Example.COM./x", "api.example.com."),
    ],
)
async def test_realm_uses_whatwg_hostname(
    url: str, realm: str, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    server = Mpp(methods=[mock()], secret_key=SECRET_KEY)
    result = await server.charge(amount="1", currency="usd")(Request("GET", url))
    assert Challenge.from_response(result.challenge).realm == realm
