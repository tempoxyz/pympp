"""Ports mppx ``src/mcp/server/Transport.test.ts`` plus ``MCPServer`` integration."""

from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.server.mcpserver import Context, MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams, CallToolResult, TextContent
from pydantic import BaseModel

from mpp import (
    InternalPaymentError,
    InvalidCredentialEncodingError,
    InvalidPayloadError,
    MalformedCredentialError,
    Method,
    PaymentRequiredError,
    Receipt,
    ServerMethod,
    VerificationFailedError,
    VerifyContext,
    expires,
)
from mpp import mcp as core_mcp
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.mcp_sdk.server import mcp_sdk, paid, request_meta, tool_name
from mpp.server import Mpp, Response

SECRET_KEY = "test-secret-key-test-secret-key-32"

challenge = Challenge(
    id="test-challenge-id",
    realm="api.example.com",
    method="tempo",
    intent="session",
    request={"amount": "1000000"},
)
credential = Credential(
    challenge=challenge,
    payload={
        "action": "voucher",
        "channelId": "0xabc",
        "cumulativeAmount": "1000000",
        "signature": "0x1234",
    },
    source="did:pkh:eip155:42431:0x1111111111111111111111111111111111111111",
)
receipt = Receipt(
    method="tempo", reference="0xabc", status="success", timestamp="2025-06-15T12:00:00.000Z"
)


def credential_meta(value: Credential[Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"challenge": value.challenge.to_dict(), "payload": value.payload}
    if value.source:
        result["source"] = value.source
    return result


class TestCaptureRequest:
    async def test_captures_a_stable_synthetic_request_snapshot(self) -> None:
        captured = await mcp_sdk().capture_request({})
        assert captured.method == "POST"
        assert captured.url == httpx.URL("mcp://request/sdk")
        assert list(captured.headers.items()) == []
        assert captured.has_body is True


class TestGetCredential:
    def test_returns_credential_from_meta(self) -> None:
        extra = {"_meta": {core_mcp.CREDENTIAL_META_KEY: credential_meta(credential)}}
        assert mcp_sdk().get_credential(extra) == credential

    def test_reads_low_level_request_params(self) -> None:
        params = CallToolRequestParams(
            name="tool", _meta={core_mcp.CREDENTIAL_META_KEY: credential_meta(credential)}
        )
        assert mcp_sdk().get_credential(params) == credential

    def test_returns_none_when_meta_is_missing(self) -> None:
        assert mcp_sdk().get_credential({}) is None
        assert mcp_sdk().get_credential(CallToolRequestParams(name="tool")) is None

    def test_raises_for_an_explicit_null_credential(self) -> None:
        with pytest.raises(InvalidCredentialEncodingError):
            mcp_sdk().get_credential({"_meta": {core_mcp.CREDENTIAL_META_KEY: None}})

    async def test_null_credential_is_reported_as_invalid_params(self) -> None:
        payment = create_mppx()
        result = await payment.charge(amount="1")({"_meta": {core_mcp.CREDENTIAL_META_KEY: None}})
        assert result.status == 402
        assert result.challenge.code == core_mcp.INVALID_PARAMS_CODE

    def test_returns_none_when_credential_key_is_missing(self) -> None:
        assert mcp_sdk().get_credential({"_meta": {"otherKey": "value"}}) is None

    def test_raises_when_credential_metadata_is_malformed(self) -> None:
        extra = {"_meta": {core_mcp.CREDENTIAL_META_KEY: {"challenge": {}, "payload": {}}}}
        with pytest.raises(InvalidCredentialEncodingError):
            mcp_sdk().get_credential(extra)


class TestRespondChallenge:
    async def test_creates_mcp_error_with_code_and_challenge_data(self) -> None:
        error = await mcp_sdk().respond_challenge(challenge=challenge, input={})
        assert isinstance(error, MCPError)
        assert error.code == core_mcp.PAYMENT_REQUIRED_CODE
        assert error.message == "Payment Required"
        assert error.data == {"httpStatus": 402, "challenges": [challenge.to_dict()]}

    async def test_includes_problem_details_when_error_is_provided(self) -> None:
        failure = VerificationFailedError(reason="bad signature")
        error = await mcp_sdk().respond_challenge(challenge=challenge, input={}, error=failure)
        assert error.code == core_mcp.PAYMENT_VERIFICATION_FAILED_CODE
        assert "verification failed" in error.message.lower()
        assert error.data["problem"]["type"] == failure.type
        assert error.data["problem"]["challengeId"] == challenge.id

    @pytest.mark.parametrize(
        ("failure", "code"),
        [
            (PaymentRequiredError(), core_mcp.PAYMENT_REQUIRED_CODE),
            (VerificationFailedError(), core_mcp.PAYMENT_VERIFICATION_FAILED_CODE),
            (MalformedCredentialError(), core_mcp.INVALID_PARAMS_CODE),
            (InvalidPayloadError(), core_mcp.INVALID_PARAMS_CODE),
            (InternalPaymentError(), core_mcp.INTERNAL_ERROR_CODE),
        ],
    )
    async def test_maps_error_codes(self, failure: Any, code: int) -> None:
        error = await mcp_sdk().respond_challenge(challenge=challenge, input={}, error=failure)
        assert error.code == code
        assert error.data["httpStatus"] == failure.status


class TestRespondReceipt:
    def respond(self, response: Any) -> CallToolResult:
        return mcp_sdk().respond_receipt(
            challenge_id="test-challenge-id",
            credential=credential,
            input={},
            receipt=receipt,
            response=response,
        )

    def test_attaches_receipt_to_response_meta(self) -> None:
        result = self.respond(CallToolResult(content=[TextContent(type="text", text="hello")]))
        assert result.meta == {
            core_mcp.RECEIPT_META_KEY: {**receipt.to_dict(), "challengeId": "test-challenge-id"}
        }

    def test_preserves_existing_meta_fields_and_content(self) -> None:
        result = self.respond(
            {
                "_meta": {"existingKey": "value"},
                "content": [{"type": "text", "text": "result data"}],
            }
        )
        assert result.meta is not None
        assert result.meta["existingKey"] == "value"
        assert core_mcp.RECEIPT_META_KEY in result.meta
        assert result.content == [TextContent(type="text", text="result data")]

    def test_http_responses_become_empty_tool_results(self) -> None:
        result = self.respond(Response(status=204))
        assert result.content == []
        assert result.meta is not None
        assert core_mcp.RECEIPT_META_KEY in result.meta


def test_request_meta_reads_every_input_shape() -> None:
    meta = {"k": "v"}
    assert request_meta({"_meta": meta}) == meta
    assert request_meta(CallToolRequestParams(name="x", _meta=meta)) == meta  # type: ignore[arg-type]
    assert request_meta({}) == {}


# -- MCPServer integration -------------------------------------------------------------------


class AmountRequest(BaseModel):
    amount: str


class TokenPayload(BaseModel):
    token: str


def mock_method(name: str = "mock") -> ServerMethod:
    async def verify(context: VerifyContext[Any]) -> Receipt:
        if context.credential.payload.token != "ok":
            raise VerificationFailedError(reason="bad token")
        return Receipt(method=name, reference="tx", timestamp=expires.to_iso(expires.now()))

    return ServerMethod(
        method=Method(
            name=name, intent="charge", request_model=AmountRequest, payload_model=TokenPayload
        ),
        verify=verify,
    )


def create_mppx(*names: str) -> Mpp:
    return Mpp(
        methods=[mock_method(name) for name in names or ("mock",)],
        realm="api.example.com",
        secret_key=SECRET_KEY,
        transport=mcp_sdk(),
    )


def paid_meta(error: MCPError, token: str = "ok", index: int = 0) -> dict[str, Any]:
    selected = Challenge.from_dict(error.data["challenges"][index])
    return {
        core_mcp.CREDENTIAL_META_KEY: credential_meta(
            Credential(challenge=selected, payload={"token": token})
        )
    }


async def test_explicit_handler_flow_over_mcp_server() -> None:
    payment = create_mppx()
    server = MCPServer("test")

    @server.tool()
    async def premium(ctx: Context) -> CallToolResult:
        result = await payment.charge(amount="1")(ctx)
        if result.status == 402:
            raise result.challenge
        return result.with_receipt(CallToolResult(content=[TextContent(type="text", text="paid")]))

    async with Client(server) as client:
        with pytest.raises(MCPError) as raised:
            await client.call_tool("premium", {})
        assert raised.value.code == core_mcp.PAYMENT_REQUIRED_CODE
        assert raised.value.data["httpStatus"] == 402

        result = await client.call_tool("premium", {}, meta=paid_meta(raised.value))  # type: ignore[arg-type]

    assert result.content == [TextContent(type="text", text="paid")]
    assert result.meta is not None
    assert (
        result.meta[core_mcp.RECEIPT_META_KEY]["challengeId"]
        == raised.value.data["challenges"][0]["id"]
    )
    assert result.meta[core_mcp.RECEIPT_META_KEY]["reference"] == "tx"


async def test_paid_decorator_injects_context_and_keeps_schemas() -> None:
    payment = create_mppx()
    server = MCPServer("test")
    calls: list[str] = []

    @server.tool()
    @paid(payment.charge(amount="1"))
    async def search(query: str) -> dict[str, str]:
        calls.append(query)
        return {"answer": query.upper()}

    async with Client(server) as client:
        tools = await client.list_tools()
        tool = next(tool for tool in tools.tools if tool.name == "search")
        assert set(tool.input_schema["properties"]) == {"query"}
        assert tool.output_schema is not None

        with pytest.raises(MCPError) as raised:
            await client.call_tool("search", {"query": "hi"})
        assert calls == []

        result = await client.call_tool("search", {"query": "hi"}, meta=paid_meta(raised.value))  # type: ignore[arg-type]

    assert calls == ["hi"]
    assert result.structured_content == {"answer": "HI"}
    assert result.meta is not None
    assert result.meta[core_mcp.RECEIPT_META_KEY]["method"] == "mock"


async def test_paid_decorator_reuses_a_declared_context_and_supports_sync_tools() -> None:
    payment = create_mppx()
    server = MCPServer("test")
    seen: list[str] = []

    @server.tool()
    @paid(payment.charge(amount="1"))
    def echo(text: str, ctx: Context) -> str:
        seen.append(ctx.request_id)
        return text

    async with Client(server) as client:
        with pytest.raises(MCPError) as raised:
            await client.call_tool("echo", {"text": "x"})
        result = await client.call_tool("echo", {"text": "x"}, meta=paid_meta(raised.value))  # type: ignore[arg-type]

    assert result.content == [TextContent(type="text", text="x")]
    assert len(seen) == 1


async def test_rejected_credentials_return_verification_errors() -> None:
    payment = create_mppx()
    server = MCPServer("test")

    @server.tool()
    @paid(payment.charge(amount="1"))
    async def tool() -> str:
        return "never"

    async with Client(server) as client:
        with pytest.raises(MCPError) as first:
            await client.call_tool("tool", {})
        with pytest.raises(MCPError) as rejected:
            await client.call_tool("tool", {}, meta=paid_meta(first.value, token="bad"))  # type: ignore[arg-type]

    assert rejected.value.code == core_mcp.PAYMENT_VERIFICATION_FAILED_CODE
    assert rejected.value.data["problem"]["type"].endswith("verification-failed")
    assert rejected.value.data["challenges"]


async def test_compose_merges_challenges_into_one_mcp_error() -> None:
    payment = create_mppx("alpha", "beta")
    handler = payment.compose(("alpha/charge", {"amount": "1"}), ("beta/charge", {"amount": "2"}))

    result = await handler({})

    assert result.status == 402
    error = result.challenge
    assert isinstance(error, MCPError)
    assert error.message == "Payment Required"
    assert [challenge["method"] for challenge in error.data["challenges"]] == ["alpha", "beta"]

    verified = await handler({"_meta": paid_meta(error, index=1)})
    assert verified.status == 200
    tool_result = verified.with_receipt(CallToolResult(content=[]))
    assert tool_result.meta is not None
    assert tool_result.meta[core_mcp.RECEIPT_META_KEY]["method"] == "beta"


# -- per-tool scope binding (pympp extension; mppx leaves MCP challenges unscoped) -------------


def test_tool_name_reads_every_input_shape() -> None:
    assert tool_name(CallToolRequestParams(name="search")) == "search"
    assert tool_name({"name": "search", "_meta": {}}) == "search"
    assert tool_name({"_meta": {}}) is None
    assert tool_name({"name": ""}) is None
    assert mcp_sdk().route_scope(CallToolRequestParams(name="search")) == "tool:search"
    assert mcp_sdk().route_scope({}) is None


def scope_of(error: MCPError) -> str | None:
    challenge = Challenge.from_dict(error.data["challenges"][0])
    return (challenge.meta or {}).get("_mppx_scope")


async def test_paid_tools_are_bound_to_the_called_tool() -> None:
    payment = create_mppx()
    server = MCPServer("test")
    handler = payment.charge(amount="1")

    @server.tool()
    @paid(handler)
    async def alpha() -> str:
        return "alpha"

    @server.tool()
    @paid(handler)
    async def beta() -> str:
        return "beta"

    async with Client(server) as client:
        with pytest.raises(MCPError) as issued:
            await client.call_tool("alpha", {})
        assert scope_of(issued.value) == "tool:alpha"

        with pytest.raises(MCPError) as replayed:
            await client.call_tool("beta", {}, meta=paid_meta(issued.value))  # type: ignore[arg-type]
        assert replayed.value.code == core_mcp.PAYMENT_VERIFICATION_FAILED_CODE
        assert "does not match" in replayed.value.data["problem"]["detail"]
        assert scope_of(replayed.value) == "tool:beta"

        result = await client.call_tool("alpha", {}, meta=paid_meta(issued.value))  # type: ignore[arg-type]

    assert result.content == [TextContent(type="text", text="alpha")]


async def test_explicit_handler_flow_is_bound_to_the_called_tool() -> None:
    payment = create_mppx()
    server = MCPServer("test")

    async def run(ctx: Context) -> CallToolResult:
        result = await payment.charge(amount="1")(ctx)
        if result.status == 402:
            raise result.challenge
        return result.with_receipt(CallToolResult(content=[]))

    server.tool(name="first")(run)
    server.tool(name="second")(run)

    async with Client(server) as client:
        with pytest.raises(MCPError) as issued:
            await client.call_tool("first", {})
        with pytest.raises(MCPError) as replayed:
            await client.call_tool("second", {}, meta=paid_meta(issued.value))  # type: ignore[arg-type]
        paid_result = await client.call_tool("first", {}, meta=paid_meta(issued.value))  # type: ignore[arg-type]

    assert replayed.value.code == core_mcp.PAYMENT_VERIFICATION_FAILED_CODE
    assert paid_result.meta is not None
    assert core_mcp.RECEIPT_META_KEY in paid_result.meta


@pytest.mark.parametrize(
    "options", [{"scope": "shared"}, {"meta": {"_mppx_scope": "shared"}}], ids=["scope", "meta"]
)
async def test_an_explicit_scope_wins_over_the_tool_name(options: dict[str, Any]) -> None:
    payment = create_mppx()
    server = MCPServer("test")
    handler = payment.charge(amount="1", **options)

    @server.tool()
    @paid(handler)
    async def alpha() -> str:
        return "alpha"

    @server.tool()
    @paid(handler)
    async def beta() -> str:
        return "beta"

    async with Client(server) as client:
        with pytest.raises(MCPError) as issued:
            await client.call_tool("alpha", {})
        assert scope_of(issued.value) == "shared"
        result = await client.call_tool("beta", {}, meta=paid_meta(issued.value))  # type: ignore[arg-type]

    assert result.content == [TextContent(type="text", text="beta")]


# -- payment capabilities ----------------------------------------------------------------------


def test_payment_capabilities_advertise_methods_and_intents() -> None:
    payment = create_mppx("alpha", "beta")
    expected = {"payment": {"methods": ["alpha", "beta"], "intents": ["charge"]}}

    assert core_mcp.payment_capabilities(payment) == expected
    assert core_mcp.payment_capabilities(payment.methods) == expected
    assert core_mcp.payment_capabilities([]) == {"payment": {"methods": [], "intents": []}}


def test_payment_capabilities_plug_into_initialization_options() -> None:
    server = MCPServer("test")
    capabilities = core_mcp.payment_capabilities(create_mppx())

    options = server._lowlevel_server.create_initialization_options(  # pyright: ignore[reportPrivateUsage]
        experimental_capabilities=capabilities
    )

    assert options.capabilities.experimental == {
        "payment": {"methods": ["mock"], "intents": ["charge"]}
    }
