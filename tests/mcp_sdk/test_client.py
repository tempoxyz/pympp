"""Ports mppx ``src/mcp/client/McpClient.test.ts`` and ``McpClient.unit.test.ts``."""

from collections.abc import Callable
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel

from mpp import (
    ClientMethod,
    CredentialParams,
    Method,
    PaymentExpiredError,
    Receipt,
    ServerMethod,
    VerifyContext,
    expires,
)
from mpp import mcp as core_mcp
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.mcp_sdk.client import (
    McpClient,
    PaymentDeclinedError,
    is_payment_required_error,
)
from mpp.mcp_sdk.server import mcp_sdk, paid
from mpp.server import Mpp

REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"


class ChargeRequest(BaseModel):
    amount: str
    currency: str = "0x20c0000000000000000000000000000000000001"
    recipient: str = "0x0000000000000000000000000000000000000002"


class Payload(BaseModel):
    signature: str
    type: str


class AccountContext(BaseModel):
    account: str


charge = Method(name="tempo", intent="charge", request_model=ChargeRequest, payload_model=Payload)


def create_challenge(*, expires_in: int = 60, method: str = "tempo") -> Challenge:
    created = Challenge.for_method(
        charge,
        realm=REALM,
        secret_key=SECRET_KEY,
        expires=expires.seconds(expires_in),
        request={"amount": "1"},
    )
    if method == "tempo":
        return created
    return Challenge.from_dict({**created.to_dict(), "method": method})


def mcp_receipt(challenge: Challenge) -> dict[str, Any]:
    return {
        "challengeId": challenge.id,
        "method": "tempo",
        "reference": "test",
        "status": "success",
        "timestamp": expires.to_iso(expires.now()),
    }


def payment_error(challenge: Challenge, code: int = core_mcp.PAYMENT_REQUIRED_CODE) -> MCPError:
    return MCPError(
        code, "Payment Required", {"httpStatus": 402, "challenges": [challenge.to_dict()]}
    )


class Recorder:
    """A ``create_credential`` recording its calls."""

    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[CredentialParams[Any]] = []
        self.error = error

    async def __call__(self, params: CredentialParams[Any]) -> str:
        self.calls.append(params)
        if self.error is not None:
            raise self.error
        return Credential(
            challenge=params.challenge, payload={"signature": "0xsignature", "type": "transaction"}
        ).serialize()


def client_method(create: Recorder, **options: Any) -> ClientMethod:
    return ClientMethod(method=charge, create_credential=create, **options)


class FakeSession:
    """Scripted ``call_tool`` responses (results or raised errors), recording each call."""

    def __init__(self, *responses: CallToolResult | dict[str, Any] | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
        progress_callback: Any = None,
        *,
        meta: Any = None,
        **options: Any,
    ) -> CallToolResult:
        self.calls.append(
            {
                "name": name,
                "arguments": arguments,
                "read_timeout_seconds": read_timeout_seconds,
                "meta": meta,
                **options,
            }
        )
        response = self.responses[0] if len(self.responses) == 1 else self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, dict):
            return CallToolResult.model_validate(response)
        return response


def text_result(text: str, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if meta is not None:
        result["_meta"] = meta
    return result


# -- approval (McpClient.unit.test.ts) ---------------------------------------------------------


async def test_calls_an_approval_hook_before_creating_a_credential() -> None:
    challenge = create_challenge()
    session = FakeSession(
        payment_error(challenge),
        text_result("ok", {core_mcp.RECEIPT_META_KEY: mcp_receipt(challenge)}),
    )
    create = Recorder()
    approvals: list[Challenge] = []

    def approve(selected: Challenge) -> bool:
        approvals.append(selected)
        return True

    result = await McpClient(session, methods=[client_method(create)]).call_tool(
        "paid_tool", {}, on_payment_required=approve
    )

    assert result.content == [TextContent(type="text", text="ok")]
    assert approvals == [challenge]
    assert len(create.calls) == 1
    assert len(session.calls) == 2


async def test_does_not_create_a_credential_when_approval_is_denied() -> None:
    session = FakeSession(payment_error(create_challenge()))
    create = Recorder()

    with pytest.raises(PaymentDeclinedError, match=r"Payment declined\."):
        await McpClient(session, methods=[client_method(create)]).call_tool(
            "paid_tool", on_payment_required=lambda challenge: False
        )
    assert create.calls == []


async def test_none_bypasses_a_configured_approval_hook() -> None:
    session = FakeSession(payment_error(create_challenge()), text_result("ok"))
    create = Recorder()
    approvals: list[Challenge] = []

    async def deny(challenge: Challenge) -> bool:
        approvals.append(challenge)
        return False

    client = McpClient(session, methods=[client_method(create)], on_payment_required=deny)
    result = await client.call_tool("paid_tool", on_payment_required=None)

    assert result.content == [TextContent(type="text", text="ok")]
    assert approvals == []
    assert len(create.calls) == 1


# -- in-place behavior (McpClient.test.ts) ----------------------------------------------------


async def test_handles_payment_and_returns_result_with_receipt() -> None:
    challenge = create_challenge()
    session = FakeSession(
        payment_error(challenge),
        text_result("Premium tool executed", {core_mcp.RECEIPT_META_KEY: mcp_receipt(challenge)}),
    )
    create = Recorder()

    result = await McpClient(session, methods=[client_method(create)]).call_tool(
        "premium_tool", {}, meta={"trace": "1"}
    )

    assert result.content == [TextContent(type="text", text="Premium tool executed")]
    assert result.is_error is False
    assert result.receipt is not None
    assert (result.receipt.status, result.receipt.method) == ("success", "tempo")
    assert result.receipt.extra["challengeId"] == challenge.id
    assert len(session.calls) == 2
    assert session.calls[0]["meta"] == {"trace": "1"}
    paid_meta = session.calls[1]["meta"]
    assert paid_meta["trace"] == "1"
    sent = paid_meta[core_mcp.CREDENTIAL_META_KEY]
    assert sent["challenge"] == challenge.to_dict()
    assert sent["payload"] == {"signature": "0xsignature", "type": "transaction"}
    assert core_mcp.parse_credential(sent).challenge == challenge


async def test_passes_through_when_no_payment_required() -> None:
    session = FakeSession(text_result("Free tool executed"))
    create = Recorder()

    result = await McpClient(session, methods=[client_method(create)]).call_tool(
        "free_tool", {}, read_timeout_seconds=30
    )

    assert result.content == [TextContent(type="text", text="Free tool executed")]
    assert result.receipt is None
    assert session.calls == [
        {"name": "free_tool", "arguments": {}, "read_timeout_seconds": 30, "meta": None}
    ]
    assert create.calls == []


async def test_passes_context_to_the_method() -> None:
    challenge = create_challenge()
    session = FakeSession(payment_error(challenge), text_result("ok"))
    create = Recorder()

    await McpClient(session, methods=[client_method(create, context=AccountContext)]).call_tool(
        "premium_tool", context={"account": "0xabc"}
    )

    assert create.calls[0].context == AccountContext(account="0xabc")


async def test_retries_a_verification_challenge_from_a_credential_bearing_call() -> None:
    challenge = create_challenge()
    session = FakeSession(
        payment_error(challenge),
        payment_error(challenge, core_mcp.PAYMENT_VERIFICATION_FAILED_CODE),
        text_result("Premium tool executed", {core_mcp.RECEIPT_META_KEY: mcp_receipt(challenge)}),
    )
    create = Recorder()

    result = await McpClient(session, methods=[client_method(create)]).call_tool("premium_tool")

    assert result.receipt is not None
    assert len(session.calls) == 3
    assert len(create.calls) == 2


async def test_limits_repeated_payment_verification_attempts() -> None:
    challenge = create_challenge()
    verification_error = payment_error(challenge, core_mcp.PAYMENT_VERIFICATION_FAILED_CODE)
    session = FakeSession(payment_error(challenge), verification_error)
    create = Recorder()

    with pytest.raises(MCPError) as raised:
        await McpClient(session, methods=[client_method(create)]).call_tool("premium_tool")

    assert raised.value is verification_error
    assert len(session.calls) == 4
    assert len(create.calls) == 3


async def test_handles_payment_challenge_metadata_returned_as_a_tool_result() -> None:
    challenge = create_challenge()
    session = FakeSession(
        {
            "_meta": {
                core_mcp.PAYMENT_REQUIRED_META_KEY: {
                    "challenges": [challenge.to_dict()],
                    "httpStatus": 402,
                }
            },
            "content": [{"type": "text", "text": "Payment Required"}],
            "isError": True,
        },
        text_result("Premium tool executed", {core_mcp.RECEIPT_META_KEY: mcp_receipt(challenge)}),
    )
    create = Recorder()

    result = await McpClient(session, methods=[client_method(create)]).call_tool("premium_tool")

    assert result.content == [TextContent(type="text", text="Premium tool executed")]
    assert result.receipt is not None
    assert len(create.calls) == 1
    assert len(session.calls) == 2


async def test_creates_credentials_with_the_selected_same_key_method() -> None:
    challenge = create_challenge()
    session = FakeSession(payment_error(challenge), text_result("paid"))
    first = Recorder(RuntimeError("unselected method used"))
    selected = Recorder()

    client = McpClient(
        session,
        methods=[client_method(first), client_method(selected)],
        order_challenges=lambda candidates: [candidates[1], candidates[0]],
    )
    await client.call_tool("premium_tool")

    assert first.calls == []
    assert len(selected.calls) == 1


async def test_raises_when_method_not_found() -> None:
    session = FakeSession(payment_error(create_challenge(method="unknown_method")))

    with pytest.raises(
        ValueError,
        match=r"No compatible payment method\. Server offers: unknown_method\.charge\. "
        r"Client has: tempo\.charge",
    ):
        await McpClient(session, methods=[client_method(Recorder())]).call_tool("tool")


async def test_rejects_expired_challenges_before_creating_credential() -> None:
    session = FakeSession(payment_error(create_challenge(expires_in=-60)))
    create = Recorder()

    with pytest.raises(PaymentExpiredError):
        await McpClient(session, methods=[client_method(create)]).call_tool("expired_tool")
    assert create.calls == []


async def test_non_payment_errors_propagate() -> None:
    error = MCPError(-32600, "Invalid Request")
    session = FakeSession(error)
    with pytest.raises(MCPError) as raised:
        await McpClient(session, methods=[client_method(Recorder())]).call_tool("tool")
    assert raised.value is error


# -- is_payment_required_error ----------------------------------------------------------------

CHALLENGE = {"id": "test", "method": "tempo", "intent": "charge", "realm": "test", "request": {}}


@pytest.mark.parametrize(
    "code", [core_mcp.PAYMENT_REQUIRED_CODE, core_mcp.PAYMENT_VERIFICATION_FAILED_CODE]
)
def test_is_payment_required_error_for_payment_codes(code: int) -> None:
    error = MCPError(code, "Payment Required", {"httpStatus": 402, "challenges": [CHALLENGE]})
    assert is_payment_required_error(error)


@pytest.mark.parametrize(
    "error",
    [
        MCPError(-32600, "Invalid Request", {"httpStatus": 402, "challenges": [CHALLENGE]}),
        MCPError(core_mcp.PAYMENT_REQUIRED_CODE, "Payment Required", {"httpStatus": 402}),
        MCPError(core_mcp.PAYMENT_REQUIRED_CODE, "Payment Required", {"challenges": [{"id": 1}]}),
        None,
        RuntimeError("test"),
        "error",
    ],
)
def test_is_payment_required_error_rejects_other_values(error: object) -> None:
    assert not is_payment_required_error(error)


# -- end to end over MCPServer ----------------------------------------------------------------


def server_method() -> ServerMethod:
    async def verify(context: VerifyContext[Any]) -> Receipt:
        return Receipt(method="tempo", reference="0xhash", timestamp=expires.to_iso(expires.now()))

    return ServerMethod(method=charge, verify=verify)


def create_server(register: Callable[[MCPServer, Mpp], None] | None = None) -> MCPServer:
    payment = Mpp(
        methods=[server_method()], realm=REALM, secret_key=SECRET_KEY, transport=mcp_sdk()
    )
    server = MCPServer("test-server")

    @server.tool(description="A tool that requires payment")
    @paid(payment.charge(amount="1"))
    async def premium_tool() -> str:
        return "Premium tool executed"

    @server.tool(description="A free tool")
    async def free_tool() -> str:
        return "Free tool executed"

    @server.tool(description="Broken")
    async def broken_tool() -> str:
        raise RuntimeError("Internal server error")

    if register is not None:
        register(server, payment)
    return server


async def test_end_to_end_pays_and_returns_result_with_receipt() -> None:
    create = Recorder()
    async with Client(create_server()) as session:
        mcp = McpClient(session, methods=[client_method(create)])
        result = await mcp.call_tool("premium_tool", {})
        free = await mcp.call_tool("free_tool", {})
        broken = await mcp.call_tool("broken_tool", {})

    assert result.content == [TextContent(type="text", text="Premium tool executed")]
    assert result.is_error is False
    assert result.receipt is not None
    assert (result.receipt.status, result.receipt.method, result.receipt.reference) == (
        "success",
        "tempo",
        "0xhash",
    )
    assert len(create.calls) == 1
    assert free.content == [TextContent(type="text", text="Free tool executed")]
    assert free.receipt is None
    assert broken.is_error is True


async def test_end_to_end_tool_raising_unknown_method_challenge() -> None:
    def register(server: MCPServer, payment: Mpp) -> None:
        @server.tool()
        async def tool_unknown_method() -> str:
            raise payment_error(create_challenge(method="unknown_method"))

    async with Client(create_server(register)) as session:
        with pytest.raises(ValueError, match="No compatible payment method"):
            await McpClient(session, methods=[client_method(Recorder())]).call_tool(
                "tool_unknown_method", {}
            )


async def test_forwards_sdk_call_options_on_first_call_and_paid_retries() -> None:
    challenge = create_challenge()
    session = FakeSession(payment_error(challenge), text_result("ok"))

    await McpClient(session, methods=[client_method(Recorder())]).call_tool(
        "tool", {}, request_state="state-1", input_responses={"q": "a"}, future_option=1
    )

    assert len(session.calls) == 2
    for call in session.calls:
        assert call["request_state"] == "state-1"
        assert call["input_responses"] == {"q": "a"}
        assert call["future_option"] == 1
