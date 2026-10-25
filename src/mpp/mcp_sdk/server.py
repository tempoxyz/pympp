"""Server-side payments for tools of the official ``mcp`` SDK.

Use :func:`mcp_sdk` as the ``Mpp`` transport and either gate tools with :func:`paid` or call
the payment handler yourself::

    from mcp.server.mcpserver import Context, MCPServer

    from mpp.mcp_sdk.server import mcp_sdk, paid
    from mpp.server import Mpp

    payment = Mpp(methods=[...], transport=mcp_sdk())
    server = MCPServer("premium")

    @server.tool()
    @paid(payment.charge(amount="0.01"))
    async def search(query: str) -> str:
        return f"results for {query}"

    # or, explicitly:
    @server.tool()
    async def premium(ctx: Context) -> CallToolResult:
        result = await payment.charge(amount="0.01")(ctx)
        if result.status == 402:
            raise result.challenge  # MCPError -32042 with challenges in error.data
        return result.with_receipt(CallToolResult(content=[...]))

Challenges are bound to the called tool (``_mppx_scope = "tool:<name>"``) unless the handler sets
``scope=``, so a credential paid for one tool is rejected by every other tool.

Credentials are read from ``params._meta["org.paymentauth/credential"]``, payment errors become
JSON-RPC errors (``-32042`` payment required, ``-32043`` verification failed, ``-32602`` invalid
params, ``-32603`` internal) with the challenges in ``error.data`` and receipts are attached to
``result._meta["org.paymentauth/receipt"]``.
"""

from mpp._extras import require

require("mcp", "mcp")

import functools
import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, cast

import anyio.to_thread
import httpx
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.utilities.context_injection import find_context_parameter
from mcp.server.mcpserver.utilities.func_metadata import func_metadata
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams, CallToolResult

from mpp import mcp as _mcp
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import PaymentError
from mpp.method import CapturedRequest, VerifiedChallengeEnvelope
from mpp.receipt import Receipt
from mpp.server import McpTransport, PaymentResult, Response, make_headers

type Extra = Context | ServerRequestContext[Any, Any] | CallToolRequestParams | Mapping[str, Any]
"""The transport input: an ``MCPServer`` tool :class:`~mcp.server.mcpserver.Context`, a
low-level ``ServerRequestContext`` or ``CallToolRequestParams``, or a mapping with ``_meta``."""

type Handler = Callable[[Any], Awaitable[PaymentResult]]

_INJECTED_CONTEXT = "mpp_context"


class McpSdkTransport(
    McpTransport[Extra, MCPError, CallToolResult | Mapping[str, Any] | Response, CallToolResult]
):
    """``Mpp`` transport for tool handlers of the official ``mcp`` SDK.

    Challenges are :class:`~mcp.shared.exceptions.MCPError` instances to raise from the tool;
    ``with_receipt`` accepts a :class:`~mcp.types.CallToolResult` (or its wire mapping) and
    returns a ``CallToolResult`` carrying the receipt in ``_meta``.
    """

    name = "mcp-sdk"

    async def capture_request(self, input: Extra) -> CapturedRequest:
        # MCP tool invocations are application content requests even though they carry no HTTP
        # body headers on the transport boundary.
        return CapturedRequest(
            method="POST",
            url=httpx.URL("mcp://request/sdk"),
            headers=make_headers(),
            has_body=True,
        )

    def route_scope(self, input: Extra) -> str | None:
        """Binds challenges to the called tool (``"tool:<name>"``) unless the route sets ``scope``.

        A credential issued for one tool is then rejected by every other tool, even one with
        identical payment terms. mppx leaves MCP challenges unscoped.
        """
        name = tool_name(input)
        return f"{TOOL_SCOPE_PREFIX}{name}" if name else None

    def get_credential(self, input: Extra) -> Credential[Any] | None:
        meta = request_meta(input)
        # Only an absent key means "no credential"; an explicit null is malformed (-32602).
        if _mcp.CREDENTIAL_META_KEY not in meta:
            return None
        return _mcp.parse_credential(meta[_mcp.CREDENTIAL_META_KEY])

    async def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: Extra,
        error: PaymentError | None = None,
    ) -> MCPError:
        data: dict[str, Any] = {
            "httpStatus": error.status if error is not None else 402,
            "challenges": [challenge.to_dict()],
        }
        if error is not None:
            data["problem"] = error.to_problem_details(challenge.id)
        return MCPError(
            _mcp.error_code(error),
            error.message if error is not None else "Payment Required",
            data,
        )

    def respond_receipt(
        self,
        *,
        challenge_id: str,
        credential: Credential[Any],
        input: Extra,
        receipt: Receipt,
        response: CallToolResult | Mapping[str, Any] | Response,
        envelope: VerifiedChallengeEnvelope[Any] | None = None,
    ) -> CallToolResult:
        if isinstance(response, Response):
            result = CallToolResult(content=[])
        elif isinstance(response, CallToolResult):
            result = response
        else:
            result = CallToolResult.model_validate(response)
        meta = {
            **(result.meta or {}),
            _mcp.RECEIPT_META_KEY: {**receipt.to_dict(), "challengeId": challenge_id},
        }
        return result.model_copy(update={"meta": meta})

    def payment_required_challenges(self, output: MCPError) -> list[Any] | None:
        if not isinstance(output, MCPError) or output.code != _mcp.PAYMENT_REQUIRED_CODE:
            return None
        data = output.data
        challenges = data.get("challenges") if isinstance(data, Mapping) else None
        return list(challenges) if challenges else None

    def with_challenges(self, output: MCPError, challenges: list[Any]) -> MCPError:
        return MCPError(output.code, "Payment Required", {**output.data, "challenges": challenges})


def mcp_sdk() -> McpSdkTransport:
    """Creates the ``mcp`` SDK server transport."""
    return McpSdkTransport()


TOOL_SCOPE_PREFIX = "tool:"
"""Prefix of the default challenge scope of a paid tool (``"tool:<name>"``)."""


def tool_name(input: Extra) -> str | None:
    """Returns the name of the called tool, or ``None`` when the input is not a tool call."""
    if isinstance(input, CallToolRequestParams):
        return input.name
    if isinstance(input, Mapping):
        name = input.get("name")
        return name if isinstance(name, str) and name else None
    if isinstance(input, Context):
        try:
            context = input.request_context
        except ValueError:
            return None
    else:
        context = input
    params = context.params
    if context.method != "tools/call" or not isinstance(params, Mapping):
        return None
    name = params.get("name")
    return name if isinstance(name, str) and name else None


def request_meta(input: Extra) -> Mapping[str, Any]:
    """Returns the request ``_meta`` of a transport input (empty when absent)."""
    if isinstance(input, Mapping):
        meta = input.get("_meta")
    elif isinstance(input, Context):
        meta = input.request_context.meta
    else:
        meta = input.meta
    return meta if isinstance(meta, Mapping) else {}


def paid[F: Callable[..., Any]](handler: Handler) -> Callable[[F], F]:
    """Requires payment before an ``MCPServer`` tool runs.

    Apply below ``@server.tool()``. Without a valid credential the call fails with the
    payment-required JSON-RPC error; otherwise the tool runs and its result is returned with
    the receipt in ``_meta``. Unless the handler sets ``scope=``, its challenges are bound to
    the called tool (``"tool:<name>"``), so a credential paid for one tool cannot be replayed
    against another. The tool keeps its input and output schemas; a ``Context``
    parameter is injected when the tool does not declare one.

    Args:
        handler: A configured payment handler of an ``Mpp`` using :func:`mcp_sdk`, e.g.
            ``payment.charge(amount="0.01")``.
    """

    def decorate(fn: F) -> F:
        context_name = find_context_parameter(fn)
        metadata = func_metadata(fn, skip_names=[context_name] if context_name else [])
        is_async = inspect.iscoroutinefunction(fn)

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> CallToolResult:
            context = kwargs[context_name] if context_name else kwargs.pop(_INJECTED_CONTEXT)
            result = await handler(context)
            if result.status == 402:
                raise result.challenge
            if is_async:
                output = await fn(*args, **kwargs)
            else:
                output = await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
            converted = metadata.convert_result(output)
            if not isinstance(converted, CallToolResult):
                raise TypeError("Paid tools must not return an InputRequiredResult.")
            return result.with_receipt(converted)

        if context_name is None:
            signature = inspect.signature(fn, eval_str=True)
            parameter = inspect.Parameter(
                _INJECTED_CONTEXT, inspect.Parameter.KEYWORD_ONLY, annotation=Context
            )
            parameters = list(signature.parameters.values())
            if parameters and parameters[-1].kind is inspect.Parameter.VAR_KEYWORD:
                parameters.insert(-1, parameter)
            else:
                parameters.append(parameter)
            wrapper.__signature__ = signature.replace(parameters=parameters)  # type: ignore[attr-defined]
            wrapper.__annotations__ = {**fn.__annotations__, _INJECTED_CONTEXT: Context}
        return cast(F, wrapper)

    return decorate


__all__ = [
    "TOOL_SCOPE_PREFIX",
    "Extra",
    "McpSdkTransport",
    "mcp_sdk",
    "paid",
    "request_meta",
    "tool_name",
]
