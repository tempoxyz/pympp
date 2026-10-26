"""Generic MCP payment verification.

This module provides framework-agnostic functions for MCP payment handling.
Use these with any MCP server implementation (FastMCP, mcp-python, custom, etc.).

Example with raw JSON-RPC handling:
    from mpp.extensions.mcp import PaymentRequiredError, verify_or_challenge
    from mpp.server import Mpp

    mpp = Mpp(methods=tempo.charge(recipient="0x..."))

    async def handle_tool_call(params: dict) -> dict:
        result = await verify_or_challenge(
            mpp.charge(amount="0.01"),
            tool="expensive_tool",
            meta=params.get("_meta"),
        )

        if isinstance(result, list):
            # Return JSON-RPC error with -32042
            return {"error": PaymentRequiredError(challenges=result).to_jsonrpc_error()}

        credential, receipt = result
        # Proceed with tool execution
        tool_result = await execute_tool(params)
        # Include receipt in response _meta
        return {
            "result": {
                **tool_result,
                "_meta": receipt.to_meta(),
            }
        }
"""

from __future__ import annotations

import json
from typing import Any

import rfc8785

from mpp import Challenge
from mpp.errors import PaymentRequiredError as CorePaymentRequiredError
from mpp.extensions.mcp.constants import META_CREDENTIAL
from mpp.extensions.mcp.errors import (
    MalformedCredentialError,
    PaymentVerificationError,
)
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt
from mpp.server import ComposedHandler, PaymentVerified, Request
from mpp.server.compose import MCP_URL_PREFIX

TOOL_ROUTE_PREFIX = "tool:"
"""Prefix of the route bound into a paid tool's challenges (``"tool:<name>"``)."""

_TOOL_CALL_URL = f"{MCP_URL_PREFIX}tools/call"


async def verify_or_challenge(
    handler: ComposedHandler,
    *,
    tool: str,
    meta: dict[str, Any] | None = None,
) -> list[MCPChallenge] | tuple[MCPCredential, MCPReceipt]:
    """Verify a tool call's payment credential or return the challenges to pay.

    Runs a route handler of a server ``Mpp`` (such as ``mpp.charge(amount="0.01")``)
    for an MCP tool call: the credential is read from
    ``_meta["org.paymentauth/credential"]`` and every challenge is bound to ``tool``,
    so a credential paid for one tool is rejected by every other tool.

    Args:
        handler: A configured payment handler of a server ``Mpp``.
        tool: Stable receiving tool identity, unique to this paid tool within the realm.
            Use the registered MCP tool name.
        meta: The ``_meta`` dict from the MCP request params (may be None).

    Returns:
        The challenges to return as a -32042 error when no valid credential was sent,
        or the verified credential and its receipt.

    Raises:
        MalformedCredentialError: If the credential structure is invalid (-32602).
        PaymentVerificationError: If the credential was rejected (-32043).
    """
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty stable identifier")

    credential: MCPCredential | None = None
    authorization: str | None = None
    credential_data = (meta or {}).get(META_CREDENTIAL)
    if credential_data is not None:
        try:
            credential = MCPCredential.from_dict(credential_data)
        except (KeyError, TypeError, AttributeError) as e:
            raise MalformedCredentialError(detail=f"Invalid credential structure: {e}") from e
        try:
            authorization = credential.to_core().to_authorization()
        except rfc8785.CanonicalizationError:
            # An echo that cannot be canonically encoded was not issued by this server.
            authorization = None

    headers = {}
    if authorization is not None:
        headers = {"Authorization": authorization, "Payment-Authorization": authorization}
    result = await handler(
        Request("POST", _TOOL_CALL_URL, headers=headers, route=f"{TOOL_ROUTE_PREFIX}{tool}")
    )

    if isinstance(result, PaymentVerified):
        assert credential is not None
        receipt = MCPReceipt.from_core(
            receipt=result.receipt,
            challenge_id=credential.challenge.id,
            method=credential.challenge.method,
            settlement=_extract_settlement(credential.challenge.request),
        )
        return credential, receipt

    response = result.challenge
    challenges = [
        _mcp_challenge(Challenge.from_www_authenticate(value))
        for value in response.headers.get_list("www-authenticate")
    ]
    try:
        problem = json.loads(response.body or b"{}")
    except ValueError:
        problem = {}
    if not isinstance(problem, dict):
        problem = {}
    if response.status == 402 and problem.get("type") in (None, CorePaymentRequiredError.type):
        return challenges
    problem_type = problem.get("type")
    raise PaymentVerificationError(
        challenges=challenges,
        http_status=response.status,
        reason=problem_type.rsplit("/", 1)[-1] if isinstance(problem_type, str) else None,
        detail=problem.get("detail"),
        details=problem.get("details"),
    )


def _mcp_challenge(challenge: Challenge) -> MCPChallenge:
    return MCPChallenge.from_core(
        challenge,
        realm=challenge.realm,
        expires=challenge.expires,
        description=challenge.description,
    )


def _extract_settlement(request: dict[str, Any]) -> dict[str, Any] | None:
    """Extract settlement info from request if available."""
    settlement: dict[str, Any] = {}
    if "amount" in request:
        settlement["amount"] = request["amount"]
    if "currency" in request:
        settlement["currency"] = request["currency"]
    return settlement if settlement else None
