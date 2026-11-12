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
from mpp._typing import is_dict
from mpp.errors import InvalidChallengeError, PaymentExpiredError
from mpp.errors import MalformedCredentialError as CoreMalformedCredentialError
from mpp.errors import PaymentRequiredError as CorePaymentRequiredError
from mpp.extensions.mcp.constants import META_CREDENTIAL
from mpp.extensions.mcp.errors import (
    MalformedCredentialError,
    PaymentVerificationError,
    RejectedChallenges,
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
        or the verified credential and its receipt. When a credential was rejected
        before settlement (malformed, unknown, already used or expired), the list is
        a :class:`RejectedChallenges` that also carries its problem details (such as
        ``invalid-challenge``), which ``PaymentRequiredError(challenges=result)`` sends
        in ``data.problem`` so clients can tell it from a first payment request.

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
    # A tool call is an application content request even though it has no HTTP body, so
    # it carries an empty one: a body-less POST would read as session management (top-up,
    # close) and serve the tool without charging (mppx's MCP transports set hasBody).
    result = await handler(
        Request(
            "POST",
            _TOOL_CALL_URL,
            headers=headers,
            body=b"",
            route=f"{TOOL_ROUTE_PREFIX}{tool}",
        )
    )

    if isinstance(result, PaymentVerified):
        assert credential is not None
        if result.response is not None:
            # The method handled the request itself (a management response): a tool call
            # cannot return it, and the tool must not run.
            raise PaymentVerificationError(
                challenges=[],
                detail="The credential is not valid for a tool call.",
            )
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
        decoded = json.loads(response.body or b"{}")
    except ValueError:
        decoded = None
    problem: dict[str, Any] = decoded if is_dict(decoded) else {}
    problem_type = problem.get("type")
    if response.status == 402 and problem_type in _RECHALLENGE_TYPES:
        if problem_type in (None, CorePaymentRequiredError.type):
            return challenges
        # A rejected credential (such as an already-used one) keeps its problem
        # details beside the fresh challenges, as the MCP transport draft and mppx
        # allow, so a client never mistakes it for a first payment request.
        return RejectedChallenges(challenges, problem=problem)
    raise PaymentVerificationError(
        challenges=challenges,
        http_status=response.status,
        reason=problem_type.rsplit("/", 1)[-1] if isinstance(problem_type, str) else None,
        detail=problem.get("detail"),
        details=problem.get("details"),
    )


_RECHALLENGE_TYPES = frozenset(
    {
        None,
        CorePaymentRequiredError.type,
        CoreMalformedCredentialError.type,
        InvalidChallengeError.type,
        PaymentExpiredError.type,
    }
)
"""Problem types of a ``402`` answered with fresh challenges (-32042): no credential, or
one rejected before settlement (malformed, unknown, already used or expired), whose
problem details go in ``data.problem``."""


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
