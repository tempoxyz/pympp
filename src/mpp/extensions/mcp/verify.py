"""Generic MCP payment verification.

This module provides framework-agnostic functions for MCP payment handling.
Use these with any MCP server implementation (FastMCP, mcp-python, custom, etc.).

Example with raw JSON-RPC handling:
    from mpp.extensions.mcp import verify_or_challenge, MCPChallenge

    async def handle_tool_call(params: dict) -> dict:
        meta = params.get("_meta", {})
        result = await verify_or_challenge(
            meta=meta,
            intent=intent,
            request={"amount": "1000", ...},
            realm="api.example.com",
        )

        if isinstance(result, MCPChallenge):
            # Return JSON-RPC error with -32042
            return {
                "error": PaymentRequiredError(challenges=[result]).to_jsonrpc_error()
            }

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

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from mpp import _constant_time_equal, generate_challenge_id
from mpp.extensions.mcp.constants import META_CREDENTIAL
from mpp.extensions.mcp.errors import (
    MalformedCredentialError,
    PaymentVerificationError,
)
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt

if TYPE_CHECKING:
    from mpp.server.intent import Intent

DEFAULT_CHALLENGE_TTL = timedelta(minutes=5)


async def verify_or_challenge(
    *,
    meta: dict[str, Any] | None,
    intent: Intent,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    method: str | None = None,
    expires_in: timedelta = DEFAULT_CHALLENGE_TTL,
    description: str | None = None,
) -> MCPChallenge | tuple[MCPCredential, MCPReceipt]:
    """Verify a payment credential or generate a new challenge.

    This is the core function for MCP payment handling. It works with any
    MCP server implementation - just extract _meta from params and pass it here.

    Args:
        meta: The _meta dict from MCP params (may be None).
        intent: The payment intent to verify against.
        request: The payment request parameters.
        realm: Protection space identifier for the challenge.
        secret_key: Server secret for HMAC-bound challenge IDs. Required.
            Enables stateless challenge verification by computing challenge IDs
            as HMAC-SHA256 over the challenge parameters.
        method: Payment method name (defaults to "tempo").
        expires_in: Challenge validity duration (default: 5 minutes).
        description: Human-readable description of what the payment is for.

    Returns:
        If no valid credential:
            An MCPChallenge to return as a -32042 error.
        If credential is valid:
            A tuple of (MCPCredential, MCPReceipt) for the successful payment.

    Raises:
        MalformedCredentialError: If credential structure is invalid (-32602).
        PaymentVerificationError: If credential verification fails (-32043).

    Example:
        # In any MCP server handler
        meta = params.get("_meta", {})
        result = await verify_or_challenge(
            meta=meta,
            intent=intent,  # ChargeIntent with rpc_url set by tempo()
            request={"amount": "1000", "currency": "0x...", "recipient": "0x..."},
            realm="api.example.com",
            secret_key="my-server-secret",
        )

        if isinstance(result, MCPChallenge):
            # No credential - return payment required error
            error = PaymentRequiredError(challenges=[result])
            return {"error": error.to_jsonrpc_error()}

        credential, receipt = result
        # Payment verified - execute tool and include receipt
        tool_result = await run_tool(...)
        return {
            "result": {
                "content": [{"type": "text", "text": tool_result}],
                "_meta": receipt.to_meta(),
            }
        }
    """
    method_name = method or "tempo"
    meta = meta or {}

    credential_data = meta.get(META_CREDENTIAL)

    if credential_data is None:
        return create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires_in=expires_in,
            description=description,
        )

    try:
        mcp_credential = MCPCredential.from_dict(credential_data)
    except (KeyError, TypeError) as e:
        raise MalformedCredentialError(detail=f"Invalid credential structure: {e}") from e

    # Stateless challenge verification: recompute expected challenge ID from
    # echoed parameters and compare to the credential's challenge ID.
    echoed = mcp_credential.challenge
    expected_id = generate_challenge_id(
        secret_key=secret_key,
        realm=echoed.realm,
        method=echoed.method,
        intent=echoed.intent,
        request=echoed.request,
        expires=echoed.expires,
        digest=echoed.digest,
        opaque=echoed.opaque,
    )
    if not _constant_time_equal(echoed.id, expected_id):
        return create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires_in=expires_in,
            description=description,
        )

    # Assert echoed challenge fields match server's values to prevent cross-realm attacks
    if echoed.realm != realm or echoed.method != method_name or echoed.intent != intent.name:
        return create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires_in=expires_in,
            description=description,
        )

    from mpp.server.intent import VerificationError

    core_credential = mcp_credential.to_core()

    try:
        core_receipt = await intent.verify(core_credential, request)
    except VerificationError as e:
        challenge = create_challenge(
            method=method_name,
            intent_name=intent.name,
            request=request,
            realm=realm,
            secret_key=secret_key,
            expires_in=expires_in,
            description=description,
        )
        raise PaymentVerificationError(
            challenges=[challenge],
            reason="verification-failed",
            detail=str(e),
        ) from e

    mcp_receipt = MCPReceipt.from_core(
        receipt=core_receipt,
        challenge_id=mcp_credential.challenge.id,
        method=mcp_credential.challenge.method,
        settlement=_extract_settlement(request),
    )

    return (mcp_credential, mcp_receipt)


def create_challenge(
    *,
    method: str,
    intent_name: str,
    request: dict[str, Any],
    realm: str,
    secret_key: str,
    expires_in: timedelta = DEFAULT_CHALLENGE_TTL,
    description: str | None = None,
) -> MCPChallenge:
    """Create a new MCP payment challenge with HMAC-bound ID.

    Use this to generate challenges for custom MCP server implementations.

    Args:
        method: Payment method identifier (e.g., "tempo", "stripe").
        intent_name: Payment intent type (e.g., "charge").
        request: Payment request parameters.
        realm: Protection space identifier.
        secret_key: Server secret for HMAC-bound challenge IDs.
        expires_in: Challenge validity duration.
        description: Human-readable description.

    Returns:
        An MCPChallenge ready to be included in a -32042 error response.
    """
    expires = (datetime.now(UTC) + expires_in).isoformat()
    if expires.endswith("+00:00"):
        expires = expires[:-6] + "Z"

    challenge_id = generate_challenge_id(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        expires=expires,
    )

    return MCPChallenge(
        id=challenge_id,
        realm=realm,
        method=method,
        intent=intent_name,
        request=request,
        expires=expires,
        description=description,
    )


def _extract_settlement(request: dict[str, Any]) -> dict[str, Any] | None:
    """Extract settlement info from request if available."""
    settlement: dict[str, Any] = {}
    if "amount" in request:
        settlement["amount"] = request["amount"]
    if "currency" in request:
        settlement["currency"] = request["currency"]
    return settlement if settlement else None
