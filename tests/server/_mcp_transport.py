"""A raw JSON-RPC MCP server transport (test double for the core MCP code paths)."""

from typing import Any
from urllib.parse import quote

import httpx

from mpp import mcp as _mcp
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import PaymentError
from mpp.method import CapturedRequest, VerifiedChallengeEnvelope
from mpp.receipt import Receipt
from mpp.server import McpTransport, make_headers


class JsonRpcMcpTransport(
    McpTransport[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]
):
    """MCP transport for raw JSON-RPC message dicts.

    Reads credentials from ``params._meta["org.paymentauth/credential"]``, issues challenges as
    JSON-RPC errors (``-32042`` / ``-32043`` / ``-32602`` / ``-32603``) and attaches receipts to
    ``result._meta["org.paymentauth/receipt"]``.
    """

    name = "mcp"

    async def capture_request(self, input: dict[str, Any]) -> CapturedRequest:
        # MCP tool invocations are application content requests even though they carry no HTTP
        # body headers on the transport boundary.
        method = input.get("method") or "unknown"
        return CapturedRequest(
            method="POST",
            url=httpx.URL(f"mcp://request/{quote(str(method), safe='')}"),
            headers=make_headers(),
            has_body=True,
        )

    def get_credential(self, input: dict[str, Any]) -> Credential[Any] | None:
        params = input.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        # Only an absent key means "no credential"; `null` is a malformed credential (mppx).
        if not isinstance(meta, dict) or _mcp.CREDENTIAL_META_KEY not in meta:
            return None
        return _mcp.parse_credential(meta[_mcp.CREDENTIAL_META_KEY])

    async def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: dict[str, Any],
        error: PaymentError | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "httpStatus": error.status if error is not None else 402,
            "challenges": [challenge.to_dict()],
        }
        if error is not None:
            data["problem"] = error.to_problem_details(challenge.id)
        return {
            "jsonrpc": "2.0",
            "id": input.get("id"),
            "error": {
                "code": _mcp.error_code(error),
                "message": error.message if error is not None else "Payment Required",
                "data": data,
            },
        }

    def respond_receipt(
        self,
        *,
        challenge_id: str,
        credential: Credential[Any],
        input: dict[str, Any],
        receipt: Receipt,
        response: dict[str, Any],
        envelope: VerifiedChallengeEnvelope[Any] | None = None,
    ) -> dict[str, Any]:
        if "error" in response:
            return response
        result = dict(response.get("result") or {})
        result["_meta"] = {
            **(result.get("_meta") or {}),
            _mcp.RECEIPT_META_KEY: {**receipt.to_dict(), "challengeId": challenge_id},
        }
        return {**response, "result": result}

    def payment_required_challenges(self, output: dict[str, Any]) -> list[Any] | None:
        error = output.get("error") if isinstance(output, dict) else None
        if not isinstance(error, dict) or error.get("code") != _mcp.PAYMENT_REQUIRED_CODE:
            return None
        data = error.get("data")
        challenges = data.get("challenges") if isinstance(data, dict) else None
        return list(challenges) if challenges else None

    def with_challenges(self, output: dict[str, Any], challenges: list[Any]) -> dict[str, Any]:
        error = output["error"]
        return {**output, "error": {**error, "data": {**error["data"], "challenges": challenges}}}


def mcp_transport() -> JsonRpcMcpTransport:
    return JsonRpcMcpTransport()
