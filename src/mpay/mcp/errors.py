"""MCP payment error types.

Per draft-payment-transport-mcp-00:
- -32042 PaymentRequiredError: No valid credential provided, issue challenge
- -32043 PaymentVerificationError: Credential provided but verification failed
- -32602 MalformedCredentialError: Credential structure invalid

All payment errors include httpStatus: 402 in error.data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mpay.mcp.constants import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    HTTP_STATUS_PAYMENT_REQUIRED,
)
from mpay.mcp.types import MCPChallenge


@dataclass
class PaymentRequiredError(Exception):
    """Payment is required to proceed.

    Raised when no credential was provided or credential was missing.
    Returns error code -32042.

    Example:
        raise PaymentRequiredError(
            challenges=[
                MCPChallenge(
                    id="ch_abc",
                    realm="api.example.com",
                    method="tempo",
                    intent="charge",
                    request={"amount": "1000"},
                )
            ]
        )
    """

    challenges: list[MCPChallenge]
    message: str = "Payment Required"

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Convert to JSON-RPC error response format."""
        return {
            "code": CODE_PAYMENT_REQUIRED,
            "message": self.message,
            "data": {
                "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
                "challenges": [c.to_dict() for c in self.challenges],
            },
        }


@dataclass
class PaymentVerificationError(Exception):
    """Payment verification failed.

    Raised when a credential was provided but verification failed.
    Returns error code -32043 with a fresh challenge.

    Example:
        raise PaymentVerificationError(
            challenges=[MCPChallenge(...)],
            reason="signature-invalid",
            detail="Signature verification failed",
        )
    """

    challenges: list[MCPChallenge]
    reason: str | None = None
    detail: str | None = None
    message: str = "Payment Verification Failed"

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Convert to JSON-RPC error response format."""
        data: dict[str, Any] = {
            "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
            "challenges": [c.to_dict() for c in self.challenges],
        }
        if self.reason is not None or self.detail is not None:
            failure: dict[str, str] = {}
            if self.reason is not None:
                failure["reason"] = self.reason
            if self.detail is not None:
                failure["detail"] = self.detail
            data["failure"] = failure
        return {
            "code": CODE_PAYMENT_VERIFICATION_FAILED,
            "message": self.message,
            "data": data,
        }


@dataclass
class MalformedCredentialError(Exception):
    """Credential structure was malformed.

    Raised when the credential JSON structure is invalid (not a verification
    failure). Uses standard JSON-RPC Invalid params code -32602.

    Example:
        raise MalformedCredentialError(detail="Missing required field: challenge.id")
    """

    detail: str
    message: str = "Invalid params"

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Convert to JSON-RPC error response format."""
        return {
            "code": CODE_MALFORMED_CREDENTIAL,
            "message": self.message,
            "data": {
                "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
                "detail": self.detail,
            },
        }
