"""MCP payment error types.

Per draft-payment-transport-mcp-00:
- -32042 PaymentRequiredError: No valid credential provided, issue challenge
- -32043 PaymentVerificationError: Credential provided but verification failed
- -32602 MalformedCredentialError: Credential structure invalid

All payment errors include httpStatus: 402 in error.data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

from mpp.extensions.mcp.constants import (
    CODE_MALFORMED_CREDENTIAL,
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    HTTP_STATUS_PAYMENT_REQUIRED,
)

if TYPE_CHECKING:
    from mpp.extensions.mcp.types import MCPChallenge


class PaymentRequiredError(McpError):
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

    def __init__(
        self,
        challenges: list[MCPChallenge],
        message: str = "Payment Required",
    ) -> None:
        self.challenges = challenges
        self.message = message
        error = ErrorData(
            code=CODE_PAYMENT_REQUIRED,
            message=message,
            data={
                "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
                "challenges": [c.to_dict() for c in challenges],
            },
        )
        super().__init__(error)

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


class PaymentVerificationError(McpError):
    """Payment verification failed.

    Raised when a credential was provided but verification failed.
    Returns error code -32043 with a fresh challenge. Machine-readable
    ``details`` (e.g. safe relay error codes) are included in the failure
    payload when provided.

    Example:
        raise PaymentVerificationError(
            challenges=[MCPChallenge(...)],
            reason="signature-invalid",
            detail="Signature verification failed",
        )
    """

    def __init__(
        self,
        challenges: list[MCPChallenge],
        reason: str | None = None,
        detail: str | None = None,
        details: dict[str, Any] | None = None,
        message: str = "Payment Verification Failed",
    ) -> None:
        self.challenges = challenges
        self.reason = reason
        self.detail = detail
        self.details = details
        self.message = message

        error = ErrorData(
            code=CODE_PAYMENT_VERIFICATION_FAILED,
            message=message,
            data=self._error_data(),
        )
        super().__init__(error)

    def _error_data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
            "challenges": [c.to_dict() for c in self.challenges],
        }
        failure: dict[str, Any] = {}
        if self.reason is not None:
            failure["reason"] = self.reason
        if self.detail is not None:
            failure["detail"] = self.detail
        if self.details is not None:
            failure["details"] = self.details
        if failure:
            data["failure"] = failure
        return data

    def to_jsonrpc_error(self) -> dict[str, Any]:
        """Convert to JSON-RPC error response format."""
        return {
            "code": CODE_PAYMENT_VERIFICATION_FAILED,
            "message": self.message,
            "data": self._error_data(),
        }


class MalformedCredentialError(McpError):
    """Credential structure was malformed.

    Raised when the credential JSON structure is invalid (not a verification
    failure). Uses standard JSON-RPC Invalid params code -32602.

    Example:
        raise MalformedCredentialError(detail="Missing required field: challenge.id")
    """

    def __init__(
        self,
        detail: str,
        message: str = "Invalid params",
    ) -> None:
        self.detail = detail
        self.message = message
        error = ErrorData(
            code=CODE_MALFORMED_CREDENTIAL,
            message=message,
            data={
                "httpStatus": HTTP_STATUS_PAYMENT_REQUIRED,
                "detail": detail,
            },
        )
        super().__init__(error)

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
