"""Constants for MCP payment transport.

Per draft-payment-transport-mcp-00:
- Meta keys use reverse-DNS naming (org.paymentauth/*)
- Error codes are in the JSON-RPC implementation-defined range (-32000 to -32099)
"""

META_CREDENTIAL = "org.paymentauth/credential"
"""Meta key for payment credentials in params._meta."""

META_RECEIPT = "org.paymentauth/receipt"
"""Meta key for payment receipts in result._meta."""

CODE_PAYMENT_REQUIRED = -32042
"""JSON-RPC error code: Payment required to proceed."""

CODE_PAYMENT_VERIFICATION_FAILED = -32043
"""JSON-RPC error code: Payment credential was invalid."""

CODE_MALFORMED_CREDENTIAL = -32602
"""JSON-RPC error code: Credential structure was malformed (Invalid params)."""

HTTP_STATUS_PAYMENT_REQUIRED = 402
"""HTTP status code included in error.data for transport compatibility."""
