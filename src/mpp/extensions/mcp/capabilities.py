"""Payment capability advertisement for MCP.

Per draft-payment-transport-mcp-00, servers advertise payment support via
the experimental.payment capability in InitializeResult.
"""

from typing import Any


def payment_capabilities(
    methods: list[str],
    intents: list[str],
) -> dict[str, Any]:
    """Build payment capabilities object for FastMCP.

    Returns a dict suitable for FastMCP's experimental capabilities:

        mcp = FastMCP(
            "my-server",
            capabilities={"experimental": payment_capabilities(["tempo"], ["charge"])},
        )

    Args:
        methods: Supported payment method identifiers (e.g., ["tempo", "stripe"]).
        intents: Supported payment intent types (e.g., ["charge", "authorize"]).

    Returns:
        Dict with payment capabilities for the experimental namespace.
    """
    return {
        "payment": {
            "methods": methods,
            "intents": intents,
        }
    }
