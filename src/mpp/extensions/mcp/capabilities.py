"""Payment capability advertisement for MCP.

Per draft-payment-transport-mcp-00, servers advertise payment support via
the experimental.payment capability in InitializeResult.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mpp.server import Mpp, ServerMethod


def payment_capabilities(methods: Mpp | Iterable[ServerMethod]) -> dict[str, Any]:
    """Build payment capabilities object for FastMCP.

    Advertises the methods and intents a server ``Mpp`` accepts, in configuration
    order without duplicates, as a dict suitable for FastMCP's experimental capabilities:

        mcp = FastMCP(
            "my-server",
            capabilities={"experimental": payment_capabilities(mpp)},
        )
        # {"payment": {"methods": ["tempo"], "intents": ["charge"]}}

    Args:
        methods: A server ``Mpp`` or its server methods.

    Returns:
        Dict with payment capabilities for the experimental namespace.
    """
    from mpp.server import Mpp

    configured = methods.methods if isinstance(methods, Mpp) else methods
    names: dict[str, None] = {}
    intents: dict[str, None] = {}
    for method in configured:
        names[method.name] = None
        intents[method.intent] = None
    return {
        "payment": {
            "methods": list(names),
            "intents": list(intents),
        }
    }
