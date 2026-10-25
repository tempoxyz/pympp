"""Integration with the official ``mcp`` Python SDK (install the ``mcp`` extra).

* :mod:`mpp.mcp_sdk.server`: the ``mcp_sdk()`` ``Mpp`` transport and the ``@paid(...)`` tool
  decorator for ``MCPServer`` / low-level servers.
* :mod:`mpp.mcp_sdk.client`: ``McpClient``, which pays tool-call challenges automatically.

Wire constants (error codes, ``_meta`` keys) live in :mod:`mpp.mcp`.
"""
