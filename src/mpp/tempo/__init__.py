"""Tempo payment method: the charge intent on the Tempo chain.

Submodules:

- :mod:`mpp.tempo.methods` - method definitions (request/payload schemas).
- :mod:`mpp.tempo.attribution` - MPP attribution memos for ``transferWithMemo``.
- :mod:`mpp.tempo.proof` - zero-amount proof credentials (EIP-712).
- :mod:`mpp.tempo.chains` / :mod:`mpp.tempo.assets` - chain IDs, deployments, tokens.

:class:`RpcClient` is the JSON-RPC client passed to ``get_client=`` for custom endpoints.
"""

from mpp._extras import require

require("tempo", "pytempo", "eth_account", "eth_abi", "rlp", "cryptography")

from mpp.tempo import assets, attribution, chains, methods, proof
from mpp.tempo._internal.rpc import RpcClient, RpcError, RpcTransportError

__all__ = [
    "RpcClient",
    "RpcError",
    "RpcTransportError",
    "assets",
    "attribution",
    "chains",
    "methods",
    "proof",
]
