"""Resolves Tempo JSON-RPC clients per chain (mppx ``Client.getResolver``)."""

from __future__ import annotations

import weakref
from collections.abc import Awaitable, Callable, Mapping

from mpp.method import resolve
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer, resolve_headers
from mpp.tempo._internal.rpc import RpcClient
from mpp.tempo.chains import RPC_URLS

type GetClient = Callable[[int | None], RpcClient | Awaitable[RpcClient]]
"""Returns the RPC client for a chain ID (``None`` asks for the default client)."""


class ClientResolver:
    """Resolves (and caches) RPC clients by chain ID.

    With ``get_client`` the caller owns client construction; otherwise clients
    are created for the default Tempo RPC URLs.
    """

    def __init__(
        self, *, get_client: GetClient | None = None, rpc_urls: Mapping[int, str] = RPC_URLS
    ) -> None:
        self._get_client = get_client
        self._rpc_urls = rpc_urls
        self._clients: dict[int, RpcClient] = {}
        self._chain_ids: weakref.WeakKeyDictionary[RpcClient, int] = weakref.WeakKeyDictionary()

    async def __call__(self, chain_id: int | None = None) -> RpcClient:
        if self._get_client is not None:
            return await resolve(self._get_client(chain_id))
        resolved = chain_id or next(iter(self._rpc_urls))
        if (client := self._clients.get(resolved)) is not None:
            return client
        url = self._rpc_urls.get(resolved)
        if url is None:
            raise ValueError(f"No `rpcUrl` configured for `chainId` ({resolved}).")
        client = self._clients[resolved] = RpcClient(url)
        self._chain_ids[client] = resolved
        return client

    async def default_chain_id(self) -> int:
        """The chain of the default client (queried once via ``eth_chainId`` if unknown)."""
        if self._get_client is None:
            return next(iter(self._rpc_urls))
        return await self.chain_id_of(await self(None))

    async def chain_id_of(self, client: RpcClient) -> int:
        """The chain a client is connected to (cached; queried via ``eth_chainId`` once)."""
        if (known := self._chain_ids.get(client)) is not None:
            return known
        chain_id = self._chain_ids[client] = await client.chain_id()
        return chain_id


def remote_fee_payer_client(config: RemoteFeePayer) -> RpcClient:
    """An RPC client for a hosted fee-payer service."""
    return RpcClient(config.url, http=config.http, headers=resolve_headers(config))
