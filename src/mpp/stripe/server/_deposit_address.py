"""Stripe crypto deposit addresses (machine-payments receiving addresses)."""

import weakref
from collections.abc import Callable

from mpp.stripe._internal.api import StripeRawClient
from mpp.stripe.server._request import stripe_request

_cache: dict[int, tuple[Callable[[], object], dict[str, str]]] = {}
"""Per-client address caches keyed by ``id(client)`` (clients need not be hashable)."""


def _client_cache(client: object) -> dict[str, str]:
    key = id(client)
    entry = _cache.get(key)
    if entry is not None and entry[0]() is client:
        return entry[1]
    try:
        owner: Callable[[], object] = weakref.ref(client, lambda _: _cache.pop(key, None))
    except TypeError:  # not weak-referenceable: keep it alive alongside its cache
        owner = lambda: client  # noqa: E731
    addresses: dict[str, str] = {}
    _cache[key] = (owner, addresses)
    return addresses


async def find_or_create_deposit_address(client: StripeRawClient, network: str) -> str:
    """Finds an existing deposit address or creates one for ``network``.

    Cached per client + network for the process lifetime.
    """
    client_cache = _client_cache(client)
    if cached := client_cache.get(network):
        return cached

    listing = await stripe_request(
        client,
        "GET",
        f"/v1/crypto/deposit_addresses?network={network}&limit=1",
    )
    data = listing.get("data") if isinstance(listing, dict) else None
    if data:
        address: str = data[0]["address"]
    else:
        created = await stripe_request(
            client, "POST", "/v1/crypto/deposit_addresses", {"network": network}
        )
        address = created["address"]
    client_cache[network] = address
    return address
