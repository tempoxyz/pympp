"""ERC-8004 agents on the client: a prover that signs each request (mppx `Erc8004.Client`)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

import httpx
from eth_account.messages import encode_defunct

from mpp.extensions.identity.erc8004 import (
    CHAIN_ID,
    ID_HEADER,
    IDENTITY_REGISTRY,
    SIGNATURE_HEADER,
    AgentRef,
    checksum,
    message,
)
from mpp.identity import ProveContext, Prover, with_headers


def prover(
    *,
    account: Any,
    agent_id: int,
    scope: Sequence[str] | Literal["*"],
    chain_id: int = CHAIN_ID,
    registry: str = IDENTITY_REGISTRY,
) -> Prover:
    """Create a prover that signs each request as an ERC-8004 agent, with the agent's wallet.

    Args:
        account: The agent's wallet, such as an ``eth_account`` ``LocalAccount``; anything
            with ``sign_message(SignableMessage)`` returning a signature with ``.signature``.
            It also pays.
        agent_id: The agent's token ID in the Identity Registry.
        scope: Origins that receive the agent's signature, or ``"*"`` for any origin.
        chain_id: The registry's chain.
        registry: The Identity Registry.

    Example::

        prover = erc8004.client.prover(
            account=account, agent_id=42, scope=["https://api.example"]
        )
        async with Mpp(methods=[tempo_method], identity=[prover]) as mpp:
            response = await mpp.fetch("https://api.example/paid")
    """
    id = AgentRef(chain_id=chain_id, registry=checksum(registry), agent_id=int(agent_id)).format()

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        text = message(
            id=id,
            method=request.method,
            url=str(request.url),
            created=context.created,
            nonce=context.nonce,
        )
        signed = account.sign_message(encode_defunct(text=text))
        signature = bytes(signed.signature).hex()
        return with_headers(
            request,
            {
                ID_HEADER: id,
                SIGNATURE_HEADER: f"{context.created}.{context.nonce}.0x{signature}",
            },
        )

    return Prover(scope="*" if scope == "*" else tuple(scope), prove=prove)


__all__ = ["prover"]
