"""First-party machine-token (MACH) charge routes.

Ported from mppx ``tempo/internal/machine-token-charge.ts``.

A Tempo charge whose ``methodDetails.machineTokenEnabled`` is ``true`` may be paid in MACH:
the payer approves the canonical swapper for the charge amount and calls
``swapTo(MACH, amount, currency, recipient, memo)``, which settles the charge currency to the
recipient atomically. The swapper is then the transfer's sender, funded by the transaction sender.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType

from mpp.methods.tempo._defaults import CHAIN_ID, MACH, TESTNET_CHAIN_ID

__all__ = [
    "DEPLOYMENTS",
    "MACH",
    "Deployment",
    "Route",
    "get_route",
    "is_supported",
    "match_route",
    "settlement_sender",
]

APPROVE_SELECTOR = "095ea7b3"
"""``approve(address,uint256)``."""
SWAP_TO_SELECTOR = "34189fed"
"""``swapTo(address,uint256,address,address,bytes32)`` on the machine-token swapper."""


@dataclass(frozen=True, slots=True)
class Deployment:
    """A chain's canonical machine-token swapper and token."""

    swap: str
    token: str


DEPLOYMENTS: MappingProxyType[int, Deployment] = MappingProxyType(
    {
        CHAIN_ID: Deployment(swap="0xF72E5107c32C655ffA7539a3C8e97B7C3cE16A3F", token=MACH),
        TESTNET_CHAIN_ID: Deployment(swap="0xd05f8EdFBB54Da0d765C9fE9b2B3f7d2E3a8C466", token=MACH),
    }
)
"""Chain ID to its first-party machine-token deployment, as mppx's ``machineTokenDeployments``."""


@dataclass(frozen=True, slots=True)
class Route:
    """The two calls that pay a charge in MACH, and the transfer they settle."""

    calls: tuple[tuple[str, str], tuple[str, str]]
    """``(to, data)`` pairs: approve on MACH, then ``swapTo`` on the swapper (0x-hex data)."""
    settlement_sender: str
    """The swapper, which sends the settled transfer to the recipient."""
    amount: int
    memo: str
    recipient: str


def is_supported(chain_id: int | None) -> bool:
    """Return whether a machine-token route is deployed on ``chain_id``."""
    return chain_id is not None and chain_id in DEPLOYMENTS


def settlement_sender(chain_id: int | None) -> str | None:
    """Return the swapper that settles machine-token charges on ``chain_id``, if deployed."""
    deployment = DEPLOYMENTS.get(chain_id) if chain_id is not None else None
    return None if deployment is None else deployment.swap


def _word(value: int) -> str:
    return format(value, "064x")


def _address_word(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def get_route(
    *, chain_id: int | None, currency: str, amount: int, recipient: str, memo: str | None
) -> Route | None:
    """Return the canonical route for a single-transfer charge with a 32-byte ``memo``."""
    deployment = DEPLOYMENTS.get(chain_id) if chain_id is not None else None
    if deployment is None or not memo:
        return None
    memo_hex = memo.removeprefix("0x").lower()
    if len(memo_hex) != 64 or amount <= 0:
        return None
    approve = "0x" + APPROVE_SELECTOR + _address_word(deployment.swap) + _word(amount)
    swap = (
        "0x"
        + SWAP_TO_SELECTOR
        + _address_word(deployment.token)
        + _word(amount)
        + _address_word(currency)
        + _address_word(recipient)
        + memo_hex
    )
    return Route(
        calls=((deployment.token, approve), (deployment.swap, swap)),
        settlement_sender=deployment.swap,
        amount=amount,
        memo="0x" + memo_hex,
        recipient=recipient,
    )


def match_route(
    calls: Sequence[tuple[str, int, str]],
    *,
    chain_id: int | None,
    currency: str,
    amount: int,
    recipient: str,
    memo: str | None = None,
) -> Route | None:
    """Return the route ``calls`` (``(to, value, data hex)``) are exactly, else ``None``.

    Without an expected ``memo``, the one in the ``swapTo`` call is used; the caller still
    binds it to the challenge.
    """
    if len(calls) != 2:
        return None
    swap_data = calls[1][2].removeprefix("0x").lower()
    if len(swap_data) != 8 + 5 * 64 or not swap_data.startswith(SWAP_TO_SELECTOR):
        return None
    route = get_route(
        chain_id=chain_id,
        currency=currency,
        amount=amount,
        recipient=recipient,
        memo=memo if memo is not None else swap_data[8 + 4 * 64 :],
    )
    if route is None:
        return None
    for (to, value, data), (expected_to, expected_data) in zip(calls, route.calls, strict=True):
        if value or to.lower() != expected_to.lower():
            return None
        if data.removeprefix("0x").lower() != expected_data.removeprefix("0x"):
            return None
    return route
