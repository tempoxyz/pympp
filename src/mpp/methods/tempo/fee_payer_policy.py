"""Fee payer policy defaults for sponsored Tempo transactions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from mpp.methods.tempo._defaults import CHAIN_ID, TESTNET_CHAIN_ID


@dataclass(frozen=True, slots=True)
class Policy:
    max_gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    max_total_fee: int
    max_validity_window_seconds: int


DEFAULT_POLICY = Policy(
    max_gas=2_000_000,
    max_fee_per_gas=100_000_000_000,
    max_priority_fee_per_gas=10_000_000_000,
    max_total_fee=50_000_000_000_000_000,
    max_validity_window_seconds=15 * 60,
)


POLICY_BY_CHAIN_ID: dict[int, Policy] = {
    CHAIN_ID: DEFAULT_POLICY,
    TESTNET_CHAIN_ID: Policy(
        max_gas=DEFAULT_POLICY.max_gas,
        max_fee_per_gas=DEFAULT_POLICY.max_fee_per_gas,
        max_priority_fee_per_gas=50_000_000_000,
        max_total_fee=DEFAULT_POLICY.max_total_fee,
        max_validity_window_seconds=DEFAULT_POLICY.max_validity_window_seconds,
    ),
}


def get_policy(chain_id: int, overrides: Mapping[str, int] | None = None) -> Policy:
    base = POLICY_BY_CHAIN_ID.get(chain_id, DEFAULT_POLICY)
    if not overrides:
        return base

    return Policy(
        max_gas=overrides.get("max_gas", base.max_gas),
        max_fee_per_gas=overrides.get("max_fee_per_gas", base.max_fee_per_gas),
        max_priority_fee_per_gas=overrides.get(
            "max_priority_fee_per_gas", base.max_priority_fee_per_gas
        ),
        max_total_fee=overrides.get("max_total_fee", base.max_total_fee),
        max_validity_window_seconds=overrides.get(
            "max_validity_window_seconds", base.max_validity_window_seconds
        ),
    )
