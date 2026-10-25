"""Port of mppx ``src/tempo/internal/address.test.ts``."""

from __future__ import annotations

import pytest

from mpp.tempo._internal.address import format_tempo, is_equal

ADDRESS = "0x742d35Cc6634C0532925a3b844Bc9e7595F2bD28"
OTHER_ADDRESS = "0x52908400098527886E0F7030069857D2E4169EE7"

REPRESENTATIONS = [
    ("mixed-case hex", ADDRESS),
    ("lowercase hex", ADDRESS.lower()),
    ("Tempo-formatted", format_tempo(ADDRESS)),
]
OTHER_REPRESENTATIONS = [
    ("mixed-case hex", OTHER_ADDRESS),
    ("lowercase hex", OTHER_ADDRESS.lower()),
    ("Tempo-formatted", format_tempo(OTHER_ADDRESS)),
]

CASES = [
    pytest.param(a, b, True, id=f"{a_name} and {b_name} representations of the same address")
    for a_name, a in REPRESENTATIONS
    for b_name, b in REPRESENTATIONS
] + [
    pytest.param(a, b, False, id=f"{a_name} and {b_name} representations of different addresses")
    for a_name, a in REPRESENTATIONS
    for b_name, b in OTHER_REPRESENTATIONS
]


@pytest.mark.parametrize(("a", "b", "expected"), CASES)
def test_is_equal(a: str, b: str, expected: bool) -> None:
    assert is_equal(a, b) is expected


def test_format_tempo_is_tempox_prefixed() -> None:
    assert format_tempo(ADDRESS).startswith("tempox")
