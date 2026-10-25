"""The common Tempo client methods (currently ``charge``)."""

from __future__ import annotations

from typing import Any

from mpp.method import ClientMethod
from mpp.tempo.client import _charge


def tempo(**parameters: Any) -> list[ClientMethod]:
    """Creates the common Tempo client methods: ``[charge]``."""
    return [_charge.charge(**parameters)]
