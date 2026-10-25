"""Port of mppx ``tempo/server/internal/fallback-store.test.ts``."""

from __future__ import annotations

import warnings

import pytest

from mpp import store as _store
from mpp.tempo.server._internal import fallback_store as fallback


class TestFallbackStore:
    @pytest.fixture(autouse=True)
    def reset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fallback, "_warned", set())

    def test_warns_once_when_store_is_omitted(self) -> None:
        from mpp.tempo import server as tempo

        recipient = "0x1234567890123456789012345678901234567890"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tempo.charge(recipient=recipient)
            tempo.charge(recipient=recipient)
        messages = [str(w.message) for w in caught if "in-memory store" in str(w.message)]
        assert len(messages) == 1
        assert messages[0].startswith("tempo.charge() has no `store` configured")

    def test_does_not_warn_when_store_is_provided(self) -> None:
        from mpp.tempo import server as tempo

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tempo.charge(
                recipient="0x1234567890123456789012345678901234567890", store=_store.memory()
            )
        assert not [w for w in caught if "in-memory store" in str(w.message)]
