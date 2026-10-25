"""Port of mppx ``src/tempo/internal/charge.test.ts``."""

from __future__ import annotations

import pytest

from mpp.tempo._internal.charge import Split, Transfer, get_transfers

RECIPIENT = "0x1234567890abcdef1234567890abcdef12345678"
SPLIT_RECIPIENT = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"


class TestGetTransfers:
    def test_returns_single_transfer_when_no_splits(self) -> None:
        assert get_transfers(amount="100", recipient=RECIPIENT) == [
            Transfer(amount="100", memo=None, recipient=RECIPIENT)
        ]

    def test_splits_amount_between_primary_and_split_recipients(self) -> None:
        transfers = get_transfers(
            amount="100",
            recipient=RECIPIENT,
            splits=[Split(amount="30", recipient=SPLIT_RECIPIENT)],
        )
        assert len(transfers) == 2
        assert transfers[0].amount == "70"
        assert transfers[0].recipient == RECIPIENT
        assert transfers[1].amount == "30"
        assert transfers[1].recipient == SPLIT_RECIPIENT

    def test_throws_when_amount_is_zero_with_no_splits(self) -> None:
        with pytest.raises(ValueError, match="split total must be less than total amount"):
            get_transfers(amount="0", recipient=RECIPIENT)

    def test_throws_when_amount_is_zero_with_splits(self) -> None:
        with pytest.raises(ValueError, match="Invalid charge request"):
            get_transfers(
                amount="0",
                recipient=RECIPIENT,
                splits=[Split(amount="0", recipient=SPLIT_RECIPIENT)],
            )

    def test_throws_when_split_total_equals_amount(self) -> None:
        with pytest.raises(ValueError, match="split total must be less than total amount"):
            get_transfers(
                amount="100",
                recipient=RECIPIENT,
                splits=[Split(amount="100", recipient=SPLIT_RECIPIENT)],
            )

    def test_throws_when_split_total_exceeds_amount(self) -> None:
        with pytest.raises(ValueError, match="split total must be less than total amount"):
            get_transfers(
                amount="100",
                recipient=RECIPIENT,
                splits=[Split(amount="200", recipient=SPLIT_RECIPIENT)],
            )
