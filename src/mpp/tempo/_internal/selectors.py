"""Function selectors used to classify Tempo payment calls."""

from __future__ import annotations

from typing import Final

from mpp.tempo._internal.abi import APPROVE, SWAP_EXACT_AMOUNT_OUT, TRANSFER, TRANSFER_WITH_MEMO

APPROVE_SELECTOR: Final = APPROVE.selector
TRANSFER_SELECTOR: Final = TRANSFER.selector
TRANSFER_WITH_MEMO_SELECTOR: Final = TRANSFER_WITH_MEMO.selector
SWAP_EXACT_AMOUNT_OUT_SELECTOR: Final = SWAP_EXACT_AMOUNT_OUT.selector
