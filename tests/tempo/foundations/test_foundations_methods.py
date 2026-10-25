"""Port of mppx ``src/tempo/Methods.test.ts``."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mpp.tempo import methods

SECONDS_PER_DAY = 86_400
CURRENCY = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x1234567890abcdef1234567890abcdef12345678"


def _accepts(method: Any, request: dict[str, Any]) -> bool:
    try:
        method.request_model.model_validate(request)
    except ValidationError:
        return False
    return True


def _accepts_payload(method: Any, payload: dict[str, Any]) -> bool:
    try:
        method.parse_payload(payload)
    except ValidationError:
        return False
    return True


# expectTypeOf (literal-type) assertions are TypeScript-only and are not ported.


class TestCharge:
    def test_has_correct_name_and_intent(self) -> None:
        assert methods.charge.intent == "charge"
        assert methods.charge.name == "tempo"

    def test_validates_valid_request(self) -> None:
        assert _accepts(
            methods.charge,
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "expires": "2025-02-05T12:05:00Z",
                "recipient": RECIPIENT,
            },
        )

    def test_validates_request_with_method_details(self) -> None:
        assert _accepts(
            methods.charge,
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "expires": "2025-02-05T12:05:00Z",
                "chainId": 42431,
                "feePayer": True,
                "recipient": RECIPIENT,
            },
        )

    def test_validates_request_with_supported_modes(self) -> None:
        request = methods.charge.normalize_request(
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "supportedModes": ["pull"],
            }
        )
        assert request["methodDetails"]["supportedModes"] == ["pull"]

    def test_rejects_empty_supported_modes(self) -> None:
        assert not _accepts(
            methods.charge,
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "supportedModes": [],
            },
        )

    def test_validates_request_with_splits(self) -> None:
        memo = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        request = methods.charge.request_model.model_validate(
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "splits": [
                    {"amount": "0.25", "recipient": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"},
                    {
                        "amount": "0.1",
                        "memo": memo,
                        "recipient": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    },
                ],
            }
        ).model_dump()
        assert request["methodDetails"]["splits"] == [
            {"amount": "250000", "recipient": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"},
            {
                "amount": "100000",
                "memo": memo,
                "recipient": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        ]

    def test_rejects_empty_splits(self) -> None:
        assert not _accepts(
            methods.charge,
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "splits": [],
            },
        )

    def test_rejects_more_than_10_splits(self) -> None:
        assert not _accepts(
            methods.charge,
            {
                "amount": "11",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "splits": [
                    {"amount": "0.1", "recipient": f"0x{index + 1:040x}"} for index in range(11)
                ],
            },
        )

    def test_rejects_split_totals_gte_amount(self) -> None:
        assert not _accepts(
            methods.charge,
            {
                "amount": "1",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "splits": [
                    {"amount": "0.5", "recipient": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"},
                    {"amount": "0.5", "recipient": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
                ],
            },
        )

    def test_rejects_zero_amount_with_splits(self) -> None:
        assert not _accepts(
            methods.charge,
            {
                "amount": "0",
                "currency": CURRENCY,
                "decimals": 6,
                "recipient": RECIPIENT,
                "splits": [
                    {"amount": "0.1", "recipient": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"}
                ],
            },
        )

    def test_accepts_zero_amount_without_splits(self) -> None:
        assert _accepts(
            methods.charge,
            {"amount": "0", "currency": CURRENCY, "decimals": 6, "recipient": RECIPIENT},
        )

    def test_rejects_invalid_request(self) -> None:
        assert not _accepts(methods.charge, {"amount": "1"})
        with pytest.raises(ValidationError):
            methods.charge.normalize_request({"amount": "1"})

    def test_validates_transaction_payload(self) -> None:
        assert _accepts_payload(
            methods.charge,
            {
                "signature": "0x76f90100000000000000000000000000000000000000000000000000000000000000000000",
                "type": "transaction",
            },
        )

    def test_validates_hash_payload(self) -> None:
        assert _accepts_payload(
            methods.charge,
            {
                "hash": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
                "type": "hash",
            },
        )

    def test_rejects_invalid_payload_type(self) -> None:
        assert not _accepts_payload(
            methods.charge, {"signature": "0x...", "type": "keyAuthorization"}
        )
