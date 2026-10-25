"""Ported from mppx src/Receipt.test.ts."""

import httpx
import pytest

from mpp import Receipt


def test_creates_success_receipt() -> None:
    receipt = Receipt(method="tempo", reference="0x1", timestamp="2025-01-06T12:00:00Z")
    assert receipt.to_dict() == {
        "method": "tempo",
        "reference": "0x1",
        "status": "success",
        "timestamp": "2025-01-06T12:00:00Z",
    }


def test_funding_currency() -> None:
    receipt = Receipt.from_dict(
        {
            "method": "tempo",
            "reference": "0x1",
            "status": "success",
            "timestamp": "2025-01-06T12:00:00Z",
            "fundingCurrency": "0xabc",
        }
    )
    assert receipt.funding_currency == "0xabc"


def test_rejects_failed_status() -> None:
    with pytest.raises(ValueError, match="status"):
        Receipt.from_dict(
            {
                "method": "tempo",
                "reference": "0x1",
                "status": "failed",
                "timestamp": "2025-01-06T12:00:00Z",
            }
        )


def test_preserves_extension_fields() -> None:
    data = {
        "method": "tempo",
        "reference": "0x1",
        "status": "success",
        "timestamp": "2025-01-06T12:00:00Z",
        "originTxHash": "0xorigin",
        "nested": {"a": [1, 2]},
    }
    receipt = Receipt.from_dict(data)
    assert receipt.extra == {"originTxHash": "0xorigin", "nested": {"a": [1, 2]}}
    assert Receipt.deserialize(receipt.serialize()).to_dict() == data


def test_rejects_invalid_base_field_with_extensions() -> None:
    with pytest.raises(ValueError, match="Invalid ISO 8601 datetime"):
        Receipt.from_dict(
            {
                "method": "tempo",
                "reference": "0x1",
                "status": "success",
                "timestamp": "not-a-date",
                "extra": 1,
            }
        )


def test_serialize_roundtrip() -> None:
    receipt = Receipt(
        method="tempo", reference="0x1", timestamp="2025-01-06T12:00:00.000Z", external_id="order-1"
    )
    encoded = receipt.serialize()
    assert "=" not in encoded
    assert Receipt.deserialize(encoded) == receipt


def test_from_headers() -> None:
    receipt = Receipt(method="tempo", reference="0x1", timestamp="2025-01-06T12:00:00Z")
    response = httpx.Response(200, headers={"Payment-Receipt": receipt.serialize()})
    assert Receipt.from_headers(response.headers) == receipt


def test_missing_header() -> None:
    with pytest.raises(ValueError, match=r"Missing Payment-Receipt header."):
        Receipt.from_headers(httpx.Headers())
