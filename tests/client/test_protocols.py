"""MPP client protocol and body-inspection helpers."""

import httpx

from mpp import Challenge
from mpp.client import mpp as mpp_protocol
from mpp.client import peek_body, set_credential_header

CHALLENGE = Challenge.create(
    secret_key="test-secret-key",
    realm="api.example.com",
    method="tempo",
    intent="charge",
    expires="2025-01-01T00:00:00.000Z",
    request={
        "amount": "1000",
        "currency": "0x20c0000000000000000000000000000000000001",
        "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
    },
)


async def test_peek_body_limit() -> None:
    response = httpx.Response(200, stream=httpx.ByteStream(b"x" * 10))
    assert await peek_body(response, limit=5) is None
    assert await response.aread() == b"x" * 10


async def test_peek_body_preserves_stream() -> None:
    response = httpx.Response(200, stream=httpx.ByteStream(b"first rest"))
    assert await peek_body(response, until=lambda buffer: len(buffer) >= 5) == b"first rest"
    assert await response.aread() == b"first rest"


async def test_mpp_protocol() -> None:
    response = httpx.Response(
        402, headers={"WWW-Authenticate": f'Bearer realm="x", {CHALLENGE.serialize()}'}
    )
    assert [c.id for c in await mpp_protocol().get_challenges(response, None)] == [CHALLENGE.id]
    assert await mpp_protocol().get_challenges(httpx.Response(402), None) == []
    assert (
        await mpp_protocol().get_challenges(
            httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE.serialize()}), None
        )
        == []
    )


def test_set_credential_header_purges_stale_credentials() -> None:
    req = httpx.Request(
        "GET",
        "https://x.example",
        headers={"Authorization": "Payment old", "PAYMENT-SIGNATURE": "old"},
    )
    updated = set_credential_header(req, "Authorization", "Payment new")
    assert updated.headers["Authorization"] == "Payment new"
    assert "payment-signature" not in updated.headers
    app = httpx.Request("GET", "https://x.example", headers={"Authorization": "Bearer app"})
    assert (
        set_credential_header(app, "Payment-Authorization", "Payment new").headers["Authorization"]
        == "Bearer app"
    )
