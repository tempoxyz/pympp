"""Local SQLite TTL replay regression; mocked chain RPC, real server verification."""

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mpp.methods.tempo._attribution import encode
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC, ChargeIntent
from mpp.server import verify_or_challenge
from mpp.server.intent import VerificationError
from mpp.stores.sqlite import SQLiteStore
from tests import make_bound_credential

REQUEST = {
    "amount": "1000",
    "currency": "0x20c0000000000000000000000000000000000000",
    "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
}
REALM = "api.example.com"
SECRET = "local-regression-test-only"


@pytest.mark.parametrize("ttl", [None, 1])
async def test_valid_payment_stays_consumed_after_store_ttl(ttl):
    now = time.time()
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    credential = make_bound_credential(
        payload={"type": "hash", "hash": "0x" + "ab" * 32},
        request=REQUEST,
        realm=REALM,
        secret_key=SECRET,
        expires=expires,
    )
    memo = encode(challenge_id=credential.challenge.id, server_id=REALM)
    response = httpx.Response(
        200,
        request=httpx.Request("POST", "https://rpc.test"),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "0x1",
                "logs": [
                    {
                        "address": REQUEST["currency"],
                        "topics": [
                            TRANSFER_WITH_MEMO_TOPIC,
                            "0x" + "00" * 12 + "12" * 20,
                            "0x" + "00" * 12 + REQUEST["recipient"][2:].lower(),
                            memo,
                        ],
                        "data": "0x" + format(1000, "064x"),
                    }
                ],
            },
        },
    )
    store = await SQLiteStore.create(":memory:", ttl_seconds=ttl)
    intent = ChargeIntent(rpc_url="https://rpc.test", store=store)
    intent._http_client = AsyncMock()
    intent._http_client.post.return_value = response

    async def attempt(at):
        with patch("mpp.stores.sqlite.time", SimpleNamespace(time=lambda: at)):
            try:
                result = await verify_or_challenge(
                    authorization=credential.to_authorization(),
                    intent=intent,
                    request=REQUEST,
                    realm=REALM,
                    secret_key=SECRET,
                )
                assert isinstance(result, tuple)
                assert result[1].status == "success"
                return "accepted"
            except VerificationError as error:
                assert "already used" in str(error), str(error)
                return "duplicate rejected"

    try:
        outcomes = [await attempt(now), await attempt(now), await attempt(now + 2)]
        assert datetime.fromisoformat(expires).timestamp() > now + 2
        expected = ["accepted", "duplicate rejected", "duplicate rejected"]
        assert outcomes == expected, outcomes
    finally:
        await store.close()
