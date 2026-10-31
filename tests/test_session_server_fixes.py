"""Regression tests for review fixes on session servers (bootstrap realm, route voucher delta)."""

from __future__ import annotations

import pytest

from mpp import Challenge
from mpp.methods.tempo.session.server._store import from_store
from mpp.server import Mpp, PaymentRequired, Request
from mpp.server.verify import _create_challenge  # pyright: ignore[reportPrivateUsage]
from mpp.store import MemoryStore
from tests.test_session_bootstrap import (
    CHANNEL_ID,
    REALM,
    SECRET,
    URL,
    Bootstrap,
    method,
    problem,
    stored,
)


async def test_bootstrap_rejects_proofs_issued_for_another_realm() -> None:
    boot = Bootstrap()
    await boot.seed()
    request = dict((await boot.challenge()).request)
    # Same secret and terms, but issued for another protection space.
    foreign = _create_challenge("tempo", "charge", request, "other.test", SECRET)
    response = await boot.prove(foreign)
    assert response.status == 402
    assert "realm mismatch" in problem(response)["detail"]
    assert "payment-session" not in response.headers
    assert boot.sources == []


@pytest.mark.parametrize("key", ["min_voucher_delta", "minVoucherDelta"])
async def test_snapshots_use_the_routes_minimum_voucher_delta(key: str) -> None:
    raw = MemoryStore()
    await from_store(raw).update_channel(CHANNEL_ID, lambda _: stored())
    server = Mpp(
        methods=[method(store=raw, resolve_channel_id=lambda _: CHANNEL_ID, min_voucher_delta="1")],
        realm=REALM,
        secret_key=SECRET,
    )
    handler = server.session(amount="0.0001", unit_type="request", **{key: "0.00005"})
    result = await handler(Request("GET", URL))
    assert isinstance(result, PaymentRequired)
    issued = Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])
    details = issued.request["methodDetails"]
    assert details["minVoucherDelta"] == "50"
    # 300 accepted + the route's 50, not the method's 1_000_000.
    assert details["sessionSnapshot"]["requiredCumulative"] == "350"
