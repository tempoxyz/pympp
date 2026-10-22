import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from mpp import Challenge, Credential, Receipt
from mpp.server import intent, pay, verify_or_challenge
from tests import MockRequest, challenge_from_402
from tests.test_server import _make_server


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["charge", "pay"])
async def test_direct_metadata_binding(api):
    calls = []

    @intent(name="charge")
    async def paid(credential, request):
        calls.append(credential)
        return Receipt.success("paid")

    server = _make_server(paid)

    async def run(meta, authorization=None):
        if api == "charge":
            return await server.charge(authorization, "1", meta=meta)

        @server.pay(amount="1", meta=meta)
        async def handler(request, credential, receipt):
            return "paid"

        return await handler(MockRequest(authorization=authorization))

    first = await run({"order": "one"})
    challenge = first if isinstance(first, Challenge) else challenge_from_402(first)
    credential = Credential(challenge=challenge.to_echo(), payload={})
    rejected = await run({"order": "two"}, credential.to_authorization())
    assert not calls
    assert isinstance(rejected, (Challenge, Response))
    if isinstance(rejected, Response):
        assert rejected.status_code == 402
    await run({"order": "one"}, credential.to_authorization())
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("meta", [None, {}, {"order": "one"}])
async def test_fixed_expiry_nonce(meta):
    @intent(name="charge")
    async def paid(credential, request):
        return Receipt.success("paid")

    options = {
        "intent": paid,
        "request": {"amount": "100"},
        "realm": "example.com",
        "secret_key": "secret",
        "expires": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "meta": meta,
    }
    first = await verify_or_challenge(authorization=None, **options)
    second = await verify_or_challenge(authorization=None, **options)
    assert isinstance(first, Challenge) and isinstance(second, Challenge)
    assert first.id != second.id
    assert first.opaque is not None and second.opaque is not None
    assert first.opaque["_mpp_nonce"] != second.opaque["_mpp_nonce"]
    assert meta is None or "_mpp_nonce" not in meta
    credential = Credential(challenge=first.to_echo(), payload={})
    assert isinstance(
        await verify_or_challenge(authorization=credential.to_authorization(), **options), tuple
    )
    tampered = dict(first.opaque, _mpp_nonce=second.opaque["_mpp_nonce"])
    from mpp import _b64url_encode

    credential = replace(
        credential,
        challenge=replace(credential.challenge, opaque=_b64url_encode(json.dumps(tampered))),
    )
    assert isinstance(
        await verify_or_challenge(authorization=credential.to_authorization(), **options), Challenge
    )


def test_http_verbs_cannot_share_credential():
    calls = []

    @intent(name="charge")
    async def paid(credential, request):
        calls.append(credential)
        return Receipt.success("paid")

    @pay(
        intent=paid,
        request={"amount": "100", "_mppx_scope": {"custom": "scope"}},
        realm="testserver",
        secret_key="secret",
    )
    async def handler(request, credential, receipt):
        return JSONResponse({"paid": True})

    app = Starlette(routes=[Route("/paid", handler, methods=["GET", "POST"])])
    with TestClient(app) as client:
        challenge = Challenge.from_www_authenticate(client.get("/paid").headers["WWW-Authenticate"])
        credential = Credential(challenge=challenge.to_echo(), payload={})
        headers = {"Authorization": credential.to_authorization()}
        assert client.post("/paid", headers=headers).status_code == 402
        assert not calls
        assert client.get("/paid", headers=headers).status_code == 200
        assert len(calls) == 1
