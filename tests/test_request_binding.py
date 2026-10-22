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


@pytest.mark.parametrize("configured_scope", [{"custom": "scope"}, "scope"])
def test_http_verbs_cannot_share_credential(configured_scope):
    calls = []

    @intent(name="charge")
    async def paid(credential, request):
        calls.append(credential)
        return Receipt.success("paid")

    @pay(
        intent=paid,
        request={"amount": "100", "_mppx_scope": configured_scope},
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


@pytest.mark.asyncio
async def test_nonce_bound_lifecycle_and_legacy_empty_metadata():
    from tests import make_bound_credential
    from tests.test_lifecycle import VerifiableCharge, _server

    payment = _server(VerifiableCharge())
    request = {"amount": "1000"}
    for unique in [False, True]:
        challenge = await verify_or_challenge(
            authorization=None,
            intent=payment.method.intents["charge"],
            request=request,
            realm=payment.realm,
            secret_key=payment.secret_key,
            meta={},
            unique_challenges=unique,
        )
        assert isinstance(challenge, Challenge)
        credential = Credential(challenge=challenge.to_echo(), payload={})
        await payment.validate_credential(credential, request=request, meta={})
        await payment.broadcast_credential(credential, request=request, meta={})
    legacy = make_bound_credential(
        payload={}, request=request, realm=payment.realm, secret_key=payment.secret_key, meta={}
    )
    result = await verify_or_challenge(
        authorization=legacy.to_authorization(),
        intent=payment.method.intents["charge"],
        request=request,
        realm=payment.realm,
        secret_key=payment.secret_key,
        meta={},
    )
    assert isinstance(result, tuple)


@pytest.mark.asyncio
@pytest.mark.parametrize("opaque", [1, True, "text", [1, 2]])
async def test_composed_malformed_opaque_is_rejected(opaque):
    from mpp import _b64url_encode
    from mpp.server import Mpp
    from mpp.server.compose import ComposedChallenges
    from tests.test_compose import MockMethod

    method = MockMethod("shared")
    payment = Mpp.create(method=method, realm="example.com", secret_key="secret")
    gate = payment.compose((method, {"amount": "1.00"}))
    initial = await gate.verify(None)
    assert isinstance(initial, ComposedChallenges)
    echo = replace(initial.challenges[0].to_echo(), opaque=_b64url_encode(json.dumps(opaque)))
    result = await gate.verify(Credential(challenge=echo, payload={}).to_authorization())
    assert isinstance(result, ComposedChallenges)


@pytest.mark.asyncio
async def test_transient_failure_reuses_authenticated_challenge():
    from mpp.errors import VerificationFailedError

    @intent(name="charge")
    async def paid(credential, request):
        raise VerificationFailedError("receipt not visible")

    options = {
        "intent": paid,
        "request": {"amount": "100"},
        "realm": "example.com",
        "secret_key": "secret",
    }
    challenge = await verify_or_challenge(authorization=None, **options)
    assert isinstance(challenge, Challenge)
    credential = Credential(challenge=challenge.to_echo(), payload={})
    with pytest.raises(VerificationFailedError) as error:
        await verify_or_challenge(authorization=credential.to_authorization(), **options)
    assert error.value.retry_challenge is not None
    assert error.value.retry_challenge.id == challenge.id


@pytest.mark.asyncio
async def test_staged_rollout_switch_applies_to_direct_and_composed():
    from mpp.server import Mpp
    from mpp.server.compose import ComposedChallenges
    from tests.test_compose import MockMethod

    method = MockMethod("shared")
    payment = Mpp.create(
        method=method, realm="example.com", secret_key="secret", unique_challenges=False
    )
    direct = await payment.charge(None, "1.00")
    assert isinstance(direct, Challenge)
    assert not direct.opaque
    gate = payment.compose((method, {"amount": "1.00"}))
    initial = await gate.verify(None)
    assert isinstance(initial, ComposedChallenges)
    assert not initial.challenges[0].opaque
    payment.unique_challenges = True
    current = await gate.verify(None)
    assert isinstance(current, ComposedChallenges)
    assert current.challenges[0].opaque
    payment.unique_challenges = False
    result = await gate.verify(
        Credential(challenge=current.challenges[0].to_echo(), payload={}).to_authorization()
    )
    assert isinstance(result, tuple)


@pytest.mark.parametrize("key", ["route", "resource", "query", "http_method", "custom"])
def test_custom_business_scope_cannot_be_overwritten(key):
    calls = []
    account = {"value": "invoice:42"}

    @intent(name="charge")
    async def paid(credential, request):
        calls.append(credential)
        return Receipt.success("paid")

    @pay(
        intent=paid,
        request=lambda request: {
            "amount": "100",
            "_mppx_scope": {key: account["value"]},
        },
        realm="testserver",
        secret_key="secret",
    )
    async def handler(request, credential, receipt):
        return JSONResponse({"paid": True})

    app = Starlette(routes=[Route("/paid", handler)])
    with TestClient(app) as client:
        challenge = Challenge.from_www_authenticate(
            client.get("/paid?item=one").headers["WWW-Authenticate"]
        )
        credential = Credential(challenge=challenge.to_echo(), payload={})
        headers = {"Authorization": credential.to_authorization()}
        account["value"] = "invoice:43"
        assert client.get("/paid?item=one", headers=headers).status_code == 402
        assert not calls
        account["value"] = "invoice:42"
        assert client.get("/paid?item=one", headers=headers).status_code == 200
        assert len(calls) == 1
