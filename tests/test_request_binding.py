import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from mpp import Challenge, Credential, Receipt
from mpp.server import Mpp, PaymentRequired, PaymentVerified, pay
from mpp.server.verify import verify_or_challenge
from tests import MockRequest, challenge, challenge_from_402, http_request, server_method


async def _shared(context):
    return Receipt.success("shared")


class _Paid:
    """A charge intent for verify_or_challenge that always settles."""

    name = "charge"

    async def verify(self, credential, request):
        return Receipt.success("paid")


def _mpp(method, **kwargs):
    return Mpp(methods=method, realm="example.com", secret_key="secret", **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["charge", "pay"])
async def test_direct_metadata_binding(api):
    calls = []

    async def paid(context):
        calls.append(context.credential)
        return Receipt.success("paid")

    server = _mpp(server_method(verify=paid))

    async def run(meta, authorization=None):
        if api == "charge":
            return await server.charge(amount="1", meta=meta)(http_request(authorization))

        @pay(server.charge(amount="1", meta=meta))
        async def handler(request, credential, receipt):
            return "paid"

        return await handler(MockRequest(authorization=authorization))

    first = await run({"order": "one"})
    issued = challenge(first) if api == "charge" else challenge_from_402(first)
    credential = Credential(challenge=issued.to_echo(), payload={})
    rejected = await run({"order": "two"}, credential.to_authorization())
    assert not calls
    if api == "charge":
        assert isinstance(rejected, PaymentRequired)
    else:
        assert isinstance(rejected, Response) and rejected.status_code == 402
    await run({"order": "one"}, credential.to_authorization())
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("meta", [None, {}, {"order": "one"}])
async def test_fixed_expiry_nonce(meta):
    options = {
        "intent": _Paid(),
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

    async def paid(context):
        calls.append(context.credential)
        return Receipt.success("paid")

    server = Mpp(
        methods=server_method(verify=paid, request={"_mppx_scope": configured_scope}),
        realm="testserver",
        secret_key="secret",
    )

    @pay(server.charge(amount="100"))
    async def handler(request, credential, receipt):
        return JSONResponse({"paid": True})

    app = Starlette(routes=[Route("/paid", handler, methods=["GET", "POST"])])
    with TestClient(app) as client:
        issued = Challenge.from_www_authenticate(client.get("/paid").headers["WWW-Authenticate"])
        credential = Credential(challenge=issued.to_echo(), payload={})
        headers = {"Authorization": credential.to_authorization()}
        assert client.post("/paid", headers=headers).status_code == 402
        assert not calls
        assert client.get("/paid", headers=headers).status_code == 200
        assert len(calls) == 1


@pytest.mark.asyncio
async def test_nonce_bound_lifecycle_and_legacy_empty_metadata():
    from tests import make_bound_credential
    from tests.test_lifecycle import VerifiableCharge, charge_method

    charge = VerifiableCharge()
    payment = Mpp(methods=charge_method(charge), realm="api.example.com", secret_key="test-secret")
    request = {"amount": "1000"}
    for unique in [False, True]:
        issued = await verify_or_challenge(
            authorization=None,
            intent=charge,
            request=request,
            realm=payment.realm,
            secret_key=payment.secret_key,
            meta={},
            unique_challenges=unique,
        )
        assert isinstance(issued, Challenge)
        credential = Credential(challenge=issued.to_echo(), payload={})
        await payment.validate_credential(credential, request=request, meta={})
        await payment.broadcast_credential(credential, request=request, meta={})
    legacy = make_bound_credential(
        payload={}, request=request, realm=payment.realm, secret_key=payment.secret_key, meta={}
    )
    result = await verify_or_challenge(
        authorization=legacy.to_authorization(),
        intent=charge,
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

    payment = _mpp(server_method(verify=_shared))
    gate = payment.compose((payment.methods[0], {"amount": "1.00"}))
    initial = await gate(http_request())
    echo = replace(challenge(initial).to_echo(), opaque=_b64url_encode(json.dumps(opaque)))
    result = await gate(http_request(Credential(challenge=echo, payload={}).to_authorization()))
    assert isinstance(result, PaymentRequired)


@pytest.mark.asyncio
async def test_transient_failure_reuses_authenticated_challenge():
    from mpp.errors import VerificationFailedError

    class Unconfirmed:
        name = "charge"

        async def verify(self, credential, request):
            raise VerificationFailedError("receipt not visible")

    options = {
        "intent": Unconfirmed(),
        "request": {"amount": "100"},
        "realm": "example.com",
        "secret_key": "secret",
    }
    issued = await verify_or_challenge(authorization=None, **options)
    assert isinstance(issued, Challenge)
    credential = Credential(challenge=issued.to_echo(), payload={})
    with pytest.raises(VerificationFailedError) as error:
        await verify_or_challenge(authorization=credential.to_authorization(), **options)
    assert error.value.retry_challenge is not None
    assert error.value.retry_challenge.id == issued.id


@pytest.mark.asyncio
async def test_staged_rollout_switch_applies_to_direct_and_composed():
    payment = _mpp(server_method(verify=_shared), unique_challenges=False)
    direct = challenge(await payment.charge(amount="1.00")(http_request()))
    assert not direct.opaque
    gate = payment.compose((payment.methods[0], {"amount": "1.00"}))
    assert not challenge(await gate(http_request())).opaque
    payment.unique_challenges = True
    current = challenge(await gate(http_request()))
    assert current.opaque
    payment.unique_challenges = False
    result = await gate(
        http_request(Credential(challenge=current.to_echo(), payload={}).to_authorization())
    )
    assert isinstance(result, PaymentVerified)


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["route", "resource", "query", "http_method", "custom"])
async def test_custom_business_scope_cannot_be_overwritten(key):
    calls = []

    async def paid(context):
        calls.append(context.credential)
        return Receipt.success("paid")

    server = Mpp(methods=server_method(verify=paid), realm="testserver", secret_key="secret")

    def handler(account):
        return server.charge(amount="100", _mppx_scope={key: account})

    url = "https://testserver/paid?item=one"
    issued = challenge(await handler("invoice:42")(http_request(url=url)))
    authorization = Credential(challenge=issued.to_echo(), payload={}).to_authorization()
    rejected = await handler("invoice:43")(http_request(authorization, url=url))
    assert isinstance(rejected, PaymentRequired)
    assert not calls
    paid_result = await handler("invoice:42")(http_request(authorization, url=url))
    assert isinstance(paid_result, PaymentVerified)
    assert len(calls) == 1
