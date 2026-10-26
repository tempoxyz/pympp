import pytest
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mpp import Challenge, Credential, Receipt
from mpp.server import Mpp
from mpp.server.asgi import PaymentMiddleware
from tests import server_method


async def _paid(context):
    return Receipt.success("0xabc")


def _client(calls, **options):
    async def echo(request: StarletteRequest):
        calls.append(await request.body())
        return JSONResponse({"ok": True}, headers={"Cache-Control": "public, max-age=60"})

    inner = Starlette(routes=[Route("/items/{id}", echo, methods=["GET", "POST"])])
    mpp = Mpp(methods=server_method(verify=_paid), realm="example.com", secret_key="secret")
    handler = mpp.charge(amount="1", **options.pop("charge", {}))
    return TestClient(PaymentMiddleware(inner, handler, **options))


def _authorization(response):
    issued = Challenge.from_www_authenticate(response.headers["WWW-Authenticate"])
    return Credential(challenge=issued.to_echo(), payload={}).to_authorization(), issued


def test_unpaid_request_gets_challenge_and_skips_app():
    calls = []
    with _client(calls) as client:
        response = client.get("/items/1")
    assert response.status_code == 402
    assert response.headers["WWW-Authenticate"].startswith("Payment ")
    assert calls == []


def test_paid_request_runs_app_with_receipt():
    calls = []
    with _client(calls, route="/items/{id}") as client:
        authorization, issued = _authorization(client.get("/items/1?x=1"))
        assert issued.request["_mppx_scope"]["route"] == "/items/{id}"
        response = client.get("/items/1?x=1", headers={"Authorization": authorization})
        replayed = client.get("/items/2?x=1", headers={"Authorization": authorization})
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert response.headers["Payment-Receipt"]
    assert response.headers["Cache-Control"] == "private, max-age=60"
    assert replayed.status_code == 402
    assert calls == [b""]


def test_bound_body_is_replayed_to_app():
    calls = []
    charge = {"body": lambda request: request.body}
    with _client(calls, charge=charge) as client:
        authorization, _ = _authorization(client.post("/items/1", content=b"order"))
        tampered = client.post(
            "/items/1", content=b"other", headers={"Authorization": authorization}
        )
        response = client.post(
            "/items/1", content=b"order", headers={"Authorization": authorization}
        )
    assert tampered.status_code == 402
    assert response.status_code == 200
    assert calls == [b"order"]


def test_oversized_bound_body_is_rejected():
    calls = []
    charge = {"body": lambda request: request.body}
    with _client(calls, charge=charge, max_body_size=4) as client:
        response = client.post("/items/1", content=b"too large")
    assert response.status_code == 413
    assert calls == []


@pytest.mark.asyncio
async def test_non_http_scopes_pass_through():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    mpp = Mpp(methods=server_method(verify=_paid), realm="example.com", secret_key="secret")
    middleware = PaymentMiddleware(inner, mpp.charge(amount="1"))
    await middleware({"type": "websocket"}, None, None)  # type: ignore[arg-type]
    assert seen == ["websocket"]


def _scope(**changes):
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/items/1",
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
    }
    scope.update(changes)
    return scope


async def _call(middleware, scope, messages=()):
    pending = list(messages) or [{"type": "http.request", "body": b"", "more_body": False}]
    sent = []

    async def receive():
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await middleware(scope, receive, send)
    return sent


def _challenge(sent):
    headers = {name.lower(): value for name, value in sent[0]["headers"]}
    return Challenge.from_www_authenticate(headers[b"www-authenticate"].decode())


def _middleware(app=None, **charge):
    async def default(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mpp = Mpp(methods=server_method(verify=_paid), realm="example.com", secret_key="secret")
    return PaymentMiddleware(app or default, mpp.charge(amount="1", **charge))


@pytest.mark.asyncio
async def test_host_header_cannot_change_bound_path():
    middleware = _middleware()
    for host in (b"h/items/9#", b"h/items/9?", b"user@h"):
        sent = await _call(middleware, _scope(headers=[(b"host", host)]))
        assert _challenge(sent).request["_mppx_scope"]["resource"] == "/items/1"


@pytest.mark.asyncio
async def test_fallback_url_brackets_ipv6_server():
    sent = await _call(_middleware(), _scope(server=("::1", 8000)))
    assert _challenge(sent).request["_mppx_scope"]["resource"] == "/items/1"


@pytest.mark.asyncio
async def test_fallback_url_keeps_root_path_once():
    sent = await _call(_middleware(), _scope(root_path="/api", path="/api/items/1"))
    assert _challenge(sent).request["_mppx_scope"]["resource"] == "/api/items/1"


@pytest.mark.asyncio
async def test_disconnect_mid_upload_skips_handler_and_app():
    calls = []

    async def app(scope, receive, send):
        calls.append(await receive())

    middleware = _middleware(app, body=lambda request: request.body)
    sent = await _call(
        middleware,
        _scope(method="POST"),
        [{"type": "http.request", "body": b"par", "more_body": True}, {"type": "http.disconnect"}],
    )
    assert sent == []
    assert calls == []


@pytest.mark.asyncio
async def test_paid_response_keeps_non_ascii_header_bytes():
    async def app(scope, receive, send):
        headers = [(b"x-name", "café €".encode())]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = _middleware(app)
    issued = _challenge(await _call(middleware, _scope()))
    authorization = Credential(challenge=issued.to_echo(), payload={}).to_authorization()
    sent = await _call(middleware, _scope(headers=[(b"authorization", authorization.encode())]))
    assert sent[0]["status"] == 200
    headers = {name.lower(): value for name, value in sent[0]["headers"]}
    assert headers[b"x-name"] == "café €".encode()
    assert headers[b"payment-receipt"]
