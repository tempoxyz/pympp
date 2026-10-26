"""MPP payments alongside the official x402 FastAPI middleware.

One x402 route table serves MPP and x402 clients: x402 credentials go to the
official middleware, which keeps its hooks and post-handler settlement, while
MPP credentials (``Authorization: Payment``) pay through the same x402
requirement, verifier and facilitator. Unpaid responses carry both the x402
``PAYMENT-REQUIRED`` header and an MPP ``WWW-Authenticate`` challenge.

Requires the ``x402`` extra: ``pip install "pympp[x402]"``.

Example:
    from fastapi import FastAPI
    from mpp.x402.fastapi import payment_middleware

    app = FastAPI()
    app.middleware("http")(payment_middleware(routes, resource_server, secret_key=SECRET_KEY))
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

try:
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import Response as StarletteResponse
    from x402.http.middleware.fastapi import FastAPIAdapter
    from x402.http.middleware.fastapi import payment_middleware as x402_payment_middleware
    from x402.http.types import HTTPRequestContext, PaywallConfig, RoutesConfig
    from x402.http.x402_http_server import PaywallProvider
    from x402.server import x402ResourceServer

    from mpp.x402._negotiator import Negotiator, x402_credential
except ImportError as error:  # pragma: no cover
    raise ImportError(
        f'{error}. Install the "x402" extra to use this module: pip install "pympp[x402]"'
    ) from error

from mpp.server.decorator import get_request_url
from mpp.server.http import Request, Response
from mpp.store import Store

__all__ = ["payment_middleware"]

CallNext = Callable[[StarletteRequest], Awaitable[StarletteResponse]]
Middleware = Callable[[StarletteRequest, CallNext], Awaitable[StarletteResponse]]


def payment_middleware(
    routes: RoutesConfig,
    server: x402ResourceServer,
    *,
    secret_key: str,
    realm: str | None = None,
    paywall_config: PaywallConfig | None = None,
    paywall_provider: PaywallProvider | None = None,
    store: Store | None = None,
) -> Middleware:
    """Create an ``@app.middleware("http")`` function serving MPP and x402 on ``routes``.

    Args:
        routes: The x402 route configuration.
        server: The x402 resource server that prices, verifies and settles payments.
        secret_key: Secret binding MPP challenge IDs (at least 32 bytes).
        realm: MPP challenge realm. Detected from the environment if omitted.
        paywall_config: Optional x402 paywall configuration.
        paywall_provider: Optional x402 paywall provider.
        store: Store claiming MPP authorizations before settlement, shared by every
            worker and replica. Defaults to an in-process store.
    """
    negotiator = Negotiator(
        routes,
        server,
        secret_key=secret_key,
        realm=realm,
        paywall_config=paywall_config,
        paywall_provider=paywall_provider,
        store=store,
    )
    # The negotiator syncs with the facilitator on the first protected request,
    # before it delegates any x402 credential, so the official middleware doesn't.
    x402 = x402_payment_middleware(
        routes, server, paywall_config, paywall_provider, sync_facilitator_on_start=False
    )

    async def middleware(request: StarletteRequest, call_next: CallNext) -> StarletteResponse:
        # The URL keeps ASGI raw_path's percent-encoding, so /a%2Fb and /a/b get
        # distinct signed scopes.
        url = get_request_url(request) or str(request.url)
        mpp_request = Request(method=request.method, url=url, headers=request.headers.items())
        context = HTTPRequestContext(
            adapter=FastAPIAdapter(request),
            path=_raw_path(request),
            decoded_path=_route_path(request),
            method=request.method,
            payment_header=x402_credential(mpp_request),
        )
        result = await negotiator.negotiate(mpp_request, context)
        if result.status == "unprotected":
            return await call_next(request)
        if result.status == "x402":
            return await x402(request, call_next)
        if result.payment is not None:
            return result.payment.with_receipt(await call_next(request))
        assert result.response is not None
        return _to_starlette(result.response)

    return middleware


def _raw_path(request: StarletteRequest) -> str:
    """The percent-encoded request path, or the decoded one when ASGI omits ``raw_path``."""
    raw_path = request.scope.get("raw_path")
    if isinstance(raw_path, bytes) and raw_path:
        return raw_path.decode("latin-1").split("?")[0]
    return request.url.path


def _route_path(request: StarletteRequest) -> str:
    """The request path without the ASGI ``root_path`` mount prefix, as Starlette routes it."""
    path = request.url.path
    root_path = request.scope.get("root_path", "")
    if not root_path or not path.startswith(root_path):
        return path
    if path == root_path:
        return ""
    return path[len(root_path) :] if path[len(root_path)] == "/" else path


def _to_starlette(response: Response) -> StarletteResponse:
    body = response.body or b""
    result = StarletteResponse(content=body, status_code=response.status)
    result.raw_headers = [
        *(
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in response.headers.multi_items()
            if name.lower() != "content-length"
        ),
        (b"content-length", str(len(body)).encode()),
    ]
    return result
