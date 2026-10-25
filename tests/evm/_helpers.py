"""Test helpers bridging the server engine and httpx."""

from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from mpp.server import Request, Response

SECRET_KEY = "test-secret-key-test-secret-key-32"
TRANSACTION = "0x" + "1" * 64
PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class Facilitator:
    """Facilitator double recording verify/settle calls."""

    def __init__(self, *, valid: bool = True, invalid_reason: str | None = None) -> None:
        self.valid = valid
        self.invalid_reason = invalid_reason
        self.reached: list[str] = []
        self.verifications: list[tuple[Any, Any]] = []
        self.settlements: list[tuple[Any, Any]] = []

    async def verify(self, payment_payload: Any, payment_requirements: Any) -> dict[str, Any]:
        self.reached.append("verify")
        self.verifications.append((payment_payload, payment_requirements))
        result: dict[str, Any] = {"isValid": self.valid}
        if self.invalid_reason is not None:
            result["invalidReason"] = self.invalid_reason
        return result

    async def settle(self, payment_payload: Any, payment_requirements: Any) -> dict[str, Any]:
        self.reached.append("settle")
        self.settlements.append((payment_payload, payment_requirements))
        return {
            "network": payment_requirements.network,
            "success": True,
            "transaction": TRANSACTION,
        }


def to_httpx(response: Response, url: str = "https://example.com/paid") -> httpx.Response:
    assert isinstance(response.body, bytes | None)
    return httpx.Response(
        response.status,
        headers=response.headers.multi_items(),
        content=response.body or b"",
        request=httpx.Request("GET", url),
    )


def to_request(request: httpx.Request) -> Request:
    return Request(
        method=request.method,
        url=str(request.url),
        headers=request.headers.multi_items(),
        body=request.content or None,
    )


type Route = Callable[[Request], Awaitable[Any]]


def mock_transport(
    route: Route, body: Callable[[], Any] = lambda: {"ok": True}
) -> httpx.MockTransport:
    """Serves ``route`` (a configured handler) over httpx, returning ``body()`` when paid."""

    async def handler(request: httpx.Request) -> httpx.Response:
        result = await route(to_request(request))
        if result.status == 402:
            return to_httpx(result.challenge)
        return to_httpx(result.with_receipt(Response.json(body())))

    return httpx.MockTransport(handler)
