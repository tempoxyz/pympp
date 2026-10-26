"""mpp test suite."""

from typing import Any

import pytest

from mpp import Challenge, ChallengeEcho, Credential, _b64url_encode
from mpp.errors import InternalPaymentError
from mpp.server import PaymentRequired, Request
from tests.network import TEMPO

# Default secret used by tests when calling verify_or_challenge
TEST_SECRET = "test-secret"
TEST_REALM = "test.example.com"

INTEGRATION = pytest.mark.skipif(
    not TEMPO.enabled,
    reason="TEMPO_NETWORK not set (localnet or moderato; see tests/network.py)",
)


def make_credential(
    payload: dict[str, Any],
    challenge_id: str = "test",
    realm: str = TEST_REALM,
    method: str = "tempo",
    intent: str = "charge",
    request: str = "e30",
    source: str | None = None,
    expires: str | None = None,
) -> Credential:
    """Create a Credential with a ChallengeEcho for testing."""
    echo = ChallengeEcho(
        id=challenge_id,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
    )
    return Credential(challenge=echo, payload=payload, source=source)


def _default_expires() -> str:
    """Return an expires timestamp 1 hour in the future."""
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


def make_bound_credential(
    payload: dict[str, Any],
    request: dict[str, Any],
    secret_key: str = TEST_SECRET,
    realm: str = TEST_REALM,
    method: str = "tempo",
    intent: str = "charge",
    source: str | None = None,
    expires: str | None = None,
    digest: str | None = None,
    meta: dict[str, str] | None = None,
    header: str | None = None,
) -> Credential:
    """Create a Credential with an HMAC-bound challenge ID for testing.

    This produces credentials that will pass stateless challenge verification
    in verify_or_challenge().  If no ``expires`` is provided, a default 1-hour
    future timestamp is used so that credentials pass expiry enforcement.
    """
    if expires is None:
        expires = _default_expires()

    challenge = Challenge.create(
        secret_key=secret_key,
        realm=realm,
        method=method,
        intent=intent,
        request=request,
        expires=expires,
        digest=digest,
        meta=meta,
        header=header,
    )
    echo = challenge.to_echo()
    return Credential(challenge=echo, payload=payload, source=source)


class MockRequest:
    """Mock request object for testing."""

    def __init__(
        self,
        authorization: str | None = None,
        body: bytes | None = None,
        path: str | None = None,
        route: str | None = None,
        query_string: str | None = None,
        payment_authorization: str | None = None,
    ) -> None:
        self.headers: dict[str, str] = {}
        if authorization:
            self.headers["authorization"] = authorization
        if payment_authorization:
            self.headers["payment-authorization"] = payment_authorization
        self.body = body
        if path is not None:
            self.path = path
        if route is not None:
            self.route = route
        if query_string is not None:
            self.query_string = query_string


def http_request(
    authorization: str | None = None,
    *,
    method: str = "GET",
    url: str = "https://test.example.com/resource",
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    route: str | None = None,
    payment_authorization: str | None = None,
) -> Request:
    """Build an engine request carrying optional Payment credentials."""
    values = dict(headers or {})
    if authorization is not None:
        values["Authorization"] = authorization
    if payment_authorization is not None:
        values["Payment-Authorization"] = payment_authorization
    return Request(method, url, headers=values, body=body, route=route)


def challenges(result: Any) -> list[Challenge]:
    """Return the challenges of a 402 :class:`PaymentRequired` result."""
    assert isinstance(result, PaymentRequired), result
    assert result.status == 402
    return [
        Challenge.from_www_authenticate(value)
        for value in result.challenge.headers.get_list("www-authenticate")
    ]


def challenge(result: Any) -> Challenge:
    """Return the single challenge of a 402 :class:`PaymentRequired` result."""
    [issued] = challenges(result)
    return issued


def challenge_from_402(result: Any) -> Challenge:
    """Extract the challenge from a 402 response (Starlette or plain-dict form)."""
    headers = result.headers if hasattr(result, "headers") else result["headers"]
    return Challenge.from_www_authenticate(headers["WWW-Authenticate"])


def internal_cause(error: BaseException) -> BaseException:
    """Return the server-side cause of a generic ``InternalPaymentError``."""
    assert isinstance(error, InternalPaymentError)
    assert str(error) == "An internal payment error occurred."
    assert error.__cause__ is not None
    return error.__cause__


def server_method(
    *,
    name: str = "tempo",
    intent: str = "charge",
    request: dict[str, Any] | None = None,
    **hooks: Any,
) -> Any:
    """A ServerMethod with the given hooks whose wire request is ``request`` plus route options.

    Credential payloads reach the hooks unparsed.
    """
    from dataclasses import dataclass

    from pydantic import BaseModel, ConfigDict

    from mpp.methods import Method
    from mpp.server import ServerMethod

    class Wire(BaseModel):
        model_config = ConfigDict(extra="allow")

    @dataclass(frozen=True, slots=True, kw_only=True)
    class Raw(Method[Any, Any]):
        def parse_payload(self, payload: Any) -> Any:
            return payload

    return ServerMethod(
        method=Raw(name=name, intent=intent, request_model=Wire, payload_model=Wire),
        defaults=request,
        **hooks,
    )
