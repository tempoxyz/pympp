from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from mpp import Challenge, Credential
from mpp.server import PaymentRequired, Request, Response
from mpp.stripe import PaymentIntent

REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"


@dataclass
class Call:
    params: dict[str, Any]
    api_version: str
    idempotency_key: str | None
    stripe_account: str | None


@dataclass
class MockStripe:
    """In-memory Stripe client; every create after the first is reported as an idempotent replay."""

    status: str = "succeeded"
    id: str = "pi_mock_123"
    error: Exception | None = None
    addresses: Mapping[str, Any] = field(default_factory=dict)
    calls: list[Call] = field(default_factory=list)
    raw_calls: list[tuple[str, str, Any, str | None]] = field(default_factory=list)
    replay: bool = True

    async def create_payment_intent(
        self,
        params: Mapping[str, Any],
        *,
        api_version: str,
        idempotency_key: str | None = None,
        stripe_account: str | None = None,
    ) -> PaymentIntent:
        if self.error is not None:
            raise self.error
        self.calls.append(Call(dict(params), api_version, idempotency_key, stripe_account))
        return PaymentIntent(
            id=self.id, status=self.status, replayed=self.replay and len(self.calls) > 1
        )

    async def raw_request(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        *,
        api_version: str,
        stripe_account: str | None = None,
    ) -> Any:
        self.raw_calls.append((method, path, params, stripe_account))
        if "deposit_addresses" in path:
            if "limit=1" in path:
                address = self.addresses.get("list", "0xabc")
                return {"data": [{"address": address}] if address else []}
            return {"address": self.addresses.get("created", "0xnew")}
        return {}


@pytest.fixture
def make_stripe() -> type[MockStripe]:
    return MockStripe


def challenge_of(result: Any) -> Challenge:
    assert isinstance(result, PaymentRequired), result
    response: Response = result.challenge
    return Challenge.deserialize(response.headers["WWW-Authenticate"])


def authorized(credential: Credential[Any]) -> Request:
    return Request("GET", "https://example.com", headers={"Authorization": credential.serialize()})


type Handle = Callable[[Request], Awaitable[Any]]


async def pay(handle: Handle, payload: Mapping[str, Any]) -> tuple[Challenge, Any]:
    """Fetches a challenge from ``handle`` and retries with a credential carrying ``payload``."""
    challenge = challenge_of(await handle(Request("GET", "https://example.com")))
    result = await handle(authorized(Credential(challenge=challenge, payload=dict(payload))))
    return challenge, result


@pytest.fixture
def helpers() -> Any:
    class Helpers:
        challenge_of = staticmethod(challenge_of)
        authorized = staticmethod(authorized)
        pay = staticmethod(pay)
        realm = REALM
        secret_key = SECRET_KEY

    return Helpers
