"""Ported from mppx src/server/Mpp.test.ts: cross-route credential replay via scope binding."""

from typing import Any

import pytest
from pydantic import BaseModel, model_serializer

from mpp import Challenge, Credential, Method, Receipt, ServerMethod, VerifyContext
from mpp.server import Mpp, Request, compose

from ._fixtures import REALM, SECRET_KEY, TokenPayload, future, receipt


class Split(BaseModel):
    amount: str
    recipient: str


class Moved(BaseModel):
    """Transform moving the economic fields into ``methodDetails`` (like Tempo)."""

    amount: str
    currency: str
    decimals: int
    recipient: str
    splits: list[Split] | None = None

    @model_serializer(mode="plain")
    def _wire(self) -> dict[str, Any]:
        details: dict[str, Any] = {
            "amount": str(round(float(self.amount) * 10**self.decimals)),
            "currency": self.currency,
            "recipient": self.recipient,
        }
        if self.splits:
            details["splits"] = [split.model_dump() for split in self.splits]
        return {"methodDetails": details}


class Session(BaseModel):
    amount: str
    currency: str
    recipient: str
    unitType: str


def server(
    name: str = "mock", intent: str = "charge", model: type[BaseModel] = Moved
) -> ServerMethod:
    async def verify(_: VerifyContext[Any]) -> Receipt:
        return receipt(name)

    return ServerMethod(
        method=Method(name=name, intent=intent, request_model=model, payload_model=TokenPayload),
        verify=verify,
    )


def opts(**overrides: Any) -> dict[str, Any]:
    return {
        "amount": "0.01",
        "currency": "0x01",
        "decimals": 6,
        "expires": future(),
        "recipient": "0x02",
        **overrides,
    }


async def replay(mppx: Mpp, source: Any, target: Any, *, intent: str = "charge") -> Any:
    first = await source(Request("GET", "https://example.com/source"))
    credential = Credential(
        challenge=Challenge.from_response(first.challenge), payload={"token": "valid"}
    )
    return await target(
        Request("GET", "https://example.com/target", {"Authorization": credential.serialize()})
    )


def make(*methods: ServerMethod) -> Mpp:
    return Mpp(methods=list(methods), realm=REALM, secret_key=SECRET_KEY)


async def test_amount_moved_into_method_details() -> None:
    mppx = make(server())
    result = await replay(mppx, mppx.charge(**opts()), mppx.charge(**opts(amount="100")))
    assert result.status == 402


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ({"meta": {"route": "a"}}, {"meta": {"route": "b"}}),
        ({"meta": {"route": "A"}}, {"meta": {"route": "a"}}),
        ({"scope": "GET /a"}, {"scope": "GET /b"}),
    ],
)
async def test_sibling_routes_with_different_metadata(a: dict[str, Any], b: dict[str, Any]) -> None:
    mppx = make(server())
    result = await replay(mppx, mppx.charge(**opts(**a)), mppx.charge(**opts(**b)))
    assert result.status == 402
    same = await replay(mppx, mppx.charge(**opts(**a)), mppx.charge(**opts(**a)))
    assert same.status == 200


async def test_request_billed_at_token_billed_route() -> None:
    mppx = make(server(intent="session", model=Session))
    base = {"amount": "1", "currency": "0x1", "recipient": "0x2", "expires": future()}
    result = await replay(
        mppx, mppx.session(**base, unitType="request"), mppx.session(**base, unitType="token")
    )
    assert result.status == 402


async def test_mismatched_method_and_intent() -> None:
    class Plain(BaseModel):
        amount: str
        currency: str
        recipient: str

    mock, other = server("mock", model=Plain), server("other", model=Plain)
    mppx = make(mock, other)
    plain = {"amount": "1", "currency": "0x1", "recipient": "0x2", "expires": future()}
    assert (await replay(mppx, mppx.other.charge(**plain), mppx.mock.charge(**plain))).status == 402
    session = server("mock", "session", Plain)
    mppx = make(mock, session)
    assert (await replay(mppx, mppx.mock.session(**plain), mppx.mock.charge(**plain))).status == 402


async def test_compose_rejects_moved_scope_fields() -> None:
    mppx = make(server())
    result = await replay(
        mppx, compose(mppx.charge(**opts())), compose(mppx.charge(**opts(amount="100")))
    )
    assert result.status == 402


async def test_no_splits_credential_at_splits_route() -> None:
    mppx = make(server())
    splits = [{"amount": "0.2", "recipient": "0x03"}]
    result = await replay(
        mppx, mppx.charge(**opts(amount="1")), mppx.charge(**opts(amount="1", splits=splits))
    )
    assert result.status == 402


async def test_compose_dispatch_includes_splits_binding() -> None:
    mppx = make(server())
    splits = [{"amount": "0.2", "recipient": "0x03"}]
    composed = compose(
        mppx.charge(**opts(amount="1")), mppx.charge(**opts(amount="1", splits=splits))
    )
    first = await composed(Request("GET", "https://example.com/resource"))
    no_splits = Challenge.from_response_list(first.challenge)[0]
    credential = Credential(challenge=no_splits, payload={"token": "valid"})
    result = await composed(
        Request("GET", "https://example.com/resource", {"Authorization": credential.serialize()})
    )
    assert result.status == 200
