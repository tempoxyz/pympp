"""Test methods mirroring the shapes used by the mppx server tests (no chain access)."""

from collections.abc import Callable
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from mpp import Method, Receipt, ServerMethod, VerifyContext, expires
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.server import Request

REALM = "api.example.com"
SECRET_KEY = "test-secret-key-test-secret-key-32"
CURRENCY = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"


class SimpleRequest(BaseModel):
    amount: str
    currency: str
    recipient: str | None = None


class SigPayload(BaseModel):
    sig: str


class TokenPayload(BaseModel):
    token: str


class ChargeRequest(BaseModel):
    """Tempo-like charge request: decimal amount -> base units; options under methodDetails."""

    model_config = ConfigDict(populate_by_name=True)

    amount: str
    currency: str
    recipient: str
    decimals: int | None = Field(default=None, exclude=True)
    chain_id: int | None = Field(default=None, alias="chainId")
    fee_payer: bool | None = Field(default=None, alias="feePayer")
    memo: str | None = None
    splits: list[dict[str, Any]] | None = None
    description: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")

    @model_serializer(mode="plain")
    def _wire(self) -> dict[str, Any]:
        amount = self.amount
        if self.decimals is not None:
            amount = str(int(Decimal(amount) * (Decimal(10) ** self.decimals)))
        details = {
            key: value
            for key, value in {
                "chainId": self.chain_id,
                "feePayer": self.fee_payer,
                "memo": self.memo,
                "splits": self.splits,
            }.items()
            if value is not None
        }
        wire: dict[str, Any] = {"amount": amount, "currency": self.currency}
        if self.description is not None:
            wire["description"] = self.description
        if self.external_id is not None:
            wire["externalId"] = self.external_id
        if details:
            wire["methodDetails"] = details
        wire["recipient"] = self.recipient
        return wire


class ChargePayload(BaseModel):
    type: str
    signature: str | None = None
    hash: str | None = None


def receipt(method: str = "mock", reference: str = "tx-ref", **extra: Any) -> Receipt:
    return Receipt(
        method=method, reference=reference, timestamp=expires.to_iso(expires.now()), **extra
    )


def simple_method(
    name: str, intent: str = "charge", payload: type[BaseModel] = SigPayload
) -> Method[Any, Any]:
    return Method(name=name, intent=intent, request_model=SimpleRequest, payload_model=payload)


def mock_server(
    name: str = "mock",
    intent: str = "charge",
    *,
    payload: type[BaseModel] = TokenPayload,
    request_model: type[BaseModel] = SimpleRequest,
    verify: Callable[[VerifyContext[Any]], Any] | None = None,
    **hooks: Any,
) -> ServerMethod:
    method = Method(name=name, intent=intent, request_model=request_model, payload_model=payload)

    async def default_verify(context: VerifyContext[Any]) -> Receipt:
        return receipt(name)

    async def wrapped(context: VerifyContext[Any]) -> Receipt:
        if verify is None:
            return await default_verify(context)
        result = verify(context)
        if hasattr(result, "__await__"):
            result = await result
        return result

    return ServerMethod(method=method, verify=wrapped, **hooks)


charge_method = Method(
    name="tempo", intent="charge", request_model=ChargeRequest, payload_model=ChargePayload
)


def tempo_charge_server(**hooks: Any) -> ServerMethod:
    async def verify(context: VerifyContext[Any]) -> Receipt:
        return receipt("tempo", "0xhash")

    hooks.setdefault("verify", verify)
    return ServerMethod(method=charge_method, **hooks)


def http_request(url: str = "https://example.com/resource", **headers: str) -> Request:
    return Request(
        "GET", url, headers={key.replace("_", "-"): value for key, value in headers.items()}
    )


def credential_header(challenge: Challenge, payload: Any) -> str:
    return Credential(challenge=challenge, payload=payload).serialize()


def future(seconds: int = 60) -> str:
    return expires.seconds(seconds)
