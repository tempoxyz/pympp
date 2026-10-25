"""Delegates Tempo credential validation and finalization to Tempo API's MPP relay."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Any, Final, Literal, get_args

import httpx
from pydantic import BaseModel

from mpp.credential import Credential
from mpp.errors import PaymentError, PaymentExpiredError, VerificationFailedError
from mpp.method import ServerMethod, ValidateContext, Validation, VerifyContext
from mpp.receipt import Receipt

DEFAULT_API_BASE_URL: Final = "https://api.tempo.xyz"

type RelayErrorCode = Literal[
    "already_used",
    "broadcast_failed",
    "expired",
    "invalid_payment",
    "insufficient_funds",
    "policy_denied",
    "screen_rejected",
    "simulation_failed",
    "temporarily_unavailable",
    "unsupported",
    "unknown",
]
_ERROR_CODES: Final = frozenset(get_args(RelayErrorCode.__value__))
_SAFE_CODES: Final = frozenset(
    {
        "already_used",
        "broadcast_failed",
        "insufficient_funds",
        "invalid_payment",
        "simulation_failed",
        "unsupported",
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class RelayOptions:
    """Tempo API relay configuration for server-side Tempo charges.

    Every submitted credential is sent to the relay for finalization: it
    broadcasts pull transactions and recognizes push transaction hashes as
    already broadcast.
    """

    api_key: str
    """Tempo API key with the ``mpp:write`` scope."""
    api_base_url: str = DEFAULT_API_BASE_URL
    """Tempo API base URL, including an optional path prefix."""
    http: httpx.AsyncClient | None = None
    """HTTP client used to call Tempo API (a new client per call when omitted)."""


def configure(method: ServerMethod, options: RelayOptions) -> ServerMethod:
    """Returns ``method`` with ``validate``/``broadcast`` delegated to ``/v1/mpp/{validate,broadcast}``.

    Challenge configuration (defaults, request hook, binding) is preserved.
    """
    relay = _Relay(options)

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        credential = context.credential
        await relay.validate(_relay_input(credential))
        return Validation(
            challenge=credential.challenge,
            credential=credential,
            details={},
            intent=method.intent,
            method=method.name,
            request=credential.challenge.request,
            source=credential.source,
        )

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        receipt = await relay.broadcast(_relay_input(context.credential))
        if receipt.get("method") != method.name:
            raise _failure()
        try:
            return Receipt.from_dict({**receipt, "status": "success"})
        except ValueError:
            raise _failure() from None

    return dataclasses.replace(method, verify=None, validate=validate, broadcast=broadcast)


class _Relay:
    def __init__(self, options: RelayOptions) -> None:
        base = httpx.URL(options.api_base_url)
        if not base.path.endswith("/"):
            base = base.copy_with(path=base.path + "/")
        self._base = base
        self._options = options

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        url = self._base.join(path)
        content = json.dumps(body, separators=(",", ":"))
        headers = {
            "Accept": "application/json",
            "content-type": "application/json",
            "tempo-api-key": self._options.api_key,
        }
        try:
            if self._options.http is not None:
                response = await self._options.http.post(url, content=content, headers=headers)
            else:
                async with httpx.AsyncClient() as http:
                    response = await http.post(url, content=content, headers=headers)
        except httpx.HTTPError:
            raise _failure() from None
        if not response.is_success:
            raise _failure()
        try:
            return response.json()
        except ValueError:
            return None

    async def validate(self, body: dict[str, Any]) -> None:
        response = await self._post("v1/mpp/validate", body)
        if not (isinstance(response, dict) and response.get("success") is True):
            raise _failure(response)

    async def broadcast(self, body: dict[str, Any]) -> dict[str, Any]:
        # Omitting an idempotency key leaves credential consumption to the relay, so a cached
        # settlement receipt never authorizes another protected operation.
        response = await self._post("v1/mpp/broadcast", body)
        if not (
            isinstance(response, dict)
            and response.get("success") is True
            and _is_relay_receipt(response.get("receipt"))
        ):
            raise _failure(response)
        return response["receipt"]


def _relay_input(credential: Credential[Any]) -> dict[str, Any]:
    payload = credential.payload
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json", by_alias=True, exclude_none=True)
    body: dict[str, Any] = {"challenge": credential.challenge.to_dict(), "payload": payload}
    if credential.source:
        body["source"] = credential.source
    return body


def _is_relay_receipt(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("method"), str)
        and isinstance(value.get("reference"), str)
        and isinstance(value.get("timestamp"), str)
        and (value.get("externalId") is None or isinstance(value.get("externalId"), str))
    )


def _failure(response: Any = None) -> PaymentError:
    error = response.get("error") if isinstance(response, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    if code not in _ERROR_CODES:
        code = None
    if code == "expired":
        return PaymentExpiredError()
    if code in _SAFE_CODES:
        return VerificationFailedError(details={"code": code})
    if code == "temporarily_unavailable":
        return VerificationFailedError(details={"code": code, "retry": "same_credential"})
    return VerificationFailedError()
