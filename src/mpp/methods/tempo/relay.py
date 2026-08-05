"""Tempo API relay adapter for server-side charges."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, get_args

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_TIMEOUT
from mpp._parsing import ParseError, _b64_decode
from mpp._validation import Validation
from mpp.errors import PaymentExpiredError, VerificationFailedError

if TYPE_CHECKING:
    import httpx

    from mpp.server.intent import Intent, SplitIntent

logger = logging.getLogger(__name__)

DEFAULT_API_BASE_URL = "https://api.tempo.xyz"

RelayErrorCode = Literal[
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

_ERROR_CODES = frozenset(get_args(RelayErrorCode))
_SAFE_ERROR_CODES = frozenset(
    {
        "already_used",
        "broadcast_failed",
        "invalid_payment",
        "insufficient_funds",
        "simulation_failed",
        "temporarily_unavailable",
        "unsupported",
    }
)


class Relay:
    """Delegate Tempo charge validation and finalization to an MPP relay."""

    def __init__(
        self,
        api_key: str,
        api_base_url: str = DEFAULT_API_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        if not api_base_url:
            raise ValueError("api_base_url is required")
        self.api_key = api_key
        self.api_base_url = api_base_url.rstrip("/") + "/"
        self._client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

    def configure(self, intent: Intent) -> SplitIntent:
        """Replace a charge intent's lifecycle hooks with relay calls."""
        if intent.name != "charge":
            raise ValueError("Relay can only configure a charge intent")
        return _RelayCharge(self)

    async def __aenter__(self) -> Relay:
        await self._get_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the internally owned HTTP client."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> Any:
        headers = {
            "Accept": "application/json",
            "content-type": "application/json",
            "tempo-api-key": self.api_key,
        }
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key

        logger.debug("relay request method=POST path=/%s", path)
        try:
            response = await (await self._get_client()).post(
                self.api_base_url + path,
                json=body,
                headers=headers,
            )
            if not response.is_success:
                raise _failure()
            return response.json()
        except (PaymentExpiredError, VerificationFailedError):
            raise
        except Exception:
            raise _failure() from None

    async def _validate(self, body: dict[str, Any]) -> None:
        result = await self._post("v1/mpp/validate", body)
        if not isinstance(result, dict) or result.get("success") is not True:
            raise _failure(result)

    async def _broadcast(self, body: dict[str, Any]) -> Receipt:
        result = await self._post(
            "v1/mpp/broadcast",
            body,
            idempotency_key=_idempotency_key(body),
        )
        if not isinstance(result, dict) or result.get("success") is not True:
            raise _failure(result)
        return _receipt(result.get("receipt"))


class _RelayCharge:
    name = "charge"

    def __init__(self, relay: Relay) -> None:
        self._relay = relay

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation:
        body = _relay_input(credential)
        await self._relay._validate(body)
        return Validation(
            challenge=credential.challenge,
            credential=credential,
            details={},
            intent=self.name,
            method=credential.challenge.method,
            request=dict(request),
            source=credential.source,
        )

    async def broadcast(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        return await self._relay._broadcast(_relay_input(credential))

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        await self.validate(credential, request)
        return await self.broadcast(credential, request)


def _relay_input(credential: Credential) -> dict[str, Any]:
    try:
        request = _b64_decode(credential.challenge.request)
    except ParseError:
        raise _failure() from None

    echo = credential.challenge
    challenge: dict[str, Any] = {
        "id": echo.id,
        "realm": echo.realm,
        "method": echo.method,
        "intent": echo.intent,
        "request": request,
    }
    for name in ("expires", "digest", "opaque"):
        if (value := getattr(echo, name)) is not None:
            challenge[name] = value

    result: dict[str, Any] = {"challenge": challenge, "payload": credential.payload}
    if credential.source:
        result["source"] = credential.source
    return result


def _idempotency_key(body: dict[str, Any]) -> str:
    payload = body.get("payload")
    if isinstance(payload, dict):
        signature = payload.get("signature")
        if payload.get("type") == "transaction" and isinstance(signature, str):
            try:
                raw = bytes.fromhex(signature.removeprefix("0x"))
            except ValueError:
                pass
            else:
                from eth_hash.auto import keccak

                return f"pympp_0x{keccak(raw).hex()}"

    canonical = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return f"pympp_0x{hashlib.sha256(canonical.encode()).hexdigest()}"


def _receipt(value: Any) -> Receipt:
    if not isinstance(value, dict):
        raise _failure()
    method = value.get("method")
    reference = value.get("reference")
    timestamp = value.get("timestamp")
    external_id = value.get("externalId")
    if (
        method != "tempo"
        or not isinstance(reference, str)
        or not isinstance(timestamp, str)
        or (external_id is not None and not isinstance(external_id, str))
    ):
        raise _failure()
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise _failure() from None
    if parsed_timestamp.tzinfo is None:
        raise _failure()
    return Receipt.success(
        reference,
        timestamp=parsed_timestamp,
        method=method,
        external_id=external_id,
    )


def _failure(value: Any = None) -> VerificationFailedError | PaymentExpiredError:
    code = _error_code(value)
    if code == "expired":
        return PaymentExpiredError()
    if code in _SAFE_ERROR_CODES:
        details = {"code": code}
        if code == "temporarily_unavailable":
            details["retry"] = "same_credential"
        return VerificationFailedError(details=details)
    return VerificationFailedError()


def _error_code(value: Any) -> str | None:
    if not isinstance(value, dict) or not isinstance(value.get("error"), dict):
        return None
    code = value["error"].get("code")
    return code if isinstance(code, str) and code in _ERROR_CODES else None
