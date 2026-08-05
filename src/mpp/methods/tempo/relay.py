"""Tempo API relay adapter for server-side charge verification."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_TIMEOUT
from mpp._parsing import ParseError, _b64_decode
from mpp.errors import PaymentExpiredError, VerificationFailedError

if TYPE_CHECKING:
    import httpx

    from mpp.server.intent import Intent, SplitIntent

from mpp.server.intent import Validation

DEFAULT_API_BASE_URL = "https://api.tempo.xyz"
logger = logging.getLogger(__name__)

_VALIDATE_PATH: Final = "v1/mpp/validate"
_BROADCAST_PATH: Final = "v1/mpp/broadcast"
_ACCEPT_HEADER: Final = "Accept"
_CONTENT_TYPE_HEADER: Final = "content-type"
_TEMPO_API_KEY_HEADER: Final = "tempo-api-key"
_IDEMPOTENCY_KEY_HEADER: Final = "idempotency-key"
_JSON_MEDIA_TYPE: Final = "application/json"

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

_RELAY_ERROR_CODES = frozenset(cast("tuple[str, ...]", RelayErrorCode.__args__))
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
    """Delegate Tempo charge validation and finalization to an MPP relay.

    The relay validates every submitted credential, broadcasts pull-mode
    transactions, and finalizes already-broadcast push-mode transaction hashes.
    """

    def __init__(
        self,
        api_key: str,
        api_base_url: str = DEFAULT_API_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Create a relay adapter.

        Args:
            api_key: Tempo API key with the ``mpp:write`` scope.
            api_base_url: Tempo API or compatible relay base URL. A path prefix
                is preserved. Defaults to ``https://api.tempo.xyz``.
            http_client: Optional HTTP client. The caller owns injected clients.
            timeout: HTTP timeout used by an internally created client.
        """
        if not api_key:
            raise ValueError("api_key is required")
        if not api_base_url:
            raise ValueError("api_base_url is required")

        self.api_key = api_key
        self.api_base_url = api_base_url.rstrip("/") + "/"
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

    def configure(self, intent: Intent) -> SplitIntent:
        """Wrap a charge intent with relay-backed verification."""
        if intent.name != "charge":
            raise ValueError("Relay can only configure a charge intent")
        return _RelayChargeIntent(self)

    async def __aenter__(self) -> Relay:
        await self._get_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the internally owned HTTP client, if one was created."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def _post(
        self,
        path: str,
        relay_input: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> Any:
        client = await self._get_client()
        logger.debug("relay request method=POST path=/%s", path)
        try:
            response = await client.post(
                self.api_base_url + path,
                json=relay_input,
                headers={
                    _ACCEPT_HEADER: _JSON_MEDIA_TYPE,
                    _CONTENT_TYPE_HEADER: _JSON_MEDIA_TYPE,
                    _TEMPO_API_KEY_HEADER: self.api_key,
                    **(headers or {}),
                },
            )
        except Exception:
            raise _failure() from None

        logger.debug("relay response path=/%s status=%d", path, response.status_code)
        if not response.is_success:
            raise _failure()
        try:
            return response.json()
        except Exception:
            raise _failure() from None

    async def _validate(self, relay_input: dict[str, Any]) -> None:
        result = await self._post(_VALIDATE_PATH, relay_input)
        if not isinstance(result, dict) or result.get("success") is not True:
            raise _failure(result)

    async def _broadcast(self, relay_input: dict[str, Any]) -> Receipt:
        result = await self._post(
            _BROADCAST_PATH,
            relay_input,
            {_IDEMPOTENCY_KEY_HEADER: _idempotency_key(relay_input)},
        )
        if not isinstance(result, dict) or result.get("success") is not True:
            raise _failure(result)
        return _receipt_from(result.get("receipt"))


class _RelayChargeIntent:
    name = "charge"

    def __init__(self, relay: Relay) -> None:
        self._relay = relay

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation:
        """Validate a credential through the relay without finalizing it."""
        relay_input = _relay_input(credential)
        await self._relay._validate(relay_input)
        return Validation(
            challenge=credential.challenge,
            credential=credential,
            details={},
            intent=self.name,
            method=credential.challenge.method,
            request=request,
            source=credential.source,
        )

    async def broadcast(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        """Finalize a credential through the relay."""
        relay_input = _relay_input(credential)
        return await self._relay._broadcast(relay_input)

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        """Legacy combined validation and finalization hook."""
        await self.validate(credential, request)
        return await self.broadcast(credential, request)

    async def aclose(self) -> None:
        await self._relay.aclose()

    async def __aenter__(self) -> _RelayChargeIntent:
        await self._relay.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


def _relay_input(credential: Credential) -> dict[str, Any]:
    try:
        request = _b64_decode(credential.challenge.request)
    except ParseError:
        raise _failure() from None

    challenge = {
        "id": credential.challenge.id,
        "realm": credential.challenge.realm,
        "method": credential.challenge.method,
        "intent": credential.challenge.intent,
        "request": request,
    }
    if credential.challenge.expires is not None:
        challenge["expires"] = credential.challenge.expires
    if credential.challenge.digest is not None:
        challenge["digest"] = credential.challenge.digest
    if credential.challenge.opaque is not None:
        challenge["opaque"] = credential.challenge.opaque

    relay_input: dict[str, Any] = {
        "challenge": challenge,
        "payload": credential.payload,
    }
    if credential.source:
        relay_input["source"] = credential.source
    return relay_input


def _idempotency_key(relay_input: dict[str, Any]) -> str:
    payload = relay_input.get("payload")
    if isinstance(payload, dict):
        signature = payload.get("signature")
        if payload.get("type") == "transaction" and isinstance(signature, str):
            try:
                raw_signature = bytes.fromhex(signature.removeprefix("0x"))
            except ValueError:
                pass
            else:
                from eth_hash.auto import keccak

                return f"pympp_0x{keccak(raw_signature).hex()}"

    canonical = json.dumps(
        relay_input,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"pympp_0x{hashlib.sha256(canonical).hexdigest()}"


def _receipt_from(value: Any) -> Receipt:
    if not isinstance(value, dict):
        raise _failure()

    method = value.get("method")
    reference = value.get("reference")
    timestamp_value = value.get("timestamp")
    external_id = value.get("externalId")
    if (
        method != "tempo"
        or not isinstance(reference, str)
        or not isinstance(timestamp_value, str)
        or (external_id is not None and not isinstance(external_id, str))
    ):
        raise _failure()

    try:
        timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
    except ValueError:
        raise _failure() from None
    if timestamp.tzinfo is None:
        raise _failure()

    return Receipt.success(
        reference,
        timestamp=timestamp,
        method=method,
        external_id=external_id,
    )


def _failure(value: Any = None) -> VerificationFailedError | PaymentExpiredError:
    code = _relay_error_code(value)
    if code == "expired":
        return PaymentExpiredError()
    if code in _SAFE_ERROR_CODES:
        details = {"code": code}
        if code == "temporarily_unavailable":
            details["retry"] = "same_credential"
        return VerificationFailedError(details=details)
    return VerificationFailedError()


def _relay_error_code(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    error = value.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) and code in _RELAY_ERROR_CODES else None
