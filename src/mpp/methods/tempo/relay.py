"""Tempo API relay adapter for server-side charges."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, Literal

from mpp import Credential, Receipt
from mpp._defaults import DEFAULT_TIMEOUT
from mpp._parsing import ParseError, _b64_decode, _parse_timestamp
from mpp._validation import Validation
from mpp.errors import (
    PaymentError,
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    VerificationError,
    VerificationFailedError,
)

if TYPE_CHECKING:
    import httpx

    from mpp.server.intent import Intent, VerifiableIntent

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
"""Stable machine-readable failure codes returned by the Tempo API relay."""

# Only these codes surface to payers in problem details; everything else stays
# opaque so relay internals and policy decisions do not leak.
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

    The relay receives every submitted credential: it validates both modes,
    broadcasts pull-mode transactions, and finalizes push-mode transaction
    hashes that are already on chain without sending them again. Relay
    failures surface as payment errors that stay opaque except for the safe
    machine-readable codes exposed in error ``details``.

    Pass a relay to :func:`~mpp.methods.tempo.tempo` to serve a charge
    intent's lifecycle through the Tempo API::

        method = tempo(
            intents={"charge": ChargeIntent()},
            relay=Relay(api_key=os.environ["TEMPO_API_KEY"]),
        )
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
            api_base_url: Tempo API or compatible relay base URL; a path
                prefix is preserved.
            http_client: Optional HTTP client to reuse. An injected client is
                owned by the caller; otherwise the relay creates one lazily
                and ``aclose()`` (or ``async with``) closes it.
            timeout: HTTP timeout for the internally created client.
        """
        if not api_key:
            raise ValueError("api_key is required")
        if not api_base_url:
            raise ValueError("api_base_url is required")
        self.api_key = api_key
        self.api_base_url = api_base_url.rstrip("/") + "/"
        self._client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

    def configure(self, intent: Intent | VerifiableIntent) -> VerifiableIntent:
        """Wrap an intent so its lifecycle is served by the relay.

        The returned intent delegates ``validate`` and ``broadcast`` to
        ``/v1/mpp/validate`` and ``/v1/mpp/broadcast``; the wrapped intent's
        local verification configuration (RPC URL, replay store, sender
        validation) is not consulted because the relay performs those checks
        itself.
        """
        return _RelayIntent(self, intent.name)

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
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "content-type": "application/json",
            "tempo-api-key": self.api_key,
        }
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key

        logger.debug("relay request method=POST path=/%s", path)
        response = await (await self._get_client()).post(
            self.api_base_url + path,
            json=body,
            headers=headers,
        )
        result = response.json() if response.is_success else None
        if not isinstance(result, dict) or result.get("success") is not True:
            raise _failure(result)
        return result


class _RelayIntent:
    def __init__(self, relay: Relay, name: str = "charge") -> None:
        self.name = name
        self._relay = relay

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation:
        body = _relay_input(credential, request)
        try:
            await self._relay._post("v1/mpp/validate", body)
        except PaymentError:
            raise
        except Exception:
            raise _failure() from None
        # The relay validates the echoed challenge request, so report the
        # exact request that was checked.
        return Validation(
            credential=credential,
            details={},
            intent=self.name,
            request=body["challenge"]["request"],
        )

    async def broadcast(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        body = _relay_input(credential, request)
        try:
            result = await self._relay._post(
                "v1/mpp/broadcast",
                body,
                idempotency_key=_idempotency_key(body),
            )
            return _receipt(result.get("receipt"))
        except PaymentError:
            raise
        except (Exception, asyncio.CancelledError) as error:
            raise PaymentOutcomeUnknownError(
                credential.challenge,
                error,
                credential=credential,
                request=request,
            ) from error


def _relay_input(credential: Credential, expected_request: dict[str, Any]) -> dict[str, Any]:
    try:
        request = _b64_decode(credential.challenge.request)
    except ParseError:
        raise _failure() from None
    if request != expected_request:
        raise _failure()

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
    """Derive a deterministic broadcast idempotency key.

    Pull-mode credentials use the signed transaction's hash so retries of the
    same transaction collapse server-side. Other payloads fall back to a hash
    of the canonical relay input.
    """
    payload = body.get("payload")
    if isinstance(payload, dict):
        signature = payload.get("signature")
        if payload.get("type") == "transaction" and isinstance(signature, str):
            from mpp.methods.tempo.intents import _raw_transaction_hash

            try:
                return f"pympp_{_raw_transaction_hash(signature)}"
            except VerificationError:
                pass

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
        parsed_timestamp = _parse_timestamp(timestamp)
    except ParseError:
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
    return code if isinstance(code, str) else None
