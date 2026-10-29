"""Coinbase's x402 facilitator (CDP), as ``@coinbase/x402`` configures it.

The facilitator authenticates every request with a short-lived JWT signed by a
CDP API key, bound to that request's method, host and path, so ``/verify`` and
``/settle`` each get their own token. Requires the ``cdp`` extra
(``pip install "pympp[cdp]"``) for JWT signing.

Example:
    from mpp.methods.evm import BASE_USDC
    from mpp.methods.evm import server as evm
    from mpp.x402.cdp import facilitator

    method = evm.charge(
        currency=BASE_USDC,
        recipient="0x...",
        facilitator=facilitator(),  # CDP_API_KEY_ID / CDP_API_KEY_SECRET
    )
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import time
from typing import Any
from urllib.parse import quote

import httpx

from mpp.x402.facilitator import CreateAuthHeaders, HttpFacilitator

COINBASE_FACILITATOR_BASE_URL = "https://api.cdp.coinbase.com"
COINBASE_FACILITATOR_V2_ROUTE = "/platform/v2/x402"
COINBASE_FACILITATOR_URL = COINBASE_FACILITATOR_BASE_URL + COINBASE_FACILITATOR_V2_ROUTE

_ENDPOINTS = (("verify", "POST"), ("settle", "POST"), ("supported", "GET"))


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("pympp")
    except PackageNotFoundError:
        return "unknown"


def create_correlation_header() -> str:
    """The ``Correlation-Context`` header Coinbase's SDKs send with each request."""
    data = {"sdk_language": "python", "source": "pympp", "source_version": _version()}
    return ",".join(f"{key}={quote(value, safe='')}" for key, value in data.items())


def _private_key(secret: str) -> Any:
    """A CDP API key secret: a PEM EC key (ES256) or a base64 Ed25519 key (EdDSA)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    # Unquoted environment values often carry a literal backslash-n.
    secret = secret.replace("\\n", "\n")
    try:
        key = serialization.load_pem_private_key(secret.encode(), password=None)
    except (ValueError, TypeError):
        key = None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key
    try:
        raw = base64.b64decode(secret, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) == 64:
        # 32-byte seed followed by the 32-byte public key.
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32])
    raise ValueError("CDP API key secret must be a PEM EC key or a base64 Ed25519 key")


def create_auth_header(
    api_key_id: str,
    api_key_secret: str,
    request_method: str,
    request_host: str,
    request_path: str,
    *,
    expires_in: int = 120,
) -> str:
    """A ``Bearer`` JWT for one CDP request, as Coinbase's ``generateJwt`` signs it:
    bound to the request's method, host and path, valid for two minutes."""
    try:
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:  # pragma: no cover - exercised without the extra
        raise ImportError(
            'Coinbase\'s facilitator needs the "cdp" extra: pip install "pympp[cdp]"'
        ) from error
    if not api_key_id or not api_key_secret:
        raise ValueError("a CDP API key id and secret are required")
    key = _private_key(api_key_secret)
    algorithm = "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "EdDSA"
    now = int(time.time())
    claims = {
        "sub": api_key_id,
        "iss": "cdp",
        "nbf": now,
        "exp": now + expires_in,
        "uris": [f"{request_method} {request_host}{request_path}"],
    }
    header = {
        "alg": algorithm,
        "kid": api_key_id,
        "typ": "JWT",
        "nonce": "".join(secrets.choice("0123456789") for _ in range(16)),
    }
    return "Bearer " + jwt.encode(claims, key, algorithm=algorithm, headers=header)


def create_cdp_auth_headers(
    api_key_id: str | None = None,
    api_key_secret: str | None = None,
) -> CreateAuthHeaders:
    """Per-endpoint headers for Coinbase's facilitator, signed fresh on every call.

    The key defaults to ``CDP_API_KEY_ID`` and ``CDP_API_KEY_SECRET``, read when
    headers are made. Without a key only ``Correlation-Context`` is sent, as
    ``@coinbase/x402`` does; the facilitator then refuses mainnet payments.
    """
    host = COINBASE_FACILITATOR_BASE_URL.removeprefix("https://")

    def create() -> dict[str, dict[str, str]]:
        key_id = api_key_id or os.environ.get("CDP_API_KEY_ID")
        key_secret = api_key_secret or os.environ.get("CDP_API_KEY_SECRET")
        headers: dict[str, dict[str, str]] = {}
        for endpoint, method in _ENDPOINTS:
            headers[endpoint] = {"Correlation-Context": create_correlation_header()}
            if key_id and key_secret:
                headers[endpoint]["Authorization"] = create_auth_header(
                    key_id, key_secret, method, host, f"{COINBASE_FACILITATOR_V2_ROUTE}/{endpoint}"
                )
        return headers

    return create


def facilitator(
    api_key_id: str | None = None,
    api_key_secret: str | None = None,
    *,
    timeout: float = 30.0,
    client: httpx.AsyncClient | None = None,
    **options: Any,
) -> HttpFacilitator:
    """Coinbase's facilitator, authenticated with a CDP API key.

    Mirrors ``createFacilitatorConfig`` from ``@coinbase/x402``.
    """
    return HttpFacilitator(
        COINBASE_FACILITATOR_URL,
        create_auth_headers=create_cdp_auth_headers(api_key_id, api_key_secret),
        timeout=timeout,
        client=client,
        **options,
    )


__all__ = [
    "COINBASE_FACILITATOR_URL",
    "create_auth_header",
    "create_cdp_auth_headers",
    "create_correlation_header",
    "facilitator",
]
