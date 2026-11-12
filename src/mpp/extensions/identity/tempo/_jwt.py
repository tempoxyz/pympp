"""Compact JWS helpers for Tempo ID: decoding, RS256 key sets and ES256 DPoP signatures."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

MAX_TOKEN_LENGTH = 16_384
KEY_SET_MAX_AGE = 300.0
"""Seconds a loaded key set serves before it is refetched."""
KEY_SET_RETRY = 30.0
"""Seconds between fetches when a key ID is unknown or the issuer is unreachable."""
KEY_SET_TIMEOUT = 5.0


@dataclass(frozen=True, slots=True)
class Decoded:
    """A decoded, unverified compact JWS."""

    header: Mapping[str, Any]
    claims: Mapping[str, Any]
    signing_input: bytes
    signature: bytes


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def encode(value: Any) -> str:
    """Encode a JSON value as unpadded base64url, compact like ``JSON.stringify``."""
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode())


def decode(token: str) -> Decoded | None:
    """Decode a compact JWS without verifying it, or None if it is malformed."""
    parts = token.split(".")
    if len(token) > MAX_TOKEN_LENGTH or len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return Decoded(
        header=cast("dict[str, Any]", header),
        claims=cast("dict[str, Any]", claims),
        signing_input=f"{parts[0]}.{parts[1]}".encode(),
        signature=signature,
    )


def sha256(value: str) -> str:
    """Unpadded base64url SHA-256 of a string, as DPoP's ``ath`` uses."""
    return b64url_encode(hashlib.sha256(value.encode()).digest())


def thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 thumbprint of a P-256 public JWK."""
    members = {"crv": jwk.get("crv"), "kty": jwk.get("kty"), "x": jwk.get("x"), "y": jwk.get("y")}
    return sha256(json.dumps(members, separators=(",", ":")))


def htu(url: str) -> str:
    """A request URL without its query and fragment, as DPoP's ``htu`` names it."""
    parsed = httpx.URL(url)
    default = {"http": 80, "https": 443}.get(parsed.scheme)
    port = "" if parsed.port in (None, default) else f":{parsed.port}"
    host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
    return f"{parsed.scheme}://{host}{port}{parsed.path or '/'}"


def verify_rs256(key: rsa.RSAPublicKey, jws: Decoded) -> bool:
    try:
        key.verify(jws.signature, jws.signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def es256_public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey | None:
    """The P-256 public key of a JWK, or None if it is not one."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        return None
    try:
        x = int.from_bytes(b64url_decode(str(jwk["x"])), "big")
        y = int.from_bytes(b64url_decode(str(jwk["y"])), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except (KeyError, ValueError):
        return None


def verify_es256(key: ec.EllipticCurvePublicKey, jws: Decoded) -> bool:
    if len(jws.signature) != 64:
        return False
    r = int.from_bytes(jws.signature[:32], "big")
    s = int.from_bytes(jws.signature[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), jws.signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def sign_es256(key: ec.EllipticCurvePrivateKey, signing_input: bytes) -> str:
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return b64url_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """The P-256 public JWK of a key, members in RFC 7638 order."""
    numbers = key.public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }


class KeySet:
    """An issuer's RS256 keys by key ID, from ``<issuer>/oauth2/jwks``.

    The set is cached for five minutes, and an unknown key ID refetches it at most every 30
    seconds. A failed fetch keeps the last set that loaded; without one, it raises.
    """

    def __init__(self, issuer: str, http: httpx.AsyncClient | None = None) -> None:
        self.url = f"{issuer}/oauth2/jwks"
        self._http = http
        self._keys: dict[str, rsa.RSAPublicKey] | None = None
        self._loaded_at = 0.0
        self._attempted_at = float("-inf")
        self._pending: asyncio.Future[dict[str, rsa.RSAPublicKey]] | None = None

    async def get(self, kid: str) -> rsa.RSAPublicKey | None:
        """The key with ID ``kid``, or None if the issuer has none.

        Raises:
            Exception: If the key set never loaded.
        """
        key = (await self._fresh(KEY_SET_MAX_AGE)).get(kid)
        return key if key is not None else (await self._fresh(KEY_SET_RETRY)).get(kid)

    async def _fresh(self, max_age: float) -> dict[str, rsa.RSAPublicKey]:
        now = time.monotonic()
        if self._keys is not None and now - self._loaded_at < max_age:
            return self._keys
        if (
            self._keys is not None
            and self._pending is None
            and now - self._attempted_at < KEY_SET_RETRY
        ):
            return self._keys
        if self._pending is None:
            self._attempted_at = now
            self._pending = asyncio.ensure_future(self._load())
        pending = self._pending
        try:
            keys = await asyncio.shield(pending)
        except Exception:
            if self._keys is not None:
                return self._keys
            raise
        finally:
            if self._pending is pending and pending.done():
                self._pending = None
        self._keys, self._loaded_at = keys, time.monotonic()
        return keys

    async def _load(self) -> dict[str, rsa.RSAPublicKey]:
        if self._http is None:
            async with httpx.AsyncClient() as http:
                response = await http.get(self.url, timeout=KEY_SET_TIMEOUT)
        else:
            response = await self._http.get(self.url, timeout=KEY_SET_TIMEOUT)
        if not response.is_success:
            raise RuntimeError(f"the key set request failed with {response.status_code}")
        body: object = response.json()
        keys: dict[str, rsa.RSAPublicKey] = {}
        entries: object = (
            cast("dict[str, Any]", body).get("keys") if isinstance(body, dict) else None
        )
        for jwk in cast("list[Any]", entries) if isinstance(entries, list) else []:
            if not isinstance(jwk, dict):
                continue
            entry = cast("dict[str, Any]", jwk)
            kid, e, n = entry.get("kid"), entry.get("e"), entry.get("n")
            if entry.get("kty") != "RSA" or not kid or not e or not n:
                continue
            try:
                numbers = rsa.RSAPublicNumbers(
                    int.from_bytes(b64url_decode(str(e)), "big"),
                    int.from_bytes(b64url_decode(str(n)), "big"),
                )
                keys[str(kid)] = numbers.public_key()
            except ValueError:
                continue
        return keys
