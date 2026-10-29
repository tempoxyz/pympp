"""Coinbase's facilitator (mpp.x402.cdp), checked against @coinbase/x402's config."""

from __future__ import annotations

import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pytest_httpx import HTTPXMock

from mpp.x402.cdp import (
    COINBASE_FACILITATOR_URL,
    create_auth_header,
    create_cdp_auth_headers,
    facilitator,
)

HOST = "api.cdp.coinbase.com"


def ed25519_key() -> tuple[str, ed25519.Ed25519PublicKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ) + key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), key.public_key()


def ec_key() -> tuple[str, ec.EllipticCurvePublicKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def decode(header: str, public_key) -> tuple[dict, dict]:
    assert header.startswith("Bearer ")
    token = header.removeprefix("Bearer ")
    head = jwt.get_unverified_header(token)
    return head, jwt.decode(token, public_key, algorithms=[head["alg"]])


@pytest.mark.parametrize(
    ("make_key", "alg"),
    [(ed25519_key, "EdDSA"), (ec_key, "ES256")],
)
def test_jwt_matches_cdp_generate_jwt(make_key, alg) -> None:
    secret, public_key = make_key()
    header = create_auth_header("kid-1", secret, "POST", HOST, "/platform/v2/x402/verify")
    head, claims = decode(header, public_key)
    assert head["alg"] == alg and head["kid"] == "kid-1" and head["typ"] == "JWT"
    assert len(head["nonce"]) == 16 and head["nonce"].isdigit()
    assert claims["sub"] == "kid-1" and claims["iss"] == "cdp"
    assert claims["uris"] == ["POST api.cdp.coinbase.com/platform/v2/x402/verify"]
    assert claims["exp"] - claims["nbf"] == 120


def test_pem_with_escaped_newlines_from_an_env_file() -> None:
    secret, public_key = ec_key()
    escaped = secret.replace("\n", "\\n")
    decode(create_auth_header("kid", escaped, "GET", HOST, "/p"), public_key)


def test_rejects_a_secret_that_is_not_a_cdp_key() -> None:
    with pytest.raises(ValueError, match="PEM EC key or a base64 Ed25519 key"):
        create_auth_header("kid", "not-a-key", "POST", HOST, "/p")


def test_headers_sign_each_endpoint_with_its_method_and_path() -> None:
    secret, public_key = ed25519_key()
    headers = create_cdp_auth_headers("kid", secret)()
    assert set(headers) == {"verify", "settle", "supported"}
    expected = {
        "verify": "POST api.cdp.coinbase.com/platform/v2/x402/verify",
        "settle": "POST api.cdp.coinbase.com/platform/v2/x402/settle",
        "supported": "GET api.cdp.coinbase.com/platform/v2/x402/supported",
    }
    for endpoint, uri in expected.items():
        assert headers[endpoint]["Correlation-Context"].startswith("sdk_language=python,")
        _, claims = decode(headers[endpoint]["Authorization"], public_key)
        assert claims["uris"] == [uri]


def test_key_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    secret, public_key = ed25519_key()
    monkeypatch.setenv("CDP_API_KEY_ID", "env-kid")
    monkeypatch.setenv("CDP_API_KEY_SECRET", secret)
    head, _ = decode(create_cdp_auth_headers()()["verify"]["Authorization"], public_key)
    assert head["kid"] == "env-kid"


def test_without_a_key_only_correlation_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CDP_API_KEY_ID", raising=False)
    monkeypatch.delenv("CDP_API_KEY_SECRET", raising=False)
    headers = create_cdp_auth_headers()()
    assert all(set(value) == {"Correlation-Context"} for value in headers.values())


async def test_facilitator_signs_every_request_afresh(httpx_mock: HTTPXMock) -> None:
    secret, public_key = ed25519_key()
    httpx_mock.add_response(url=f"{COINBASE_FACILITATOR_URL}/verify", json={"isValid": True})
    httpx_mock.add_response(
        url=f"{COINBASE_FACILITATOR_URL}/settle",
        json={"success": True, "transaction": "0xabc", "network": "eip155:8453"},
    )
    client = facilitator("kid", secret)
    await client.verify({"x402Version": 2}, {"scheme": "exact"})  # type: ignore[arg-type]
    await client.settle({"x402Version": 2}, {"scheme": "exact"})  # type: ignore[arg-type]
    verify, settle = httpx_mock.get_requests()
    assert decode(verify.headers["authorization"], public_key)[1]["uris"] == [
        "POST api.cdp.coinbase.com/platform/v2/x402/verify"
    ]
    assert decode(settle.headers["authorization"], public_key)[1]["uris"] == [
        "POST api.cdp.coinbase.com/platform/v2/x402/settle"
    ]
