"""Tempo ID on the client: a prover that sends the access token (mppx `TempoId.Client`)."""

from __future__ import annotations

import inspect
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal, TypeVar

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from mpp.extensions.identity.tempo import ID_TOKEN_HEADER
from mpp.extensions.identity.tempo import _jwt as jwt
from mpp.identity import ProveContext, Prover, with_headers

T = TypeVar("T")
MaybeAwaitable = T | Awaitable[T]


@dataclass(frozen=True, slots=True)
class DpopKey:
    """An ES256 DPoP key (RFC 9449), such as the Tempo ID SDK's session key."""

    private_key: ec.EllipticCurvePrivateKey

    def __post_init__(self) -> None:
        if not isinstance(self.private_key.curve, ec.SECP256R1):
            raise ValueError("a DPoP key must be a P-256 key")

    @classmethod
    def generate(cls) -> DpopKey:
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @property
    def jwk(self) -> dict[str, str]:
        """The public key as a JWK."""
        return jwt.public_jwk(self.private_key.public_key())

    @property
    def thumbprint(self) -> str:
        """The RFC 7638 thumbprint a DPoP-bound token names in ``cnf.jkt``."""
        return jwt.thumbprint(self.jwk)

    def proof(self, access_token: str, method: str, url: str) -> str:
        """Sign a DPoP proof of ``access_token`` for one request."""
        header = jwt.encode({"alg": "ES256", "jwk": self.jwk, "typ": "dpop+jwt"})
        claims = jwt.encode(
            {
                "ath": jwt.sha256(access_token),
                "htm": method,
                "htu": jwt.htu(url),
                "iat": int(time.time()),
                "jti": str(uuid.uuid4()),
            }
        )
        signing_input = f"{header}.{claims}"
        return f"{signing_input}.{jwt.sign_es256(self.private_key, signing_input.encode())}"


def prover(
    *,
    access_token: Callable[[], MaybeAwaitable[str]],
    scope: Sequence[str] | Literal["*"],
    dpop: DpopKey | None = None,
    id_token: Callable[[], MaybeAwaitable[str | None]] | None = None,
) -> Prover:
    """Create a prover that sends a Tempo ID access token with each request.

    The token goes as ``DPoP`` with a new proof per request when ``dpop`` is set, else as
    ``Bearer``; ``id_token``, when it returns one, goes in ``Tempo-Id-Token`` so the API reads the
    user's email. Send the token only to the API it was issued for: ``scope`` lists its origins.

    Example::

        prover = tempo.client.prover(
            access_token=session.access_token, scope=["https://api.example"]
        )
        async with Mpp(methods=[tempo_method], identity=[prover]) as mpp:
            response = await mpp.fetch("https://api.example/paid")
    """

    async def prove(request: httpx.Request, context: ProveContext) -> httpx.Request:
        # Authorization holds the Payment Credential, which outranks the access token: a server
        # that reads Tempo ID sets requires_auth=True and takes the Credential elsewhere.
        if request.headers.get("Authorization", "").lower().startswith("payment "):
            return request
        token = await _call(access_token)
        headers = {"Authorization": f"{'DPoP' if dpop else 'Bearer'} {token}"}
        if dpop is not None:
            headers["DPoP"] = dpop.proof(token, request.method, str(request.url))
        if id_token is not None and (value := await _call(id_token)):
            headers[ID_TOKEN_HEADER] = value
        return with_headers(request, headers)

    return Prover(
        scope="*" if scope == "*" else tuple(scope),
        prove=prove,
        headers=("dpop", ID_TOKEN_HEADER.lower()),
    )


async def _call(function: Callable[[], MaybeAwaitable[T]]) -> T:
    value = function()
    if inspect.isawaitable(value):
        return await value
    return value


__all__ = ["DpopKey", "prover"]
