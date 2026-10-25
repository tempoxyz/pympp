"""Client protocol: a 402 with ``PAYMENT-REQUIRED`` is paid back in ``PAYMENT-SIGNATURE``."""

from typing import Final, Literal

import httpx
from pydantic import ValidationError

from mpp.challenge import Challenge
from mpp.constants import Header
from mpp.x402._header import decode_payment_required_envelope
from mpp.x402._types import (
    EXACT_INTENT,
    PAYMENT_METHOD,
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    SYNTHETIC_CHALLENGE_ID_PREFIX,
    PaymentRequirements,
)

PROTOCOL: Final = "x402"
"""Provenance tag carried by synthesized challenges (:attr:`mpp.Challenge.protocol`)."""


def is_x402_challenge(challenge: Challenge) -> bool:
    """Returns whether a challenge was synthesized from an x402 ``PAYMENT-REQUIRED`` response."""
    return challenge.protocol == PROTOCOL


def challenges_from_response(response: httpx.Response) -> list[Challenge]:
    """Synthesizes one branded ``evm/charge`` challenge per supported x402 ``accepts`` entry.

    Unsupported entries (non-EVM networks, non-``exact`` schemes, malformed values) are skipped.

    Raises:
        mpp.x402.InvalidJsonHeaderError: When the ``PAYMENT-REQUIRED`` envelope is malformed.
        ValueError: When ``resource.url`` is not an absolute URL (no offer is usable).
    """
    if response.status_code != 402:
        return []
    header = response.headers.get(PAYMENT_REQUIRED_HEADER)
    if not header:
        return []
    envelope = decode_payment_required_envelope(header)
    realm = _host(envelope.resource.url)
    challenges: list[Challenge] = []
    for index, raw in enumerate(envelope.accepts):
        try:
            accepted = PaymentRequirements.model_validate(raw)
        except ValidationError:
            continue
        request = accepted.to_dict()
        if envelope.extensions is not None:
            request["extensions"] = {
                key: value.to_dict() for key, value in envelope.extensions.items()
            }
        request["resource"] = envelope.resource.to_dict()
        challenges.append(
            Challenge(
                id=f"{SYNTHETIC_CHALLENGE_ID_PREFIX}{index}",
                realm=realm,
                method=PAYMENT_METHOD,
                intent=EXACT_INTENT,
                request=request,
                protocol=PROTOCOL,
            )
        )
    return challenges


def _host(url: str) -> str:
    """``new URL(url).host``: raises for non-absolute URLs, keeps IPv6 brackets."""
    parsed = httpx.URL(url)
    if not parsed.scheme:
        raise ValueError(f"Invalid URL: {url}")
    host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
    return f"{host}:{parsed.port}" if parsed.port is not None else host


class X402Protocol:
    """x402 client protocol for :func:`mpp.client.http_transport`."""

    name = PROTOCOL

    async def get_challenges(
        self, response: httpx.Response, request: httpx.Request | None = None
    ) -> list[Challenge]:
        return challenges_from_response(response)

    def set_credential(
        self, request: httpx.Request, credential: str, challenge: Challenge | None = None
    ) -> httpx.Request:
        from mpp.client import set_credential_header

        return set_credential_header(request, PAYMENT_SIGNATURE_HEADER, credential)


def protocol() -> X402Protocol:
    """Creates the x402 client protocol."""
    return X402Protocol()


type ProtocolPreference = Literal["auto", "mpp", "x402"]
"""Payment protocol selection (the ``mppx --protocol`` option)."""


def collect_challenges(
    response: httpx.Response, protocol: ProtocolPreference = "auto"
) -> list[Challenge]:
    """Reads the challenges allowed by the selected protocol.

    ``"auto"`` lists native Payment-auth challenges first, then x402 ones, and tolerates a
    malformed offer of one protocol when the other yields challenges. Explicit selection raises
    on malformed offers so callers can diagnose the requested protocol.
    """
    if protocol == "mpp":
        return _mpp_challenges(response)
    if protocol == "x402":
        return challenges_from_response(response)
    errors: list[Exception] = []
    collected: list[Challenge] = []
    for read in (_mpp_challenges, challenges_from_response):
        try:
            collected.extend(read(response))
        except Exception as error:
            errors.append(error)
    if collected or not errors:
        return collected
    raise errors[0]


def _mpp_challenges(response: httpx.Response) -> list[Challenge]:
    if response.status_code != 402 or Header.WWW_AUTHENTICATE not in response.headers:
        return []
    return Challenge.deserialize_list(", ".join(response.headers.get_list(Header.WWW_AUTHENTICATE)))
