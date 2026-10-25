"""Client-side transports: how challenges are received and credentials sent."""

import contextlib
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

import httpx

from mpp.challenge import Challenge
from mpp.client._protocols import PAYMENT_REQUIRED_STATUS, mpp
from mpp.client._protocols import Protocol as PaymentProtocol


@runtime_checkable
class ClientTransport[RequestT, ResponseT](Protocol):
    """Client-side transport adapter (mppx client ``Transport``)."""

    name: str

    async def is_payment_required(self, response: ResponseT, request: RequestT | None) -> bool:
        """Whether ``response`` asks for payment (may inspect the request and read the body)."""
        ...

    async def get_challenges(
        self, response: ResponseT, request: RequestT | None
    ) -> list[Challenge]:
        """Extracts all challenges from a payment-required response."""
        ...

    def set_credential(
        self, request: RequestT, credential: str, challenge: Challenge | None
    ) -> RequestT:
        """Attaches a credential to a request."""
        ...


def default_protocols() -> list[PaymentProtocol]:
    """``[mpp(), x402 (when mpp.x402 provides it)]``."""
    protocols: list[PaymentProtocol] = [mpp()]
    try:
        from mpp.x402 import protocol as x402_protocol
    except ImportError:
        pass
    else:
        protocols.append(x402_protocol())
    return protocols


class HttpTransport:
    """HTTP transport composing payment protocols over ``httpx``.

    Challenges from every protocol are collected (in protocol order) and the credential is
    attached using the protocol that produced the selected challenge.
    """

    name = "http"

    def __init__(self, protocols: Sequence[PaymentProtocol] | None = None) -> None:
        self.protocols: tuple[PaymentProtocol, ...] = tuple(
            default_protocols() if protocols is None else protocols
        )

    async def is_payment_required(
        self, response: httpx.Response, request: httpx.Request | None
    ) -> bool:
        if response.status_code == PAYMENT_REQUIRED_STATUS:
            return True
        return bool(await self.get_challenges(response, request))

    async def get_challenges(
        self, response: httpx.Response, request: httpx.Request | None
    ) -> list[Challenge]:
        cached = response.extensions.get("mpp.challenges")
        if cached is not None:
            return list(cached)
        target = request
        if target is None:
            with contextlib.suppress(RuntimeError):
                target = response.request
        challenges: list[Challenge] = []
        for protocol in self.protocols:
            challenges.extend(await protocol.get_challenges(response, target))
        response.extensions["mpp.challenges"] = tuple(challenges)  # type: ignore[index]
        return challenges

    def set_credential(
        self, request: httpx.Request, credential: str, challenge: Challenge | None
    ) -> httpx.Request:
        name = (challenge.protocol if challenge is not None else None) or "mpp"
        protocol = next((p for p in self.protocols if p.name == name), None)
        if protocol is None:
            if not self.protocols:
                raise ValueError("No protocol to attach the credential.")
            protocol = self.protocols[0]
        return protocol.set_credential(request, credential, challenge)


def http_transport(protocols: Sequence[PaymentProtocol] | None = None) -> HttpTransport:
    """Creates the HTTP client transport (default protocols: MPP, x402 when available)."""
    return HttpTransport(protocols)
