"""Identity provers on the client: applies every in-scope prover to each HTTP attempt."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Sequence

import httpx

from mpp import AUTHORIZATION_HEADER, PAYMENT_AUTHORIZATION_HEADER, Challenge
from mpp.identity import (
    REQUEST_HEADERS,
    HeaderPairs,
    PrepareContext,
    ProveContext,
    Prover,
    RetryContext,
)
from mpp.identity import _requirements as requirements

Send = Callable[[httpx.Request], Awaitable[httpx.Response]]

_X402_HEADERS: frozenset[str] = frozenset(("payment-signature", "x-payment"))
"""x402 credential headers (v2 and v1), lowercased: a request carrying one is a paid attempt."""

CREDENTIAL_HEADERS = frozenset(
    (AUTHORIZATION_HEADER.lower(), PAYMENT_AUTHORIZATION_HEADER.lower(), *_X402_HEADERS)
)
"""Payment credential headers that a prover's retry headers never set, lowercased."""

_PAYMENT_SCHEME_RE = re.compile(r"(?:^|,)\s*payment\s+\S", re.IGNORECASE)


def holds_payment(value: str) -> bool:
    """Whether a header value carries a Payment credential."""
    return _PAYMENT_SCHEME_RE.search(value) is not None


def is_paid(request: httpx.Request) -> bool:
    """Whether a request carries a Payment or x402 credential, which may already have settled."""
    return any(name.lower() in _X402_HEADERS for name in request.headers) or any(
        holds_payment(value) for value in request.headers.values()
    )


class IdentityClient:
    """Sends HTTP attempts with every in-scope prover applied (mppx `Identity.Client`).

    Provers run in order on every attempt, sharing one :class:`~mpp.identity.ProveContext`; list
    request signers last so their signatures cover headers added by earlier provers. A rejected
    (non-402) response to an unpaid attempt may be resent once if a prover's ``retry`` asks; a
    paid attempt is never resent, since its payment may have settled.
    """

    def __init__(self, provers: Sequence[Prover]) -> None:
        if not provers:
            raise ValueError("client identity needs at least one prover")
        if any(not isinstance(prover, Prover) for prover in provers):
            raise TypeError("client identity accepts only identity.Prover values")
        self.provers = tuple(provers)
        self.sensitive_headers = frozenset(
            (*REQUEST_HEADERS, *(name for prover in self.provers for name in prover.headers))
        )
        """Headers the client never sends across origins on a redirect, lowercased."""

    def in_scope(self, url: httpx.URL) -> tuple[Prover, ...]:
        """The provers that run for a request to ``url``."""
        return tuple(prover for prover in self.provers if prover.covers(url))

    def strip_sensitive(self, request: httpx.Request) -> None:
        """Remove sensitive identity headers from a cross-origin redirect's request."""
        for name in list(request.headers):
            if name.lower() in self.sensitive_headers:
                del request.headers[name]

    async def send(
        self,
        send: Send,
        request: httpx.Request,
        *,
        challenge: Challenge | None = None,
        carried: HeaderPairs = (),
        replayable: bool = True,
    ) -> tuple[httpx.Response, HeaderPairs]:
        """Prove and send one request, resending an unpaid rejection once if a prover asks.

        Returns the response and the retry headers the last attempt carried, to pass on to the
        paid attempt. The caller's request is never changed: provers work on a copy.
        """
        paid = challenge is not None or is_paid(request)
        retriers = () if paid else tuple(p for p in self.in_scope(request.url) if p.retry)
        sent, response = await self._send_once(send, request, challenge, carried)
        if (
            not retriers
            or not replayable
            or response.status_code < 400
            or response.status_code == 402
        ):
            return response, carried
        resend = await _resend_headers(retriers, response, sent)
        if resend is None:
            return response, carried
        await response.aclose()
        headers = _merge(carried, resend)
        _, response = await self._send_once(send, request, challenge, headers)
        return response, headers

    async def prepare(self, response: httpx.Response, challenge: Challenge, url: httpx.URL) -> None:
        """Let provers in scope of ``url`` prepare proofs for its 402 before the paid retry."""
        context = PrepareContext(
            challenge=challenge,
            requirements=requirements.parse(response.headers.get(requirements.HEADER)),
        )
        for prover in self.in_scope(url):
            if prover.prepare is not None:
                await prover.prepare(response, context)

    async def _send_once(
        self,
        send: Send,
        request: httpx.Request,
        challenge: Challenge | None,
        carried: HeaderPairs,
    ) -> tuple[httpx.Request, httpx.Response]:
        scoped = self.in_scope(request.url)
        if not scoped:
            return request, await send(request)
        # Retry headers never replace a payment credential: the fixed credential headers, the
        # one the Challenge names, or any header already holding a Payment credential.
        protected = set(CREDENTIAL_HEADERS)
        if challenge is not None:
            protected.add(challenge.credential_header.lower())
        protected.update(
            name.lower() for name, value in request.headers.items() if holds_payment(value)
        )
        headers = httpx.Headers(request.headers)
        for name, value in carried:
            if name.lower() not in protected:
                headers[name] = value
        proved = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            stream=request.stream,
            extensions=dict(request.extensions),
        )
        context = ProveContext.new(challenge)
        for prover in scoped:
            proved = await prover.prove(proved, context)
            if not isinstance(proved, httpx.Request):
                raise TypeError("Prover.prove must return an httpx.Request")
        return proved, await send(proved)


async def _resend_headers(
    provers: Sequence[Prover], response: httpx.Response, request: httpx.Request
) -> HeaderPairs | None:
    """Ask each prover whether to resend a rejected response.

    Same-named headers from several provers are combined, comma-separated, in prover order;
    payment credential headers are dropped. None when no prover asks to resend.
    """
    context = RetryContext(request=request)
    resend = False
    combined: dict[str, tuple[str, list[str]]] = {}
    for prover in provers:
        assert prover.retry is not None
        decision = await prover.retry(response, context)
        if decision is None:
            continue
        resend = True
        for name, value in decision.items():
            if name.lower() in CREDENTIAL_HEADERS:
                continue
            combined.setdefault(name.lower(), (name, []))[1].append(value)
    if not resend:
        return None
    return tuple((name, ", ".join(values)) for name, values in combined.values())


def _merge(previous: HeaderPairs, next: HeaderPairs) -> HeaderPairs:
    """Merge retry headers; ``next`` replaces same-named headers of ``previous``."""
    merged = {name.lower(): (name, value) for name, value in previous}
    merged.update({name.lower(): (name, value) for name, value in next})
    return tuple(merged.values())


__all__ = ["CREDENTIAL_HEADERS", "IdentityClient", "is_paid"]
