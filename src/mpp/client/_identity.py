"""Identity provers on the client: applies every in-scope prover to each HTTP attempt."""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

import anyio
import httpx

from mpp import AUTHORIZATION_HEADER, PAYMENT_AUTHORIZATION_HEADER, Challenge, ChallengeEcho
from mpp._parsing import parse_authorization
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

_SETTLEMENT_HEADERS = ("payment-receipt", "payment-response", "x-payment-response")
"""Response headers that report a settled payment (MPP receipt, x402 settlement response)."""

_MAX_FALLBACK_BYTES = 64 * 1024
"""Largest part of a rejected paid response's body kept to return when it is not resent."""

_FALLBACK_TIMEOUT = 2.0
"""Longest wait, in seconds, for a rejected paid response's body."""


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
    (non-402) response to an unpaid attempt may be resent once if a prover's ``retry`` asks. A
    paid attempt is resent only after a 401 with no receipt, with the same Payment credential and
    while its Challenge has not expired: servers check other authentication before verifying a
    Payment credential, so a 401 means nothing settled.
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
        """Prove and send one request, resending a rejection once if a prover asks.

        An unpaid attempt may be resent after any non-402 rejection. A paid attempt is resent,
        with the same Payment credential, only after a 401 that carries no receipt and while
        the Challenge its credential answers has not expired; if a retry hook or re-proving
        fails, or the Challenge expires first, that 401 is returned without resending.

        Returns the response and the retry headers the last attempt carried, to pass on to the
        paid attempt. The caller's request is never changed: provers work on a copy.
        """
        paid = challenge is not None or is_paid(request)
        retriers = tuple(p for p in self.in_scope(request.url) if p.retry)
        # A paid attempt may be resent only with the Payment credential for its Challenge.
        expires = _resendable_expiry(request, challenge) if paid and retriers else None
        if paid and (expires is None or not _unexpired(expires)):
            retriers = ()
        sent, response = await self._send_once(send, request, challenge, carried)
        if not retriers or not replayable or not _can_resend(paid, response, expires):
            return response, carried
        if paid:
            # A paid attempt's 401 is copied, within a size and time bound, and released before
            # the retry hooks run, so a hook refreshing identity through the same connection
            # pool never waits on it. The copy is returned if the attempt is not resent.
            response = await _detach(response)
        try:
            resend = await _resend_headers(retriers, response, sent)
        except Exception:
            # The server's 401 to a paid attempt was received and nothing was resent, so a
            # failing retry hook returns that 401 rather than leaving the payment's outcome
            # unknown.
            if paid:
                return response, carried
            await response.aclose()
            raise
        except BaseException:
            await response.aclose()
            raise
        if resend is None:
            return response, carried
        if not paid:
            await response.aclose()
        headers = _merge(carried, resend)

        def proceed() -> bool:
            # The Challenge may expire while provers refresh identity: a paid attempt is
            # checked again right before the resend.
            return expires is None or _unexpired(expires)

        try:
            proved = await self._prove(request, challenge, headers, proceed=proceed)
        except Exception:
            # A prover failing before the paid resend was sent: the 401 stands.
            if paid:
                return response, carried
            raise
        if proved is None:
            return response, carried
        # Sent outside the guard above: once the paid resend went out, a transport failure
        # leaves the payment's outcome unknown and propagates to the caller.
        return await send(proved), headers

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
        """Prove and send one attempt, returning the request as sent and its response."""
        proved = await self._prove(request, challenge, carried)
        assert proved is not None
        return proved, await send(proved)

    async def _prove(
        self,
        request: httpx.Request,
        challenge: Challenge | None,
        carried: HeaderPairs,
        *,
        proceed: Callable[[], bool] | None = None,
    ) -> httpx.Request | None:
        """Apply every in-scope prover to a copy of the request.

        ``proceed`` runs after the provers; False means the attempt is not sent (None).
        """
        scoped = self.in_scope(request.url)
        if not scoped:
            if proceed is not None and not proceed():
                return None
            return request
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
        # A payment credential the request carries survives every prover: a prover that writes
        # the same header (such as Authorization) never replaces it.
        credentials = [
            (name, value)
            for name, value in request.headers.multi_items()
            if holds_payment(value)
            or name.lower() in _X402_HEADERS
            or (challenge is not None and name.lower() == challenge.credential_header.lower())
        ]
        context = ProveContext.new(challenge)
        for prover in scoped:
            proved = await prover.prove(proved, context)
            if not isinstance(proved, httpx.Request):
                raise TypeError("Prover.prove must return an httpx.Request")
        for name, value in credentials:
            proved.headers[name] = value
        if proceed is not None and not proceed():
            return None
        return proved


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


def _can_resend(paid: bool, response: httpx.Response, expires: datetime | None) -> bool:
    """Whether a rejected response may be resent.

    An unpaid attempt after any non-402 rejection. A paid attempt only after a 401, which never
    follows settlement, that carries no receipt or other settlement header, while its Challenge
    has not expired. A 403 can follow a settled payment, so a paid one is never resent.
    """
    if not paid:
        return response.status_code >= 400 and response.status_code != 402
    if response.status_code != 401 or expires is None:
        return False
    if any(name in response.headers for name in _SETTLEMENT_HEADERS):
        return False
    return _unexpired(expires)


def _unexpired(expires: datetime) -> bool:
    """Whether ``expires`` is still in the future."""
    return expires.timestamp() > time.time()


def _parse_expires(expires: str | None) -> datetime | None:
    if not expires:
        return None
    try:
        return datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        return None


def _resendable_expiry(request: httpx.Request, challenge: Challenge | None) -> datetime | None:
    """The expiry of the Challenge a paid attempt may be resent for, if any.

    That is ``challenge`` (or, without one, the Challenge of the request's Payment credential),
    when a header holds a Payment credential for it. A request carrying an x402 credential
    header is never resent, nor one whose Payment credential answers another Challenge, nor
    one whose Challenge has no ``expires``.
    """
    if any(name.lower() in _X402_HEADERS for name in request.headers):
        return None
    echoes: list[ChallengeEcho] = []
    for value in request.headers.values():
        for part in value.split(","):
            if not part.strip().lower().startswith("payment "):
                continue
            try:
                echoes.append(parse_authorization(part).challenge)
            except Exception:  # noqa: BLE001 - an unreadable credential is never resent
                continue
    if challenge is not None:
        if any(echo.id == challenge.id for echo in echoes):
            return _parse_expires(challenge.expires)
        return None
    return _parse_expires(echoes[0].expires) if echoes else None


async def _detach(response: httpx.Response) -> httpx.Response:
    """Read a rejected response into a copy within a size and time bound, then release it.

    A body larger than 64 KiB, or still arriving after 2 seconds, is cut off to what arrived,
    marked with an ``Mppx-Body-Truncated: true`` header.
    """
    chunks: list[bytes] = []
    received = 0
    truncated = True
    decoded = False
    try:
        if response.is_stream_consumed:
            # The body was already read and decoded: the copy holds the decoded bytes.
            decoded = True
            chunks.append(response.content)
            received = len(response.content)
            truncated = received > _MAX_FALLBACK_BYTES
        else:
            with anyio.move_on_after(_FALLBACK_TIMEOUT):
                async for chunk in response.aiter_raw():
                    chunks.append(chunk)
                    received += len(chunk)
                    if received > _MAX_FALLBACK_BYTES:
                        break
                else:
                    truncated = False
    except Exception:  # noqa: BLE001 - a failed read keeps what arrived
        truncated = True
    finally:
        await response.aclose()
    headers = httpx.Headers(response.headers)
    if decoded:
        # The decoded body no longer matches the encoding or length the server sent.
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
    if truncated:
        headers.pop("content-length", None)
        headers["Mppx-Body-Truncated"] = "true"
    copy = httpx.Response(
        response.status_code,
        headers=headers,
        stream=httpx.ByteStream(b"".join(chunks)[:_MAX_FALLBACK_BYTES]),
        extensions=dict(response.extensions),
    )
    try:
        copy.request = response.request
    except RuntimeError:  # the transport sets no request
        pass
    return copy


def _merge(previous: HeaderPairs, next: HeaderPairs) -> HeaderPairs:
    """Merge retry headers; ``next`` replaces same-named headers of ``previous``."""
    merged = {name.lower(): (name, value) for name, value in previous}
    merged.update({name.lower(): (name, value) for name, value in next})
    return tuple(merged.values())


__all__ = ["CREDENTIAL_HEADERS", "IdentityClient", "is_paid"]
