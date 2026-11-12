"""Route identity on the server: runs a route's verifiers and payment check for one request."""

from __future__ import annotations

from typing import Any, Literal

from mpp.identity import (
    AnyOf,
    AnyOfValue,
    PaymentCheck,
    PaymentCheckInput,
    Rejected,
    Rejection,
    Results,
    Route,
    Valid,
    Verification,
    Verifier,
    _combine_any_of,
    _decide,
    invalid,
)
from mpp.server.http import Response

X402_REJECTED = invalid("This route's identity payment check does not accept x402 credentials.")


class IdentityRejectedError(Exception):
    """A route rejected the request's identity; ``response`` is sent as is, never a fresh 402.

    Raised from the paid retry's payment check, so it reaches ``payment.failed`` handlers.
    """

    def __init__(self, stage: Literal["request", "payment"], rejected: Rejected) -> None:
        super().__init__(rejected.reason)
        self.rejected = rejected
        self.rejection = Rejection(stage=stage, status=rejected.status, reason=rejected.reason)

    @property
    def response(self) -> Response:
        """The rejection response: the fixed status code, the reason and the headers."""
        headers = [
            (name, value)
            for name, value in self.rejected.headers
            if name.lower() not in ("cache-control", "content-type")
        ]
        headers += [("Cache-Control", "no-store"), ("Content-Type", "text/plain; charset=utf-8")]
        return Response(status=self.rejected.code, headers=headers, body=self.rejected.reason)


class IdentityContext:
    """The identity state of one request.

    Each verifier runs at most once, and each payment check once per Challenge, so replay
    nonces are spent once even when several offers of a composed route share a verifier.
    """

    def __init__(self, request: Any) -> None:
        self.request = request
        self._verifications: dict[Verifier[Any], Verification[Any]] = {}
        self._checks: dict[tuple[PaymentCheck[Any], str], Verification[Any]] = {}

    async def evaluate(self, verifier: Verifier[Any]) -> Verification[Any]:
        """Run one verifier (each ``any_of`` member through this context) at most once."""
        cached = self._verifications.get(verifier)
        if cached is not None:
            return cached
        if isinstance(verifier, AnyOf):
            outcome = _combine_any_of([await self.evaluate(member) for member in verifier.members])
        else:
            outcome = await verifier.verify(self.request)
            if not isinstance(outcome, Valid | Rejected):
                raise TypeError("identity verifier must return Valid or Rejected")
        self._verifications[verifier] = outcome
        return outcome

    async def verify(self, route: Route) -> Results | Rejected:
        """Run a route's verifiers: their values if all are valid, else the deciding rejection.

        Values are recorded at every ``any_of`` level, so a nested member finds its own.
        """
        values: dict[Verifier[Any] | PaymentCheck[Any], Any] = {}
        rejected: list[Rejected] = []
        for verifier in route.request:
            outcome = await self.evaluate(verifier)
            if isinstance(outcome, Rejected):
                rejected.append(outcome)
                continue
            current: Verifier[Any] = verifier
            value: Any = outcome.value
            while True:
                values[current] = value
                if not isinstance(current, AnyOf):
                    break
                matched: AnyOfValue = value
                current, value = current.members[matched.index], matched.value
        return _decide(rejected) if rejected else Results(values)

    async def check(self, check: PaymentCheck[Any], input: PaymentCheckInput) -> Verification[Any]:
        """Run a payment check at most once per Challenge."""
        key = (check, input.challenge.id)
        cached = self._checks.get(key)
        if cached is not None:
            return cached
        outcome = await check.verify(input)
        if not isinstance(outcome, Valid | Rejected):
            raise TypeError("identity payment check must return Valid or Rejected")
        self._checks[key] = outcome
        return outcome


__all__ = ["X402_REJECTED", "IdentityContext", "IdentityRejectedError"]
