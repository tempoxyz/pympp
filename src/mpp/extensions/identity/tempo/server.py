"""Tempo ID on the server: a verifier and a payment check for one API (mppx `TempoId.Server`)."""

from __future__ import annotations

import inspect
import math
import re
import time
import weakref
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

import httpx

from mpp._did import parse_pkh_source
from mpp.extensions.identity.tempo import (
    CLOCK_TOLERANCE,
    DEFAULT_CHAIN_ID,
    ID_TOKEN_HEADER,
    ISSUER,
    PROOF_MAX_AGE,
    TYPE,
    Caller,
    ComplianceState,
    Payer,
)
from mpp.extensions.identity.tempo import _jwt as jwt
from mpp.identity import (
    PaymentCheck,
    PaymentCheckInput,
    Rejected,
    Requirement,
    Valid,
    Verification,
    Verifier,
    _origin,  # pyright: ignore[reportPrivateUsage]
    forbidden,
    invalid,
    missing,
    unavailable,
)

if TYPE_CHECKING:
    from mpp.server.http import Request
    from mpp.store import ExpiringStore

Allow = Callable[[Caller], bool | Awaitable[bool]]
"""Decides whether a verified user may call the API; on the paid retry it gets a :class:`Payer`."""

CHALLENGE = (("WWW-Authenticate", 'DPoP algs="ES256", Bearer'),)
KEYS_UNAVAILABLE = unavailable("Tempo ID's signing keys are unavailable.")

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


@dataclass(frozen=True, slots=True)
class TempoId:
    """A Tempo ID verifier from :func:`create`.

    - ``verifier``: requires a Tempo ID access token from an allowed app, before any 402.
    - ``payment_check``: also requires that the payer is one of the token's accounts.
    """

    verifier: Verifier[Caller]
    payment_check: PaymentCheck[Payer]


def create(
    *,
    client_id: str | Sequence[str] | None = None,
    store: ExpiringStore | None = None,
    chain_id: int = DEFAULT_CHAIN_ID,
    audience: str | None = None,
    issuer: str = ISSUER,
    allow: Allow | None = None,
    http: httpx.AsyncClient | None = None,
) -> TempoId:
    """Create a Tempo ID verifier and payment check for one API.

    Tokens verify offline against Tempo ID's keys. A DPoP-bound token also needs a proof of
    its key for the request, which ``store`` accepts once (without one, a proof can be replayed
    for five minutes). The token uses ``Authorization``, so create the server with
    ``requires_auth=True``.

    The payment check requires a ``tempo`` charge whose ``source`` is an account the token
    grants to the app on ``chain_id``, so one user's token cannot pay with another user's
    wallet, and refuses an account Tempo ID screened as anything but ``clear``. After
    settlement the account that paid must be that source.

    Args:
        client_id: The app or apps whose tokens the API accepts; None (the default) accepts
            any app's, and ``allow`` can still decide by ``Caller.client_id``.
        store: Accepts each DPoP proof once.
        chain_id: The chain payments settle on.
        audience: The audience tokens must name; defaults to the issuer's origin.
        issuer: Tempo ID's origin.
        allow: Decides by the user's ID, app, accounts, compliance states and email, and on
            the paid retry the paying account (a :class:`Payer`).
        http: Client used to fetch Tempo ID's keys.

    Example::

        tempo_id = create(
            client_id="app_...",
            store=store,
            allow=lambda user: user.email_verified is True
            and (user.email or "").endswith("@example.com"),
        )
        mpp.charge(amount="0.01", identity=identity.Route(payment=tempo_id.payment_check))
    """
    client_ids: frozenset[str] | None = None
    if client_id is not None:
        client_ids = frozenset((client_id,) if isinstance(client_id, str) else client_id)
        if not client_ids:
            raise ValueError("client_id must name at least one app")
    origin = _origin(issuer)
    rules = _Rules(
        issuer=origin,
        audience=audience or origin,
        client_ids=client_ids,
        chain_id=chain_id,
        store=store,
        keys=jwt.KeySet(origin, http),
    )
    # One verification per request, so a DPoP proof is spent once across both checks.
    verified = _PerRequest()

    async def caller(request: Request) -> Verification[Caller]:
        outcome = verified.get(request)
        if outcome is None:
            outcome = await rules.verify(request)
            verified.put(request, outcome)
        return outcome

    async def allowed(outcome: Verification[Any]) -> Verification[Any]:
        if isinstance(outcome, Rejected) or allow is None:
            return outcome
        decision = allow(outcome.value)
        if inspect.isawaitable(decision):
            decision = await decision
        return outcome if decision else forbidden("This user may not call this API.")

    async def verify_request(request: Request) -> Verification[Caller]:
        return await allowed(await caller(request))

    async def verify_payment(input: PaymentCheckInput) -> Verification[Payer]:
        outcome = await caller(input.request)
        if isinstance(outcome, Rejected):
            return outcome
        return await allowed(rules.payer(outcome.value, input))

    return TempoId(
        verifier=Verifier(verify=verify_request, authorization=True),
        payment_check=PaymentCheck(
            requires=(Requirement(type=TYPE, issuer=origin),),
            verify=verify_payment,
            authorization=True,
            payer=lambda payer: payer.account,
        ),
    )


class _PerRequest:
    """Verification outcomes keyed by request object, dropped with the request."""

    def __init__(self) -> None:
        self._outcomes: dict[int, tuple[weakref.ref[Request], Verification[Caller]]] = {}

    def get(self, request: Request) -> Verification[Caller] | None:
        entry = self._outcomes.get(id(request))
        return entry[1] if entry is not None and entry[0]() is request else None

    def put(self, request: Request, outcome: Verification[Caller]) -> None:
        key = id(request)
        reference = weakref.ref(request, lambda _: self._outcomes.pop(key, None))
        self._outcomes[key] = (reference, outcome)


@dataclass(frozen=True, slots=True)
class _Rules:
    """How one API verifies Tempo ID tokens."""

    issuer: str
    audience: str
    client_ids: frozenset[str] | None
    chain_id: int
    store: ExpiringStore | None
    keys: jwt.KeySet

    async def verify(self, request: Request) -> Verification[Caller]:
        # RFC 9110: one or more spaces separate the scheme and the token.
        match = _AUTHORIZATION_RE.fullmatch(request.headers.get("Authorization") or "")
        scheme, token = match.groups() if match else ("", "")
        dpop = scheme.lower() == "dpop"
        if not token or (not dpop and scheme.lower() != "bearer"):
            return missing("Sign in with Tempo ID.", CHALLENGE)

        access = jwt.decode(token)
        if access is None or access.header.get("typ") != "at+jwt":
            return _invalid("The token is not a Tempo ID access token.")
        signed = await self._signed(access)
        if signed is None:
            return KEYS_UNAVAILABLE
        if not signed:
            return _invalid("The access token signature is invalid.")

        claims = access.claims
        now = int(time.time())
        audiences = _list(claims.get("aud"))
        sub = claims.get("sub")
        if claims.get("iss") != self.issuer or not isinstance(sub, str):
            return _invalid("The access token is not from Tempo ID.")
        # A token that also names another API is that API's too: only ours (and userinfo) pass.
        userinfo = f"{self.issuer}/oauth2/userinfo"
        if self.audience not in audiences or any(
            entry not in (self.audience, userinfo) for entry in audiences
        ):
            return _invalid("The access token is for another API.")
        if not _expires_after(claims.get("exp"), now):
            return _invalid("The access token has expired.")
        if not _valid_yet(claims.get("nbf"), now):
            return _invalid("The access token is not valid yet.")
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or (
            self.client_ids is not None and client_id not in self.client_ids
        ):
            return forbidden("This app may not call this API.")

        # RFC 9449: a DPoP-bound token needs a proof from its key; a Bearer token takes none.
        jkt: object = _dict(claims.get("cnf")).get("jkt")
        if dpop != (jkt is not None):
            return _invalid("The access token scheme does not match its binding.")
        if dpop:
            reason = await self._check_proof(request, jkt=str(jkt), now=now, token=token)
            if isinstance(reason, Rejected):
                return reason
            if reason is not None:
                return _invalid(reason)

        id_token = await self._id_token(request, client_id=client_id, now=now, sub=sub)
        if isinstance(id_token, Rejected):
            return id_token
        email, email_verified = id_token
        return Valid(
            Caller(
                user_id=sub,
                client_id=client_id,
                accounts=self._accounts(claims),
                compliance=MappingProxyType(
                    {
                        _checksum(address): cast("ComplianceState", state)
                        for address, state in _dict(claims.get("compliance")).items()
                        if _ADDRESS_RE.fullmatch(address)
                    }
                ),
                email=email,
                email_verified=email_verified,
            )
        )

    def payer(self, caller: Caller, input: PaymentCheckInput) -> Verification[Payer]:
        """Check that the paid retry's Credential pays from one of the caller's accounts."""
        # Only a tempo charge reports the account that paid, which the engine compares with
        # the source after settlement; a session's source can be a signer for another payer.
        if (input.challenge.method, input.challenge.intent) != ("tempo", "charge"):
            return forbidden("Pay with a tempo charge.")
        source = parse_pkh_source(input.credential.source or "")
        if source is None or source.chain_id != self.chain_id:
            return invalid(f"The payment must name its source account on chain {self.chain_id}.")
        account = _checksum(source.address)
        if account not in caller.accounts:
            return forbidden("The paying account is not one this user granted to the app.")
        state = caller.compliance.get(account)
        # Tempo ID screens the accounts in a registered app's realms; only a clear one pays.
        if state is not None and state != "clear":
            return forbidden("The paying account is not cleared to pay.")
        return Valid(Payer(**_fields(caller), account=account))

    def _accounts(self, claims: Any) -> tuple[str, ...]:
        keys: list[object] = [
            _dict(entry).get("account")
            for entry in _list(claims.get("access_keys"))
            if _dict(entry).get("chain_id") == self.chain_id
        ]
        candidates: list[object] = [*keys, *_list(claims.get("tempo_accounts"))]
        accounts = [
            _checksum(a) for a in candidates if isinstance(a, str) and _ADDRESS_RE.fullmatch(a)
        ]
        return tuple(dict.fromkeys(accounts))

    async def _signed(self, jws: jwt.Decoded) -> bool | None:
        """Whether Tempo ID's RS256 keys signed a JWS; None when the keys are unavailable."""
        if jws.header.get("alg") != "RS256":
            return False
        try:
            key = await self.keys.get(str(jws.header.get("kid")))
        except Exception:
            return None
        return key is not None and jwt.verify_rs256(key, jws)

    async def _id_token(
        self, request: Request, *, client_id: str, now: int, sub: str
    ) -> tuple[str | None, bool | None] | Rejected:
        """The email of the request's ID token, issued to the same app for the same user."""
        value = request.headers.get(ID_TOKEN_HEADER)
        if not value:
            return (None, None)
        token = jwt.decode(value)
        if token is None:
            return _invalid("The ID token is malformed.")
        signed = await self._signed(token)
        if signed is None:
            return KEYS_UNAVAILABLE
        if not signed:
            return _invalid("The ID token signature is invalid.")
        claims = token.claims
        if (
            claims.get("iss") != self.issuer
            or client_id not in _list(claims.get("aud"))
            or claims.get("sub") != sub
        ):
            return _invalid("The ID token is for another user or app.")
        # An expired ID token names no email, so allow decides without it.
        email = claims.get("email")
        if not _expires_after(claims.get("exp"), now) or not isinstance(email, str):
            return (None, None)
        return (email.lower(), claims.get("email_verified") is True)

    async def _check_proof(
        self, request: Request, *, jkt: str, now: int, token: str
    ) -> str | Rejected | None:
        """Why a request's DPoP proof fails, or None; a rejection when the replay store fails."""
        proof = jwt.decode(request.headers.get("DPoP") or "")
        if (
            proof is None
            or proof.header.get("alg") != "ES256"
            or proof.header.get("typ") != "dpop+jwt"
        ):
            return "The DPoP proof is malformed."
        jwk = proof.header.get("jwk")
        if (
            not isinstance(jwk, dict)
            or "d" in jwk
            or jwt.thumbprint(cast("dict[str, Any]", jwk)) != jkt
        ):
            return "The DPoP proof key does not bind the token."
        key = jwt.es256_public_key(cast("dict[str, Any]", jwk))
        if key is None or not jwt.verify_es256(key, proof):
            return "The DPoP proof signature is invalid."

        claims = proof.claims
        try:
            target = jwt.htu(request.url)
        except (ValueError, httpx.InvalidURL):
            # A request URL with no ASCII form can match no proof.
            return "The DPoP proof is for another request."
        if claims.get("htm") != request.method or claims.get("htu") != target:
            return "The DPoP proof is for another request."
        if claims.get("ath") != jwt.sha256(token):
            return "The DPoP proof is for another token."
        iat: object = claims.get("iat")
        if not _is_number(iat) or cast("float", iat) > now + CLOCK_TOLERANCE:
            return "The DPoP proof has expired."
        expires = float(cast("float", iat)) + PROOF_MAX_AGE + CLOCK_TOLERANCE
        if expires < now:
            return "The DPoP proof has expired."
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return "The DPoP proof has no ID."
        if self.store is not None:
            try:
                key_id = f"mppx:tempo-id:dpop:{jwt.sha256(f'{jkt}:{jti}')}"
            except UnicodeEncodeError:
                # A lone surrogate decodes from JSON but has no UTF-8 form to hash.
                return "The DPoP proof is malformed."
            # `now` is whole seconds, so the proof is accepted until the second after
            # `expires` begins: the replay claim must last at least that long.
            until = math.floor(expires) + 1
            try:
                fresh = await self.store.put_if_absent_until(key_id, "1", until)
            except Exception:
                # A replay store that fails rejects, so a proof cannot be spent twice.
                return unavailable("The DPoP replay store is unavailable.")
            if not fresh:
                return "The DPoP proof was already used."
        return None


_AUTHORIZATION_RE = re.compile(r"(\S+) +(\S+) *")


def _invalid(reason: str) -> Rejected:
    return invalid(reason, CHALLENGE)


def _is_number(value: object) -> bool:
    """Whether a claim is a finite JSON number (not a bool, NaN, an infinity or too large)."""
    if not isinstance(value, int | float) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _expires_after(exp: object, now: int) -> bool:
    return _is_number(exp) and cast("float", exp) + CLOCK_TOLERANCE > now


def _valid_yet(nbf: object, now: int) -> bool:
    """Whether an optional ``nbf`` claim has passed, allowing for clock skew."""
    return nbf is None or (_is_number(nbf) and cast("float", nbf) - CLOCK_TOLERANCE <= now)


def _list(value: object) -> list[Any]:
    if isinstance(value, list):
        return cast("list[Any]", value)
    return [] if value is None else [value]


def _dict(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _fields(caller: Caller) -> dict[str, Any]:
    return {name: getattr(caller, name) for name in Caller.__dataclass_fields__}


def _checksum(address: str) -> str:
    """EIP-55 checksum of a hex address."""
    from eth_hash.auto import keccak

    lower = address[2:].lower()
    digest = keccak(lower.encode()).hex()
    return "0x" + "".join(
        char.upper() if int(digest[index], 16) >= 8 else char for index, char in enumerate(lower)
    )


__all__ = ["CHALLENGE", "Allow", "TempoId", "create"]
