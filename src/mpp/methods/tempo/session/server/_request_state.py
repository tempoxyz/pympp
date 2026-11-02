"""Session request resolution and the response gate (mppx ``server/RequestState.ts``).

Resolves the TIP-1034 method details a ``tempo/session`` challenge advertises, reads the
payment fields and verification context back from an authenticated challenge, and decides
whether a verified credential serves content or gets a management response.
Also resolves the reusable channel a challenge or bootstrap response advertises as a
session snapshot.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx

from mpp._typing import is_dict
from mpp._units import parse_units
from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    SESSION_PROTOCOL_V2,
    is_session_credential_action,
)

if TYPE_CHECKING:
    from mpp import Challenge, Credential
    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.session._snapshot import SessionSnapshot
    from mpp.server.http import Request, Response

__all__ = [
    "ChallengePaymentFields",
    "CredentialVerificationContext",
    "RequestProbe",
    "ResolveSessionChannelId",
    "ResolveSessionChannelIdParameters",
    "SessionMethodDetails",
    "SnapshotPaymentFields",
    "capture_request_probe",
    "get_challenge_payment_fields",
    "has_captured_request_body",
    "is_session_content_request",
    "normalize_session_channel_id",
    "resolve_credential_fee_payer",
    "resolve_credential_verification_context",
    "resolve_request_fee_payer",
    "resolve_session_channel_id",
    "resolve_session_payment_request",
    "resolve_session_snapshot",
    "respond_to_session_credential",
]


# --------------------------------------------------------------------------------------------
# Request classification (mppx tempo/server/internal/request-body.ts)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestProbe:
    """The request fields the session content/management classifier reads."""

    method: str
    headers: httpx.Headers
    has_body: bool | None = None
    url: str | None = None


def capture_request_probe(request: Request) -> RequestProbe:
    """Capture the classifier's fields from an engine request."""
    return RequestProbe(
        method=request.method.upper(),
        headers=request.headers,
        has_body=request.body is not None,
        url=request.url,
    )


def _has_body_framing_headers(headers: httpx.Headers) -> bool:
    content_length = headers.get("content-length")
    return (content_length is not None and content_length != "0") or (
        "transfer-encoding" in headers
    )


def has_captured_request_body(probe: RequestProbe) -> bool:
    """Whether request metadata indicates a meaningful body is present."""
    headers = probe.headers
    if headers.get("content-length") == "0" and "transfer-encoding" not in headers:
        return False
    if _has_body_framing_headers(headers):
        return True
    return probe.has_body is True


def _has_query(url: str | None) -> bool:
    if not url:
        return False
    try:
        return bool(httpx.URL(url).query)
    except Exception:
        return "?" in url and not url.endswith("?")


def is_session_content_request(probe: RequestProbe) -> bool:
    """Whether a verified session credential lets the route serve (billable) content.

    ``HEAD`` never does; other non-``POST`` methods always do; a ``POST`` does when it has a
    query string or a body. A bare ``POST`` is a management request (top-up, close).
    """
    if probe.method == "HEAD":
        return False
    if probe.method != "POST":
        return True
    if _has_query(probe.url):
        return True
    return has_captured_request_body(probe)


def respond_to_session_credential(
    *, payload_action: str, request: Request | RequestProbe | None
) -> Response | None:
    """The management response for a verified credential, or None to serve content.

    ``close`` and ``topUp`` always get ``204``; ``open`` and ``voucher`` get ``204`` unless the
    request is a content request.
    """
    from mpp.server.http import Request as EngineRequest
    from mpp.server.http import Response

    if not is_session_credential_action(payload_action):
        raise VerificationFailedError("invalid session credential action")
    if payload_action in ("close", "topUp"):
        return Response(status=204)
    if request is None:
        return None
    probe = capture_request_probe(request) if isinstance(request, EngineRequest) else request
    if is_session_content_request(probe):
        return None
    return Response(status=204)


# --------------------------------------------------------------------------------------------
# Fee payer resolution (mppx Settlement.ts resolveRequestFeePayer / resolveCredentialFeePayer)
# --------------------------------------------------------------------------------------------


FEE_PAYER_DISABLED = "_fee_payer_disabled"
"""Route-input key recording a route turning sponsorship off; the wire request ignores it."""


def resolve_request_fee_payer(
    *,
    default_fee_payer: TempoAccount | None,
    request_fee_payer: Any = None,
) -> TempoAccount | bool | None:
    """Whether a challenge advertises fee sponsorship (``methodDetails.feePayer``).

    A route's ``fee_payer=False`` turns sponsorship off; otherwise a configured fee payer
    advertises it. A route's own fee-payer account is returned as is, so verification co-signs
    with it (mppx ``resolveRequestFeePayer``); the wire request advertises it as ``true``.
    (mppx returns ``false`` for credential requests; it is omitted here so the wire request is
    the same with and without a credential.)
    """
    if request_fee_payer is False:
        return None
    if request_fee_payer is not None and request_fee_payer is not True:
        return cast("TempoAccount", request_fee_payer)
    if default_fee_payer is not None:
        return True
    return None


def resolve_credential_fee_payer(
    *,
    method_details: Mapping[str, Any],
    fee_payer: TempoAccount | None,
    request_fee_payer: Any = None,
) -> TempoAccount | None:
    """The fee payer allowed for a credential: only when its challenge advertised one.

    A route's fee-payer account (``request_fee_payer``) takes precedence over the method's.
    """
    if method_details.get("feePayer") is not True or request_fee_payer is False:
        return None
    if request_fee_payer is not None and request_fee_payer is not True:
        return cast("TempoAccount", request_fee_payer)
    return fee_payer


# --------------------------------------------------------------------------------------------
# Challenge requests
# --------------------------------------------------------------------------------------------


def normalize_session_channel_id(value: Any) -> str | None:
    """A lowercase channel ID when ``value`` is one, else None."""
    from mpp.methods.tempo.session.server._store import normalize_channel_id

    if not isinstance(value, str):
        return None
    try:
        return normalize_channel_id(value)
    except ValueError:
        return None


def is_address(value: Any) -> bool:
    """Whether ``value`` is a 0x-prefixed 20-byte hex address (any case)."""
    return (
        isinstance(value, str)
        and len(value) == 42
        and value[:2] in ("0x", "0X")
        and all(c in "0123456789abcdefABCDEF" for c in value[2:])
    )


def _read_challenge_address(value: Any, label: str) -> str:
    if is_address(value):
        return str(value)
    raise VerificationFailedError(f"missing challenge {label}")


@dataclass(frozen=True, slots=True)
class ChallengePaymentFields:
    """Destination, token and raw amount read from a session challenge request."""

    amount: int
    currency: str
    recipient: str


def get_challenge_payment_fields(challenge: Challenge) -> ChallengePaymentFields:
    """Read the destination, token and raw amount from a session challenge request."""
    request = challenge.request
    amount = request.get("amount")
    if not isinstance(amount, str) or not amount.isdigit():
        raise VerificationFailedError("missing challenge amount")
    return ChallengePaymentFields(
        amount=int(amount),
        currency=_read_challenge_address(request.get("currency"), "currency"),
        recipient=_read_challenge_address(request.get("recipient"), "recipient"),
    )


@dataclass(frozen=True, slots=True)
class SessionMethodDetails:
    """TIP-1034 details embedded in a ``tempo/session`` challenge request."""

    chain_id: int
    escrow_contract: str
    fee_payer: bool | None = None
    fee_token: str | None = None
    min_voucher_delta: str | None = None
    operator: str | None = None
    session_protocol: str | None = None


def read_method_details(request: Mapping[str, Any]) -> SessionMethodDetails:
    """Read and check the canonical TIP-1034 method details of a session request."""
    details: Any = request.get("methodDetails")
    if not is_dict(details):
        raise VerificationFailedError("invalid session request")
    chain_id = details.get("chainId")
    escrow = details.get("escrowContract")
    fee_payer = details.get("feePayer")
    fee_token = details.get("feeToken")
    min_voucher_delta = details.get("minVoucherDelta")
    operator = details.get("operator")
    protocol = details.get("sessionProtocol")
    if (
        not isinstance(chain_id, int)
        or isinstance(chain_id, bool)
        or not is_address(escrow)
        or (fee_payer is not None and not isinstance(fee_payer, bool))
        or (fee_token is not None and not is_address(fee_token))
        or (min_voucher_delta is not None and not isinstance(min_voucher_delta, str))
        or (operator is not None and not is_address(operator))
        or (protocol is not None and protocol != SESSION_PROTOCOL_V2)
        or not isinstance(request.get("amount"), str)
        or not isinstance(request.get("currency"), str)
        or not isinstance(request.get("unitType"), str)
    ):
        raise VerificationFailedError("invalid session request")
    return SessionMethodDetails(
        chain_id=chain_id,
        escrow_contract=str(escrow),
        fee_payer=fee_payer if isinstance(fee_payer, bool) else None,
        fee_token=str(fee_token) if fee_token is not None else None,
        min_voucher_delta=str(min_voucher_delta) if min_voucher_delta is not None else None,
        operator=str(operator) if operator is not None else None,
        session_protocol=str(protocol) if protocol is not None else None,
    )


@dataclass(frozen=True, slots=True)
class CredentialVerificationContext:
    """Verification context derived from the HMAC-bound challenge request."""

    request: Mapping[str, Any]
    method_details: SessionMethodDetails
    chain_id: int
    escrow: str
    fee_payer: TempoAccount | None
    min_voucher_delta: int


def resolve_credential_verification_context(
    *,
    challenge: Challenge,
    decimals: int,
    fee_payer: TempoAccount | None,
    min_voucher_delta: str | None,
    request_fee_payer: Any = None,
) -> CredentialVerificationContext:
    """Resolve every non-payload verification input from a session challenge.

    ``request_fee_payer`` is the route's resolved ``fee_payer``: a route account sponsors in
    place of the method's ``fee_payer`` (mppx ``resolveCredentialFeePayer``).
    """
    request = challenge.request
    details = read_method_details(request)
    if details.min_voucher_delta is not None:
        if not details.min_voucher_delta.isdigit():
            raise VerificationFailedError("invalid session request")
        delta = int(details.min_voucher_delta)
    else:
        delta = parse_units(min_voucher_delta or "0", decimals)
    return CredentialVerificationContext(
        request=request,
        method_details=details,
        chain_id=details.chain_id,
        escrow=details.escrow_contract,
        fee_payer=resolve_credential_fee_payer(
            method_details={"feePayer": details.fee_payer},
            fee_payer=fee_payer,
            request_fee_payer=request_fee_payer,
        ),
        min_voucher_delta=delta,
    )


def _resolve_escrow(request_escrow: Any, parameter_escrow: str | None) -> str:
    if isinstance(request_escrow, str):
        if not is_address(request_escrow):
            raise ValueError("Invalid escrow_contract configured for tempo.session().")
        return request_escrow
    return parameter_escrow or ESCROW_ADDRESS


def _resolve_operator(request_operator: Any) -> str | None:
    if request_operator is None:
        return None
    if is_address(request_operator):
        return str(request_operator)
    raise ValueError("Invalid operator configured for tempo.session().")


def resolve_session_payment_request(
    *,
    request: Mapping[str, Any],
    chain_id: int,
    default_fee_payer: TempoAccount | None,
    parameter_escrow_contract: str | None,
    fee_token: str | None,
) -> dict[str, Any]:
    """Add the TIP-1034 method details a session challenge carries to the route input.

    ``chain_id``, ``escrow_contract`` (the canonical precompile by default), ``fee_payer``,
    ``fee_token`` and ``session_protocol="v2"``, as mppx's ``request`` hook does.
    """
    resolved = {key: value for key, value in request.items() if value is not None}
    route_chain_id = resolved.pop("chainId", None)
    resolved["chain_id"] = resolved.get("chain_id") or route_chain_id or chain_id
    resolved["escrow_contract"] = _resolve_escrow(
        resolved.pop("escrow_contract", resolved.pop("escrowContract", None)),
        parameter_escrow_contract,
    )
    operator = _resolve_operator(resolved.pop("operator", None))
    if operator is not None:
        resolved["operator"] = operator
    request_fee_payer = resolved.pop("fee_payer", resolved.pop("feePayer", None))
    fee_payer = resolve_request_fee_payer(
        default_fee_payer=default_fee_payer,
        request_fee_payer=request_fee_payer,
    )
    if fee_payer is not None:
        resolved["fee_payer"] = fee_payer
    elif request_fee_payer is False:
        # Kept out of the wire request, but verification must still refuse sponsorship for a
        # reusable challenge issued before the route turned it off (mppx passes feePayer false).
        resolved[FEE_PAYER_DISABLED] = True
    if fee_token is not None:
        resolved["fee_token"] = fee_token
    resolved["session_protocol"] = SESSION_PROTOCOL_V2
    return resolved


# --------------------------------------------------------------------------------------------
# Channel ID resolution and session snapshots (mppx RequestState.ts)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolveSessionChannelIdParameters:
    """Arguments for ``resolve_channel_id`` (mppx ``ResolveSessionChannelIdParameters``).

    Attributes:
        request: The HTTP request being challenged or bootstrapped, when known; read its
            headers (cookies, application auth) to identify the caller.
        credential: The submitted credential, set only for a verified bootstrap proof.
        source: The payer's ``did:pkh`` identity from a verified zero-amount bootstrap proof.
        payment_request: The session route input being challenged.
        store: The method's channel store.
    """

    request: Request | None
    credential: Credential | None
    source: str | None
    payment_request: Mapping[str, Any]
    store: Any


ResolveSessionChannelId = Callable[
    [ResolveSessionChannelIdParameters], "str | None | Awaitable[str | None]"
]
"""Application-owned lookup from authenticated identity and payment scope to a channel ID.

pympp does not derive a storage key or scan the store: the returned channel is loaded and
validated against the challenge's payment scope before its snapshot is advertised.
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class SnapshotPaymentFields:
    """The payment fields a reusable channel must match before it is advertised."""

    chain_id: int
    currency: str
    escrow_contract: str
    recipient: str


async def resolve_session_channel_id(
    *,
    request: Request | None,
    credential: Credential | None,
    payment_request: Mapping[str, Any],
    resolve_channel_id: ResolveSessionChannelId | None,
    store: Any,
    source: str | None = None,
) -> str | None:
    """The channel to snapshot: the route's ``channel_id``, else ``resolve_channel_id``'s."""
    from mpp.methods.tempo.session.server._store import normalize_channel_id

    explicit = normalize_session_channel_id(
        payment_request.get("channel_id", payment_request.get("channelId"))
    )
    if explicit is not None:
        return explicit
    if resolve_channel_id is None:
        return None
    resolved = resolve_channel_id(
        ResolveSessionChannelIdParameters(
            request=request,
            credential=credential if source else None,
            source=source,
            payment_request=payment_request,
            store=store,
        )
    )
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if resolved is None:
        return None
    return normalize_channel_id(resolved)


async def resolve_session_snapshot(
    *,
    amount: int,
    channel_id: str | None,
    store: Any,
    expected: SnapshotPaymentFields | None = None,
    minimum_voucher_advance: int = 0,
    require_voucher_advance: bool = False,
) -> SessionSnapshot | None:
    """The snapshot of a reusable channel, or None when it can't be advertised.

    A channel is advertised only when it is a stored, open precompile channel with a signed
    highest voucher matching its accepted amount, in the challenge's payment scope.
    ``required_cumulative`` covers the spend plus ``amount`` and, when the next voucher
    must advance, the accepted amount plus ``minimum_voucher_advance`` (at least 1).
    """
    from mpp.methods.tempo.session._snapshot import SessionSnapshot
    from mpp.methods.tempo.session.server._store import is_precompile_state, normalize_channel_id

    if channel_id is None:
        return None
    channel = await store.get_channel(normalize_channel_id(channel_id))
    if channel is None or not is_precompile_state(channel) or channel.descriptor is None:
        return None
    if channel.finalized or channel.close_requested_at != 0:
        return None
    voucher = channel.highest_voucher
    if voucher is None or voucher.cumulative_amount != channel.highest_voucher_amount:
        return None
    if expected is not None and not (
        channel.chain_id == expected.chain_id
        and channel.escrow_contract.lower() == expected.escrow_contract.lower()
        and channel.payee.lower() == expected.recipient.lower()
        and channel.token.lower() == expected.currency.lower()
    ):
        return None
    spend_boundary = channel.spent + amount
    advance_boundary = (
        channel.highest_voucher_amount + (minimum_voucher_advance or 1)
        if require_voucher_advance
        else 0
    )
    return SessionSnapshot(
        accepted_cumulative=channel.highest_voucher_amount,
        chain_id=channel.chain_id,
        channel_id=channel.channel_id,
        deposit=channel.deposit,
        descriptor=channel.descriptor,
        escrow=channel.escrow_contract,
        highest_voucher=voucher,
        required_cumulative=max(spend_boundary, advance_boundary),
        settled=channel.settled_on_chain,
        spent=channel.spent,
        units=channel.units,
    )
