"""Session bootstrap: same-route ``HEAD`` channel recovery (mppx ``server/Session.ts`` preflight).

With ``tempo.session(bootstrap=True)``, a ``HEAD`` request to a session route is answered before
the payment flow. Without a credential the server issues a zero-amount ``tempo/charge`` challenge;
the client answers it with a proof that authenticates its account (``did:pkh`` source), and the
server returns ``204`` with ``Payment-Session`` and ``Payment-Session-Snapshot`` headers naming the
caller's reusable channel, as ``resolve_channel_id`` resolves it. A client without local channel
state can then resume that channel instead of opening a new one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    InvalidChallengeError,
    InvalidPayloadError,
    PaymentError,
    PaymentExpiredError,
    VerificationFailedError,
)
from mpp.methods.tempo.session._proof import parse_pkh_source, verify_proof
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS
from mpp.methods.tempo.session._snapshot import (
    PAYMENT_SESSION_HEADER,
    PAYMENT_SESSION_SNAPSHOT_HEADER,
    serialize_snapshot,
)
from mpp.methods.tempo.session.server._request_state import (
    ResolveSessionChannelId,
    SnapshotPaymentFields,
    is_address,
    resolve_session_channel_id,
    resolve_session_snapshot,
)
from mpp.server.http import Response

if TYPE_CHECKING:
    from mpp import Challenge, ChallengeEcho, Credential
    from mpp.server.method import PreflightContext
    from mpp.store import Store

__all__ = ["handle_bootstrap_preflight"]

PROOF_CLAIM_PREFIX = "mppx:charge:proof:"
"""Store key prefix claiming a used proof's challenge ID, shared with mppx."""


def _respond_challenge(challenge: Challenge, error: PaymentError | None = None) -> Response:
    headers = {"Cache-Control": "no-store"}
    # A 403 is final: omit the challenge, as the HTTP transport does.
    if error is None or error.status != 403:
        headers["WWW-Authenticate"] = challenge.to_www_authenticate(challenge.realm)
    if error is None:
        return Response(status=402, headers=headers)
    headers["Content-Type"] = "application/problem+json"
    problem = error.to_problem_details(None if error.status == 403 else challenge.id)
    return Response(status=error.status, headers=headers, body=json.dumps(problem))


def _method_detail(request: Mapping[str, Any], key: str) -> Any:
    details: Any = request.get("methodDetails")
    return cast(Mapping[str, Any], details).get(key) if isinstance(details, Mapping) else None


def _assert_matches(
    expected: Mapping[str, Any], echo: ChallengeEcho, actual: Mapping[str, Any]
) -> None:
    """Like mppx, the echoed challenge must quote this route's zero-amount terms."""
    for field in ("amount", "currency", "recipient"):
        if expected.get(field) != actual.get(field):
            raise InvalidChallengeError(echo.id, f"bootstrap {field} mismatch")
    if _method_detail(expected, "chainId") != _method_detail(actual, "chainId"):
        raise InvalidChallengeError(echo.id, "bootstrap chain mismatch")


def _assert_not_expired(echo: ChallengeEcho) -> None:
    if not echo.expires:
        raise InvalidChallengeError(echo.id, "missing expires")
    try:
        expires = datetime.fromisoformat(echo.expires.replace("Z", "+00:00"))
    except ValueError as error:
        raise InvalidChallengeError(echo.id, "invalid expires") from error
    if expires.tzinfo is None:
        raise InvalidChallengeError(echo.id, "invalid expires")
    if expires <= datetime.now(UTC):
        raise PaymentExpiredError(echo.expires)


async def _claim_proof(store: Store, challenge_id: str, expires: str) -> bool:
    from mpp.store import ExpiringStore

    key = PROOF_CLAIM_PREFIX + challenge_id
    if isinstance(store, ExpiringStore):
        until = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        return await store.put_if_absent_until(key, True, until)
    return await store.put_if_absent(key, True)


async def _verify_proof_credential(
    credential: Credential, expected: Mapping[str, Any], *, secret_key: str, store: Store
) -> None:
    """Authenticate a zero-amount charge proof answering this route's bootstrap challenge."""
    from mpp.server.verify import (
        _authenticate_echo,  # pyright: ignore[reportPrivateUsage]
    )

    echo = credential.challenge
    actual, _ = _authenticate_echo(credential, secret_key=secret_key)
    _assert_not_expired(echo)
    _assert_matches(expected, echo, actual)
    payload = credential.payload
    signature = payload.get("signature") if isinstance(payload, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or payload.get("type") != "proof"
        or not isinstance(signature, str)
    ):
        raise InvalidPayloadError("zero-amount challenges require a proof credential")
    if not credential.source:
        raise VerificationFailedError("Proof credential must include a source")
    source = parse_pkh_source(credential.source)
    chain_id = _method_detail(actual, "chainId")
    if source is None or source[1] != chain_id:
        raise VerificationFailedError("Proof credential source is invalid")
    if not verify_proof(
        signature, account=source[0], chain_id=source[1], challenge_id=echo.id, realm=echo.realm
    ):
        raise VerificationFailedError("Proof signature does not match source")
    assert echo.expires is not None
    if not await _claim_proof(store, echo.id, echo.expires):
        raise CredentialReplayedError("Proof credential has already been used")


async def handle_bootstrap_preflight(
    context: PreflightContext,
    *,
    chain_id: int,
    escrow_contract: str | None,
    resolve_channel_id: ResolveSessionChannelId | None,
    store: Any,
    proof_store: Store,
) -> Response | None:
    """Answer a session route's ``HEAD`` bootstrap, or None to continue the payment flow.

    ``chain_id`` is the challenge chain when the route sets none; ``store`` is the channel store
    and ``proof_store`` records used proofs so each is accepted once.
    """
    from mpp.server.verify import _create_challenge  # pyright: ignore[reportPrivateUsage]

    if context.input.method != "HEAD":
        return None
    route = context.request
    route_chain_id = route.get("chain_id", route.get("chainId"))
    resolved_chain_id = route_chain_id if isinstance(route_chain_id, int) else chain_id
    currency = route.get("currency")
    recipient = route.get("recipient")
    request: dict[str, Any] = {"amount": "0", "currency": currency}
    if recipient is not None:
        request["recipient"] = recipient
    request["methodDetails"] = {"chainId": resolved_chain_id}
    challenge = _create_challenge(
        "tempo",
        "charge",
        request,
        context.realm,
        context.secret_key,
        expires=context.expires,
        header=context.header,
    )
    credential = context.credential
    if credential is None:
        return _respond_challenge(challenge)
    if credential.challenge.method != "tempo" or credential.challenge.intent != "charge":
        return None
    try:
        if not is_address(currency):
            raise VerificationFailedError("missing bootstrap currency")
        if not is_address(recipient):
            raise VerificationFailedError("missing bootstrap recipient")
        await _verify_proof_credential(
            credential, request, secret_key=context.secret_key, store=proof_store
        )
    except PaymentError as error:
        return _respond_challenge(challenge, error)
    except Exception as error:
        internal = InternalPaymentError()
        internal.__cause__ = error
        return _respond_challenge(challenge, internal)

    route_escrow = route.get("escrow_contract", route.get("escrowContract"))
    escrow = route_escrow if isinstance(route_escrow, str) else escrow_contract or ESCROW_ADDRESS
    channel_id = await resolve_session_channel_id(
        request=context.input,
        credential=credential,
        payment_request=route,
        resolve_channel_id=resolve_channel_id,
        store=store,
        source=credential.source,
    )
    snapshot = await resolve_session_snapshot(
        amount=0,
        channel_id=channel_id,
        store=store,
        expected=SnapshotPaymentFields(
            chain_id=resolved_chain_id,
            currency=str(currency),
            escrow_contract=escrow,
            recipient=str(recipient),
        ),
    )
    headers = {"Cache-Control": "no-store"}
    if snapshot is not None:
        headers[PAYMENT_SESSION_HEADER] = snapshot.channel_id
        headers[PAYMENT_SESSION_SNAPSHOT_HEADER] = serialize_snapshot(snapshot)
    return Response(status=204, headers=headers)
