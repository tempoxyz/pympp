"""Payment-aware MCP client wrapper.

Wraps an MCP SDK ``ClientSession`` with automatic payment handling.
When a tool call returns a ``-32042`` payment required error, the wrapper
creates a Credential and retries the call—mirroring the TypeScript
``McpClient.wrap`` API.

Example:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    from mpp.extensions.mcp import McpClient
    from mpp.methods.tempo import TempoAccount
    from mpp.methods.tempo import client as tempo

    account = TempoAccount.from_key("0x...")
    method = tempo.charge(account=account)

    async with sse_client("http://localhost:8000/sse") as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()

            client = McpClient(session, methods=[method])
            result = await client.call_tool("premium_tool", {"query": "hello"})
            print(result.receipt)
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from typing import Any

from mpp import Challenge as CoreChallenge
from mpp import Credential as CoreCredential
from mpp._challenge_identity import same_challenge
from mpp._parsing import is_payment_authorization_header
from mpp._pending_settlement import resume as resume_pending_settlement
from mpp._typing import is_dict, is_list
from mpp.errors import NoMethodFoundError, ZoneSettlementPendingError, ZoneWithdrawalBouncedError
from mpp.errors import PaymentOutcomeUnknownError as PaymentOutcomeUnknownError
from mpp.extensions.mcp.constants import (
    CODE_PAYMENT_REQUIRED,
    CODE_PAYMENT_VERIFICATION_FAILED,
    HTTP_STATUS_PAYMENT_REQUIRED,
    META_CREDENTIAL,
    META_RECEIPT,
)
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt
from mpp.runtime import (
    AttemptOutcome,
    ChallengeCandidate,
    ClientMethod,
    OrderChallenges,
    PaymentAttempt,
    PaymentRuntime,
)
from mpp.x402._client import is_x402_challenge

logger = logging.getLogger(__name__)

# Credential creations per paid call while a Zone withdrawal settles, as mppx's McpClient.
_MAX_PAYMENT_ATTEMPTS = 3

# Errors a method raises to report funds it may already have moved (a broadcast payment, a
# Zone withdrawal on chain), with the Challenge to resume or reconcile it: raised as is.
_FUNDS_MOVED_ERRORS = (
    PaymentOutcomeUnknownError,
    ZoneSettlementPendingError,
    ZoneWithdrawalBouncedError,
)


def _error_code(error: Exception) -> int | None:
    code = getattr(error, "code", None)
    if code is not None:
        return code
    nested = getattr(error, "error", None)
    return getattr(nested, "code", None)


def _error_data(error: Exception) -> Any:
    data = getattr(error, "data", None)
    if data is not None:
        return data
    nested = getattr(error, "error", None)
    return getattr(nested, "data", None)


def _is_payment_required_error(error: Exception) -> bool:
    """Check whether an MCP error is a -32042 payment required error.

    Distinguishes payment errors from other uses of -32042 (such as
    URL elicitation) by checking for a ``challenges`` array in ``error.data``.
    """
    if _error_code(error) != CODE_PAYMENT_REQUIRED:
        return False
    data = _error_data(error)
    if not is_dict(data):
        return False
    challenges = data.get("challenges")
    return is_list(challenges) and any(isinstance(challenge, dict) for challenge in challenges)


def _parse_challenge(raw_challenge: Any) -> MCPChallenge | None:
    """Parse a server-provided challenge, skipping malformed entries."""
    if not is_dict(raw_challenge):
        logger.warning(
            "Ignoring malformed MCP challenge: expected dict, got %s",
            type(raw_challenge).__name__,
        )
        return None

    for field in ("id", "realm", "method", "intent"):
        value = raw_challenge.get(field)
        if not isinstance(value, str) or not value:
            logger.warning("Ignoring malformed MCP challenge: invalid %s", field)
            return None

    if not isinstance(raw_challenge.get("request"), dict):
        logger.warning("Ignoring malformed MCP challenge: invalid request")
        return None

    if _has_unsupported_credential_header(raw_challenge):
        logger.warning("Ignoring MCP challenge: unsupported credential header")
        return None

    try:
        return MCPChallenge.from_dict(raw_challenge)
    except (KeyError, TypeError, ValueError):
        logger.warning("Ignoring malformed MCP challenge payload", exc_info=True)
        return None


def _has_unsupported_credential_header(raw_challenge: object) -> bool:
    """Whether a raw challenge selects a credential header other than Payment-Authorization.

    Such a challenge is unrecognized and gets no credential (https://paymentauth.org).
    """
    if not is_dict(raw_challenge) or "header" not in raw_challenge:
        return False
    header = raw_challenge["header"]
    return not (isinstance(header, str) and is_payment_authorization_header(header))


def _only_unsupported_credential_headers(error: Exception) -> bool:
    """Whether every offered challenge was dropped for an unsupported credential header."""
    data = _error_data(error)
    raw_challenges = data.get("challenges") if is_dict(data) else None
    return (
        is_list(raw_challenges)
        and len(raw_challenges) > 0
        and all(_has_unsupported_credential_header(raw) for raw in raw_challenges)
    )


def _extract_challenges(error: Exception) -> list[MCPChallenge]:
    """Extract valid payment challenges from a payment required error."""
    data = _error_data(error)
    if not is_dict(data):
        return []

    raw_challenges = data.get("challenges")
    if not is_list(raw_challenges):
        return []

    challenges: list[MCPChallenge] = []
    for raw_challenge in raw_challenges:
        challenge = _parse_challenge(raw_challenge)
        if challenge is not None:
            challenges.append(challenge)
    return challenges


@dataclass(frozen=True, slots=True)
class McpToolResult:
    """Result of a payment-aware tool call.

    Wraps the raw MCP ``CallToolResult`` and surfaces the payment receipt.
    """

    result: Any
    receipt: MCPReceipt | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.result, name)


class McpClient:
    """Payment-aware MCP client wrapper.

    Wraps an MCP SDK ``ClientSession`` and overrides ``call_tool`` with
    automatic payment handling. When a tool call returns ``-32042``, the
    wrapper matches the challenge to an installed payment method, creates
    a credential, and retries.

    Args:
        session: An initialized ``mcp.ClientSession``.
        methods: Client payment methods available for credential creation, in
            preference order (nested sequences are flattened).
        trusted_tempo_realms: Explicitly trusted realms for zero-amount Tempo
            charges and Tempo sessions; MCP has no authenticated HTTP host to compare.
        order_challenges: Filters and sorts the payable challenges before credential
            creation (mppx ``orderChallenges``); the first returned candidate is paid.

    Example:
        client = McpClient(session, methods=[tempo.charge(account=account)])
        result = await client.call_tool("premium_tool", {"query": "hello"})
        print(result.receipt)
    """

    def __init__(
        self,
        session: Any,
        methods: Sequence[ClientMethod | Any],
        *,
        trusted_tempo_realms: Sequence[str] = (),
        order_challenges: OrderChallenges | None = None,
    ) -> None:
        self._session = session
        self._runtime = PaymentRuntime(methods)
        self._trusted_tempo_realms = set(trusted_tempo_realms)
        self._order_challenges = order_challenges

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        meta: dict[str, Any] | None = None,
    ) -> McpToolResult:
        """Call an MCP tool with automatic payment handling.

        On a ``-32042`` error, matches the challenge to an installed method,
        creates a credential, and retries the call with the credential in
        ``params._meta``.

        Args:
            name: Tool name.
            arguments: Tool arguments.
            timeout: Per-call timeout override (passed as ``read_timeout_seconds``).
            meta: Additional ``_meta`` fields to include in the request.

        Returns:
            An ``McpToolResult`` with the tool result and an optional receipt.

        Raises:
            McpError: If the error is not payment-related or no method matches.
            PaymentOutcomeUnknownError: If the paid retry fails after sending a credential.
            ZoneSettlementPendingError: If a Zone withdrawal paying a challenge has not
                settled yet: retry with its ``challenge`` to resume waiting.
            NoMethodFoundError: If no installed method matches the server's challenge.
            ValueError: If the server's challenges are malformed.
        """
        from mcp.shared.exceptions import McpError

        call_kwargs: dict[str, Any] = {}
        if timeout is not None:
            call_kwargs["read_timeout_seconds"] = timeout
        if meta is not None:
            call_kwargs["meta"] = meta

        try:
            result = await self._session.call_tool(name, arguments, **call_kwargs)
            receipt = self._extract_receipt(result)
            return McpToolResult(result=result, receipt=receipt)

        except McpError as e:
            if not _is_payment_required_error(e) or (meta and META_CREDENTIAL in meta):
                raise
            return await self._pay(name, arguments, e, meta=meta, timeout=timeout)

    async def _pay(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        error: Exception,
        *,
        meta: dict[str, Any] | None,
        timeout: float | None,
    ) -> McpToolResult:
        """Pay the challenges of a ``-32042`` error and call the tool again with the credential.

        As mppx ``Fetch``: a ``-32042``, or a ``-32043`` with HTTP status 402, answering a
        credential starts a new round, selected with every check. A new Challenge (such as
        the real charge after a zero-amount proof) rejects the credential and pays it; the
        same Challenge (by id) resends the same credential unless its method reports the
        attempt settled. A call sends at most ``_MAX_PAYMENT_ATTEMPTS`` credentials.
        """
        from anyio import CancelScope, get_cancelled_exc_class

        challenge, method = await self._select_challenge(error)
        sends = 0
        # The Credential last sent and the server's refusal of it, once a round has ended.
        refused: tuple[MCPChallenge, BaseException] | None = None
        while True:
            attempt = PaymentAttempt()
            try:
                core_challenge = challenge.to_core()

                def create(
                    check_expiry: bool,
                    challenge: CoreChallenge = core_challenge,
                    method: ClientMethod = method,
                    attempt: PaymentAttempt = attempt,
                ) -> Awaitable[CoreCredential]:
                    return self._runtime.create_credential(
                        challenge, method, attempt=attempt, check_expiry=check_expiry
                    )

                # A Zone withdrawal still settling is resumed for this same Challenge
                # rather than paid again under a new one (mppx).
                core_credential = await resume_pending_settlement(create, _MAX_PAYMENT_ATTEMPTS)
                mcp_credential = MCPCredential.from_core(core_credential, challenge)
                retry_meta = dict(meta) if meta else {}
                retry_meta.update(mcp_credential.to_meta())
            except BaseException as failure:
                # A credential that never reaches the server is rejected, so the method
                # releases its state, even when an event handler fails or the call is
                # cancelled after signing (as over HTTP).
                with CancelScope(shield=True):
                    await _settle_attempt(attempt, AttemptOutcome(status="rejected"))
                if (
                    refused is None
                    or not isinstance(failure, Exception)
                    # The method's own report of funds it moved (a broadcast push payment's
                    # hash, a pending Zone withdrawal's Challenge): keep it, as over HTTP.
                    or isinstance(failure, _FUNDS_MOVED_ERRORS)
                ):
                    raise
                # A later round failed before sending (such as an expired replacement): the
                # Credential already sent is what the caller must reconcile.
                raise PaymentOutcomeUnknownError(*refused) from failure

            retry_kwargs: dict[str, Any] = {"meta": retry_meta}
            if timeout is not None:
                retry_kwargs["read_timeout_seconds"] = timeout

            while True:
                sends += 1
                # The method may keep state for this credential until it learns the outcome,
                # as over HTTP. The server verifies a credential before it runs the tool and
                # refuses it with a -32042 error, so a returned tool result counts as
                # accepted, even one reporting a tool error.
                try:
                    retry_result = await self._session.call_tool(name, arguments, **retry_kwargs)
                except (Exception, get_cancelled_exc_class()) as exc:
                    # A replacement challenge may still acknowledge what the credential opened.
                    replacements = _error_challenges(exc)
                    selected: tuple[MCPChallenge, ClientMethod] | None = None
                    if (
                        replacements
                        and isinstance(exc, Exception)
                        and _starts_new_round(exc)
                        and sends < _MAX_PAYMENT_ATTEMPTS
                        # An x402 or evm/charge authorization stays spendable after a
                        # refusal: paying a new challenge could pay twice (as over HTTP).
                        and not _stays_spendable(core_challenge)
                    ):
                        try:
                            selected = await self._select_challenge(exc)
                        except (NoMethodFoundError, ValueError):
                            pass
                        except Exception as selection_error:
                            # A failing order hook ends the call like no payable challenge.
                            logger.warning(
                                "Selecting a new payment round failed (%s)",
                                type(selection_error).__name__,
                            )
                        except BaseException:
                            # Cancelled while selecting: release what the credential holds
                            # (such as a deferred open's scope lock), then propagate.
                            with CancelScope(shield=True):
                                await _settle_attempt(
                                    attempt,
                                    AttemptOutcome(status="rejected", challenges=replacements),
                                )
                            raise
                    if selected is None:
                        # No payable challenge: the server's final answer to this credential.
                        await _settle_attempt(
                            attempt, AttemptOutcome(status="rejected", challenges=replacements)
                        )
                        raise PaymentOutcomeUnknownError(challenge, exc) from exc
                    same = selected[1] is method and same_challenge(
                        selected[0].to_core(), core_challenge
                    )
                    settled = await _settle_reporting(
                        attempt,
                        AttemptOutcome(
                            status="pending" if same else "rejected", challenges=replacements
                        ),
                    )
                    if settled is None:
                        # The method failed to settle: its state is unknown, so neither
                        # resend nor pay again.
                        raise PaymentOutcomeUnknownError(challenge, exc) from exc
                    if same and not settled:
                        # The method still holds this credential (a session voucher or open):
                        # resend it rather than sign another (mppx ``canReusePrevious``).
                        continue
                    if _is_pushed(core_credential):
                        # A payment already on chain: paying again could pay twice.
                        raise PaymentOutcomeUnknownError(challenge, exc) from exc
                    refused = (challenge, exc)
                    challenge, method = selected
                    break

                await _settle_attempt(attempt, AttemptOutcome(status="accepted"))
                receipt = self._extract_receipt(retry_result)
                return McpToolResult(result=retry_result, receipt=receipt)

    async def _select_challenge(self, error: Exception) -> tuple[MCPChallenge, ClientMethod]:
        """Return the challenge of a payment error to pay and the method that pays it.

        Raises:
            NoMethodFoundError: If no installed method matches a challenge.
            ValueError: If the server's challenges are malformed.
        """
        challenges = _extract_challenges(error)
        if not challenges and _only_unsupported_credential_headers(error):
            # Well-formed but unsupported challenges: nothing this client may pay.
            raise NoMethodFoundError(
                (),
                self._runtime.methods,
                message=(
                    "No supported payment challenge: every challenge selects an "
                    "unsupported credential header"
                ),
            ) from error
        if not challenges:
            raise ValueError("Server returned malformed payment challenges") from error

        # A challenge that can't be converted (such as a request that won't
        # canonicalize) is unpayable on its own; it doesn't block the others.
        usable: list[MCPChallenge] = []
        cores: list[CoreChallenge] = []
        for offered in challenges:
            try:
                cores.append(offered.to_core())
            except Exception:  # noqa: BLE001 - any conversion failure means unpayable
                continue
            usable.append(offered)
        candidates = await self._runtime.order_challenges(cores, self._order_challenges)
        return self._match_challenge(usable, candidates)

    def _match_challenge(
        self,
        challenges: Sequence[MCPChallenge],
        candidates: Sequence[ChallengeCandidate] | None = None,
    ) -> tuple[MCPChallenge, ClientMethod]:
        """Return the first payable challenge and the installed method that pays it.

        ``candidates`` come from :meth:`PaymentRuntime.order_challenges` over
        ``challenges``; by default challenges keep the server's order (mppx ``McpClient``).
        Untrusted zero-amount Tempo charges and Tempo sessions are skipped.
        """
        if candidates is None:
            candidates = self._runtime.challenge_candidates([c.to_core() for c in challenges])
        skipped_zero_tempo = False
        for candidate in candidates:
            challenge = challenges[candidate.index]
            if self._is_untrusted_tempo_realm(challenge):
                skipped_zero_tempo = True
                continue
            return challenge, candidate.method

        available = ", ".join(f"{c.method}.{c.intent}" for c in challenges)
        installed = ", ".join(f"{m.name}.{m.intent}" for m in self._runtime.methods)
        message = (
            f"No compatible payment method. Server offers: {available}. Client has: {installed}"
        )
        if skipped_zero_tempo:
            message += (
                ". Zero-amount Tempo charges and Tempo sessions require a pinned "
                "trusted_tempo_realms entry."
            )
        raise NoMethodFoundError(challenges, self._runtime.methods, message=message)

    def _is_untrusted_tempo_realm(self, challenge: MCPChallenge) -> bool:
        """Whether ``challenge`` signs for a realm MCP cannot authenticate: a zero-amount
        ``tempo/charge`` proof or a ``tempo/session`` payment not pinned in
        ``trusted_tempo_realms`` (mppx ``ProofRealm.assertWithoutOrigin``)."""
        if challenge.method == "tempo" and challenge.intent == "session":
            return challenge.realm not in self._trusted_tempo_realms
        if challenge.method != "tempo" or challenge.intent != "charge":
            return False
        try:
            zero = int(challenge.request["amount"]) == 0
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        return zero and challenge.realm not in self._trusted_tempo_realms

    @staticmethod
    def _extract_receipt(result: Any) -> MCPReceipt | None:
        """Extract a payment receipt from a tool result's _meta."""
        meta = getattr(result, "meta", None)
        if not meta or not is_dict(meta):
            return None
        receipt_data = meta.get(META_RECEIPT)
        if receipt_data is None:
            return None
        try:
            return MCPReceipt.from_dict(receipt_data)
        except (KeyError, TypeError):
            logger.warning("Failed to parse receipt from _meta")
            return None


def _stays_spendable(challenge: CoreChallenge) -> bool:
    """Whether a credential for ``challenge`` stays spendable after a refusal: an x402 or
    ``evm/charge`` authorization could be redeemed as well as a new payment."""
    return is_x402_challenge(challenge) or (
        challenge.method == "evm" and challenge.intent == "charge"
    )


def _is_pushed(credential: CoreCredential) -> bool:
    """Whether the credential reports a payment the client already broadcast."""
    payload = credential.payload
    return is_dict(payload) and payload.get("type") in ("hash", "zone")


def _core_challenges(challenges: Sequence[MCPChallenge]) -> tuple[CoreChallenge, ...]:
    """The challenges among ``challenges`` that convert to core challenges."""
    cores: list[CoreChallenge] = []
    for offered in challenges:
        try:
            cores.append(offered.to_core())
        except Exception:  # noqa: BLE001 - an unconvertible challenge acknowledges nothing
            continue
    return tuple(cores)


def _error_challenges(error: BaseException) -> tuple[CoreChallenge, ...]:
    """The challenges of a ``-32042`` payment required or ``-32043`` verification
    failed error, else none: the server sends fresh challenges with either."""
    if not isinstance(error, Exception):
        return ()
    if not _is_payment_required_error(error) and _error_code(error) != (
        CODE_PAYMENT_VERIFICATION_FAILED
    ):
        return ()
    return _core_challenges(_extract_challenges(error))


def _starts_new_round(error: Exception) -> bool:
    """Whether a refusal may start a new payment round: a ``-32042``, or a ``-32043``
    whose ``httpStatus`` is 402 or absent. As over HTTP, only a 402 starts one, so a
    channel that is gone (410) is final."""
    code = _error_code(error)
    if code == CODE_PAYMENT_REQUIRED:
        return True
    if code != CODE_PAYMENT_VERIFICATION_FAILED:
        return False
    data = _error_data(error)
    status = (
        data.get("httpStatus", HTTP_STATUS_PAYMENT_REQUIRED)
        if is_dict(data)
        else HTTP_STATUS_PAYMENT_REQUIRED
    )
    return (
        isinstance(status, int)
        and not isinstance(status, bool)
        and status == HTTP_STATUS_PAYMENT_REQUIRED
    )


async def _settle_reporting(attempt: PaymentAttempt, outcome: AttemptOutcome) -> bool | None:
    """Report ``outcome`` to the method; whether it settled the attempt (mppx
    ``settleAttempt``), or ``None`` when its settle hook failed.

    A method without a settle hook keeps no state, so only a pending outcome leaves its
    credential unsettled. A failing hook is logged, never raised: the tool call's own
    outcome wins.
    """
    settle = attempt.settle
    if settle is None:
        return outcome.status != "pending"
    attempt.settle = None
    try:
        settled = await settle(outcome)
    except Exception as error:  # noqa: BLE001 - the tool call's own outcome wins
        logger.warning(
            "Payment method failed to settle a paid tool call (%s)", type(error).__name__
        )
        return None
    if not settled:
        attempt.settle = settle
    return settled


async def _settle_attempt(attempt: PaymentAttempt, outcome: AttemptOutcome) -> None:
    """Report a paid retry's outcome to the method that created its credential.

    A tool call has no redirect or resend, so an accepted outcome the method doesn't settle
    is settled as rejected, which releases whatever it kept for the credential. A failing
    settle hook is logged, never raised: the server has already answered the call.
    """
    settle = attempt.settle
    if settle is None:
        return
    attempt.settle = None
    try:
        if await settle(outcome) or outcome.status == "rejected":
            return
        await settle(AttemptOutcome(status="rejected", challenges=outcome.challenges))
    except Exception as error:  # noqa: BLE001 - the tool call's own outcome wins
        logger.warning(
            "Payment method failed to settle a paid tool call (%s)", type(error).__name__
        )
