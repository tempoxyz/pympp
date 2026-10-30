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
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from mpp import Challenge as CoreChallenge
from mpp._typing import is_dict, is_list
from mpp.errors import NoMethodFoundError
from mpp.errors import PaymentOutcomeUnknownError as PaymentOutcomeUnknownError
from mpp.extensions.mcp.constants import CODE_PAYMENT_REQUIRED, META_CREDENTIAL, META_RECEIPT
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential, MCPReceipt
from mpp.runtime import ChallengeCandidate, ClientMethod, OrderChallenges, PaymentRuntime

logger = logging.getLogger(__name__)


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

    try:
        return MCPChallenge.from_dict(raw_challenge)
    except (KeyError, TypeError, ValueError):
        logger.warning("Ignoring malformed MCP challenge payload", exc_info=True)
        return None


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
            charges; MCP has no authenticated HTTP host to compare.
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
            NoMethodFoundError: If no installed method matches the server's challenge.
            ValueError: If the server's challenges are malformed.
        """
        from anyio import get_cancelled_exc_class
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

            challenges = _extract_challenges(e)
            if not challenges:
                raise ValueError("Server returned malformed payment challenges") from e

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
            challenge, method = self._match_challenge(usable, candidates)

            core_credential = await self._runtime.create_credential(challenge.to_core(), method)
            mcp_credential = MCPCredential.from_core(core_credential, challenge)

            retry_meta = dict(meta) if meta else {}
            retry_meta.update(mcp_credential.to_meta())

            retry_kwargs: dict[str, Any] = {"meta": retry_meta}
            if timeout is not None:
                retry_kwargs["read_timeout_seconds"] = timeout

            try:
                retry_result = await self._session.call_tool(name, arguments, **retry_kwargs)
            except (Exception, get_cancelled_exc_class()) as exc:
                raise PaymentOutcomeUnknownError(challenge, exc) from exc

            receipt = self._extract_receipt(retry_result)
            return McpToolResult(result=retry_result, receipt=receipt)

    def _match_challenge(
        self,
        challenges: Sequence[MCPChallenge],
        candidates: Sequence[ChallengeCandidate] | None = None,
    ) -> tuple[MCPChallenge, ClientMethod]:
        """Return the first payable challenge and the installed method that pays it.

        ``candidates`` come from :meth:`PaymentRuntime.order_challenges` over
        ``challenges``; by default challenges keep the server's order (mppx ``McpClient``).
        Untrusted zero-amount Tempo charges are skipped.
        """
        if candidates is None:
            candidates = self._runtime.challenge_candidates([c.to_core() for c in challenges])
        skipped_zero_tempo = False
        for candidate in candidates:
            challenge = challenges[candidate.index]
            if self._is_untrusted_zero_tempo_charge(challenge):
                skipped_zero_tempo = True
                continue
            return challenge, candidate.method

        available = ", ".join(f"{c.method}.{c.intent}" for c in challenges)
        installed = ", ".join(f"{m.name}.{m.intent}" for m in self._runtime.methods)
        message = (
            f"No compatible payment method. Server offers: {available}. Client has: {installed}"
        )
        if skipped_zero_tempo:
            message += ". Zero-amount Tempo charges require a pinned trusted_tempo_realms entry."
        raise NoMethodFoundError(challenges, self._runtime.methods, message=message)

    def _is_untrusted_zero_tempo_charge(self, challenge: MCPChallenge) -> bool:
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
