"""Automatic payments for tool calls made with the official ``mcp`` SDK client.

::

    from mcp import Client

    from mpp.mcp_sdk.client import McpClient
    from mpp.tempo import client as tempo

    async with Client("https://example.com/mcp") as session:
        mcp = McpClient(session, methods=[tempo.charge(account=account)])
        result = await mcp.call_tool("premium_tool", {"query": "..."})
        print(result.content, result.receipt)

Payment challenges are handled whether they arrive as payment-required JSON-RPC errors
(``-32042``/``-32043``) or as tool results carrying ``_meta["org.paymentauth/payment-required"]``.
The credential is sent in ``params._meta["org.paymentauth/credential"]``.
"""

from mpp._extras import require

require("mcp", "mcp")

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Protocol

from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult
from pydantic import Field

from mpp import _accept_payment
from mpp import expires as _expires
from mpp import mcp as _mcp
from mpp.challenge import Challenge
from mpp.client import OrderChallenges
from mpp.credential import Credential
from mpp.method import ClientMethod, CredentialParams, resolve
from mpp.receipt import Receipt

MAX_PAYMENT_ATTEMPTS = 3
"""Maximum credentials created for one tool call."""

type OnPaymentRequired = Callable[[Challenge], bool | Awaitable[bool]]
"""Approval hook called with the selected challenge before a credential is created."""

type Methods = Sequence[ClientMethod | Sequence[ClientMethod]]


class ToolSession(Protocol):
    """The tool-calling surface of ``mcp.Client`` / ``mcp.ClientSession``."""

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
        progress_callback: Any = None,
        *,
        input_responses: Any = None,
        request_state: str | None = None,
        meta: Any = None,
    ) -> CallToolResult: ...


class PaidCallToolResult(CallToolResult):
    """A tool result with the payment receipt (``None`` when no payment was made)."""

    receipt: Receipt | None = Field(default=None, exclude=True)


class PaymentDeclinedError(Exception):
    """The payment approval hook declined the selected challenge."""

    def __init__(self) -> None:
        super().__init__("Payment declined.")


class _Unset:
    pass


_UNSET = _Unset()


class McpClient:
    """Wraps an ``mcp`` client session to pay tool-call challenges automatically.

    Args:
        session: An ``mcp.Client`` or ``mcp.ClientSession`` (anything with ``call_tool``).
        methods: Client payment methods (nested sequences are flattened).
        on_payment_required: Approval hook called before creating a credential.
        order_challenges: Filters/sorts supported challenge candidates before payment.
        payment_preferences: Per-capability q-values keyed by ``"method/intent"``.
    """

    def __init__(
        self,
        session: ToolSession,
        *,
        methods: Methods,
        on_payment_required: OnPaymentRequired | None = None,
        order_challenges: OrderChallenges | None = None,
        payment_preferences: _accept_payment.Preferences | None = None,
    ) -> None:
        self.session = session
        self.methods = tuple(
            method
            for entry in methods
            for method in ((entry,) if isinstance(entry, ClientMethod) else entry)
        )
        self.on_payment_required = on_payment_required
        self.order_challenges = order_challenges
        self._preferences = _accept_payment.resolve(self.methods, payment_preferences).entries

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
        progress_callback: Any = None,
        *,
        meta: Mapping[str, Any] | None = None,
        context: Any = None,
        on_payment_required: OnPaymentRequired | _Unset | None = _UNSET,
        **options: Any,
    ) -> PaidCallToolResult:
        """Calls a tool, paying payment challenges with the configured methods.

        Args:
            name: Tool name.
            arguments: Tool arguments.
            read_timeout_seconds: Forwarded to the session.
            progress_callback: Forwarded to the session.
            meta: Request ``_meta`` (the credential is added to it on paid retries).
            context: Context passed to the selected method's ``create_credential``.
            on_payment_required: Per-call approval hook overriding the configured one;
                ``None`` bypasses the configured hook.
            **options: Other session ``call_tool`` keyword arguments (e.g. ``input_responses``,
                ``request_state``), forwarded on the first call and on paid retries.

        Raises:
            ValueError: When no configured method can pay the offered challenges.
            PaymentDeclinedError: When the approval hook declines the payment.
            mpp.PaymentExpiredError: When the selected challenge has expired.
            mcp.shared.exceptions.MCPError: Non-payment errors, or payment errors once
                ``MAX_PAYMENT_ATTEMPTS`` credentials were rejected.
        """
        approve = (
            self.on_payment_required
            if isinstance(on_payment_required, _Unset)
            else on_payment_required
        )

        async def call(call_meta: Mapping[str, Any] | None) -> CallToolResult:
            return await self.session.call_tool(
                name,
                arguments,
                read_timeout_seconds,
                progress_callback,
                meta=dict(call_meta) if call_meta is not None else None,
                **options,
            )

        async def pay(
            required: Mapping[str, Any], cause: object, remaining: int
        ) -> PaidCallToolResult:
            challenge, method = await self._select(required, cause)
            if approve is not None and not await resolve(approve(challenge)):
                raise PaymentDeclinedError() from _exception(cause)
            credential = Credential.deserialize(
                await method.create_credential(
                    CredentialParams(challenge=challenge, context=_parse_context(method, context))
                )
            )
            paid_meta = {**(meta or {}), _mcp.CREDENTIAL_META_KEY: _credential_meta(credential)}
            try:
                result = await call(paid_meta)
            except MCPError as error:
                data = payment_required_data(error)
                if data is None or remaining <= 1:
                    raise
                return await pay(data, error, remaining - 1)
            data = _result_payment_required(result)
            if data is not None and remaining > 1:
                return await pay(data, result, remaining - 1)
            return _with_receipt(result)

        try:
            result = await call(meta)
        except MCPError as error:
            data = payment_required_data(error)
            if data is None:
                raise
            return await pay(data, error, MAX_PAYMENT_ATTEMPTS)
        data = _result_payment_required(result)
        if data is not None:
            return await pay(data, result, MAX_PAYMENT_ATTEMPTS)
        return _with_receipt(result)

    async def _select(
        self, required: Mapping[str, Any], cause: object
    ) -> tuple[Challenge, ClientMethod]:
        challenges = [Challenge.from_dict(challenge) for challenge in required["challenges"]]
        candidates: Sequence[_accept_payment.ChallengeCandidate[ClientMethod]] = (
            _accept_payment.select_challenge_candidates(challenges, self.methods, self._preferences)
        )
        if self.order_challenges is not None:
            candidates = await resolve(self.order_challenges(candidates))
        if not candidates:
            offered = ", ".join(f"{c.method}.{c.intent}" for c in challenges)
            installed = ", ".join(f"{m.name}.{m.intent}" for m in self.methods)
            raise ValueError(
                f"No compatible payment method. Server offers: {offered}. Client has: {installed}"
            ) from _exception(cause)
        selected = candidates[0]
        if selected.challenge.expires:
            _expires.ensure(selected.challenge.expires, selected.challenge.id)
        return selected.challenge, selected.method


def is_payment_required_error(error: object) -> bool:
    """Returns whether ``error`` is an MCP payment error (``-32042``/``-32043``) with challenges."""
    return isinstance(error, MCPError) and payment_required_data(error) is not None


def payment_required_data(error: MCPError) -> Mapping[str, Any] | None:
    """Returns the payment-required ``error.data`` of a payment error, else ``None``."""
    if error.code not in (_mcp.PAYMENT_REQUIRED_CODE, _mcp.PAYMENT_VERIFICATION_FAILED_CODE):
        return None
    return _payment_required(error.data)


def _result_payment_required(result: CallToolResult) -> Mapping[str, Any] | None:
    return _payment_required((result.meta or {}).get(_mcp.PAYMENT_REQUIRED_META_KEY))


def _payment_required(data: object) -> Mapping[str, Any] | None:
    """Validates payment-required data: at least one valid challenge; extra fields pass."""
    if not isinstance(data, Mapping):
        return None
    challenges = data.get("challenges")
    if not isinstance(challenges, list) or not challenges:
        return None
    try:
        for challenge in challenges:
            Challenge.from_dict(challenge)
    except ValueError:
        return None
    return data


def _credential_meta(credential: Credential[Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "challenge": credential.challenge.to_dict(),
        "payload": credential.payload,
    }
    if credential.source:
        value["source"] = credential.source
    return value


def _parse_context(method: ClientMethod, context: Any) -> Any:
    if method.context is None or context is None:
        return None
    return method.context.model_validate(context)


def _with_receipt(result: CallToolResult) -> PaidCallToolResult:
    raw = (result.meta or {}).get(_mcp.RECEIPT_META_KEY)
    receipt: Receipt | None = None
    if isinstance(raw, Mapping):
        try:
            receipt = Receipt.from_dict(raw)
        except ValueError:
            receipt = None
    fields = {name: getattr(result, name) for name in type(result).model_fields}
    return PaidCallToolResult.model_construct(
        _fields_set=result.model_fields_set, **fields, receipt=receipt
    )


def _exception(cause: object) -> BaseException | None:
    return cause if isinstance(cause, BaseException) else None


__all__ = [
    "MAX_PAYMENT_ATTEMPTS",
    "McpClient",
    "OnPaymentRequired",
    "PaidCallToolResult",
    "PaymentDeclinedError",
    "ToolSession",
    "is_payment_required_error",
    "payment_required_data",
]
