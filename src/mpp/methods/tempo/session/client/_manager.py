"""The TIP-1034 session manager (mppx session/client/SessionManager.ts, HTTP parts).

:class:`SessionManager` drives one payer channel over HTTP: :meth:`~SessionManager.fetch`
pays each request with the session method (open, then incremental vouchers,
topping up when needed), :meth:`~SessionManager.top_up` adds deposit and
:meth:`~SessionManager.close` cooperatively closes the channel.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from mpp import AUTHORIZATION_HEADER, Challenge
from mpp._typing import is_dict
from mpp._units import parse_units
from mpp.events import CHALLENGE_RECEIVED
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import SessionReceipt, parse_uint96_amount
from mpp.methods.tempo.session.client._session import (
    SessionMethod,
    post_management_credential,
    read_receipt,
)
from mpp.methods.tempo.session.client._state import (
    SessionContext,
    assert_voucher_within_local_limit,
    is_tip1034_session_challenge,
    read_session_snapshot,
)
from mpp.methods.tempo.session.client._store import (
    ChannelEntry,
    ChannelStore,
    UncertainFundingError,
    create_channel_store,
    delete_channel,
    entry_key,
    persist_channel,
    store_get,
    with_funding_lock,
)

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount

PAYMENT_SESSION_HEADER = "Payment-Session"


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class PaymentResponse:
    """An HTTP response with the session payment metadata (mppx ``PaymentResponse``).

    Other attributes (``status_code``, ``headers``, ``json()``, ...) come from
    :attr:`response`.
    """

    response: httpx.Response
    receipt: SessionReceipt | None
    """The parsed ``Payment-Receipt``, when the response carried one."""
    challenge: Challenge | None
    """The last session challenge the manager saw."""
    channel_id: str | None
    """The active channel ID, when there is one."""
    cumulative: int
    """The local cumulative voucher authorization in raw token units."""

    @property
    def status_code(self) -> int:
        return self.response.status_code

    @property
    def headers(self) -> httpx.Headers:
        return self.response.headers

    def __getattr__(self, name: str) -> Any:
        return getattr(self.response, name)


@dataclass(slots=True, kw_only=True)
class _FetchUse:
    """One fetch's channel bookkeeping, for rolling it back (mppx ``ChannelUse``)."""

    previous: ChannelEntry | None
    previous_spent: int
    committed: tuple[ChannelEntry | None, int] | None = None
    """The state once a server snapshot referenced a channel this fetch opened."""
    challenges_received: int = 0
    created: list[ChannelEntry] = field(default_factory=list[ChannelEntry])


def _is_hash(value: str | None) -> bool:
    if not value or not value.startswith("0x") or len(value) != 66:
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def is_expected_close_receipt(
    receipt: SessionReceipt,
    *,
    challenge_id: str,
    channel_id: str,
    expected_close_amount: str,
    minimum_spent: int = 0,
) -> bool:
    """Whether a close receipt matches the close the client signed."""
    expected = parse_uint96_amount(expected_close_amount)
    spent = parse_uint96_amount(receipt.spent)
    if expected is None or spent is None:
        return False
    return (
        bool(receipt.tx_hash)
        and receipt.challenge_id == challenge_id
        and receipt.channel_id == channel_id
        and receipt.accepted_cumulative == expected_close_amount
        and minimum_spent <= spent <= expected
    )


class SessionManager:
    """Client manager for one TIP-1034 session over HTTP (mppx ``tempo.session.manager``).

    Requests are single-flight: one manager drives one channel, so overlapping
    :meth:`fetch` calls raise. Close it with :meth:`aclose` or ``async with``.
    """

    def __init__(
        self,
        *,
        account: TempoAccount,
        max_deposit: str | None = None,
        top_up_amount: str | None = None,
        decimals: int = 6,
        escrow: str | None = None,
        allow_custom_escrow: bool = False,
        allowed_chain_ids: Sequence[int] | None = None,
        channel_store: ChannelStore | None = None,
        rpc_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        from mpp.client.transport import PaymentTransport

        self._store: ChannelStore = (
            channel_store if channel_store is not None else create_channel_store()
        )
        self._method = SessionMethod(
            account=account,
            max_deposit=max_deposit,
            top_up_amount=top_up_amount,
            decimals=decimals,
            escrow=escrow,
            allow_custom_escrow=allow_custom_escrow,
            allowed_chain_ids=allowed_chain_ids,
            channel_store=self._store,
            on_channel_update=self._on_channel_update,
            rpc_url=rpc_url,
            http_client=http_client,
        )
        # The manager keeps its own transaction boundary (mppx unregisters the
        # response hook): opens are stored at once and rolled back on failure.
        self._method._defer_opens = False  # pyright: ignore[reportPrivateUsage]
        self._decimals = decimals
        self._max_voucher_cumulative = self._method.max_deposit
        self._inner = transport if transport is not None else httpx.AsyncHTTPTransport()
        self._payment_transport = PaymentTransport(
            methods=[self._method.client_method()], inner=self._inner
        )
        self._payment_transport.on(CHALLENGE_RECEIVED, self._on_challenge_received)
        self._client = httpx.AsyncClient(transport=self._payment_transport)
        self._channel: ChannelEntry | None = None
        self._spent = 0
        self._last_challenge: Challenge | None = None
        self._last_url: httpx.URL | None = None
        self._last_authorization: str | None = None
        self._use: _FetchUse | None = None
        self._uncertain_funding: Exception | None = None

    # ── state ──────────────────────────────────────────────────────

    @property
    def channel_id(self) -> str | None:
        """The active channel ID, when a channel was opened or recovered."""
        return self._channel.channel_id if self._channel else None

    @property
    def cumulative(self) -> int:
        """The local cumulative voucher authorization in raw token units."""
        return self._channel.cumulative_amount if self._channel else 0

    @property
    def deposit(self) -> int:
        """The channel deposit the manager knows, in raw token units."""
        return self._channel.deposit if self._channel else 0

    @property
    def spent(self) -> int:
        """The spend the server confirmed in receipts, in raw token units."""
        return self._spent

    @property
    def opened(self) -> bool:
        """Whether the manager has an open local channel."""
        return bool(self._channel and self._channel.opened)

    @property
    def channel(self) -> ChannelEntry | None:
        """The active channel entry."""
        return self._channel

    @property
    def last_challenge(self) -> Challenge | None:
        """The last session challenge the manager saw."""
        return self._last_challenge

    def _on_channel_update(self, entry: ChannelEntry) -> None:
        if self._channel is None or entry.channel_id != self._channel.channel_id:
            self._spent = 0
            if self._use is not None and entry.opened:
                self._use.created.append(entry)
        self._channel = entry

    def _commit_referenced_channel(self, challenge: Challenge) -> bool:
        """Keep a channel this fetch opened once a server snapshot references it."""
        use, channel = self._use, self._channel
        details = challenge.request.get("methodDetails")
        snapshot = details.get("sessionSnapshot") if is_dict(details) else None
        channel_id = snapshot.get("channelId") if is_dict(snapshot) else None
        if not isinstance(channel_id, str) or use is None or not use.created or channel is None:
            return False
        for entry in use.created:
            if entry.channel_id.lower() == channel_id.lower() == channel.channel_id.lower():
                use.created.remove(entry)
                use.committed = (channel.copy(), self._spent)
                return True
        return False

    async def _on_challenge_received(self, payload: Any) -> None:
        challenge: object = payload.get("challenge") if is_dict(payload) else None
        if not isinstance(challenge, Challenge) or not is_tip1034_session_challenge(challenge):
            return
        use, last = self._use, self._last_challenge
        if use is not None:
            # A replacement challenge on a paid retry: undo what the rejected credential
            # changed before signing again (mppx SessionManager onChallenge).
            retry = use.challenges_received > 0
            use.challenges_received += 1
            repeated = retry and last is not None and challenge.id == last.id
            if repeated and challenge == last:
                return
            if retry and not self._commit_referenced_channel(challenge):
                if use.created or repeated:
                    await self._rollback()
        self._last_challenge = challenge

    def _apply_receipt(self, receipt: SessionReceipt | None) -> None:
        channel = self._channel
        if receipt is None or channel is None or receipt.channel_id != channel.channel_id:
            return
        accepted = int(receipt.accepted_cumulative)
        spent = int(receipt.spent)
        if spent > accepted:
            raise ValueError("session receipt spent exceeds accepted cumulative amount")
        # A receipt may not raise the local signing boundary (mppx assertReceiptWithinLocalState).
        if accepted > channel.cumulative_amount:
            raise ValueError("receipt accepted cumulative exceeds local voucher state")
        assert_voucher_within_local_limit(accepted, self._max_voucher_cumulative)
        assert_voucher_within_local_limit(spent, self._max_voucher_cumulative)
        self._spent = max(self._spent, spent)

    async def _send(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        try:
            await response.aread()
        finally:
            await response.aclose()
        return response

    def _response(self, response: httpx.Response) -> PaymentResponse:
        receipt = read_receipt(response)
        self._apply_receipt(receipt)
        return PaymentResponse(
            response=response,
            receipt=receipt,
            challenge=self._last_challenge,
            channel_id=self.channel_id,
            cumulative=self.cumulative,
        )

    async def _rollback(self) -> None:
        """Undo a failed request: drop channels it created, restore the voucher boundary."""
        use = self._use
        if use is None:
            return
        previous, previous_spent = (
            use.committed if use.committed is not None else (use.previous, use.previous_spent)
        )
        created = use.created
        if created:
            for entry in created:
                if entry.uncertain_top_up:
                    raise UncertainFundingError(
                        "Session funding outcome is unknown; reconcile the pending payment "
                        "before discarding the channel."
                    )
                await delete_channel(self._store, entry_key(entry))
            created.clear()
            self._channel = previous
            self._spent = previous_spent
            return
        current = self._channel
        if (
            previous is not None
            and current is not None
            and current.channel_id == previous.channel_id
            and current.cumulative_amount != previous.cumulative_amount
        ):
            restored = current.copy(cumulative_amount=previous.cumulative_amount)
            await persist_channel(self._store, restored)
            self._channel = restored

    # ── requests ───────────────────────────────────────────────────

    async def fetch(
        self, url: str | httpx.URL, *, method: str = "GET", **kwargs: Any
    ) -> PaymentResponse:
        """Send a request, paying its 402 challenge with the session channel.

        Keyword arguments go to ``httpx.AsyncClient.request``. Adds a
        ``Payment-Session`` header naming the open channel, as mppx does.
        """
        if self._use is not None:
            raise RuntimeError(
                "SessionManager: a request is already in flight; concurrent requests on one "
                "manager are not supported"
            )
        if self._uncertain_funding is not None:
            raise self._uncertain_funding
        self._use = _FetchUse(
            previous=self._channel.copy() if self._channel else None, previous_spent=self._spent
        )
        try:
            headers = httpx.Headers(kwargs.pop("headers", None))
            self._last_url = httpx.URL(url)
            self._last_authorization = headers.get(AUTHORIZATION_HEADER)
            if self._channel is not None and self._channel.opened:
                headers.setdefault(PAYMENT_SESSION_HEADER, self._channel.channel_id)
            try:
                response = await self._client.request(method, url, headers=headers, **kwargs)
            except UncertainFundingError as error:
                self._uncertain_funding = error
                raise
            except asyncio.CancelledError:
                await self._note_cancelled_funding()
                raise
            except Exception:
                await self._rollback()
                raise
            result = self._response(response)
            if not response.is_success and result.receipt is None:
                await self._rollback()
                result = PaymentResponse(
                    response=response,
                    receipt=None,
                    challenge=self._last_challenge,
                    channel_id=self.channel_id,
                    cumulative=self.cumulative,
                )
            return result
        finally:
            self._use = None

    async def _note_cancelled_funding(self) -> None:
        """Block funding when a cancelled top-up left its outcome unknown."""
        channel = self._channel
        if channel is None or self._uncertain_funding is not None:
            return
        stored = await store_get(self._store, entry_key(channel))
        if stored is not None and stored.uncertain_top_up:
            self._uncertain_funding = UncertainFundingError(
                "Session top-up was cancelled; its payment outcome is unknown."
            )

    async def top_up(self, amount: str | int) -> SessionReceipt | None:
        """Add deposit to the open channel.

        A string is in token units (parsed with the manager's decimals), an
        int in raw units. Posts a top-up credential to the last requested URL.
        """
        channel = self._channel
        if channel is None or not channel.opened:
            raise ValueError("Cannot top up session: no open channel.")
        challenge = self._last_challenge
        if challenge is None:
            raise ValueError("Cannot top up session: no challenge available. Make a request first.")
        url = self._last_url
        if url is None:
            raise ValueError("Cannot top up session: no URL available. Call fetch() first.")
        if self._uncertain_funding is not None:
            raise self._uncertain_funding
        additional = parse_units(amount, self._decimals) if isinstance(amount, str) else amount
        if additional <= 0:
            raise ValueError("Top-up amount must be greater than zero.")
        assert_voucher_within_local_limit(
            channel.cumulative_amount + additional, self._max_voucher_cumulative
        )

        def set_challenge(fresh: Challenge) -> None:
            self._last_challenge = fresh

        async def run() -> SessionReceipt | None:
            current = await store_get(self._store, entry_key(channel))
            target = (
                current
                if current is not None and current.channel_id == channel.channel_id
                else channel
            )
            try:
                receipt = await self._method.post_top_up(
                    challenge=challenge,
                    channel=target,
                    additional_deposit=additional,
                    url=url,
                    send=self._send,
                    authorization=self._last_authorization,
                    on_challenge=set_challenge,
                )
            except UncertainFundingError as error:
                self._uncertain_funding = error
                raise
            except asyncio.CancelledError:
                await self._note_cancelled_funding()
                raise
            self._apply_receipt(receipt)
            latest = self._channel if self._channel is not None else target
            if latest.channel_id != target.channel_id:
                # The manager moved to another channel meanwhile: still record the deposit
                # on the funded channel when it is the one stored for its scope.
                stored = await store_get(self._store, entry_key(target))
                if stored is not None and stored.channel_id == target.channel_id:
                    funded = max(stored.deposit, target.deposit) + additional
                    await persist_channel(self._store, stored.copy(deposit=funded))
                return receipt
            updated = latest.copy(deposit=max(latest.deposit, target.deposit) + additional)
            await persist_channel(self._store, updated)
            self._channel = updated
            return receipt

        return await with_funding_lock(self._store, entry_key(channel), run)

    def _close_amount(self, channel: ChannelEntry, challenge: Challenge, apply: bool) -> int:
        """The cumulative amount to close at: the server snapshot's accepted amount, else ours."""
        details = challenge.request.get("methodDetails")
        snapshot = read_session_snapshot(details) if is_dict(details) else None
        amount = channel.cumulative_amount
        if snapshot is not None:
            computed = compute_channel_id(
                snapshot.descriptor, chain_id=channel.chain_id, escrow=channel.escrow
            )
            if computed.lower() != snapshot.channel_id.lower():
                raise ValueError("close snapshot descriptor does not match its channel ID")
            if snapshot.channel_id.lower() != channel.channel_id.lower():
                raise ValueError("close snapshot channel ID does not match local session")
            if snapshot.spent > snapshot.accepted_cumulative:
                raise ValueError("close snapshot spent exceeds accepted cumulative amount")
            if snapshot.accepted_cumulative > channel.cumulative_amount:
                raise ValueError("close snapshot accepted cumulative exceeds local voucher state")
            if apply:
                if self._spent > snapshot.accepted_cumulative:
                    raise ValueError(
                        "close snapshot accepted cumulative is below locally confirmed spend"
                    )
                self._spent = max(self._spent, snapshot.spent)
            amount = snapshot.accepted_cumulative
        assert_voucher_within_local_limit(amount, self._max_voucher_cumulative)
        return amount

    async def close(self) -> SessionReceipt | None:
        """Cooperatively close the open channel at the locally authorized amount.

        POSTs a close credential to the last requested URL; the server settles
        and closes on chain and answers 204 with a receipt carrying the close
        transaction hash.
        """
        channel = self._channel
        if channel is None or not channel.opened:
            raise ValueError("Cannot close session: no open channel.")
        challenge = self._last_challenge
        if challenge is None:
            raise ValueError("Cannot close session: no challenge available. Make a request first.")
        url = self._last_url
        if url is None:
            raise ValueError(
                "Cannot close session: no URL available. Call fetch() on this manager first."
            )
        state = {"challenge": challenge, "amount": self._close_amount(channel, challenge, False)}

        async def create(current: Challenge, _: SessionContext) -> str:
            if current is not challenge:
                state["challenge"] = current
                state["amount"] = self._close_amount(channel, current, True)
                self._last_challenge = current
            return await self._method.create_session_credential(
                current,
                SessionContext(
                    action="close",
                    channel_id=channel.channel_id,
                    descriptor=channel.descriptor,
                    cumulative_amount_raw=str(state["amount"]),
                ),
            )

        response = await post_management_credential(
            challenge=challenge,
            context=SessionContext(action="close"),
            create_session_credential=create,
            send=self._send,
            url=url,
            authorization=self._last_authorization,
        )
        if not response.is_success:
            detail = response.text[:500] if response.content else ""
            www = response.headers.get("www-authenticate", "")
            message = f"Close request failed with status {response.status_code}"
            if detail:
                message += f": {detail}"
            if www:
                message += f" [WWW-Authenticate: {www}]"
            raise RuntimeError(message)
        receipt = read_receipt(response)
        if receipt is None:
            return None
        close_challenge = state["challenge"]
        assert isinstance(close_challenge, Challenge)
        if not _is_hash(receipt.tx_hash) or not is_expected_close_receipt(
            receipt,
            challenge_id=close_challenge.id,
            channel_id=channel.channel_id,
            expected_close_amount=str(state["amount"]),
            minimum_spent=self._spent,
        ):
            raise ValueError("Session close response included a mismatched payment receipt.")
        self._spent = max(self._spent, int(receipt.spent))
        return receipt

    async def aclose(self) -> None:
        """Close the HTTP client and transport."""
        await self._client.aclose()

    async def __aenter__(self) -> SessionManager:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


def session_manager(
    *,
    account: TempoAccount,
    max_deposit: str | None = None,
    top_up_amount: str | None = None,
    decimals: int = 6,
    escrow: str | None = None,
    allow_custom_escrow: bool = False,
    allowed_chain_ids: Sequence[int] | None = None,
    channel_store: ChannelStore | None = None,
    rpc_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SessionManager:
    """Create a :class:`SessionManager` (mppx ``tempo.session.manager``).

    Options are those of :func:`~mpp.methods.tempo.session.client._session`, plus
    ``transport``, the httpx transport requests go through (mppx ``fetch``).

    Example:
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo import client as tempo

        async with tempo.session_manager(account=account, max_deposit="5") as manager:
            response = await manager.fetch("https://api.example.com/resource")
            await manager.top_up("1")
            receipt = await manager.close()
    """
    return SessionManager(
        account=account,
        max_deposit=max_deposit,
        top_up_amount=top_up_amount,
        decimals=decimals,
        escrow=escrow,
        allow_custom_escrow=allow_custom_escrow,
        allowed_chain_ids=allowed_chain_ids,
        channel_store=channel_store,
        rpc_url=rpc_url,
        http_client=http_client,
        transport=transport,
    )
