"""The TIP-1034 session client method (mppx session/client/Session.ts).

:func:`session` returns the :class:`~mpp.runtime.ClientMethod` that pays
``tempo/session`` challenges: it opens a channel on the first challenge, then
signs incremental cumulative vouchers on the same deposit, topping the deposit
up first when it cannot cover the next voucher.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING

import httpx

from mpp import AUTHORIZATION_HEADER, Challenge
from mpp._parsing import ParseError
from mpp._typing import is_dict
from mpp._units import parse_units
from mpp.methods.tempo.session.client.ops import serialize_credential
from mpp.methods.tempo.session.client.state import (
    ChallengeContext,
    ChannelSink,
    CredentialPlan,
    SessionContext,
    assert_voucher_within_local_limit,
    can_sign_descriptor,
    execute_credential_plan,
    is_tip1034_session_challenge,
    plan_credential,
    read_session_snapshot,
    resolve_automatic_top_up,
    resolve_challenge_context,
)
from mpp.methods.tempo.session.client.store import (
    ChannelEntry,
    ChannelStore,
    UncertainFundingError,
    create_channel_store,
    entry_key,
    maybe_await,
    persist_channel,
    store_get,
    store_lock,
    with_funding_lock,
)
from mpp.methods.tempo.session.protocol import (
    SessionReceipt,
    definition,
    deserialize_session_receipt,
)

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount
    from mpp.runtime import AttemptOutcome, ClientMethod, CredentialParams

Send = Callable[[httpx.Request], Awaitable[httpx.Response]]
"""Sends a management request without payment handling and returns the read response."""

MANAGEMENT_TIMEOUT = 30.0
"""Seconds a management request may take before its outcome is treated as unknown."""


def management_url(url: str | httpx.URL) -> httpx.URL:
    """The URL a management request posts to: the request URL without its fragment."""
    return httpx.URL(url).copy_with(fragment=None)


def management_headers(
    challenge: Challenge, credential: str, authorization: str | None = None
) -> httpx.Headers:
    """Headers for a management POST: the credential, plus a non-Payment Authorization
    when the challenge selects another credential header."""
    header = challenge.credential_header
    headers = httpx.Headers()
    if (
        header.lower() != AUTHORIZATION_HEADER.lower()
        and authorization
        and not authorization.startswith("Payment ")
    ):
        headers[AUTHORIZATION_HEADER] = authorization
    headers[header] = credential
    return headers


def session_challenges(response: httpx.Response) -> list[Challenge]:
    """The TIP-1034 session challenges in a 402 response."""
    from mpp.client.transport import (
        _payment_challenges,  # pyright: ignore[reportPrivateUsage]
    )

    found: list[Challenge] = []
    for header in response.headers.get_list("www-authenticate"):
        for field in _payment_challenges(header):
            try:
                challenge = Challenge.from_www_authenticate(field)
            except ParseError:
                continue
            if is_tip1034_session_challenge(challenge):
                found.append(challenge)
    return found


def read_receipt(response: httpx.Response) -> SessionReceipt | None:
    """The response's session ``Payment-Receipt``, or ``None`` when absent or invalid."""
    header = response.headers.get("payment-receipt")
    if not header:
        return None
    try:
        return deserialize_session_receipt(header)
    except ValueError:
        return None


CreateSessionCredential = Callable[[Challenge, SessionContext], Awaitable[str]]


async def post_management_credential(
    *,
    challenge: Challenge,
    context: SessionContext,
    create_session_credential: CreateSessionCredential,
    send: Send,
    url: str | httpx.URL,
    authorization: str | None = None,
    on_challenge: Callable[[Challenge], None] | None = None,
    on_cancelled_top_up: Callable[[], Awaitable[None]] | None = None,
) -> httpx.Response:
    """POST a management credential (top-up or close), retrying once on a fresh challenge.

    A top-up whose request fails is reported as :class:`UncertainFundingError`,
    since the server may have broadcast its transaction. A top-up cancelled while
    its request is in flight calls ``on_cancelled_top_up`` before the cancellation
    propagates.
    """
    target = management_url(url)

    async def post(current: Challenge) -> httpx.Response:
        credential = await create_session_credential(current, context)
        request = httpx.Request(
            "POST", target, headers=management_headers(current, credential, authorization)
        )
        try:
            return await asyncio.wait_for(send(request), MANAGEMENT_TIMEOUT)
        except asyncio.CancelledError:
            # Like mppx's aborted request: the server may still broadcast the deposit.
            if context.action == "topUp" and on_cancelled_top_up is not None:
                await on_cancelled_top_up()
            raise
        except Exception as error:
            if context.action == "topUp":
                raise UncertainFundingError(
                    "Session top-up request failed; its payment outcome is unknown."
                ) from error
            raise

    response = await post(challenge)
    if response.status_code != 402:
        return response
    fresh = session_challenges(response)
    if not fresh:
        return response
    if on_challenge is not None:
        on_challenge(fresh[0])
    return await post(fresh[0])


class SessionMethod:
    """The configured session client method behind :func:`session` and the session manager."""

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
        on_channel_update: Callable[[ChannelEntry], None] | None = None,
        rpc_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if allowed_chain_ids is not None:
            if isinstance(allowed_chain_ids, (str, bytes)):
                raise ValueError("allowed_chain_ids must be a sequence of chain IDs")
            allowed_chain_ids = tuple(allowed_chain_ids)
        self.account = account
        self.decimals = decimals
        self.max_deposit = parse_units(max_deposit, decimals) if max_deposit is not None else None
        self.top_up_amount = (
            parse_units(top_up_amount, decimals) if top_up_amount is not None else None
        )
        self.escrow = escrow
        self.allow_custom_escrow = allow_custom_escrow
        self.allowed_chain_ids: tuple[int, ...] | None = allowed_chain_ids
        self.store: ChannelStore = (
            channel_store if channel_store is not None else create_channel_store()
        )
        self.on_channel_update = on_channel_update
        self.rpc_url = rpc_url
        self.http_client = http_client
        self.sink = ChannelSink(store=self.store, notify_update=self._notify)
        # SessionManager keeps its own transaction boundary and turns this off.
        self._defer_opens = True
        self._rpc_chain_id: int | None = None

    def _notify(self, entry: ChannelEntry) -> None:
        if self.on_channel_update is not None:
            self.on_channel_update(entry)

    async def _resolve_rpc(self, requested: int | None) -> tuple[str, int]:
        from mpp.methods.tempo._defaults import CHAIN_ID, rpc_url_for_chain

        if self.rpc_url is not None:
            if self._rpc_chain_id is None:
                from mpp.methods.tempo._rpc import _rpc_call  # pyright: ignore[reportPrivateUsage]

                result = await _rpc_call(self.rpc_url, "eth_chainId", [], client=self.http_client)
                self._rpc_chain_id = int(result, 16)
            return self.rpc_url, self._rpc_chain_id
        chain_id = requested if requested is not None else CHAIN_ID
        return rpc_url_for_chain(chain_id), chain_id

    async def resolve(self, challenge: Challenge) -> ChallengeContext:
        """Resolve a challenge against this method's escrow and chain policy."""
        return await resolve_challenge_context(
            challenge,
            resolve_rpc=self._resolve_rpc,
            allow_custom_escrow=self.allow_custom_escrow,
            escrow_override=self.escrow,
            allowed_chain_ids=self.allowed_chain_ids,
        )

    def can_handle_challenge(self, challenge: Challenge) -> bool:
        return is_tip1034_session_challenge(challenge)

    async def create_session_credential(
        self, challenge: Challenge, context: SessionContext | None = None
    ) -> str:
        """Create a credential for ``challenge``, with an optional low-level context."""
        from mpp.runtime import CredentialParams

        return await self.create_credential(CredentialParams(challenge=challenge, context=context))

    async def create_credential(self, params: CredentialParams) -> str:
        """Create the next open, voucher or manual credential for a challenge.

        Automatic credentials are serialized per channel scope, so concurrent
        requests sign strictly increasing cumulative vouchers. When the request
        and an auxiliary sender are known, a deposit that cannot cover the next
        voucher is topped up first.

        When a transport reports the credential's outcome (``params.attempt``), a
        new channel is stored only once the server accepts or acknowledges its
        open, and the scope stays locked until then (mppx Session.ts).
        """
        challenge = params.challenge
        context = params.context
        if context is not None and not isinstance(context, SessionContext):
            raise TypeError("tempo session context must be a SessionContext")
        resolved = await self.resolve(challenge)
        automatic = context is None or (context.action is None and context.descriptor is None)
        scope = f"channel:{resolved.key}"
        lock = store_lock(self.store, scope)
        held = False
        try:
            if automatic:
                await lock.acquire()
                held = True
                await self._top_up_before_voucher(resolved, params)
            entry = await store_get(self.store, resolved.key)
            plan = self._plan(resolved, context, entry)
            if not automatic and plan.type == "open":
                # Fetched again: an unacquired lock may have been dropped meanwhile.
                lock = store_lock(self.store, scope)
                await lock.acquire()
                held = True
                next_entry = await store_get(self.store, resolved.key)
                if next_entry is not entry:
                    plan = self._plan(resolved, context, next_entry)
            attempt = params.attempt
            pending: list[ChannelEntry] = []
            sink = self.sink
            if attempt is not None and self._defer_opens and plan.type == "open":
                sink = ChannelSink(
                    store=_PendingOpenStore(self.store, pending), notify_update=_ignore
                )
            payload = await execute_credential_plan(plan, sink, client=self.http_client)
            credential = serialize_credential(challenge, payload, resolved.chain_id, plan.account)
            if attempt is not None:
                if pending:
                    attempt.settle = self._settle_open(challenge, resolved.key, pending[0], lock)
                    held = False
                else:
                    attempt.settle = _settle_stateless
            return credential
        finally:
            if held:
                lock.release()

    def _settle_open(
        self, challenge: Challenge, key: str, opened: ChannelEntry, lock: asyncio.Lock
    ) -> Callable[[AttemptOutcome], Awaitable[bool]]:
        """Store a deferred open once the server accepts or acknowledges it."""

        async def settle(outcome: AttemptOutcome) -> bool:
            try:
                accepted = outcome.status == "accepted" or _acknowledges_open(
                    outcome, challenge, opened
                )
            except BaseException:
                lock.release()
                raise
            if not accepted and outcome.status == "pending":
                return False
            try:
                if accepted:
                    current = await store_get(self.store, key)
                    if (
                        current is None
                        or not current.opened
                        or current.channel_id.lower() != opened.channel_id.lower()
                    ):
                        await persist_channel(self.store, opened)
                        self._notify(opened)
                return True
            finally:
                lock.release()

        return settle

    def _plan(
        self,
        resolved: ChallengeContext,
        context: SessionContext | None,
        entry: ChannelEntry | None,
    ) -> CredentialPlan:
        return plan_credential(
            account=self.account,
            entry=entry,
            resolved=resolved,
            context=context,
            decimals=self.decimals,
            max_deposit=self.max_deposit,
        )

    async def _top_up_before_voucher(
        self, resolved: ChallengeContext, params: CredentialParams
    ) -> None:
        """Top up a channel whose deposit cannot cover the next voucher (mppx challenge hook)."""
        channel = await store_get(self.store, resolved.key)
        if channel is None or not channel.opened:
            return
        snapshot = resolved.snapshot
        if snapshot is not None and snapshot.channel_id.lower() != channel.channel_id.lower():
            snapshot = None
        next_cumulative = channel.cumulative_amount + resolved.amount
        required = (
            max(snapshot.required_cumulative, next_cumulative) if snapshot else next_cumulative
        )
        deposit = max(snapshot.deposit, channel.deposit) if snapshot else channel.deposit
        if required <= deposit and deposit == channel.deposit:
            return
        if not can_sign_descriptor(self.account, channel.descriptor):
            return
        if required > deposit:
            assert_voucher_within_local_limit(required, self.max_deposit)
        request = params.request
        fetch = params.fetch
        if not isinstance(request, httpx.Request) or fetch is None:
            if required > deposit:
                raise ValueError(
                    "Session deposit cannot cover the next voucher and no request is available "
                    "to top it up."
                )
            return
        authorization = request.headers.get(AUTHORIZATION_HEADER)
        send: Send = fetch
        await self.top_up_channel_if_needed(
            challenge=resolved.challenge,
            channel=channel,
            deposit=deposit,
            required_cumulative=required,
            url=request.url,
            send=send,
            authorization=authorization,
        )

    async def top_up_channel_if_needed(
        self,
        *,
        challenge: Challenge,
        channel: ChannelEntry,
        deposit: int,
        required_cumulative: int,
        url: str | httpx.URL,
        send: Send,
        authorization: str | None = None,
    ) -> SessionReceipt | None:
        """POST an automatic top-up when ``required_cumulative`` exceeds the deposit."""

        async def run() -> SessionReceipt | None:
            nonlocal channel
            funding = await store_get(self.store, entry_key(channel))
            if funding is not None and funding.channel_id == channel.channel_id:
                channel = funding
            if channel.uncertain_top_up:
                raise UncertainFundingError(
                    "Session funding outcome is unknown; reconcile the pending payment before "
                    "another top-up."
                )
            known = max(channel.deposit, deposit)
            suggested = challenge.request.get("suggestedDeposit")
            additional = resolve_automatic_top_up(
                deposit=known,
                required_cumulative=required_cumulative,
                max_deposit=self.max_deposit,
                suggested_deposit=int(suggested) if isinstance(suggested, str) else None,
                top_up_amount=self.top_up_amount,
            )
            receipt = None
            if additional > 0:
                receipt = await self.post_top_up(
                    challenge=challenge,
                    channel=channel,
                    additional_deposit=additional,
                    url=url,
                    send=send,
                    authorization=authorization,
                )
            next_deposit = known + additional
            if next_deposit == channel.deposit:
                return receipt
            current = await store_get(self.store, entry_key(channel))
            latest = (
                current
                if current is not None and current.channel_id.lower() == channel.channel_id.lower()
                else channel
            )
            updated = latest.copy(deposit=max(latest.deposit, next_deposit))
            await persist_channel(self.store, updated)
            self._notify(updated)
            return receipt

        return await with_funding_lock(self.store, entry_key(channel), run)

    async def post_top_up(
        self,
        *,
        challenge: Challenge,
        channel: ChannelEntry,
        additional_deposit: int,
        url: str | httpx.URL,
        send: Send,
        authorization: str | None = None,
        on_challenge: Callable[[Challenge], None] | None = None,
    ) -> SessionReceipt | None:
        """POST a top-up credential for ``channel`` and return the receipt, when present."""
        if channel.uncertain_top_up:
            raise UncertainFundingError(
                "Session funding outcome is unknown; reconcile the pending payment before "
                "another top-up."
            )

        async def mark_uncertain() -> None:
            current = await store_get(self.store, entry_key(channel))
            base = (
                current
                if current is not None and current.channel_id == channel.channel_id
                else channel
            )
            unresolved = base.copy(uncertain_top_up=True)
            await persist_channel(self.store, unresolved)
            self._notify(unresolved)

        try:
            response = await post_management_credential(
                challenge=challenge,
                context=SessionContext(
                    action="topUp",
                    channel_id=channel.channel_id,
                    descriptor=channel.descriptor,
                    additional_deposit_raw=str(additional_deposit),
                ),
                create_session_credential=self.create_session_credential,
                send=send,
                url=url,
                authorization=authorization,
                on_challenge=on_challenge,
                on_cancelled_top_up=mark_uncertain,
            )
        except UncertainFundingError:
            await mark_uncertain()
            raise
        if not response.is_success:
            raise RuntimeError(f"Top-up POST failed with status {response.status_code}")
        return read_receipt(response)

    def client_method(self) -> ClientMethod:
        """This method as a :class:`~mpp.runtime.ClientMethod`."""
        from mpp.runtime import ClientMethod

        return ClientMethod(
            method=definition,
            create_credential=self.create_credential,
            can_handle_challenge=self.can_handle_challenge,
        )


def _ignore(_: ChannelEntry) -> None:
    """Drop update notifications for an open that is not stored yet."""


async def _settle_stateless(outcome: AttemptOutcome) -> bool:
    """Settle a credential that keeps no state (mppx ``settleAttempt`` without ``settle``)."""
    return outcome.status != "pending"


class _PendingOpenStore:
    """A store view that holds back the open it is asked to persist."""

    def __init__(self, store: ChannelStore, pending: list[ChannelEntry]) -> None:
        self._store = store
        self._pending = pending

    async def get(self, key: str) -> ChannelEntry | None:
        return await store_get(self._store, key)

    def set(self, entry: ChannelEntry) -> None:
        self._pending.append(entry)

    async def delete(self, key: str) -> None:
        await maybe_await(self._store.delete(key))


def _matches_open(opened: ChannelEntry, channel_id: str, accepted_cumulative: str | int) -> bool:
    try:
        accepted = int(accepted_cumulative)
    except ValueError:
        return False
    return channel_id.lower() == opened.channel_id.lower() and accepted == opened.cumulative_amount


def _acknowledges_open(outcome: AttemptOutcome, challenge: Challenge, opened: ChannelEntry) -> bool:
    """Whether the server acknowledged an open (mppx ``acknowledgesOpen``).

    A receipt must match the open's challenge, channel and cumulative amount; a
    replacement challenge may acknowledge the same channel and amount in its
    session snapshot.
    """
    response = outcome.response
    try:
        receipt = read_receipt(response) if isinstance(response, httpx.Response) else None
    except Exception:
        # Malformed acknowledgements are ignored, whatever fails parsing them (mppx).
        receipt = None
    if (
        receipt is not None
        and receipt.challenge_id == challenge.id
        and _matches_open(opened, receipt.channel_id, receipt.accepted_cumulative)
    ):
        return True
    for candidate in outcome.challenges:
        if not is_tip1034_session_challenge(candidate):
            continue
        details = candidate.request.get("methodDetails")
        snapshot = read_session_snapshot(details) if is_dict(details) else None
        if snapshot is not None and _matches_open(
            opened, snapshot.channel_id, snapshot.accepted_cumulative
        ):
            return True
    return False


def session(
    *,
    account: TempoAccount,
    max_deposit: str | None = None,
    top_up_amount: str | None = None,
    decimals: int = 6,
    escrow: str | None = None,
    allow_custom_escrow: bool = False,
    allowed_chain_ids: Sequence[int] | None = None,
    channel_store: ChannelStore | None = None,
    on_channel_update: Callable[[ChannelEntry], None] | None = None,
    rpc_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> ClientMethod:
    """Create the client method that pays Tempo session (TIP-1034) challenges.

    The first challenge opens a channel whose deposit is the server's
    ``suggestedDeposit`` (or one request's amount), capped at ``max_deposit``.
    Later challenges for the same payee, token, escrow and chain sign the next
    cumulative voucher on that channel. When the deposit cannot cover it, the
    method first POSTs a top-up of ``top_up_amount``, else the server's
    ``suggestedDeposit``, else the exact shortfall, never past ``max_deposit``.

    Args:
        account: The payer; it signs the channel transactions and vouchers.
        max_deposit: Maximum channel deposit and cumulative authorization, in
            token units (such as ``"10"``). Uncapped when omitted.
        top_up_amount: Preferred automatic top-up size in token units.
        decimals: Token decimals for the amounts above.
        escrow: Exact escrow address to trust instead of the canonical precompile.
        allow_custom_escrow: Accept a non-canonical escrow the server advertises
            (ignored when ``escrow`` pins one).
        allowed_chain_ids: Chains credentials may be signed for; ``None`` allows
            any and an empty sequence rejects all.
        channel_store: Persistence for reusable channels (in memory by default).
        on_channel_update: Called with the channel entry whenever it changes.
        rpc_url: Tempo RPC for open/top-up transactions; the challenge chain's
            default RPC when omitted.
        http_client: httpx client for RPC calls.

    Example:
        from mpp.client import Mpp
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo import client as tempo

        account = TempoAccount.from_key("0x...")
        async with Mpp(methods=[tempo.session(account=account, max_deposit="5")]) as mpp:
            response = await mpp.fetch("https://api.example.com/resource")
    """
    return SessionMethod(
        account=account,
        max_deposit=max_deposit,
        top_up_amount=top_up_amount,
        decimals=decimals,
        escrow=escrow,
        allow_custom_escrow=allow_custom_escrow,
        allowed_chain_ids=allowed_chain_ids,
        channel_store=channel_store,
        on_channel_update=on_channel_update,
        rpc_url=rpc_url,
        http_client=http_client,
    ).client_method()
